//! Controlled media extraction. Provider components receive projected metadata,
//! never arbitrary tool arguments, local paths, headers, or credential bytes.
use omd_domain::{
    CollectionKind, HostGrant, Locator, LogicalOutput, MediaSelection, Plan, Problem, Recipe,
    ResolvedRelease, SelectionPolicy, digest, path_segment,
};
use omd_network::Network;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

mod container;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    pub path: PathBuf,
    pub sha256: String,
    pub version: String,
}
impl Tool {
    pub async fn verify(&self) -> Result<(), Problem> {
        self.read_verified().await.map(|_| ())
    }
    pub async fn read_verified(&self) -> Result<Vec<u8>, Problem> {
        use tokio::io::AsyncReadExt;
        let unavailable = || {
            issue(
                "tool_unavailable",
                "Restore the managed media tool and retry.",
                "restore_tool",
            )
        };
        let parent = self.path.parent().ok_or_else(unavailable)?;
        let name = self
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(unavailable)?;
        let root = omd_files::Root::open(parent).map_err(|_| unavailable())?;
        // Handle-relative nonblocking open rejects symlinks and special files,
        // including a FIFO substituted after manifest review.
        let file = root.read_file(name).map_err(|_| unavailable())?;
        if file.metadata().map_err(|_| unavailable())?.len() > 200 * 1024 * 1024 {
            return Err(issue(
                "tool_integrity",
                "The managed media tool failed integrity verification.",
                "restore_tool",
            ));
        }
        let file = tokio::fs::File::from_std(file);
        let mut bytes = Vec::new();
        file.take(200 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| {
                issue(
                    "tool_unavailable",
                    "Restore the managed media tool and retry.",
                    "restore_tool",
                )
            })?;
        if bytes.len() > 200 * 1024 * 1024 || digest(&bytes) != self.sha256 {
            return Err(issue(
                "tool_integrity",
                "The managed media tool failed integrity verification.",
                "restore_tool",
            ));
        }
        Ok(bytes)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tools {
    pub yt_dlp: Tool,
    pub node: Option<Tool>,
    pub ffmpeg: Option<Tool>,
    pub ffprobe: Option<Tool>,
}
#[cfg(windows)]
impl Tool {
    pub async fn stage(&self, directory: &Path) -> Result<Self, Problem> {
        use std::io::Write;
        let bytes = self.read_verified().await?;
        let name = self.path.file_name().ok_or_else(|| {
            issue(
                "tool_storage",
                "The managed tool path is invalid.",
                "restore_tool",
            )
        })?;
        let path = directory.join(name);
        let mut file = omd_files::create_private_file(&path).map_err(|_| {
            issue(
                "tool_storage",
                "The private runtime could not be created.",
                "retry",
            )
        })?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| {
                issue(
                    "tool_storage",
                    "The private runtime could not be saved.",
                    "retry",
                )
            })?;
        Ok(Self {
            path,
            sha256: self.sha256.clone(),
            version: self.version.clone(),
        })
    }
}
#[cfg(windows)]
impl Tools {
    async fn stage(&self, work: &Path) -> Result<(Self, tempfile::TempDir), Problem> {
        let runtime = tempfile::Builder::new()
            .prefix(".omd-runtime-")
            .tempdir_in(work)
            .map_err(|_| {
                issue(
                    "tool_storage",
                    "The private runtime directory is unavailable.",
                    "retry",
                )
            })?;
        let stage = async |tool: &Option<Tool>| match tool {
            Some(tool) => tool.stage(runtime.path()).await.map(Some),
            None => Ok(None),
        };
        let tools = Self {
            yt_dlp: self.yt_dlp.stage(runtime.path()).await?,
            node: stage(&self.node).await?,
            ffmpeg: stage(&self.ffmpeg).await?,
            ffprobe: stage(&self.ffprobe).await?,
        };
        Ok((tools, runtime))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inspect {
    pub url: String,
    pub cursor: Option<String>,
    pub page_size: u32,
}
#[derive(Clone)]
pub struct Media {
    pub tools: Tools,
    pub network: Network,
    pub work_root: PathBuf,
    pub revoked: CancellationToken,
}
fn issue(code: &str, message: &str, action: &str) -> Problem {
    Problem {
        code: code.into(),
        message: message.into(),
        retryable: action == "retry",
        actions: vec![action.into()],
    }
}
impl Media {
    pub fn matches(&self, selection: &MediaSelection) -> bool {
        !self.revoked.is_cancelled()
            && self.tools.yt_dlp.sha256 == selection.yt_dlp_digest
            && self
                .tools
                .ffmpeg
                .as_ref()
                .is_some_and(|t| t.sha256 == selection.ffmpeg_digest)
            && self
                .tools
                .ffprobe
                .as_ref()
                .is_some_and(|t| t.sha256 == selection.ffprobe_digest)
            && self.tools.node.as_ref().map(|t| &t.sha256) == selection.node_digest.as_ref()
    }
    pub async fn inspect(
        &self,
        request: &Inspect,
        provider: &str,
        grants: &[HostGrant],
        credential_profile: Option<&str>,
        cancel: &CancellationToken,
    ) -> Result<Value, Problem> {
        tokio::select! { biased;
            _=self.revoked.cancelled()=>Err(issue("tool_removed","Restore the approved tool set to continue.","restore_tool")),
            result=self.inspect_inner(request,provider,grants,credential_profile,cancel)=>result,
        }
    }
    async fn inspect_inner(
        &self,
        request: &Inspect,
        provider: &str,
        grants: &[HostGrant],
        credential_profile: Option<&str>,
        cancel: &CancellationToken,
    ) -> Result<Value, Problem> {
        let raw = self
            .extract(request, provider, grants, credential_profile, cancel, None)
            .await?;
        let offset = request
            .cursor
            .as_deref()
            .unwrap_or("0")
            .parse()
            .map_err(|_| issue("media_cursor", "Invalid media cursor.", "retry"))?;
        project(&raw, offset, request.page_size)
    }
    async fn extract(
        &self,
        request: &Inspect,
        provider: &str,
        grants: &[HostGrant],
        credential_profile: Option<&str>,
        cancel: &CancellationToken,
        selection: Option<(Recipe, &SelectionPolicy)>,
    ) -> Result<Value, Problem> {
        self.tools.yt_dlp.verify().await?;
        let url = url::Url::parse(&request.url).map_err(|_| {
            issue(
                "media_url",
                "Use a canonical HTTPS media URL.",
                "prepare_again",
            )
        })?;
        if !grants
            .iter()
            .any(|g| omd_network::validate_url(&url, g).is_ok())
            || request.page_size == 0
            || request.page_size > 200
        {
            return Err(issue(
                "media_permission",
                "The media URL is outside the source permission.",
                "review_permissions",
            ));
        }
        let offset = request
            .cursor
            .as_deref()
            .unwrap_or("0")
            .parse::<u32>()
            .map_err(|_| {
                issue(
                    "media_cursor",
                    "Refresh this collection to obtain a valid cursor.",
                    "retry",
                )
            })?;
        let end = offset
            .checked_add(request.page_size + 1)
            .filter(|n| *n <= 200_001)
            .ok_or_else(|| {
                issue(
                    "media_cursor",
                    "The collection exceeds the enumeration budget.",
                    "prepare_again",
                )
            })?;
        let session = self
            .network
            .session(provider, credential_profile, grants)
            .await
            .map_err(credential_problem)?;
        let redactor = session.clone();
        let input = cookie_config(session.as_ref(), &url, grants)?;
        let broker = omd_helper_broker::Broker::start_media(
            self.network.clone(),
            grants.to_vec(),
            session,
            &url,
            32 * 1024 * 1024,
        )
        .await
        .and_then(|b| b.native())
        .map_err(|_| {
            issue(
                "broker_unavailable",
                "The media network broker could not start.",
                "retry",
            )
        })?;
        let work = tempfile::Builder::new()
            .prefix("media-")
            .tempdir_in(&self.work_root)
            .map_err(|_| {
                issue(
                    "tool_storage",
                    "The private helper workspace is unavailable.",
                    "retry",
                )
            })?;
        #[cfg(windows)]
        let (tools, _runtime) = self.tools.stage(work.path()).await?;
        #[cfg(not(windows))]
        let tools = &self.tools;
        let cert = work.path().join("broker-ca.pem");
        tokio::fs::write(&cert, &broker.ca_pem).await.map_err(|_| {
            issue(
                "tool_storage",
                "The private helper workspace is unavailable.",
                "retry",
            )
        })?;
        let mut args: Vec<String> = [
            "--ignore-config",
            "--no-plugin-dirs",
            "--no-cache-dir",
            "--no-warnings",
            "--no-progress",
            "--skip-download",
            "--dump-single-json",
            "--ignore-errors",
            "--socket-timeout",
            "20",
            "--retries",
            "1",
            "--compat-options",
            "no-certifi",
            "--proxy",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        args.push(broker.proxy_url());
        args.extend(["--config-locations".into(), "-".into()]);
        args.extend(enumeration_args(offset, end, selection.is_none()));
        let mut executables = vec![];
        if let Some((recipe, policy)) = selection {
            args.extend([
                "--no-playlist".into(),
                "--format".into(),
                format_expression(recipe, policy)?,
            ]);
            if !policy.subtitle_languages.is_empty() {
                if policy.subtitle_languages.iter().any(|s| {
                    s.len() > 35
                        || s.len() < 2
                        || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                }) {
                    return Err(issue(
                        "subtitle_selection",
                        "Use explicit subtitle language tags.",
                        "prepare_again",
                    ));
                }
                args.extend([
                    "--write-subs".into(),
                    "--sub-langs".into(),
                    policy.subtitle_languages.join(","),
                    "--sub-format".into(),
                    "vtt".into(),
                ]);
                if policy.automatic_subtitles {
                    args.push("--write-auto-subs".into());
                }
            }
            for tool in [&tools.ffmpeg, &tools.ffprobe] {
                let tool = tool.as_ref().ok_or_else(|| {
                    issue(
                        "tool_unavailable",
                        "Install the approved FFmpeg and FFprobe tools.",
                        "restore_tool",
                    )
                })?;
                tool.verify().await?;
                executables.push(tool.path.clone());
            }
            args.extend([
                "--ffmpeg-location".into(),
                tools
                    .ffmpeg
                    .as_ref()
                    .expect("validated")
                    .path
                    .to_string_lossy()
                    .into_owned(),
            ]);
        }

        if let Some(node) = &tools.node {
            node.verify().await?;
            args.extend([
                "--js-runtimes".into(),
                format!("node:{}", node.path.display()),
            ]);
            executables.push(node.path.clone());
        } else {
            args.push("--no-js-runtimes".into());
        }
        args.extend(["--".into(), url.to_string()]);
        let policy = omd_isolation::Policy {
            executable: tools.yt_dlp.path.clone(),
            readable: vec![],
            executables,
            work: work.path().into(),
            broker_port: Some(broker.port),
            broker_upstream_port: broker.isolation_upstream(),
            interactive: false,
        };
        let environment = BTreeMap::from([
            ("SSL_CERT_FILE".into(), cert.to_string_lossy().into_owned()),
            (
                "NODE_EXTRA_CA_CERTS".into(),
                cert.to_string_lossy().into_owned(),
            ),
        ]);
        let captured=omd_isolation::capture(&policy,&args,input,&environment,32*1024*1024,self.network.bandwidth.operation_timeout(Duration::from_secs(120)).await,cancel).await.map_err(|e|match e {
            omd_isolation::Error::Elevated=>issue("elevated_engine","Close OMD and start it without Run as administrator.","restart_engine"),
            omd_isolation::Error::Unavailable=>issue("confinement_unavailable","Required media helper confinement is unavailable. Install or repair the platform sandbox support.","repair_confinement"),
            omd_isolation::Error::Canceled=>issue("canceled","The media operation was canceled.","retry"),
            omd_isolation::Error::Budget=>issue("media_budget","The source exceeded the media operation budget.","retry"),
            _=>issue("media_tool_failed","The confined media tool could not complete this operation.","restore_tool")
        })?;
        let failure = || classify_failure(&captured.stderr, broker.response_limit_reached());
        if !captured.success || captured.stdout.is_empty() {
            return Err(failure());
        }
        let mut raw: Value = serde_json::from_slice(&captured.stdout).map_err(|_| failure())?;
        if let Some(session) = redactor {
            session.redact_value(&mut raw);
        }
        Ok(raw)
    }
}
/// Generic, bounded enumeration for every provider. Listings ask the tool not to
/// resolve each entry (`--flat-playlist`), so they carry only what the extractor
/// reports by default. Core never selects a site's extraction strategy, such as
/// extractor-specific `--extractor-args`. A plugin that needs more per-entry
/// metadata inspects that entry individually or reads its own granted pages.
fn enumeration_args(offset: u32, end: u32, listing: bool) -> Vec<String> {
    let mut args = vec![
        "--playlist-start".into(),
        (offset + 1).to_string(),
        "--playlist-end".into(),
        end.to_string(),
    ];
    if listing {
        args.push("--flat-playlist".into());
    }
    args
}
/// yt-dlp needs its own in-memory cookie jar to recognize authenticated
/// extractors and derive request authorization. Only initially applicable
/// cookies enter it. The broker retains the original path/domain boundaries.
/// Explicit config is supplied on stdin, never in argv or a retained file.
fn cookie_config(
    session: Option<&omd_credentials::Session>,
    url: &url::Url,
    grants: &[HostGrant],
) -> Result<Vec<u8>, Problem> {
    let Some(session) = session else {
        return Ok(Vec::new());
    };
    let Some(grant) = grants
        .iter()
        .find(|g| g.credential && omd_network::validate_url(url, g).is_ok())
    else {
        return Ok(Vec::new());
    };
    let headers = session
        .headers_for(
            url,
            grant,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
        )
        .map_err(|e| e.problem())?;
    let Some(cookie) = headers.get("cookie") else {
        return Ok(Vec::new());
    };
    let cookie = cookie.to_str().map_err(|_| {
        issue(
            "credentials_invalid",
            "The source cookies are invalid.",
            "reauthenticate",
        )
    })?;
    // POSIX shlex quoting, as used by the pinned yt-dlp config parser. This is
    // not a shell command; metacharacters and newlines cannot become options.
    Ok(format!(
        "--add-header 'Cookie: {}'\n",
        cookie.replace('\'', "'\"'\"'")
    )
    .into_bytes())
}
fn download_metadata(stdout: &[u8]) -> Result<Value, Problem> {
    let mut records = stdout
        .split(|b| *b == b'\n')
        .filter_map(|line| line.strip_prefix(b"OMD_SOURCE "));
    let raw = records
        .next()
        .and_then(|record| serde_json::from_slice::<Value>(record).ok());
    if records.next().is_some() || !raw.as_ref().is_some_and(Value::is_object) {
        return Err(issue(
            "media_metadata_invalid",
            "The media source could not be verified; no files were published.",
            "retry",
        ));
    }
    Ok(raw.expect("validated metadata"))
}

fn credential_problem(error: omd_network::NetworkError) -> Problem {
    match error {
        omd_network::NetworkError::Credential(error) => error.problem(),
        _ => issue(
            "credentials_unavailable",
            "The credential store could not be reached.",
            "retry",
        ),
    }
}

fn classify_failure(diagnostic: &[u8], response_limit_reached: bool) -> Problem {
    let problem = classify(diagnostic);
    // A previous optional request may have hit the cap. Preserve specific
    // terminal diagnostics; use that signal only to explain a generic failure.
    if response_limit_reached && problem.code == "media_extraction" {
        issue(
            "media_budget",
            "The source exceeded the media operation budget.",
            "retry",
        )
    } else {
        problem
    }
}

fn classify(diagnostic: &[u8]) -> Problem {
    let text = String::from_utf8_lossy(diagnostic).to_lowercase();
    if text.contains("private video") {
        issue(
            "media_access_denied",
            "This account cannot access the private video.",
            "reauthenticate",
        )
    } else if text.contains("join this channel to get access to members-only content") {
        issue(
            "media_access_denied",
            "This video requires a channel membership with access to this content.",
            "reauthenticate",
        )
    } else if text.contains("sign in") || text.contains("cookies") {
        issue(
            "authentication_required",
            "This item requires sign-in or the source session has expired.",
            "reauthenticate",
        )
    } else if text.contains("unavailable") || text.contains("removed") || text.contains("deleted") {
        issue(
            "media_unavailable",
            "The source reports that this media item is unavailable.",
            "refresh",
        )
    } else if text.contains("429") || text.contains("too many requests") {
        issue(
            "source_rate_limited",
            "The source is rate limiting requests. Wait before retrying.",
            "retry",
        )
    } else if text.contains("certificate") || text.contains("proxy") || text.contains("urlopen") {
        issue(
            "media_connection",
            "The controlled media connection failed. Check source availability and retry.",
            "retry",
        )
    } else {
        issue(
            "media_extraction",
            "The media tool could not extract this item. Check for a managed tool update and retry.",
            "update_tool",
        )
    }
}
fn item(raw: &Value) -> Value {
    // Deliberate projection: never return format URLs, HTTP headers, cookies,
    // filenames, helper diagnostics, or extractor-private fields to a component.
    let mut value = serde_json::Map::new();
    for key in [
        "id",
        "title",
        "description",
        "duration",
        "view_count",
        "channel_follower_count",
        "timestamp",
        "upload_date",
        "channel",
        "channel_id",
        "uploader",
        "uploader_id",
        "availability",
        "live_status",
        "playlist_count",
        "channel_url",
        "webpage_url",
        "thumbnail",
    ] {
        if let Some(v) = raw
            .get(key)
            .filter(|v| v.is_null() || v.is_string() || v.is_number())
        {
            value.insert(key.into(), v.clone());
        }
    }
    // A flat entry's raw `url` is never projected or promoted to `webpage_url`.
    // Depending on the extractor it can be a page, a manifest, a signed media
    // URL or a URL with embedded credentials; core cannot tell which. Plugins
    // own their navigation: they rebuild page URLs from `id` and the URL they
    // inspected. `webpage_url` appears only when the extractor reports it,
    // normally after full inspection of one item.
    // Flat entries also carry artwork in `thumbnails` instead of `thumbnail`.
    if (!value.contains_key("thumbnail") || value.get("thumbnail").is_some_and(Value::is_null))
        && let Some(thumbnails) = raw.get("thumbnails").and_then(Value::as_array)
        && let Some(thumbnail) = thumbnails
            .iter()
            .filter(|t| {
                t.get("url")
                    .and_then(Value::as_str)
                    .is_some_and(|u| u.starts_with("https://"))
            })
            .max_by_key(|t| t.get("width").and_then(Value::as_u64).unwrap_or(0))
    {
        value.insert("thumbnail".into(), thumbnail["url"].clone());
    }
    // Privacy labels describe visibility, not the current account's access.
    // Only full extraction can prove that playable, non-DRM media is present.
    // Flat collection entries deliberately omit this evidence.
    if let Some(formats) = raw.get("formats").and_then(Value::as_array) {
        let accessible = formats.iter().any(|format| {
            format
                .get("url")
                .and_then(Value::as_str)
                .is_some_and(|u| !u.is_empty())
                && format.get("has_drm").and_then(Value::as_bool) != Some(true)
                && ["acodec", "vcodec"].iter().any(|codec| {
                    format
                        .get(*codec)
                        .and_then(Value::as_str)
                        .is_some_and(|c| !c.is_empty() && c != "none")
                })
        });
        value.insert("accessible".into(), json!(accessible));
    }
    Value::Object(value)
}
fn project(raw: &Value, offset: u32, size: u32) -> Result<Value, Problem> {
    if raw.is_null() {
        return Err(issue(
            "media_unavailable",
            "The source returned no available media item.",
            "refresh",
        ));
    }
    let mut result = item(raw);
    let result = result.as_object_mut().expect("projection is an object");
    if let Some(entries) = raw.get("entries").and_then(Value::as_array) {
        let more = entries.len() > size as usize;
        result.insert("kind".into(), json!("collection"));
        result.insert(
            "entries".into(),
            Value::Array(
                entries
                    .iter()
                    .take(size as usize)
                    .map(|entry| {
                        if entry.is_null() {
                            json!({"availability":"unavailable","position":null})
                        } else {
                            item(entry)
                        }
                    })
                    .collect(),
            ),
        );
        result.insert(
            "next_cursor".into(),
            if more {
                json!((offset + size).to_string())
            } else {
                Value::Null
            },
        );
    } else {
        result.insert("kind".into(), json!("video"));
    }
    Ok(Value::Object(result.clone()))
}
pub fn tool_manifest_path(root: &Path) -> PathBuf {
    root.join("tools-v2.json")
}

/// A yt-dlp format filter that leaves out VP9 video (codec `vp09…` or `vp9…`).
/// A format whose codec the extractor did not report still passes (`?`).
const NOT_VP9: &str = "[vcodec!^=?vp09][vcodec!^=?vp9]";
fn format_expression(recipe: Recipe, policy: &SelectionPolicy) -> Result<String, Problem> {
    if policy.max_height > MAX_HEIGHT {
        return Err(issue(
            "quality_selection",
            "Choose a supported maximum resolution.",
            "prepare_again",
        ));
    }
    let video = |filter: &str| match recipe {
        Recipe::Mp4 => format!("bv[ext=mp4]{filter}+ba[ext=m4a]/b[ext=mp4]{filter}"),
        Recipe::Webm => format!("bv[ext=webm]{filter}+ba[ext=webm]/b[ext=webm]{filter}"),
        _ => format!("bv{filter}+ba/b{filter}"),
    };
    // Formats with a known height within the cap come first. Direct files
    // often have no extractor dimensions; those are admitted only as a
    // fallback, and `check_height_cap` enforces the cap on the saved output
    // before anything is published.
    let heights = match policy.max_height {
        0 => vec![String::new()],
        cap => vec![format!("[height<={cap}]"), format!("[height<=?{cap}]")],
    };
    // MP4 is the output that plays everywhere, and QuickTime and Photos do not
    // play VP9 in MP4, so within each height group H.264, HEVC and AV1 video
    // come before VP9. A known in-cap VP9 format still precedes any format of
    // unknown height, whose saved height may exceed the cap and be rejected.
    let codecs: &[&str] = if recipe == Recipe::Mp4 {
        &[NOT_VP9, ""]
    } else {
        &[""]
    };
    let selection = || {
        heights
            .iter()
            .flat_map(|height| {
                codecs
                    .iter()
                    .map(move |codec| video(&format!("{codec}{height}")))
            })
            .collect::<Vec<_>>()
            .join("/")
    };
    Ok(match recipe {
        Recipe::Mp4 | Recipe::Webm | Recipe::Mkv => selection(),
        Recipe::M4a => "ba[ext=m4a]/ba/b".into(),
        Recipe::Mp3 | Recipe::Opus => "ba/b".into(),
        _ => {
            return Err(issue(
                "media_recipe",
                "Choose a video or audio output recipe.",
                "prepare_again",
            ));
        }
    })
}
fn media_type(recipe: Recipe) -> &'static str {
    match recipe {
        Recipe::Mp4 => "video/mp4",
        Recipe::Mkv => "video/x-matroska",
        Recipe::Webm => "video/webm",
        Recipe::M4a => "audio/mp4",
        Recipe::Mp3 => "audio/mpeg",
        Recipe::Opus => "audio/ogg",
        _ => "application/octet-stream",
    }
}
pub struct Preparation {
    pub resolved: ResolvedRelease,
    pub recipe: Recipe,
    pub policy: SelectionPolicy,
    pub provider_digest: String,
    pub credential_profile: Option<String>,
}
impl Media {
    pub async fn prepare(
        &self,
        request: Preparation,
        grants: &[HostGrant],
        cancel: &CancellationToken,
    ) -> Result<Plan, Problem> {
        tokio::select! { biased;
            _=self.revoked.cancelled()=>Err(issue("tool_removed","Restore the approved tool set to continue.","restore_tool")),
            result=self.prepare_inner(request,grants,cancel)=>result,
        }
    }
    async fn prepare_inner(
        &self,
        request: Preparation,
        grants: &[HostGrant],
        cancel: &CancellationToken,
    ) -> Result<Plan, Problem> {
        let Preparation {
            resolved,
            recipe,
            policy,
            provider_digest,
            credential_profile,
        } = request;
        if resolved.resources.len() != 1
            || resolved.release.availability != omd_domain::Availability::Available
        {
            return Err(issue(
                "media_resources",
                "The source did not return exactly one available media item.",
                "prepare_again",
            ));
        }
        let resource = &resolved.resources[0];
        let Locator::Media {
            url, permission, ..
        } = &resource.locator
        else {
            return Err(issue(
                "media_resources",
                "This output is not a managed media item.",
                "prepare_again",
            ));
        };
        let raw = self
            .extract(
                &Inspect {
                    url: url.clone(),
                    cursor: None,
                    page_size: 1,
                },
                &resolved.release.reference.provider,
                grants,
                credential_profile.as_deref(),
                cancel,
                Some((recipe, &policy)),
            )
            .await?;
        let format_ids =
            if let Some(formats) = raw.get("requested_formats").and_then(Value::as_array) {
                formats
                    .iter()
                    .map(|f| {
                        f.get("format_id")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
                    .collect::<Option<Vec<_>>>()
            } else {
                raw.get("format_id")
                    .and_then(Value::as_str)
                    .map(|s| vec![s.into()])
            }
            .ok_or_else(|| {
                issue(
                    "media_formats",
                    "The source did not return a complete format selection.",
                    "prepare_again",
                )
            })?;
        if format_ids.is_empty()
            || format_ids.len() > 2
            || format_ids.iter().any(|id| {
                id.is_empty()
                    || id.len() > 100
                    || !id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            })
        {
            return Err(issue(
                "media_formats",
                "The source returned an unsupported format identity.",
                "prepare_again",
            ));
        }
        let available = raw.get("requested_subtitles").and_then(Value::as_object);
        let mut subtitles = Vec::new();
        for language in &policy.subtitle_languages {
            if !available.is_some_and(|a| a.get(language).is_some_and(|s| s["ext"] == "vtt")) {
                return Err(issue(
                    "subtitle_unavailable",
                    "A selected subtitle language is unavailable. Adjust the selection and prepare again.",
                    "prepare_again",
                ));
            }
            if !subtitles.contains(language) {
                subtitles.push(language.clone());
            }
        }
        let locator = Locator::Media {
            url: url.clone(),
            permission: permission.clone(),
            credential_profile: credential_profile.clone(),
        };
        let mut outputs = vec![LogicalOutput {
            id: format!("{}:main", resource.id),
            position: 0,
            relative_path: format!("media.{}", recipe.extension()),
            role: "media".into(),
            media_type: Some(media_type(recipe).into()),
            expected_size: None,
            expected_sha256: None,
            locator: locator.clone(),
        }];
        for language in &subtitles {
            outputs.push(LogicalOutput {
                id: format!("{}:subtitle:{language}", resource.id),
                position: outputs.len() as u32,
                relative_path: format!("media.{language}.vtt"),
                role: "subtitle".into(),
                media_type: Some("text/vtt".into()),
                expected_size: None,
                expected_sha256: None,
                locator: locator.clone(),
            });
        }
        let final_relative_path = format!(
            "{} [{}]/{} [{}]",
            path_segment(&resolved.collection.title, "Collection"),
            &resolved.collection.reference.key()[..10],
            path_segment(&resolved.release.title, "Video"),
            &resolved.release.reference.key()[..10]
        );
        let source_formats = raw
            .get("requested_formats")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_else(|| vec![raw.clone()]);
        let duration_ms = duration_ms(&raw);
        let source_signature = source_signature(&raw);
        let selected_height = source_formats
            .iter()
            .filter_map(|f| {
                f.get("height")
                    .and_then(Value::as_u64)
                    .and_then(|n| u32::try_from(n).ok())
            })
            .max();
        let selection = MediaSelection {
            source_signature,
            selected_height,
            duration_ms,
            format_ids,
            subtitles,
            yt_dlp_digest: self.tools.yt_dlp.sha256.clone(),
            ffmpeg_digest: self.tools.ffmpeg.as_ref().expect("verified").sha256.clone(),
            ffprobe_digest: self
                .tools
                .ffprobe
                .as_ref()
                .expect("verified")
                .sha256
                .clone(),
            node_digest: self.tools.node.as_ref().map(|t| t.sha256.clone()),
        };
        Ok(Plan {
            metadata: Default::default(),
            media: Some(selection),
            credential_profile,
            generation: 0,
            release: resolved.release,
            collection: resolved.collection,
            recipe,
            policy,
            outputs,
            final_relative_path,
            expires_at: None,
            provider_digest,
        })
    }
}

pub struct Download<'a> {
    pub plan: &'a Plan,
    pub grants: &'a [HostGrant],
    pub work: &'a Path,
    pub progress: tokio::sync::watch::Sender<Value>,
}
impl Media {
    pub async fn download(
        &self,
        request: Download<'_>,
        cancel: &CancellationToken,
    ) -> Result<(), Problem> {
        tokio::select! { biased;
            _=self.revoked.cancelled()=>Err(issue("tool_removed","Restore the approved tool set to continue.","restore_tool")),
            result=self.download_inner(request,cancel)=>result,
        }
    }
    async fn download_inner(
        &self,
        request: Download<'_>,
        cancel: &CancellationToken,
    ) -> Result<(), Problem> {
        let Download {
            plan,
            grants,
            work,
            progress,
        } = request;
        #[cfg(windows)]
        let (tools, _runtime) = self.tools.stage(work).await?;
        #[cfg(not(windows))]
        let tools = &self.tools;
        let selected = plan.media.as_ref().ok_or_else(|| {
            issue(
                "media_selection",
                "Prepare this media item before downloading.",
                "prepare_again",
            )
        })?;
        for (tool, expected) in [
            (Some(&tools.yt_dlp), Some(&selected.yt_dlp_digest)),
            (tools.ffmpeg.as_ref(), Some(&selected.ffmpeg_digest)),
            (tools.ffprobe.as_ref(), Some(&selected.ffprobe_digest)),
            (tools.node.as_ref(), selected.node_digest.as_ref()),
        ] {
            match (tool, expected) {
                (Some(tool), Some(expected)) if &tool.sha256 == expected => tool.verify().await?,
                (None, None) => {}
                _ => {
                    return Err(issue(
                        "tool_version_unavailable",
                        "Restore the approved media tool version used by this preparation.",
                        "restore_tool",
                    ));
                }
            }
        }
        if selected.format_ids.is_empty()
            || selected.format_ids.len() > 2
            || selected.format_ids.iter().any(|id| {
                id.is_empty()
                    || !id
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
            })
        {
            return Err(issue(
                "media_selection",
                "The saved format selection is invalid.",
                "prepare_again",
            ));
        }
        let output = plan.outputs.first().ok_or_else(|| {
            issue(
                "media_selection",
                "The saved output selection is empty.",
                "prepare_again",
            )
        })?;
        let Locator::Media { url, .. } = &output.locator else {
            return Err(issue(
                "media_selection",
                "The saved media locator is invalid.",
                "prepare_again",
            ));
        };
        let session = self
            .network
            .session(
                &plan.release.reference.provider,
                plan.credential_profile.as_deref(),
                grants,
            )
            .await
            .map_err(credential_problem)?;
        let source_url = url::Url::parse(url).map_err(|_| {
            issue(
                "media_url",
                "The saved source URL is invalid.",
                "prepare_again",
            )
        })?;
        let input = cookie_config(session.as_ref(), &source_url, grants)?;
        let broker = omd_helper_broker::Broker::start_media(
            self.network.clone(),
            grants.to_vec(),
            session,
            &source_url,
            1024 * 1024 * 1024 * 1024,
        )
        .await
        .and_then(|b| b.native())
        .map_err(|_| {
            issue(
                "broker_unavailable",
                "The media network broker could not start.",
                "retry",
            )
        })?;
        let cert = work.join("broker-ca.pem");
        tokio::fs::write(&cert, &broker.ca_pem).await.map_err(|_| {
            issue(
                "media_storage",
                "The media staging directory is unavailable.",
                "retry",
            )
        })?;
        let mut args:Vec<String>=["--ignore-config","--no-plugin-dirs","--no-cache-dir","--no-warnings","--no-playlist","--no-write-info-json","--no-simulate","--print","before_dl:OMD_SOURCE %()j","--config-locations","-","--continue","--no-overwrites","--no-mtime","--newline","--progress","--progress-delta","0.5","--progress-template","download:OMD_PROGRESS {\"format\":%(info.format_id)j,\"done\":%(progress.downloaded_bytes)j,\"total\":%(progress.total_bytes)j}","--socket-timeout","30","--retries","2","--fragment-retries","2","--downloader","native","--compat-options","no-certifi","--output","media.%(ext)s","--format"].iter().map(|s|s.to_string()).collect();
        args.push(selected.format_ids.join("+"));
        args.extend([
            "--proxy".into(),
            broker.proxy_url(),
            "--ffmpeg-location".into(),
            tools
                .ffmpeg
                .as_ref()
                .expect("verified")
                .path
                .to_string_lossy()
                .into_owned(),
        ]);
        if plan.recipe.audio_only() {
            args.extend([
                "--extract-audio".into(),
                "--audio-format".into(),
                plan.recipe.extension().into(),
                "--audio-quality".into(),
                "192K".into(),
            ]);
        } else {
            args.extend([
                "--merge-output-format".into(),
                plan.recipe.extension().into(),
                "--remux-video".into(),
                plan.recipe.extension().into(),
            ]);
        }
        if !selected.subtitles.is_empty() {
            args.extend([
                "--write-subs".into(),
                "--sub-langs".into(),
                selected.subtitles.join(","),
                "--sub-format".into(),
                "vtt".into(),
            ]);
            if plan.policy.automatic_subtitles {
                args.push("--write-auto-subs".into());
            }
        }
        let mut executables = vec![
            tools.ffmpeg.as_ref().expect("verified").path.clone(),
            tools.ffprobe.as_ref().expect("verified").path.clone(),
        ];
        if let Some(node) = &tools.node {
            args.extend([
                "--js-runtimes".into(),
                format!("node:{}", node.path.display()),
            ]);
            executables.push(node.path.clone());
        } else {
            args.push("--no-js-runtimes".into());
        }
        args.extend(["--".into(), url.clone()]);
        let policy = omd_isolation::Policy {
            executable: tools.yt_dlp.path.clone(),
            readable: vec![],
            executables,
            work: work.into(),
            broker_port: Some(broker.port),
            broker_upstream_port: broker.isolation_upstream(),
            interactive: false,
        };
        let environment = BTreeMap::from([
            ("SSL_CERT_FILE".into(), cert.to_string_lossy().into_owned()),
            (
                "NODE_EXTRA_CA_CERTS".into(),
                cert.to_string_lossy().into_owned(),
            ),
        ]);
        let result = omd_isolation::capture_progress(
            &policy,
            &args,
            omd_isolation::CaptureOptions {
                browser: false,
                input,
                environment: &environment,
                limit: 32 * 1024 * 1024,
                timeout: Duration::from_secs(24 * 60 * 60),
                progress: Some(progress),
            },
            cancel,
        )
        .await
        .map_err(|e| match e {
            omd_isolation::Error::Canceled => issue(
                "canceled",
                "The media acquisition was paused or canceled.",
                "retry",
            ),
            omd_isolation::Error::Elevated => issue(
                "elevated_engine",
                "Close OMD and start it without Run as administrator.",
                "restart_engine",
            ),
            omd_isolation::Error::Unavailable => issue(
                "confinement_unavailable",
                "Repair native helper confinement before resuming.",
                "repair_confinement",
            ),
            _ => issue(
                "media_tool_failed",
                "The media helper stopped; useful partial files were retained.",
                "retry",
            ),
        })?;
        if !result.success {
            return Err(classify(&result.stderr));
        }
        let raw = download_metadata(&result.stdout)?;
        if source_signature(&raw) != selected.source_signature {
            return Err(issue(
                "media_source_changed",
                "The downloaded source differs from the confirmed selection; no files were published.",
                "prepare_again",
            ));
        }
        self.verify(plan, work, cancel).await
    }
    pub async fn verify(
        &self,
        plan: &Plan,
        work: &Path,
        cancel: &CancellationToken,
    ) -> Result<(), Problem> {
        tokio::select! { biased;
            _=self.revoked.cancelled()=>Err(issue("tool_removed","Restore the approved tool set to continue.","restore_tool")),
            result=self.verify_inner(plan,work,cancel)=>result,
        }
    }
    async fn verify_inner(
        &self,
        plan: &Plan,
        work: &Path,
        cancel: &CancellationToken,
    ) -> Result<(), Problem> {
        use std::io::Read;
        let root = omd_files::Root::open(work).map_err(|_| {
            issue(
                "media_storage",
                "The media staging directory is unavailable.",
                "retry",
            )
        })?;
        for output in &plan.outputs {
            let mut file = root.read_file(&output.relative_path).map_err(|_| {
                issue(
                    "media_output_missing",
                    "A confirmed output was not produced; no files were published.",
                    "retry",
                )
            })?;
            if file
                .metadata()
                .map_err(|_| issue("media_storage", "A staged file is unavailable.", "retry"))?
                .len()
                == 0
            {
                return Err(issue(
                    "media_output_empty",
                    "A confirmed output is empty; no files were published.",
                    "retry",
                ));
            }
            if output.role == "subtitle" {
                let mut header = [0u8; 16];
                let count = file.read(&mut header).map_err(|_| {
                    issue(
                        "subtitle_invalid",
                        "A subtitle file could not be verified.",
                        "retry",
                    )
                })?;
                let header = std::str::from_utf8(&header[..count])
                    .unwrap_or("")
                    .trim_start_matches('\u{feff}');
                if !header.starts_with("WEBVTT") {
                    return Err(issue(
                        "subtitle_invalid",
                        "The source returned invalid subtitle content.",
                        "retry",
                    ));
                }
            }
        }
        #[cfg(windows)]
        let (tools, _runtime) = self.tools.stage(work).await?;
        #[cfg(not(windows))]
        let tools = &self.tools;
        let probe = tools.ffprobe.as_ref().ok_or_else(|| {
            issue(
                "tool_unavailable",
                "Restore the approved FFprobe tool.",
                "restore_tool",
            )
        })?;
        probe.verify().await?;
        let expected = plan.media.as_ref().ok_or_else(|| {
            issue(
                "media_selection",
                "The media selection is missing.",
                "prepare_again",
            )
        })?;
        let name = format!("media.{}", plan.recipe.extension());
        let source = check_output(
            plan,
            expected,
            &probe_output(probe, work, &name, probe_budget(plan.recipe), cancel).await?,
        )?;
        if !plan.recipe.audio_only() {
            return Ok(());
        }
        // Every audio output is rebuilt by a confined stream copy of its first
        // audio stream. Only engine-selected text tags and at most one still
        // cover, decoded and re-encoded by the managed FFmpeg, are written
        // back; no other source metadata, picture, chapter or attachment is.
        // The audio packets must be identical before and after, and the engine
        // checks the container structure, tags and picture byte by byte before
        // the rebuilt file replaces the download.
        let ffmpeg = tools.ffmpeg.as_ref().ok_or_else(|| {
            issue(
                "tool_unavailable",
                "Restore the approved FFmpeg tool.",
                "restore_tool",
            )
        })?;
        ffmpeg.verify().await?;
        let rebuilt = format!("media.audio-only.{}", plan.recipe.extension());
        let root = omd_files::Root::open(work).map_err(|_| unverified())?;
        let before =
            audio_packets(probe, &root, work, &name, plan.recipe, "source", cancel).await?;
        if before.packets == 0 {
            return Err(unverified());
        }
        let tags = with_plan_fallback(plan, source_tags(probe, work, &name, cancel).await);
        let cover = cover(plan.recipe, &source);
        let rebuild = Rebuild {
            ffmpeg,
            probe,
            plan,
            expected,
            work,
            root: &root,
            name: &name,
            rebuilt: &rebuilt,
            before: &before,
        };
        // A cover that cannot be re-encoded or verified is left out; the audio
        // and tags are then rebuilt and verified again without it.
        let result = match rebuild.run(&tags, cover.as_ref(), cancel).await {
            Err(problem) if cover.is_some() && problem.code == "media_verification" => {
                rebuild.run(&tags, None, cancel).await
            }
            result => result,
        };
        drop(before);
        result?;
        root.remove_file(&name).map_err(|_| unverified())?;
        root.publish(&rebuilt, &root, &name)
            .map_err(|_| unverified())
    }
}

/// One verified rebuild of a downloaded audio file into `rebuilt`.
struct Rebuild<'a> {
    ffmpeg: &'a Tool,
    probe: &'a Tool,
    plan: &'a Plan,
    expected: &'a MediaSelection,
    work: &'a Path,
    root: &'a omd_files::Root,
    name: &'a str,
    rebuilt: &'a str,
    before: &'a Listing,
}
impl Rebuild<'_> {
    /// Rebuild with `tags` and `cover`, then verify the result; a rejected
    /// rebuild is removed, never left for publication.
    async fn run(
        &self,
        tags: &[(&'static str, String)],
        cover: Option<&Cover>,
        cancel: &CancellationToken,
    ) -> Result<(), Problem> {
        let result = self.attempt(tags, cover, cancel).await;
        if result.is_err() {
            let _ = self.root.remove_file(self.rebuilt);
        }
        result
    }
    async fn attempt(
        &self,
        tags: &[(&'static str, String)],
        cover: Option<&Cover>,
        cancel: &CancellationToken,
    ) -> Result<(), Problem> {
        let (recipe, work) = (self.plan.recipe, self.work);
        rebuild_audio(
            self.ffmpeg,
            recipe,
            work,
            self.name,
            self.rebuilt,
            tags,
            cover,
            cancel,
        )
        .await?;
        let after = audio_packets(
            self.probe,
            self.root,
            work,
            self.rebuilt,
            recipe,
            "rebuilt",
            cancel,
        )
        .await?;
        if !same_packets(self.before, &after, Compare::Exact).await? {
            return Err(Problem::new(
                "media_verification",
                "The audio could not be copied exactly, so the file was not saved.",
            ));
        }
        let checked = {
            let root = self.root.try_clone().map_err(|_| unverified())?;
            let rebuilt = self.rebuilt.to_owned();
            tokio::task::spawn_blocking(move || check_structure(&root, recipe, &rebuilt))
                .await
                .map_err(|_| unverified())??
        };
        if checked {
            // Only bytes after the last whole MPEG frame were cut: the audio
            // must be the rebuilt packets, except that a last packet which also
            // held those bytes may now be shorter.
            let trimmed = audio_packets(
                self.probe,
                self.root,
                work,
                self.rebuilt,
                recipe,
                "trimmed",
                cancel,
            )
            .await?;
            if !same_packets(&trimmed, &after, Compare::TrimmedPrefix).await? {
                return Err(unverified());
            }
        }
        let streams = check_output(
            self.plan,
            self.expected,
            &probe_output(self.probe, work, self.rebuilt, MAX_PIXELS, cancel).await?,
        )?;
        match &streams[..] {
            [audio] if audio["codec_type"] == "audio" => Ok(()),
            [audio, picture]
                if audio["codec_type"] == "audio"
                    && cover.is_some_and(|c| picture["codec_name"] == c.codec)
                    && attached(picture)
                    && picture_dimensions(picture).is_some() =>
            {
                Ok(())
            }
            _ => Err(unverified()),
        }
    }
}

/// A deterministic rejection of a rebuilt audio file: retrying downloads the
/// same bytes again, so it is not offered.
fn unverified() -> Problem {
    Problem::new(
        "media_verification",
        "The audio file contains data that OMD cannot verify as audio, so it was not saved.",
    )
}
fn rejected(violation: container::Violation) -> Problem {
    if violation == container::BETWEEN_FRAMES {
        Problem::new(
            "media_verification",
            "This MP3 has other data between its audio frames, so OMD cannot verify it as audio only and did not save it.",
        )
    } else {
        unverified()
    }
}
/// The engine-side structure check of a rebuilt audio output. Returns whether
/// trailing non-audio bytes were cut from an MP3.
fn check_structure(root: &omd_files::Root, recipe: Recipe, name: &str) -> Result<bool, Problem> {
    let mut file = root
        .open_existing_read_write(name)
        .map_err(|_| unverified())?;
    let len = file.metadata().map_err(|_| unverified())?.len();
    match recipe {
        Recipe::Mp3 => {
            let end = container::mp3(&mut file, len).map_err(rejected)?;
            if end == len {
                return Ok(false);
            }
            file.set_len(end).map_err(|_| unverified())?;
            file.sync_all().map_err(|_| unverified())?;
            Ok(true)
        }
        Recipe::M4a => container::m4a(&mut file, len)
            .map(|()| false)
            .map_err(rejected),
        Recipe::Opus => container::ogg_opus(&mut file, len)
            .map(|()| false)
            .map_err(rejected),
        _ => Err(unverified()),
    }
}
fn helper_policy(tool: &Tool, work: &Path) -> omd_isolation::Policy {
    omd_isolation::Policy {
        executable: tool.path.clone(),
        readable: vec![],
        executables: vec![],
        work: work.into(),
        broker_port: None,
        broker_upstream_port: None,
        interactive: false,
    }
}
async fn run_probe(
    probe: &Tool,
    work: &Path,
    args: &[&str],
    name: &str,
    pixels: &str,
    cancel: &CancellationToken,
) -> Result<Value, Problem> {
    let bytes = run_probe_raw(probe, work, args, name, 1024 * 1024, pixels, cancel).await?;
    serde_json::from_slice(&bytes).map_err(|_| {
        issue(
            "media_verification",
            "The media tool returned invalid verification data.",
            "restore_tool",
        )
    })
}
/// Runs the confined ffprobe on `name` within the per-frame pixel budget
/// `pixels` (`probe_budget`). Only a file that ffprobe positively rejects is
/// `container_rejected` (`probe_result`); anything else stays retryable.
async fn run_probe_raw(
    probe: &Tool,
    work: &Path,
    args: &[&str],
    name: &str,
    limit: usize,
    pixels: &str,
    cancel: &CancellationToken,
) -> Result<Vec<u8>, Problem> {
    // The pixel budget applies to every decoder of the input, so a frame or
    // picture with absurd dimensions is never decoded (it would allocate
    // gigabytes).
    let args = ["-max_pixels", pixels]
        .iter()
        .chain(args)
        .map(|s| s.to_string())
        .chain(["-i".into(), name.into()])
        .collect::<Vec<_>>();
    let captured = omd_isolation::capture(
        &helper_policy(probe, work),
        &args,
        vec![],
        &BTreeMap::new(),
        limit,
        Duration::from_secs(60 * 60),
        cancel,
    )
    .await
    .map_err(|_| probe_failed())?;
    probe_result(captured)
}
/// ffprobe's result. Only when ffprobe ran, exited with its own failure status
/// (1) and reported that the input is invalid data (FFmpeg's
/// AVERROR_INVALIDDATA text) is the file itself rejected: the same bytes fail
/// the same way on every attempt. A crash or kill, another status, or another
/// error (a missing or unreadable file, a listing it could not write, a
/// detached volume) may not recur, so it stays retryable.
fn probe_result(captured: omd_isolation::Capture) -> Result<Vec<u8>, Problem> {
    if captured.success {
        return Ok(captured.stdout);
    }
    let rejected = captured.exit == omd_isolation::Exit::Code(1)
        && captured
            .stderr
            .windows(INVALID_DATA.len())
            .any(|window| window == INVALID_DATA);
    Err(if rejected {
        container_rejected()
    } else {
        probe_failed()
    })
}
/// The message FFmpeg prints for AVERROR_INVALIDDATA when it cannot open or
/// read an input as media.
const INVALID_DATA: &[u8] = b"Invalid data found when processing input";
/// The confined ffprobe could not run or finish; another attempt may succeed.
fn probe_failed() -> Problem {
    issue(
        "media_verification",
        "The media container could not be verified.",
        "retry",
    )
}
/// The download completed, but its container or streams fail verification.
/// The same selection produces the same bytes on every attempt, so retrying
/// is not offered: preparing again lets a person choose another format.
fn container_rejected() -> Problem {
    output_rejected("OMD could not verify the downloaded media file, so it was not saved.")
}
fn output_rejected(reason: &str) -> Problem {
    issue(
        "media_verification",
        &format!(
            "{reason} Trying again would give the same result; prepare it again and choose another format."
        ),
        "prepare_again",
    )
}
/// `container::MAX_PICTURE_SIDE` squared: the largest picture any managed
/// decoder may decode while an audio output and its cover are verified or
/// rebuilt.
const MAX_PIXELS: &str = "16777216";
/// The highest maximum resolution (`SelectionPolicy::max_height`) a selection
/// may choose.
const MAX_HEIGHT: u32 = 8640;
/// The largest video frame a probe of a video output may decode: a 16:9 frame
/// at `MAX_HEIGHT` (15360x8640), so a VP9 output within any accepted cap keeps
/// its dimensions. The bundled FFmpeg is built with this as every decoder's
/// default limit (`scripts/build-media.py`), which also bounds the decoding
/// that yt-dlp's own FFmpeg and FFprobe runs do.
const MAX_VIDEO_PIXELS: &str = "132710400";
/// The pixel budget for probing an output of `recipe`.
fn probe_budget(recipe: Recipe) -> &'static str {
    if recipe.audio_only() {
        MAX_PIXELS
    } else {
        MAX_VIDEO_PIXELS
    }
}
/// One audio packet: its size and the 128-bit murmur3 hash of its bytes.
type Packet = (u32, u128);
/// The most audio packets one verification lists: about 290 hours of 44.1 kHz
/// MP3, 250 hours of AAC or 220 hours of Opus. A listing is streamed from a
/// temporary file (about 45 bytes per packet, so at most about 2 GB), never
/// held in memory, so this bounds only disk use and time.
const MAX_PACKETS: u64 = 40_000_000;
/// The longest listing line ffprobe writes for one packet (`size,murmur3:<32
/// hex digits>` plus side-data columns), used to bound the listing file.
const MAX_LISTING_LINE: u64 = 128;
fn too_long() -> Problem {
    Problem::new(
        "media_too_long",
        "This file is too long for OMD to verify (over about 200 hours of audio), so it was not saved.",
    )
}
/// A packet listing written by the confined ffprobe into the work folder. The
/// file is removed when the listing is dropped.
struct Listing {
    root: omd_files::Root,
    file: String,
    packets: u64,
}
impl Drop for Listing {
    fn drop(&mut self) {
        let _ = self.root.remove_file(&self.file);
    }
}
/// Size and hash of every packet of the first audio stream, in order, as a
/// listing file of exactly the counted packets. Audio with more than
/// `MAX_PACKETS` packets fails with `too_long`, never unchecked. For M4A the
/// edit list is ignored, so the listing holds every stored sample: a rebuilt
/// file's edit list may end before a final padding-only packet that the
/// source's edit list included (Apple HE-AAC).
async fn audio_packets(
    probe: &Tool,
    root: &omd_files::Root,
    work: &Path,
    name: &str,
    recipe: Recipe,
    label: &str,
    cancel: &CancellationToken,
) -> Result<Listing, Problem> {
    let mut args = vec!["-v", "error"];
    if recipe == Recipe::M4a {
        args.extend(["-ignore_editlist", "1"]);
    }
    args.extend(["-select_streams", "a:0"]);
    // Count first: the count bounds the listing file before it is written.
    let mut count_args = args.clone();
    count_args.extend([
        "-count_packets",
        "-show_entries",
        "stream=nb_read_packets",
        "-of",
        "csv=p=0",
    ]);
    let count = run_probe_raw(probe, work, &count_args, name, 1024, MAX_PIXELS, cancel).await?;
    let packets = std::str::from_utf8(&count)
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
        .ok_or_else(probe_failed)?;
    if packets > MAX_PACKETS {
        return Err(too_long());
    }
    let listing = Listing {
        root: root.try_clone().map_err(|_| probe_failed())?,
        file: format!(".omd-packets-{label}.csv"),
        packets,
    };
    match root.remove_file(&listing.file) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(probe_failed()),
    }
    args.extend([
        "-show_entries",
        "packet=size,data_hash",
        "-show_data_hash",
        "murmur3",
        "-of",
        "csv=p=0",
        "-o",
        &listing.file,
    ]);
    run_probe_raw(probe, work, &args, name, 1024, MAX_PIXELS, cancel).await?;
    let written = root
        .read_file(&listing.file)
        .and_then(|file| file.metadata())
        .map_err(|_| probe_failed())?
        .len();
    if written > packets.saturating_mul(MAX_LISTING_LINE) {
        return Err(probe_failed());
    }
    Ok(listing)
}
fn packet(line: &str) -> Option<Packet> {
    let mut fields = line.split(',');
    let size = fields.next()?.trim().parse().ok()?;
    let hash = fields.next()?.trim().strip_prefix("murmur3:")?;
    if hash.len() != 32 {
        return None;
    }
    Some((size, u128::from_str_radix(hash, 16).ok()?))
}
/// The packets of a listing file, read line by line. Only size and payload
/// hash count: later columns are side data (for example MP3 gapless skip
/// counts), which the rebuilt header may state anew.
fn packets(
    listing: &Listing,
) -> Result<impl Iterator<Item = Result<Packet, Problem>> + Send + use<>, Problem> {
    use std::io::BufRead;
    let file = listing
        .root
        .read_file(&listing.file)
        .map_err(|_| probe_failed())?;
    Ok(std::io::BufReader::new(file).split(b'\n').map(|line| {
        line.ok()
            .and_then(|line| String::from_utf8(line).ok())
            .and_then(|line| packet(&line))
            .ok_or_else(probe_failed)
    }))
}
#[derive(Clone, Copy)]
enum Compare {
    /// The same packets, in order.
    Exact,
    /// The first listing is the second with trailing bytes cut: at least one
    /// packet and no more than the second, all but the last identical.
    TrimmedPrefix,
}
/// Compare two listings packet by packet in bounded memory. A listing that
/// does not hold exactly its counted packets is a verification failure.
async fn same_packets(a: &Listing, b: &Listing, compare: Compare) -> Result<bool, Problem> {
    let (count_a, count_b) = (a.packets, b.packets);
    // Packets compared in full; for a trimmed listing its last may differ.
    let compared = match compare {
        Compare::Exact if count_a == count_b => count_a,
        Compare::TrimmedPrefix if count_a > 0 && count_a <= count_b => count_a - 1,
        _ => return Ok(false),
    };
    let (mut left, mut right) = (packets(a)?, packets(b)?);
    tokio::task::spawn_blocking(move || {
        let next = |listing: &mut dyn Iterator<Item = Result<Packet, Problem>>| {
            listing.next().ok_or_else(probe_failed)?
        };
        for _ in 0..compared {
            if next(&mut left)? != next(&mut right)? {
                return Ok(false);
            }
        }
        if compared < count_a {
            next(&mut left)?;
        }
        // The compared listing must end exactly at its count.
        if left.next().is_some() || (matches!(compare, Compare::Exact) && right.next().is_some()) {
            return Err(probe_failed());
        }
        Ok(true)
    })
    .await
    .map_err(|_| probe_failed())?
}
async fn probe_output(
    probe: &Tool,
    work: &Path,
    name: &str,
    pixels: &str,
    cancel: &CancellationToken,
) -> Result<Value, Problem> {
    run_probe(
        probe,
        work,
        &[
            "-v",
            "error",
            "-show_entries",
            "format=format_name,duration:stream=index,codec_type,codec_name,width,height:stream_disposition=attached_pic:stream_tags=comment",
            "-of",
            "json",
        ],
        name,
        pixels,
        cancel,
    )
    .await
}
/// Duration, stream and container checks of one probe; returns its streams.
fn check_output(
    plan: &Plan,
    expected: &MediaSelection,
    data: &Value,
) -> Result<Vec<Value>, Problem> {
    let streams = data["streams"]
        .as_array()
        .ok_or_else(|| output_rejected("The output contains no media streams."))?;
    let duration = data["format"]["duration"]
        .as_str()
        .and_then(|s| s.parse::<f64>().ok())
        .filter(|s| s.is_finite() && *s >= 0.0)
        .map(|s| (s * 1000.0).round() as u64);
    if duration.is_none_or(|duration| duration == 0)
        || expected
            .duration_ms
            .is_some_and(|a| duration.is_none_or(|b| a.abs_diff(b) > 1500))
    {
        return Err(issue(
            "media_truncated",
            "The output duration differs from the confirmed source; no files were published.",
            "prepare_again",
        ));
    }
    check_streams(plan.recipe, streams, expected.selected_height)?;
    check_height_cap(
        plan.recipe,
        streams,
        expected.selected_height,
        plan.policy.max_height,
    )?;
    let format = data["format"]["format_name"].as_str().unwrap_or("");
    let matches = match plan.recipe {
        Recipe::Mp4 | Recipe::M4a => format.split(',').any(|s| s == "mp4"),
        Recipe::Mkv | Recipe::Webm => format.split(',').any(|s| s == "matroska" || s == "webm"),
        Recipe::Mp3 => format == "mp3",
        Recipe::Opus => format == "ogg",
        _ => false,
    };
    if !matches {
        return Err(issue(
            "media_container_changed",
            "The saved container differs from the confirmed recipe.",
            "prepare_again",
        ));
    }
    Ok(streams.clone())
}

fn number(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
}
/// A cover picture to keep: the source stream and the encoder that rewrites
/// it (the decoder of the same name reads it).
#[derive(Debug, PartialEq)]
struct Cover {
    index: u64,
    codec: &'static str,
}
/// The still cover a rebuild may keep: an attached JPEG or PNG picture that the
/// managed ffprobe decoded within the pixel budget, preferring the one labelled
/// as the front cover. Ogg Opus covers are not written back: FFmpeg's Ogg
/// muxer cannot store a picture.
fn cover(recipe: Recipe, streams: &[Value]) -> Option<Cover> {
    if !matches!(recipe, Recipe::Mp3 | Recipe::M4a) {
        return None;
    }
    let candidates = streams.iter().filter_map(|stream| {
        let codec = ["mjpeg", "png"]
            .into_iter()
            .find(|codec| stream["codec_name"] == *codec)?;
        (attached(stream) && picture_dimensions(stream).is_some()).then_some((
            stream,
            Cover {
                index: number(&stream["index"])?,
                codec,
            },
        ))
    });
    let (front, other): (Vec<_>, Vec<_>) =
        candidates.partition(|(stream, _)| stream["tags"]["comment"] == "Cover (front)");
    front
        .into_iter()
        .chain(other)
        .next()
        .map(|(_, cover)| cover)
}
/// The decoded dimensions of a picture stream, within `MAX_PICTURE_SIDE`.
fn picture_dimensions(stream: &Value) -> Option<(u32, u32)> {
    let side = |value: &Value| {
        number(value)
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| (1..=container::MAX_PICTURE_SIDE).contains(n))
    };
    Some((side(&stream["width"])?, side(&stream["height"])?))
}
/// The source's text tags that a rebuild may keep (`container::TAGS`): the
/// first value of each, from the container or else the audio stream (Ogg
/// comments), when it is `container::plain_text`; track and disc numbers only
/// as `N` or `N/M`. Tags that cannot be read within the probe budget are
/// left out; they never fail a download.
async fn source_tags(
    probe: &Tool,
    work: &Path,
    name: &str,
    cancel: &CancellationToken,
) -> Vec<(&'static str, String)> {
    let args = [
        "-v",
        "error",
        "-select_streams",
        "a:0",
        "-show_entries",
        "format_tags:stream_tags",
        "-of",
        "json",
    ];
    let Ok(bytes) = run_probe_raw(probe, work, &args, name, 1024 * 1024, MAX_PIXELS, cancel).await
    else {
        return vec![];
    };
    let Ok(data) = serde_json::from_slice::<Value>(&bytes) else {
        return vec![];
    };
    select_tags(&data)
}
fn select_tags(data: &Value) -> Vec<(&'static str, String)> {
    let sources = [&data["format"]["tags"], &data["streams"][0]["tags"]];
    let found = |key: &str| {
        sources.iter().find_map(|tags| {
            tags.as_object()?
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(key))
                .and_then(|(_, value)| value.as_str())
        })
    };
    let number = |value: &str| {
        let mut parts = value.split('/');
        let valid = |part: Option<&str>| {
            part.is_some_and(|p| {
                (1..=4).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit())
            })
        };
        valid(parts.next()) && parts.next().is_none_or(|p| valid(Some(p))) && parts.next().is_none()
    };
    container::TAGS
        .iter()
        .filter_map(|(key, _, _, _)| {
            let value = found(key)?.trim();
            let valid = container::plain_text(value.as_bytes())
                && (!matches!(*key, "track" | "disc") || number(value));
            valid.then(|| (*key, value.to_owned()))
        })
        .collect()
}
/// The tags a rebuild writes: the source's own kept tags (`select_tags`), and
/// for values the source left out a conservative fallback from the reviewed
/// plan. The title comes from the release title (or its reviewed override),
/// the artist from the release's creators or else, for a channel, the
/// collection title (or its override), and the date only when the release's
/// published time is a valid calendar date (`calendar_date`). A kept source tag
/// is never replaced,
/// no album or album artist is made up, and a fallback that is not
/// `container::plain_text` is left out. The order follows `container::TAGS`.
fn with_plan_fallback(
    plan: &Plan,
    source: Vec<(&'static str, String)>,
) -> Vec<(&'static str, String)> {
    let plain = |value: String| container::plain_text(value.as_bytes()).then_some(value);
    let creators = || {
        let summary = plan.release.preview.as_ref()?.summary.as_ref()?;
        let mut names: Vec<&str> = Vec::new();
        for name in summary.creators.iter().map(|name| name.trim()) {
            if !name.is_empty() && !names.contains(&name) {
                names.push(name);
            }
        }
        plain(names.join(", "))
    };
    let fallback = |key: &str| match key {
        "title" => plain(plan.release_title().trim().to_owned()),
        // A channel's title names who publishes it. Other collections (a
        // series, a playlist, search results) are not artists.
        "artist" => creators().or_else(|| {
            (plan.collection.kind == CollectionKind::Channel)
                .then(|| plain(plan.collection_title().trim().to_owned()))
                .flatten()
        }),
        "date" => plan.release.published_at.as_deref().and_then(calendar_date),
        _ => None,
    };
    container::TAGS
        .iter()
        .filter_map(|(key, _, _, _)| {
            let kept = source.iter().find(|(name, _)| name == key);
            match kept {
                Some((_, value)) => Some((*key, value.clone())),
                None => fallback(key).map(|value| (*key, value)),
            }
        })
        .collect()
}
/// The calendar date of a release's published time, as `YYYY-MM-DD`, when it
/// is a valid ISO 8601 calendar date or RFC 3339 timestamp. Partial dates,
/// impossible days and free text are rejected.
fn calendar_date(value: &str) -> Option<String> {
    let value = value.trim();
    let (date, time) = match value.split_once(['T', 't', ' ']) {
        Some((date, time)) => (date, Some(time)),
        None => (value, None),
    };
    let field = |text: &str, width: usize| {
        (text.len() == width && text.bytes().all(|b| b.is_ascii_digit()))
            .then(|| text.parse::<u32>().ok())
            .flatten()
    };
    let mut parts = date.split('-');
    let year = field(parts.next()?, 4)?;
    let month = field(parts.next()?, 2)?;
    let day = field(parts.next()?, 2)?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => return None,
    };
    let valid = parts.next().is_none()
        && year > 0
        && (1..=days).contains(&day)
        && time.is_none_or(rfc3339_time);
    valid.then(|| date.to_owned())
}
/// An RFC 3339 time of day with its offset: `HH:MM:SS[.fraction](Z|±HH:MM)`.
fn rfc3339_time(time: &str) -> bool {
    let two = |text: &str, max: u32| {
        text.len() == 2
            && text.bytes().all(|b| b.is_ascii_digit())
            && text.parse::<u32>().is_ok_and(|n| n <= max)
    };
    let (clock, offset) = match time.strip_suffix(['Z', 'z']) {
        Some(clock) => (clock, None),
        None => match time.rfind(['+', '-']) {
            Some(at) => (&time[..at], Some(&time[at + 1..])),
            None => return false,
        },
    };
    let (clock, fraction) = match clock.split_once('.') {
        Some((clock, fraction)) => (clock, Some(fraction)),
        None => (clock, None),
    };
    let fields: Vec<&str> = clock.split(':').collect();
    fields.len() == 3
        && two(fields[0], 23)
        && two(fields[1], 59)
        && two(fields[2], 60)
        && fraction
            .is_none_or(|f| (1..=9).contains(&f.len()) && f.bytes().all(|b| b.is_ascii_digit()))
        && offset.is_none_or(
            |offset| matches!(offset.split_once(':'), Some((h, m)) if two(h, 23) && two(m, 59)),
        )
}
/// The confined FFmpeg arguments that rebuild an audio output: a stream copy
/// of the first audio stream, no source metadata, chapters, pictures or
/// attachments, and only the given engine-selected `tags`. A `cover` is
/// decoded (within the pixel budget), stripped of all frame side data (ICC
/// profiles, EXIF, orientation) and re-encoded bit-exactly, so the file can
/// hold only picture bytes the managed encoder wrote. Without tags or a
/// cover the output has no tag at all (no ID3v2/ID3v1 for MP3, an empty
/// metadata list for M4A, no comments for Opus). The audio is not re-encoded.
fn rebuild_args(
    recipe: Recipe,
    name: &str,
    rebuilt: &str,
    tags: &[(&'static str, String)],
    cover: Option<&Cover>,
) -> Option<Vec<String>> {
    let tagged = !tags.is_empty() || cover.is_some();
    let format: &[&str] = match recipe {
        Recipe::Mp3 if tagged => &["-id3v2_version", "4", "-write_id3v1", "0", "-f", "mp3"],
        Recipe::Mp3 => &["-id3v2_version", "0", "-write_id3v1", "0", "-f", "mp3"],
        Recipe::M4a => &["-movflags", "+faststart", "-f", "ipod"],
        Recipe::Opus if cover.is_none() => &["-f", "opus"],
        _ => return None,
    };
    let mut args: Vec<String> = [
        "-nostdin",
        "-v",
        "error",
        "-max_pixels",
        MAX_PIXELS,
        "-i",
        name,
        "-map",
        "0:a:0",
    ]
    .map(String::from)
    .into();
    if let Some(cover) = cover {
        args.extend(["-map".into(), format!("0:{}", cover.index)]);
    }
    args.extend(["-c:a", "copy"].map(String::from));
    if let Some(cover) = cover {
        args.extend(["-filter:v", "sidedata=mode=delete", "-c:v", cover.codec].map(String::from));
        if cover.codec == "mjpeg" {
            args.extend(["-q:v", "2"].map(String::from));
        }
        args.extend(
            [
                "-flags:v",
                "+bitexact",
                "-disposition:v:0",
                "attached_pic",
                "-metadata:s:v:0",
                "comment=Cover (front)",
            ]
            .map(String::from),
        );
    }
    args.extend(["-map_metadata", "-1", "-map_chapters", "-1"].map(String::from));
    for (key, value) in tags {
        args.extend(["-metadata".into(), format!("{key}={value}")]);
    }
    args.extend(["-fflags", "+bitexact"].map(String::from));
    args.extend(format.iter().map(|s| s.to_string()));
    args.push(rebuilt.into());
    Some(args)
}
/// Rebuild an audio output in the confined FFmpeg (`rebuild_args`).
#[allow(clippy::too_many_arguments)]
async fn rebuild_audio(
    ffmpeg: &Tool,
    recipe: Recipe,
    work: &Path,
    name: &str,
    rebuilt: &str,
    tags: &[(&'static str, String)],
    cover: Option<&Cover>,
    cancel: &CancellationToken,
) -> Result<(), Problem> {
    let failed = || {
        issue(
            "media_verification",
            "The audio output could not be rebuilt; no files were published.",
            "retry",
        )
    };
    let args = rebuild_args(recipe, name, rebuilt, tags, cover).ok_or_else(failed)?;
    let root = omd_files::Root::open(work).map_err(|_| failed())?;
    match root.remove_file(rebuilt) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(failed()),
    }
    omd_isolation::run(
        &helper_policy(ffmpeg, work),
        &args,
        vec![],
        1024 * 1024,
        Duration::from_secs(60 * 60),
        cancel,
    )
    .await
    .map_err(|_| failed())?;
    Ok(())
}

/// A stream flagged as an attached picture (ID3v2 APIC frame, MP4 `covr`
/// atom, Ogg/FLAC picture block). An audio output keeps at most one, and only
/// as a still JPEG/PNG re-encoded by the audio rebuild (`rebuild_args`).
fn attached(stream: &Value) -> bool {
    stream["codec_type"] == "video" && number(&stream["disposition"]["attached_pic"]) == Some(1)
}
fn moving_video(stream: &Value) -> bool {
    stream["codec_type"] == "video" && !attached(stream)
}
/// Check the ffprobe streams of a produced output against its recipe.
///
/// Audio recipes reject moving video; attached pictures are left to the
/// audio rebuild (`rebuild_args`), which keeps at most one re-encoded cover.
/// Attached pictures never count as the video stream of a video recipe.
fn check_streams(
    recipe: Recipe,
    streams: &[Value],
    selected_height: Option<u32>,
) -> Result<(), Problem> {
    let required = if recipe.audio_only() {
        streams.iter().any(|s| s["codec_type"] == "audio")
    } else {
        streams.iter().any(moving_video)
    };
    if !required {
        return Err(output_rejected(
            "The output is missing its required media stream.",
        ));
    }
    if recipe.audio_only() && streams.iter().any(moving_video) {
        return Err(output_rejected(
            "The audio output unexpectedly contains video.",
        ));
    }
    if recipe == Recipe::Webm
        && streams.iter().any(|s| {
            (s["codec_type"] == "video"
                && !["vp8", "vp9", "av1"].contains(&s["codec_name"].as_str().unwrap_or("")))
                || (s["codec_type"] == "audio"
                    && !["opus", "vorbis"].contains(&s["codec_name"].as_str().unwrap_or("")))
        })
    {
        return Err(issue(
            "media_verification",
            "The output uses a codec that is incompatible with WebM.",
            "prepare_again",
        ));
    }
    if !recipe.audio_only()
        && selected_height.is_some_and(|h| {
            !streams
                .iter()
                .any(|s| moving_video(s) && s["height"].as_u64() == Some(h as u64))
        })
    {
        return Err(issue(
            "media_quality_changed",
            "The saved resolution differs from the confirmed selection.",
            "prepare_again",
        ));
    }
    Ok(())
}
/// When the extractor reported no height, the confirmed cap is checked against
/// the saved moving video instead. Known heights are already within the cap
/// (format selection) and must match the output exactly (`check_streams`).
fn check_height_cap(
    recipe: Recipe,
    streams: &[Value],
    selected_height: Option<u32>,
    max_height: u32,
) -> Result<(), Problem> {
    if recipe.audio_only() || max_height == 0 || selected_height.is_some() {
        return Ok(());
    }
    let within = streams.iter().filter(|s| moving_video(s)).all(|s| {
        s["height"]
            .as_u64()
            .is_some_and(|h| h > 0 && h <= max_height as u64)
    });
    if within {
        Ok(())
    } else {
        Err(issue(
            "media_quality_changed",
            "The saved resolution exceeds the chosen maximum; no files were published.",
            "prepare_again",
        ))
    }
}
fn duration_ms(raw: &Value) -> Option<u64> {
    raw.get("duration")
        .and_then(Value::as_f64)
        .filter(|n| n.is_finite() && *n >= 0.0 && *n < 31_536_000.0)
        .map(|n| (n * 1000.0).round() as u64)
}
fn source_signature(raw: &Value) -> String {
    let formats = raw
        .get("requested_formats")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_else(|| vec![raw.clone()]);
    let properties = formats.iter().map(|f| json!({"id":f["format_id"],"video_codec":f["vcodec"],"audio_codec":f["acodec"],"width":f["width"],"height":f["height"],"fps":f["fps"],"size":f["filesize"]})).collect::<Vec<_>>();
    digest(
        &serde_json::to_vec(
            &json!({"id":raw["id"],"duration_ms":duration_ms(raw),"formats":properties}),
        )
        .expect("metadata serializes"),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn an_earlier_budget_cut_preserves_specific_terminal_errors() {
        for diagnostic in [
            b"Private video".as_slice(),
            b"Sign in to continue",
            b"Media was removed",
            b"HTTP 429: Too many requests",
            b"Certificate verification failed",
        ] {
            assert_eq!(
                classify_failure(diagnostic, true).code,
                classify(diagnostic).code
            );
        }
        assert_eq!(
            classify_failure(b"Broken transfer", true).code,
            "media_budget"
        );
        assert_eq!(
            classify_failure(b"Broken transfer", false).code,
            "media_extraction"
        );
    }

    #[test]
    fn membership_denial_does_not_fail_the_channel_as_an_expired_session() {
        let diagnostic = b"WARNING: account cookies may have rotated\nERROR: This video is available to this channel's members on level: Members Plus (or any higher level). Join this channel to get access to members-only content and other exclusive perks.";
        assert_eq!(classify(diagnostic).code, "media_access_denied");
        assert_eq!(
            classify(b"Sign in to confirm your age").code,
            "authentication_required"
        );
        assert_eq!(
            classify(b"Your cookies are no longer valid").code,
            "authentication_required"
        );
    }

    // Fictional providers with different navigation and transport layouts.
    // Neither is privileged by core; both must project identically.
    const LANTERN: &str = "https://lantern.example";
    const HARBOR: &str = "https://harbor.example";
    const PROJECTED: [&str; 20] = [
        "id",
        "title",
        "description",
        "duration",
        "view_count",
        "channel_follower_count",
        "timestamp",
        "upload_date",
        "channel",
        "channel_id",
        "uploader",
        "uploader_id",
        "availability",
        "live_status",
        "playlist_count",
        "channel_url",
        "webpage_url",
        "thumbnail",
        "accessible",
        "position",
    ];
    fn only_projected_keys(value: &Value) {
        for key in value.as_object().expect("projected object").keys() {
            assert!(PROJECTED.contains(&key.as_str()), "unexpected key {key}");
        }
    }

    #[test]
    fn flat_entries_keep_artwork_and_metadata_but_leave_navigation_to_plugins() {
        for (base, id) in [(LANTERN, "lv-1"), (HARBOR, "hb-1")] {
            let value = item(&json!({
                "_type":"url","ie_key":"Fixture","id":id,"url":format!("{base}/watch/{id}"),
                "view_count":123,"duration":61,
                "thumbnails":[
                    {"url":format!("{base}/art/{id}-small.jpg"),"width":120},
                    {"url":"http://insecure.example/art.jpg","width":4000},
                    {"url":format!("{base}/art/{id}-large.jpg"),"width":720}
                ]
            }));
            // Core does not rebuild or promote site navigation for any host.
            assert!(value.get("webpage_url").is_none(), "{base}");
            assert!(value.get("url").is_none());
            assert_eq!(value["id"], id);
            assert_eq!(value["thumbnail"], format!("{base}/art/{id}-large.jpg"));
            assert_eq!(value["view_count"], 123);
            // Flat entries never claim playable access.
            assert!(value.get("accessible").is_none());
            only_projected_keys(&value);
        }
        // Core never derives a page URL from a host's path layout, for any host.
        for url in [
            "https://www.video.example/watch?v=abcdefghijk",
            "https://video.example/shorts/abcdefghijk",
        ] {
            assert!(
                item(&json!({"id":"abcdefghijk","url":url}))
                    .get("webpage_url")
                    .is_none()
            );
        }
        // An extractor that reports a page URL itself keeps it unchanged.
        let reported = item(&json!({
            "id":"hb-2","url":"https://cdn.harbor.example/hb-2.mp4?sig=SECRET",
            "webpage_url":format!("{HARBOR}/clip/hb-2")
        }));
        assert_eq!(reported["webpage_url"], format!("{HARBOR}/clip/hb-2"));
        assert!(!reported.to_string().contains("SECRET"));
    }

    #[test]
    fn flat_entries_never_project_transport_or_credential_bearing_urls() {
        let listing = json!({"id":"mixed","title":"Mixed","entries":[
            {"id":"lv-2","url":"https://cdn.lantern.example/v/lv-2/master.m3u8?token=SECRET_TOKEN&expires=1",
             "http_headers":{"Cookie":"lantern_session=SECRET_COOKIE","Authorization":"Bearer SECRET_BEARER"},
             "cookies":"lantern_session=SECRET_COOKIE; Domain=.lantern.example"},
            {"id":"lv-3","url":"https://viewer:SECRET_PASSWORD@lantern.example/watch/lv-3"},
            {"id":"hb-3","url":"https://harbor.example/clip/hb-3?session=SECRET_SESSION",
             "original_url":"https://harbor.example/clip/hb-3?session=SECRET_SESSION",
             "manifest_url":"https://cdn.harbor.example/hb-3.mpd?sig=SECRET_SIG",
             "fragments":[{"url":"https://cdn.harbor.example/hb-3/1.m4s?sig=SECRET_SIG"}],
             "_filename":"/private/SECRET_PATH/media.mp4","filename":"/private/SECRET_PATH/media.mp4",
             "requested_downloads":[{"filepath":"/private/SECRET_PATH/media.mp4"}]},
            {"id":"hb-4","url":"data:text/plain,SECRET_DATA","title":"Harbor 4"},
            {"id":"hb-5","url":"http://harbor.example/clip/hb-5?SECRET_PLAIN"}
        ]});
        let page = project(&listing, 0, 10).unwrap();
        let text = page.to_string();
        assert!(!text.contains("SECRET"), "{text}");
        assert!(!text.contains("cdn."), "{text}");
        let entries = page["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 5);
        for entry in entries {
            assert!(entry.get("webpage_url").is_none(), "{entry}");
            only_projected_keys(entry);
        }
        assert_eq!(entries[3]["title"], "Harbor 4");
    }

    #[test]
    fn full_and_flat_inspection_paginate_identically_for_every_provider() {
        // Pagination is a generic tool window: never site-specific options.
        assert_eq!(
            enumeration_args(0, 3, true),
            [
                "--playlist-start",
                "1",
                "--playlist-end",
                "3",
                "--flat-playlist"
            ]
        );
        assert_eq!(
            enumeration_args(20, 23, false),
            ["--playlist-start", "21", "--playlist-end", "23"]
        );
        for listing in [true, false] {
            assert!(
                !enumeration_args(4, 7, listing)
                    .iter()
                    .any(|a| a.starts_with("--extractor") || a.contains(':'))
            );
        }
        for base in [LANTERN, HARBOR] {
            // Full extraction of one item: extractor-reported page and evidence.
            let full = project(
                &json!({"id":"one","title":"One","webpage_url":format!("{base}/watch/one"),
                    "timestamp":1_793_491_200,"upload_date":"20261101",
                    "formats":[{"url":format!("{base}/media/one.mp4?token=SECRET"),"vcodec":"avc1","acodec":"mp4a",
                        "http_headers":{"Cookie":"SECRET"}}],
                    "http_headers":{"Cookie":"SECRET"}}),
                0,
                1,
            )
            .unwrap();
            assert_eq!(full["kind"], "video");
            assert_eq!(full["webpage_url"], format!("{base}/watch/one"));
            assert_eq!(full["timestamp"], 1_793_491_200);
            assert_eq!(full["accessible"], true);
            assert!(full.get("next_cursor").is_none());
            assert!(!full.to_string().contains("SECRET"));
            // A windowed flat listing returns page_size + 1 entries when more exist.
            let window = |ids: &[&str]| {
                let entries: Vec<Value> = ids
                    .iter()
                    .map(|id| match *id {
                        "gone" => Value::Null,
                        id => json!({"id":id,"url":format!("{base}/watch/{id}?t=SECRET")}),
                    })
                    .collect();
                json!({"id":"list","webpage_url":format!("{base}/list"),"entries":entries})
            };
            let first = project(&window(&["a", "b", "c"]), 0, 2).unwrap();
            assert_eq!(first["kind"], "collection");
            assert_eq!(first["webpage_url"], format!("{base}/list"));
            assert_eq!(first["entries"].as_array().unwrap().len(), 2);
            assert_eq!(first["next_cursor"], "2");
            let second = project(&window(&["c", "gone", "e"]), 2, 2).unwrap();
            assert_eq!(second["entries"][0]["id"], "c");
            assert_eq!(
                second["entries"][1],
                json!({"availability":"unavailable","position":null})
            );
            assert_eq!(second["next_cursor"], "4");
            let last = project(&window(&["e"]), 4, 2).unwrap();
            assert_eq!(last["entries"].as_array().unwrap().len(), 1);
            assert!(last["next_cursor"].is_null());
            for page in [&first, &second, &last] {
                assert!(!page.to_string().contains("SECRET"));
                assert!(
                    page["entries"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .all(|e| e.get("webpage_url").is_none())
                );
            }
        }
        let offset_page = project(
            &json!({"entries":[{"id":"a"},{"id":"b"},{"id":"c"}]}),
            20,
            2,
        )
        .unwrap();
        assert_eq!(offset_page["entries"].as_array().unwrap().len(), 2);
        assert_eq!(offset_page["next_cursor"], "22");
        assert!(project(&Value::Null, 0, 1).is_err());
    }
    #[test]
    fn download_verification_requires_exactly_one_object_before_publication() {
        let raw = b"[download] Resuming at byte 65536\nOMD_SOURCE {\"id\":\"same-video\",\"duration\":20}\r\n[download] already downloaded\n";
        assert_eq!(download_metadata(raw).unwrap()["id"], "same-video");
        for invalid in [
            b"[download] completed without metadata".as_slice(),
            b"OMD_SOURCE null\n",
            b"OMD_SOURCE []\n",
            b"OMD_SOURCE {PRIVATE_TOKEN}\n",
            b"OMD_SOURCE {}\nOMD_SOURCE {}\n",
            b"OMD_SOURCE {}\nOMD_SOURCE invalid\n",
        ] {
            let error = download_metadata(invalid).unwrap_err();
            assert_eq!(error.code, "media_metadata_invalid");
            assert!(!error.message.contains("PRIVATE_TOKEN"));
        }
    }
    #[test]
    fn access_projection_preserves_privacy_without_leaking_transport_secrets() {
        let raw = json!({"id":"private-video","availability":"private","formats":[{"url":"https://media.example/?token=SECRET","http_headers":{"Cookie":"SECRET"},"vcodec":"av1","acodec":"none"}]});
        let public = item(&raw);
        assert_eq!(public["availability"], "private");
        assert_eq!(public["accessible"], true);
        assert!(!public.to_string().contains("SECRET"));
        assert!(
            item(&json!({"availability":"private"}))
                .get("accessible")
                .is_none()
        );
        assert_eq!(item(&json!({"formats":[]}))["accessible"], false);
        assert_eq!(
            item(
                &json!({"formats":[{"url":"https://example.com/storyboard","vcodec":"none","acodec":"none"}]})
            )["accessible"],
            false
        );
        assert_eq!(
            item(
                &json!({"formats":[{"url":"https://example.com/drm","vcodec":"av1","has_drm":true}]})
            )["accessible"],
            false
        );
    }
    #[test]
    fn source_signature_binds_identity_and_selected_formats_without_expiring_urls() {
        let original = json!({"id":"video-a","duration":20,"requested_formats":[{"format_id":"140","acodec":"aac","url":"https://cdn.example/a?expires=1"},{"format_id":"395","vcodec":"av1","height":240}]});
        let mut refreshed = original.clone();
        refreshed["requested_formats"][0]["url"] = json!("https://cdn.example/b?expires=2");
        assert_eq!(source_signature(&original), source_signature(&refreshed));
        refreshed["id"] = json!("video-b");
        assert_ne!(source_signature(&original), source_signature(&refreshed));
        refreshed = original.clone();
        refreshed["requested_formats"][1]["height"] = json!(720);
        assert_ne!(source_signature(&original), source_signature(&refreshed));
        refreshed = original.clone();
        refreshed["requested_formats"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        assert_ne!(source_signature(&original), source_signature(&refreshed));
    }
    #[test]
    fn only_explicit_formats_are_selected_for_each_recipe() {
        let policy = SelectionPolicy::default();
        for recipe in [
            Recipe::Mp4,
            Recipe::Webm,
            Recipe::Mkv,
            Recipe::M4a,
            Recipe::Mp3,
            Recipe::Opus,
        ] {
            assert!(!format_expression(recipe, &policy).unwrap().is_empty());
        }
        assert!(format_expression(Recipe::Cbz, &policy).is_err());
    }
    fn parts(problem: Problem) -> (String, String, bool, Vec<String>) {
        (
            problem.code,
            problem.message,
            problem.retryable,
            problem.actions,
        )
    }
    fn stream(codec_type: &str, codec_name: &str, attached_pic: u8, height: u64) -> Value {
        json!({"codec_type":codec_type,"codec_name":codec_name,"width":height,"height":height,
            "disposition":{"attached_pic":attached_pic}})
    }
    #[test]
    fn audio_outputs_reject_moving_video_and_leave_flagged_pictures_to_the_cover_policy() {
        // The ffprobe view of a publisher's podcast MP3 with an ID3v2 APIC PNG
        // cover that was not decoded (so no dimensions).
        let episode: Value = serde_json::from_str(
            r#"[{"index":0,"codec_name":"mp3","codec_type":"audio","disposition":{"attached_pic":0}},
                {"index":1,"codec_name":"png","codec_type":"video","width":0,"height":0,
                 "disposition":{"attached_pic":1}}]"#,
        )
        .unwrap();
        let episode = episode.as_array().unwrap();
        for recipe in [Recipe::Mp3, Recipe::M4a, Recipe::Opus] {
            // Flagged pictures pass the stream check whatever their label says;
            // the audio rebuild then removes them.
            check_streams(recipe, episode, None).unwrap();
            assert!(episode.iter().any(attached));
            for label in ["mjpeg", "png", "gif", "webp", "h264", ""] {
                let streams = [stream("audio", "aac", 0, 0), stream("video", label, 1, 600)];
                check_streams(recipe, &streams, None)
                    .unwrap_or_else(|p| panic!("{recipe:?} {label}: {}", p.message));
                assert!(attached(&streams[1]) && !moving_video(&streams[1]));
            }
            for video in [
                // Real video, motion-JPEG/PNG tracks, and a missing disposition.
                stream("video", "h264", 0, 720),
                stream("video", "mjpeg", 0, 500),
                stream("video", "png", 0, 500),
                json!({"codec_type":"video","codec_name":"png"}),
            ] {
                let problem =
                    check_streams(recipe, &[stream("audio", "aac", 0, 0), video.clone()], None)
                        .unwrap_err();
                assert_eq!(
                    parts(problem),
                    parts(output_rejected(
                        "The audio output unexpectedly contains video."
                    )),
                    "{recipe:?} {video}"
                );
            }
            // A picture alone is not an audio output.
            assert_eq!(
                parts(check_streams(recipe, &[stream("video", "png", 1, 500)], None).unwrap_err()),
                parts(output_rejected(
                    "The output is missing its required media stream."
                ))
            );
        }
    }
    #[test]
    fn a_cover_picture_never_stands_in_for_the_video_of_a_video_recipe() {
        let cover = stream("video", "mjpeg", 1, 720);
        let audio = stream("audio", "aac", 0, 0);
        for recipe in [Recipe::Mp4, Recipe::Mkv] {
            assert_eq!(
                parts(check_streams(recipe, &[audio.clone(), cover.clone()], None).unwrap_err()),
                parts(output_rejected(
                    "The output is missing its required media stream."
                ))
            );
            // The selected height must come from the moving video.
            let video = stream("video", "h264", 0, 480);
            assert_eq!(
                check_streams(
                    recipe,
                    &[audio.clone(), video.clone(), cover.clone()],
                    Some(720)
                )
                .unwrap_err()
                .code,
                "media_quality_changed"
            );
            check_streams(recipe, &[audio.clone(), video, cover.clone()], Some(480)).unwrap();
        }
        let webm = [
            stream("audio", "opus", 0, 0),
            stream("video", "vp9", 0, 720),
        ];
        check_streams(Recipe::Webm, &webm, Some(720)).unwrap();
        assert_eq!(
            check_streams(
                Recipe::Webm,
                &[webm[0].clone(), webm[1].clone(), cover],
                Some(720)
            )
            .unwrap_err()
            .message,
            "The output uses a codec that is incompatible with WebM."
        );
    }
    #[test]
    fn capped_selection_admits_unknown_heights_only_as_a_checked_fallback() {
        let capped = SelectionPolicy {
            max_height: 720,
            ..Default::default()
        };
        assert_eq!(
            format_expression(Recipe::Webm, &capped).unwrap(),
            "bv[ext=webm][height<=720]+ba[ext=webm]/b[ext=webm][height<=720]/\
             bv[ext=webm][height<=?720]+ba[ext=webm]/b[ext=webm][height<=?720]"
        );
        // MP4 admits a format of unknown height only after every known one
        // within the cap, VP9 included.
        let mp4 = format_expression(Recipe::Mp4, &capped).unwrap();
        let alternatives = mp4.split('/').collect::<Vec<_>>();
        let last_known = alternatives
            .iter()
            .rposition(|a| a.contains("[height<=720]"))
            .unwrap();
        let first_unknown = alternatives
            .iter()
            .position(|a| a.contains("[height<=?720]"))
            .unwrap();
        assert!(last_known < first_unknown, "{mp4}");
        let open = SelectionPolicy {
            max_height: 0,
            ..Default::default()
        };
        assert_eq!(format_expression(Recipe::Mkv, &open).unwrap(), "bv+ba/b");
        let audio = stream("audio", "aac", 0, 0);
        let cover = stream("video", "mjpeg", 1, 3000);
        let hd = stream("video", "h264", 0, 720);
        let full = stream("video", "h264", 0, 1080);
        // Unknown extractor height: the saved video decides.
        check_height_cap(
            Recipe::Mp4,
            &[audio.clone(), hd.clone(), cover.clone()],
            None,
            720,
        )
        .unwrap();
        let problem =
            check_height_cap(Recipe::Mp4, &[audio.clone(), full.clone()], None, 720).unwrap_err();
        assert_eq!(problem.code, "media_quality_changed");
        let unknown =
            json!({"codec_type":"video","codec_name":"h264","disposition":{"attached_pic":0}});
        assert!(check_height_cap(Recipe::Mkv, &[audio.clone(), unknown], None, 720).is_err());
        // Unrestricted, known-height and audio recipes are unaffected.
        check_height_cap(Recipe::Mp4, &[audio.clone(), full.clone()], None, 0).unwrap();
        check_height_cap(Recipe::Mp4, &[audio.clone(), full.clone()], Some(1080), 720).unwrap();
        check_height_cap(Recipe::M4a, &[audio, cover], None, 720).unwrap();
    }
    /// A file that ffprobe ran on and rejected fails the same way on every
    /// attempt, so it asks for a new preparation; a helper that could not run
    /// or finish stays retryable.
    #[test]
    fn a_rejected_container_asks_for_another_format_instead_of_a_retry() {
        use omd_isolation::Exit;
        let invalid: &[u8] = b"[mov,mp4,m4a,3gp,3g2,mj2 @ 0x1] Empty VP Codec Configuration box\n\
            [mov,mp4,m4a,3gp,3g2,mj2 @ 0x1] error reading header\n\
            media.mp4: Invalid data found when processing input\n";
        let capture = |exit: Exit, stderr: &[u8]| omd_isolation::Capture {
            stdout: b"{}".to_vec(),
            stderr: stderr.to_vec(),
            success: exit == Exit::Code(0),
            exit,
        };
        assert_eq!(probe_result(capture(Exit::Code(0), b"")).unwrap(), b"{}");
        let rejected = probe_result(capture(Exit::Code(1), invalid)).unwrap_err();
        assert_eq!(rejected.code, "media_verification");
        assert!(!rejected.retryable);
        assert_eq!(rejected.actions, ["prepare_again"]);
        assert_eq!(
            rejected.message,
            "OMD could not verify the downloaded media file, so it was not saved. \
             Trying again would give the same result; prepare it again and choose another format."
        );
        // Anything short of ffprobe's own rejection of the media may not
        // recur: a crash or kill (directly, or as 128 plus the signal under
        // the Linux guardian, or an NTSTATUS on Windows), another status, a
        // missing or unreadable file, a listing it could not write, or a
        // failure without a diagnostic.
        for (exit, stderr) in [
            (Exit::Signal(11), invalid),
            (Exit::Signal(9), &b""[..]),
            (Exit::Code(139), invalid),
            (Exit::Code(-1073741819), invalid),
            (Exit::Code(255), invalid),
            (
                Exit::Code(1),
                &b"media.mp4: No such file or directory\n"[..],
            ),
            (Exit::Code(1), &b"media.mp4: Input/output error\n"[..]),
            (Exit::Code(1), &b"media.mp4: Operation not permitted\n"[..]),
            (
                Exit::Code(1),
                &b"Failed to open output file '.omd-packets-source.csv': No space left on device\n"
                    [..],
            ),
            (Exit::Code(1), &b""[..]),
        ] {
            let transient = probe_result(capture(exit, stderr)).unwrap_err();
            assert_eq!(transient.code, "media_verification", "{exit:?}");
            assert!(
                transient.retryable,
                "{exit:?} {}",
                String::from_utf8_lossy(stderr)
            );
            assert_eq!(transient.actions, ["retry"]);
        }
        // Stream checks of a completed download are just as deterministic.
        let missing =
            check_streams(Recipe::Mp4, &[stream("audio", "aac", 0, 0)], None).unwrap_err();
        assert!(!missing.retryable && missing.actions == ["prepare_again"]);
    }
    /// MP4 is the recipe that plays everywhere: within each height group,
    /// formats without VP9 come before VP9, and every format of known height
    /// within the cap comes before any of unknown height. A source that offers
    /// only VP9 in MP4 still yields a file.
    #[test]
    fn mp4_prefers_video_other_than_vp9_and_keeps_it_only_as_a_last_resort() {
        let not_vp9 = "[vcodec!^=?vp09][vcodec!^=?vp9]";
        let capped = SelectionPolicy {
            max_height: 1080,
            ..Default::default()
        };
        assert_eq!(
            format_expression(Recipe::Mp4, &capped).unwrap(),
            [
                format!("bv[ext=mp4]{not_vp9}[height<=1080]+ba[ext=m4a]"),
                format!("b[ext=mp4]{not_vp9}[height<=1080]"),
                "bv[ext=mp4][height<=1080]+ba[ext=m4a]".into(),
                "b[ext=mp4][height<=1080]".into(),
                format!("bv[ext=mp4]{not_vp9}[height<=?1080]+ba[ext=m4a]"),
                format!("b[ext=mp4]{not_vp9}[height<=?1080]"),
                "bv[ext=mp4][height<=?1080]+ba[ext=m4a]".into(),
                "b[ext=mp4][height<=?1080]".into(),
            ]
            .join("/")
        );
        let open = SelectionPolicy {
            max_height: 0,
            ..Default::default()
        };
        assert_eq!(
            format_expression(Recipe::Mp4, &open).unwrap(),
            format!(
                "bv[ext=mp4]{not_vp9}+ba[ext=m4a]/b[ext=mp4]{not_vp9}/bv[ext=mp4]+ba[ext=m4a]/b[ext=mp4]"
            )
        );
        // Every alternative keeps the MP4 container, and only MP4 leaves out
        // VP9: WebM and MKV select as before.
        for policy in [&capped, &open] {
            let mp4 = format_expression(Recipe::Mp4, policy).unwrap();
            assert!(mp4.split('/').all(|alternative| {
                alternative
                    .split('+')
                    .all(|part| part.contains("[ext=mp4]") || part == "ba[ext=m4a]")
            }));
            for recipe in [Recipe::Webm, Recipe::Mkv] {
                assert!(
                    !format_expression(recipe, policy)
                        .unwrap()
                        .contains("vcodec")
                );
            }
        }
        // The filters negate a prefix match and admit an unreported codec.
        assert!(not_vp9.contains("!^=?vp09") && not_vp9.contains("!^=?vp9]"));
        assert_eq!(NOT_VP9, not_vp9);
    }
    /// A video output is probed with a pixel budget that fits a 16:9 frame at
    /// the highest accepted cap, so an 8K or 16K VP9 frame keeps its
    /// dimensions; audio outputs and their covers keep the 4096x4096 budget.
    /// The bundled FFmpeg's built-in default is the same video budget.
    #[test]
    fn video_probes_fit_every_accepted_cap_and_audio_keeps_the_picture_budget() {
        let video: u64 = MAX_VIDEO_PIXELS.parse().unwrap();
        let height = u64::from(MAX_HEIGHT);
        assert_eq!(video, height * height * 16 / 9);
        assert_eq!(
            video,
            15360 * 8640,
            "16K UHD; an 8K frame is a quarter of it"
        );
        assert!(
            video <= i32::MAX as u64,
            "FFmpeg's max_pixels is at most INT_MAX"
        );
        let side = u64::from(container::MAX_PICTURE_SIDE);
        assert_eq!(MAX_PIXELS.parse::<u64>().unwrap(), side * side);
        for recipe in [Recipe::Mp4, Recipe::Mkv, Recipe::Webm] {
            assert_eq!(probe_budget(recipe), MAX_VIDEO_PIXELS);
        }
        for recipe in [Recipe::M4a, Recipe::Mp3, Recipe::Opus] {
            assert_eq!(probe_budget(recipe), MAX_PIXELS);
        }
        // The highest cap is accepted; a higher one is not.
        let policy = |max_height| SelectionPolicy {
            max_height,
            ..Default::default()
        };
        assert!(format_expression(Recipe::Mp4, &policy(MAX_HEIGHT)).is_ok());
        assert!(format_expression(Recipe::Mp4, &policy(MAX_HEIGHT + 1)).is_err());
        // The media build pins the same value as every decoder's default.
        let build = include_str!("../../../scripts/build-media.py");
        assert!(build.contains(&format!("VIDEO_PIXEL_BUDGET = {MAX_VIDEO_PIXELS}\n")));
    }
    #[test]
    fn only_plain_engine_tags_are_selected() {
        let data = json!({
            "format": {"tags": {
                "TITLE": "  Episode One ", "artist": "Fixture Artist", "track": "3/12",
                "disc": "one", "date": "2026", "comment": "kept nowhere",
                "id3v2_priv.owner": "SECRET", "lyrics-eng": "la", "genre": "a\u{7}b",
                "album": "x".repeat(container::MAX_TEXT + 1), "encoder": "Lavf"
            }},
            "streams": [{"tags": {"title": "stream title", "ALBUMARTIST": "ignored", "album_artist": "Band"}}]
        });
        assert_eq!(
            select_tags(&data),
            [
                ("title", "Episode One".to_string()),
                ("artist", "Fixture Artist".into()),
                ("album_artist", "Band".into()),
                ("date", "2026".into()),
                ("track", "3/12".into()),
            ]
        );
        // Ogg Opus comments live on the audio stream.
        let opus = json!({"format": {}, "streams": [{"tags": {"TRACKNUMBER": "4", "DISCNUMBER": "2/2/2"}}]});
        assert!(
            select_tags(&opus).is_empty(),
            "Vorbis field names are not FFmpeg keys"
        );
        let opus = json!({"format": {}, "streams": [{"tags": {"track": "4", "disc": "1/2"}}]});
        assert_eq!(
            select_tags(&opus),
            [("track", "4".to_string()), ("disc", "1/2".into())]
        );
        assert!(select_tags(&json!({})).is_empty());
    }
    #[test]
    fn plan_values_fill_only_missing_tags() {
        use omd_domain::{Collection, CollectionSummary, OutputMetadata};
        let mut plan: Plan =
            serde_json::from_str(include_str!("../../../tests/fixtures/v2-plan.json")).unwrap();
        plan.release.title = "Episode Seven".into();
        plan.collection.title = "Fixture Show".into();
        plan.collection.kind = CollectionKind::Channel;
        plan.release.published_at = Some("2026-02-28T09:30:00+01:00".into());
        let tags = |plan: &Plan, source: &[(&'static str, &str)]| {
            with_plan_fallback(
                plan,
                source.iter().map(|(k, v)| (*k, v.to_string())).collect(),
            )
        };
        let owned = |list: &[(&'static str, &str)]| -> Vec<(&'static str, String)> {
            list.iter().map(|(k, v)| (*k, v.to_string())).collect()
        };
        // Nothing in the source: title, artist (collection title) and date.
        assert_eq!(
            tags(&plan, &[]),
            owned(&[
                ("title", "Episode Seven"),
                ("artist", "Fixture Show"),
                ("date", "2026-02-28")
            ])
        );
        // Kept source tags win; only missing keys are filled, in TAGS order.
        assert_eq!(
            tags(&plan, &[("track", "3/12"), ("artist", "Source Artist")]),
            owned(&[
                ("title", "Episode Seven"),
                ("artist", "Source Artist"),
                ("date", "2026-02-28"),
                ("track", "3/12")
            ])
        );
        assert_eq!(
            tags(&plan, &[("title", "Source Title"), ("date", "2025")]),
            owned(&[
                ("title", "Source Title"),
                ("artist", "Fixture Show"),
                ("date", "2025")
            ])
        );
        // Release creators come before the collection title; reviewed
        // overrides replace the source titles.
        plan.release.preview = Some(Collection {
            summary: Some(CollectionSummary {
                creators: vec![
                    " Host One ".into(),
                    "".into(),
                    "Host Two".into(),
                    "Host One".into(),
                ],
                ..Default::default()
            }),
            ..plan.collection.clone()
        });
        plan.metadata.release.title = Some("Reviewed Episode".into());
        plan.metadata.collection.title = Some("Reviewed Show".into());
        plan.release.published_at = Some("yesterday".into());
        assert_eq!(
            tags(&plan, &[]),
            owned(&[
                ("title", "Reviewed Episode"),
                ("artist", "Host One, Host Two")
            ])
        );
        plan.release.preview = None;
        assert_eq!(tags(&plan, &[])[1], ("artist", "Reviewed Show".to_string()));
        // Only a channel's title stands in for the artist: a series, a
        // playlist or search results, or a standalone item, is not one.
        for kind in [
            CollectionKind::Manga,
            CollectionKind::Playlist,
            CollectionKind::Item,
        ] {
            let other = Plan {
                collection: Collection {
                    kind,
                    ..plan.collection.clone()
                },
                ..plan.clone()
            };
            assert_eq!(tags(&other, &[]), owned(&[("title", "Reviewed Episode")]));
            assert_eq!(
                tags(&other, &[("artist", "Source Artist")]),
                owned(&[("title", "Reviewed Episode"), ("artist", "Source Artist")])
            );
        }
        // Never an album or album artist, and nothing that is not plain text.
        plan.metadata = OutputMetadata::default();
        plan.release.title = "x".repeat(container::MAX_TEXT + 1);
        plan.collection.title = "Line\nbreak".into();
        assert_eq!(tags(&plan, &[]), owned(&[]));
        assert_eq!(
            tags(&plan, &[("album", "Source Album")]),
            owned(&[("album", "Source Album")])
        );
    }
    #[test]
    fn only_valid_calendar_dates_become_date_tags() {
        for (value, date) in [
            ("2026-01-01", Some("2026-01-01")),
            ("2026-01-01T00:00:00Z", Some("2026-01-01")),
            ("2024-02-29T23:59:60.123+05:30", Some("2024-02-29")),
            (" 2026-12-31 ", Some("2026-12-31")),
            ("2026-01-01 08:00:00-08:00", Some("2026-01-01")),
            ("2025-02-29", None),
            ("1900-02-29", None),
            ("2026-04-31", None),
            ("2026-13-01", None),
            ("2026-00-10", None),
            ("0000-01-01", None),
            ("2026", None),
            ("2026-05", None),
            ("26-05-01", None),
            ("2026-1-01", None),
            ("2026-01-01T25:00:00Z", None),
            ("2026-01-01T10:00Z", None),
            ("2026-01-01T10:00:00", None),
            ("2026-01-01T10:00:00+0100", None),
            ("2026-01-01T10:00:00.Z", None),
            ("2026-01-01-01", None),
            ("2 hours ago", None),
            ("", None),
        ] {
            assert_eq!(calendar_date(value).as_deref(), date, "{value:?}");
        }
    }
    #[test]
    fn the_front_cover_is_kept_only_as_a_decoded_still_picture() {
        let picture = |index: u64, codec: &str, side: u64, comment: &str| {
            json!({"index":index,"codec_type":"video","codec_name":codec,"width":side,"height":side,
                "disposition":{"attached_pic":1},"tags":{"comment":comment}})
        };
        let audio = json!({"index":0,"codec_type":"audio","codec_name":"mp3","disposition":{"attached_pic":0}});
        let streams = [
            audio.clone(),
            picture(1, "png", 600, "Other"),
            picture(2, "mjpeg", 3000, "Cover (front)"),
        ];
        assert_eq!(
            cover(Recipe::Mp3, &streams),
            Some(Cover {
                index: 2,
                codec: "mjpeg"
            })
        );
        assert_eq!(
            cover(Recipe::M4a, &streams[..2]),
            Some(Cover {
                index: 1,
                codec: "png"
            })
        );
        // FFmpeg's Ogg muxer cannot store a picture.
        assert_eq!(cover(Recipe::Opus, &streams), None);
        for unusable in [
            picture(1, "gif", 600, "Cover (front)"),
            picture(1, "webp", 600, "Cover (front)"),
            // Not decoded within the pixel budget, or not decodable at all.
            picture(1, "png", 0, "Cover (front)"),
            picture(1, "mjpeg", 5000, "Cover (front)"),
            // Moving video is never a cover.
            json!({"index":1,"codec_type":"video","codec_name":"mjpeg","width":600,"height":600,"disposition":{"attached_pic":0}}),
        ] {
            assert_eq!(
                cover(Recipe::Mp3, &[audio.clone(), unusable.clone()]),
                None,
                "{unusable}"
            );
        }
    }
    #[test]
    fn rebuilds_copy_audio_and_write_only_selected_tags_and_a_re_encoded_cover() {
        let args = |recipe, tags: &[(&'static str, String)], cover: Option<&Cover>| {
            rebuild_args(recipe, "media.x", "out.x", tags, cover).map(|a| a.join(" "))
        };
        assert_eq!(
            args(Recipe::Mp3, &[], None).unwrap(),
            "-nostdin -v error -max_pixels 16777216 -i media.x -map 0:a:0 -c:a copy -map_metadata -1 -map_chapters -1 -fflags +bitexact -id3v2_version 0 -write_id3v1 0 -f mp3 out.x"
        );
        let tags = [("title", "-map 0:v -c copy".to_string())];
        let cover = Cover {
            index: 2,
            codec: "mjpeg",
        };
        let full = rebuild_args(Recipe::Mp3, "media.x", "out.x", &tags, Some(&cover)).unwrap();
        // A tag value stays one argument; it can never become an option.
        assert!(full.contains(&"title=-map 0:v -c copy".to_string()));
        assert_eq!(
            full.join(" "),
            "-nostdin -v error -max_pixels 16777216 -i media.x -map 0:a:0 -map 0:2 -c:a copy -filter:v sidedata=mode=delete -c:v mjpeg -q:v 2 -flags:v +bitexact -disposition:v:0 attached_pic -metadata:s:v:0 comment=Cover (front) -map_metadata -1 -map_chapters -1 -metadata title=-map 0:v -c copy -fflags +bitexact -id3v2_version 4 -write_id3v1 0 -f mp3 out.x"
        );
        let png = Cover {
            index: 1,
            codec: "png",
        };
        let m4a = args(Recipe::M4a, &[], Some(&png)).unwrap();
        assert!(
            m4a.contains("-c:v png -flags:v")
                && m4a.ends_with("-movflags +faststart -f ipod out.x")
        );
        assert!(
            args(Recipe::Opus, &tags, None)
                .unwrap()
                .ends_with("-f opus out.x")
        );
        assert_eq!(args(Recipe::Opus, &[], Some(&png)), None);
        assert_eq!(args(Recipe::Mp4, &[], None), None);
        // Nothing copies a stream other than the first audio stream.
        assert!(
            !full
                .windows(2)
                .any(|w| w[0].starts_with("-c") && w[1] == "copy" && w[0] != "-c:a")
        );
    }
    fn listing(root: &omd_files::Root, file: &str, lines: &[&str]) -> Listing {
        root.write_new(file, lines.concat().as_bytes()).unwrap();
        Listing {
            root: root.try_clone().unwrap(),
            file: file.into(),
            packets: lines.len() as u64,
        }
    }
    #[tokio::test]
    async fn packet_listings_are_compared_as_streams_and_removed() {
        let work = tempfile::tempdir().unwrap();
        let root = omd_files::Root::open(work.path()).unwrap();
        let line =
            |size: u32, hash: u8| format!("{size},murmur3:{}\n", format!("{hash:02x}").repeat(16));
        let lines: Vec<String> = (0..5).map(|i| line(417, i)).collect();
        let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
        let same = listing(&root, "a", &lines);
        let copy = listing(&root, "b", &lines);
        assert!(same_packets(&same, &copy, Compare::Exact).await.unwrap());
        let mut changed = lines.clone();
        let other = line(417, 9);
        changed[2] = &other;
        let changed = listing(&root, "c", &changed);
        assert!(!same_packets(&same, &changed, Compare::Exact).await.unwrap());
        let shorter = listing(&root, "d", &lines[..4]);
        assert!(!same_packets(&same, &shorter, Compare::Exact).await.unwrap());
        // A trimmed listing: a prefix whose last packet may be shorter.
        let short_last = line(200, 3);
        let trimmed = listing(&root, "e", &[lines[0], lines[1], lines[2], &short_last]);
        assert!(
            same_packets(&trimmed, &same, Compare::TrimmedPrefix)
                .await
                .unwrap()
        );
        assert!(
            !same_packets(&same, &trimmed, Compare::TrimmedPrefix)
                .await
                .unwrap()
        );
        let wrong = listing(&root, "f", &[lines[0], &other, lines[2]]);
        assert!(
            !same_packets(&wrong, &same, Compare::TrimmedPrefix)
                .await
                .unwrap()
        );
        // A listing that does not hold exactly its counted packets, or holds
        // something other than packets, is a failure, never a match.
        let mut miscounted = listing(&root, "g", &lines);
        miscounted.packets = 4;
        assert!(
            same_packets(&miscounted, &shorter, Compare::Exact)
                .await
                .is_err()
        );
        let garbage = listing(
            &root,
            "h",
            &[lines[0], "417,md5:00\n", lines[2], lines[3], lines[4]],
        );
        assert!(same_packets(&garbage, &same, Compare::Exact).await.is_err());
        drop((
            same, copy, changed, shorter, trimmed, wrong, miscounted, garbage,
        ));
        assert_eq!(std::fs::read_dir(work.path()).unwrap().count(), 0);
    }
}
