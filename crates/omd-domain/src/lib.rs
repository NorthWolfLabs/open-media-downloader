//! Source-independent acquisition contracts. No transport or filesystem effects.
mod discovery;
pub use discovery::*;
mod presentation;
pub use presentation::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use utoipa::ToSchema;

pub const API_VERSION: &str = "2";
pub const PLUGIN_API: &str = "omd:provider@2.0.0";

#[derive(
    Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(deny_unknown_fields)]
pub struct SourceRef {
    pub provider: String,
    pub id: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IdentifiedSource {
    Collection { reference: SourceRef },
    Release { reference: SourceRef },
}
impl SourceRef {
    pub fn key(&self) -> String {
        digest(&serde_json::to_vec(self).expect("source reference serializes"))
    }
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.provider.is_empty()
            || self.provider.len() > 200
            || self.id.is_empty()
            || self.id.len() > 4096
        {
            return Err(DomainError::Invalid("invalid source identity".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CollectionKind {
    /// A standalone media item with no declared parent collection.
    Item,
    Manga,
    Playlist,
    Channel,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Available,
    External,
    AuthenticationRequired,
    Unavailable,
    Unknown,
}

/// Source-provided artwork geometry and collection navigation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ArtworkLayout {
    Portrait,
    Landscape,
    Square,
    Banner,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CollectionSectionKind {
    Releases,
    Collections,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CollectionSection {
    pub reference: SourceRef,
    pub label: String,
    pub kind: CollectionSectionKind,
}

/// A downloadable image post. One release contains every image in the post.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ImageSummary {
    pub release_id: String,
    pub count: u32,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub format: Option<String>,
    pub bytes: Option<u64>,
    #[serde(default)]
    pub previews: Vec<String>,
}

/// Small, source-provided discovery facts. No executable presentation or social actions.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CollectionLink {
    pub reference: SourceRef,
    pub title: String,
    pub kind: CollectionKind,
    pub canonical_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CreatorLink {
    pub role: String,
    pub collection: CollectionLink,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, ToSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CollectionSummary {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub creator_links: Vec<CreatorLink>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<ImageSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artwork_layout: Option<ArtworkLayout>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub banner_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub video_count_label: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sections: Vec<CollectionSection>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub creators: Vec<String>,
    #[serde(default)]
    pub languages: Vec<String>,
    pub original_language: Option<String>,
    pub status: Option<String>,
    pub year: Option<u16>,
    pub content_rating: Option<String>,
    pub rating: Option<f64>,
    pub rating_max: Option<f64>,
    pub followers: Option<u64>,
    /// Duration and audience facts supplied by a media source, including flat listings.
    pub duration_seconds: Option<u64>,
    pub view_count: Option<u64>,
    /// Source display text (for example “2 hours ago”); never treated as an exact date.
    pub published_label: Option<String>,
    /// The containing collection, such as the channel that published a video.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<CollectionLink>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_appearance: Option<LabelAppearance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_rating_appearance: Option<LabelAppearance>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub tag_appearances: std::collections::BTreeMap<String, LabelAppearance>,
}
impl CollectionSummary {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.creator_links.len() > 32
            || self
                .profile
                .as_ref()
                .is_some_and(|p| !["artist", "uploader"].contains(&p.as_str()))
        {
            return Err(DomainError::Invalid("Invalid creator profile".into()));
        }
        if let Some(image) = &self.image
            && (image.release_id.is_empty()
                || image.release_id.len() > 4096
                || image.count == 0
                || image.count > 20_000
                || image.width == Some(0)
                || image.height == Some(0)
                || image.previews.len() > 100
                || image
                    .previews
                    .iter()
                    .any(|url| url.len() > 8192 || !url.starts_with("https://"))
                || image
                    .format
                    .as_ref()
                    .is_some_and(|f| f.is_empty() || f.len() > 32))
        {
            return Err(DomainError::Invalid("Invalid image post summary".into()));
        }
        if self.tag_appearances.len() > 64
            || self
                .tag_appearances
                .keys()
                .any(|key| !self.tags.contains(key))
            || self
                .status_appearance
                .iter()
                .chain(self.content_rating_appearance.iter())
                .chain(self.tag_appearances.values())
                .any(|a| !a.valid())
        {
            return Err(DomainError::Invalid("Invalid label appearance".into()));
        }
        if self.tags.len() > 64
            || self.creators.len() > 32
            || self.languages.len() > 200
            || self
                .tags
                .iter()
                .chain(self.creators.iter())
                .chain(self.languages.iter())
                .chain(self.original_language.iter())
                .chain(self.status.iter())
                .chain(self.content_rating.iter())
                .chain(self.published_label.iter())
                .chain(self.handle.iter())
                .chain(self.video_count_label.iter())
                .any(|s| s.is_empty() || s.len() > 512)
            || self.rating.is_some_and(|v| !v.is_finite() || v < 0.0)
            || self.rating_max.is_some_and(|v| !v.is_finite() || v <= 0.0)
            || self
                .rating
                .zip(self.rating_max)
                .is_some_and(|(value, max)| value > max)
        {
            return Err(DomainError::Invalid("Invalid discovery summary".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Collection {
    pub reference: SourceRef,
    pub title: String,
    pub kind: CollectionKind,
    pub canonical_url: String,
    pub description: Option<String>,
    pub artwork_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<CollectionSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Release {
    /// Metadata for browsing the release without fetching each item's details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<Collection>,
    pub reference: SourceRef,
    pub collection: SourceRef,
    pub title: String,
    pub canonical_url: String,
    pub chapter: Option<String>,
    pub volume: Option<String>,
    pub language: Option<String>,
    pub group: Option<String>,
    pub published_at: Option<String>,
    pub revision: Option<String>,
    pub availability: Availability,
    pub unavailable_reason: Option<String>,
    pub position: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
#[schemars(rename = "Page_{T}")]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct SelectionPolicy {
    pub languages: Vec<String>,
    pub groups: Vec<String>,
    pub max_height: u32,
    pub subtitle_languages: Vec<String>,
    pub automatic_subtitles: bool,
}
impl Default for SelectionPolicy {
    fn default() -> Self {
        Self {
            languages: vec!["en".into()],
            groups: vec![],
            max_height: 1080,
            subtitle_languages: vec![],
            automatic_subtitles: false,
        }
    }
}
impl SelectionPolicy {
    pub fn accepts(&self, release: &Release) -> bool {
        release.availability == Availability::Available
            && (self.languages.is_empty()
                || release
                    .language
                    .as_ref()
                    .is_none_or(|l| self.languages.contains(l)))
            && (self.groups.is_empty()
                || release
                    .group
                    .as_ref()
                    .is_some_and(|g| self.groups.contains(g)))
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Recipe {
    Cbz,
    ImageFolder,
    OriginalImages,
    Mp4,
    Mkv,
    Webm,
    M4a,
    Mp3,
    Opus,
}
impl Recipe {
    pub fn extension(self) -> &'static str {
        match self {
            Self::Cbz => "cbz",
            Self::ImageFolder | Self::OriginalImages => "",
            Self::Mp4 => "mp4",
            Self::Mkv => "mkv",
            Self::Webm => "webm",
            Self::M4a => "m4a",
            Self::Mp3 => "mp3",
            Self::Opus => "opus",
        }
    }
    pub fn audio_only(self) -> bool {
        matches!(self, Self::M4a | Self::Mp3 | Self::Opus)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Locator {
    Http {
        url: String,
        permission: String,
        #[serde(default)]
        headers: BTreeMap<String, String>,
        credential_profile: Option<String>,
    },
    Media {
        url: String,
        permission: String,
        credential_profile: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub id: String,
    pub position: u32,
    pub role: String,
    pub media_type: Option<String>,
    pub expected_size: Option<u64>,
    pub expected_sha256: Option<String>,
    pub locator: Locator,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ResolvedRelease {
    pub release: Release,
    pub collection: Collection,
    pub resources: Vec<Resource>,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LogicalOutput {
    pub id: String,
    pub position: u32,
    pub relative_path: String,
    pub role: String,
    pub media_type: Option<String>,
    pub expected_size: Option<u64>,
    pub expected_sha256: Option<String>,
    pub locator: Locator,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MediaSelection {
    pub source_signature: String,
    pub selected_height: Option<u32>,
    pub duration_ms: Option<u64>,
    pub format_ids: Vec<String>,
    pub subtitles: Vec<String>,
    pub yt_dlp_digest: String,
    pub ffmpeg_digest: String,
    pub ffprobe_digest: String,
    pub node_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    #[serde(default)]
    pub metadata: OutputMetadata,
    #[serde(default)]
    pub media: Option<MediaSelection>,
    #[serde(default)]
    pub credential_profile: Option<String>,
    /// Artifact-set version, assigned by the engine before confirmation.
    #[serde(default)]
    pub generation: u32,
    pub release: Release,
    pub collection: Collection,
    pub recipe: Recipe,
    pub policy: SelectionPolicy,
    pub outputs: Vec<LogicalOutput>,
    pub final_relative_path: String,
    pub expires_at: Option<String>,
    pub provider_digest: String,
}
impl Plan {
    pub fn estimated_bytes(&self) -> Option<u64> {
        self.outputs.iter().try_fold(0_u64, |total, output| {
            total.checked_add(output.expected_size?)
        })
    }

    pub fn acquisition_key(&self) -> String {
        digest(
            &serde_json::to_vec(&(
                &self.release.reference,
                &self.release.revision,
                self.recipe,
                &self.policy,
            ))
            .expect("plan serializes"),
        )
    }
    /// Refresh transport locations only. Never inherit a different output's path/checkpoint.
    pub fn refresh(&self, refreshed: &Self) -> Result<Self, DomainError> {
        if self.acquisition_key() != refreshed.acquisition_key()
            || self.media != refreshed.media
            || self.credential_profile != refreshed.credential_profile
            || self.provider_digest != refreshed.provider_digest
            || self.collection.reference != refreshed.collection.reference
        {
            return Err(DomainError::PlanChanged);
        }
        let replacements: BTreeMap<_, _> = refreshed.outputs.iter().map(|o| (&o.id, o)).collect();
        let original_ids: BTreeSet<_> = self.outputs.iter().map(|o| &o.id).collect();
        if original_ids.len() != self.outputs.len()
            || replacements.len() != refreshed.outputs.len()
            || replacements.len() != self.outputs.len()
        {
            return Err(DomainError::PlanChanged);
        }
        let mut result = self.clone();
        for output in &mut result.outputs {
            let next = replacements
                .get(&output.id)
                .ok_or(DomainError::PlanChanged)?;
            if output.position != next.position
                || output.role != next.role
                || output.media_type != next.media_type
                || output.expected_size != next.expected_size
                || output.expected_sha256 != next.expected_sha256
                || locator_authority(&output.locator) != locator_authority(&next.locator)
            {
                return Err(DomainError::PlanChanged);
            }
            output.locator = next.locator.clone();
        }
        result.expires_at = refreshed.expires_at.clone();
        Ok(result)
    }
}
fn locator_authority(locator: &Locator) -> (&str, &str, Option<&str>) {
    match locator {
        Locator::Http {
            permission,
            credential_profile,
            ..
        } => ("http", permission, credential_profile.as_deref()),
        Locator::Media {
            permission,
            credential_profile,
            ..
        } => ("media", permission, credential_profile.as_deref()),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub id: String,
    pub label: String,
    pub root: String,
    pub available: bool,
    #[serde(default)]
    pub storage_operation: Option<String>,
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DuplicateBehavior {
    #[default]
    SkipSatisfied,
    NewVersion,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Resolving,
    Transferring,
    Verifying,
    Publishing,
    Completed,
    Paused,
    Failed,
    Canceled,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct Job {
    pub id: String,
    pub group_id: Option<String>,
    pub acquisition_key: String,
    pub title: String,
    pub destination_id: String,
    pub state: JobState,
    pub plan: Plan,
    pub bytes_done: u64,
    pub bytes_total: Option<u64>,
    pub attempt: u32,
    pub issue: Option<Problem>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct Artifact {
    pub id: String,
    pub job_id: String,
    pub relative_path: String,
    pub size: u64,
    pub sha256: String,
    pub media_type: String,
    pub status: FileStatus,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FileStatus {
    Present,
    Missing,
    Modified,
    Detached,
    DestinationUnavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct Problem {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    pub actions: Vec<String>,
}
impl Problem {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            retryable: false,
            actions: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct Event {
    pub id: i64,
    pub kind: String,
    pub resource_id: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ActionPolicy {
    Notify,
    Download,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SubscribeRequest {
    /// Optional name shown in subscriptions, independent of the source title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Saved discovery input. Search subscriptions observe matching items, not their releases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search: Option<SubscriptionSearch>,
    pub target: SourceRef,
    pub policy: SelectionPolicy,
    pub action: ActionPolicy,
    pub destination_id: String,
    pub recipe: Recipe,
    pub include_existing: bool,
    pub interval_minutes: u32,
    pub credential_profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionSearch {
    pub query: String,
    #[serde(default)]
    pub discovery: Option<DiscoveryQuery>,
}
impl SubscribeRequest {
    pub fn normalize_search(&mut self) -> Result<(), DomainError> {
        self.target.validate()?;
        self.name = self
            .name
            .take()
            .map(|name| name.trim().to_owned())
            .filter(|name| !name.is_empty());
        if self
            .name
            .as_ref()
            .is_some_and(|name| name.chars().count() > 200 || name.chars().any(char::is_control))
        {
            return Err(DomainError::Invalid(
                "Use a subscription name of up to 200 characters".into(),
            ));
        }
        if let Some(search) = &mut self.search {
            search.query = search.query.trim().to_owned();
            if search.query.is_empty()
                || search.query.len() > 2000
                || !matches!(self.action, ActionPolicy::Notify)
            {
                return Err(DomainError::Invalid(
                    "Search subscriptions require a query and notify action".into(),
                ));
            }
            if let Some(options) = &mut search.discovery {
                options.validate()?;
                for values in options.filters.values_mut() {
                    values.sort();
                    values.dedup();
                }
                options.filters.retain(|_, values| !values.is_empty());
            }
            self.policy.languages.sort();
            self.policy.languages.dedup();
            // Equal searches share identity regardless of layout, pagination, or check schedule.
            let options = search.discovery.clone().unwrap_or_default();
            self.target.id = format!(
                "omd-search:{}",
                digest(
                    &serde_json::to_vec(&(&search.query, options, &self.policy.languages))
                        .expect("search serializes")
                )
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct ObservationProgress {
    pub state: String,
    pub processed: u64,
    pub started_at: String,
    pub source_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct Subscription {
    pub id: String,
    /// Cached source collection title with any user title override applied.
    #[serde(default)]
    pub title: Option<String>,
    pub request: SubscribeRequest,
    pub enabled: bool,
    pub initialized: bool,
    #[serde(default)]
    pub current_check: Option<ObservationProgress>,
    pub last_success: Option<String>,
    pub next_check: String,
    pub issue: Option<Problem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct HostGrant {
    /// Additional pacing for upstream endpoints with a stricter limit than ordinary browsing.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub request_intervals: BTreeMap<String, u64>,
    pub id: String,
    pub hosts: Vec<String>,
    pub methods: Vec<String>,
    pub credential: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderManifest {
    pub api: String,
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub source_hosts: Vec<String>,
    /// The operations this source implements (such as `search`, `releases`
    /// and `resolve`), plus `collection_hint` when its `resolve` reads the
    /// request's `collection_hint`.
    pub capabilities: BTreeSet<String>,
    pub grants: Vec<HostGrant>,
    #[serde(default)]
    pub media_tools: bool,
    #[serde(default)]
    pub browser: bool,
    /// Used only by the interactive engine-owned sign-in browser. These grants
    /// are never handed to source HTTP, media, or browser broker operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_in: Option<SignIn>,
    /// Preferred reference-UI connection method. Imports store credentials without
    /// asserting authentication; browser completion remains engine-owned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_mode: Option<AccountMode>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccountMode {
    Browser,
    Cookies,
    Header,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SignIn {
    pub url: String,
    /// Cookie names required before saving an authenticated source session.
    /// Values stay inside the engine and are never exposed to plugins or clients.
    #[serde(default)]
    pub completion_cookies: Vec<String>,
    pub grants: Vec<HostGrant>,
}

/// Explicit chapter browsing order. Absent for complete acquisition/subscription scans.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseOrder {
    Asc,
    Desc,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderRequest {
    #[serde(default)]
    pub release_order: Option<ReleaseOrder>,
    #[serde(default)]
    pub discovery: Option<DiscoveryQuery>,
    #[serde(default)]
    pub credential_profile: Option<String>,
    pub operation: String,
    pub reference: Option<SourceRef>,
    pub query: Option<String>,
    pub url: Option<String>,
    pub cursor: Option<String>,
    pub page_size: u32,
    pub policy: SelectionPolicy,
    pub now: String,
    /// Sent only to a source whose manifest declares the `collection_hint`
    /// capability, and only on `resolve`, when the engine resolves a release
    /// again for a download: the collection the release was listed under when
    /// it was selected (for example a search-results or playlist collection),
    /// or the collection of an approved plan being refreshed. A source that
    /// files a release under more than one collection may return this
    /// collection as the release's collection while the release still belongs
    /// to it. The engine still requires the returned collection to match.
    /// Absent otherwise: a source that does not declare the capability gets
    /// requests without this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collection_hint: Option<SourceRef>,
}

/// The manifest capability a source declares to receive
/// [`ProviderRequest::collection_hint`]. Unlike the other capabilities it names
/// a request field, not an operation.
pub const COLLECTION_HINT_CAPABILITY: &str = "collection_hint";

impl ProviderManifest {
    /// Whether this source asked for [`ProviderRequest::collection_hint`].
    pub fn accepts_collection_hint(&self) -> bool {
        self.capabilities.contains(COLLECTION_HINT_CAPABILITY)
    }
}

impl ProviderRequest {
    /// The request as this source receives it: without the collection hint
    /// unless its manifest declares [`COLLECTION_HINT_CAPABILITY`], so a source
    /// that validates requests against the schema it was built with gets
    /// exactly the fields it knows.
    pub fn for_source(&self, manifest: &ProviderManifest) -> std::borrow::Cow<'_, Self> {
        if self.collection_hint.is_none() || manifest.accepts_collection_hint() {
            std::borrow::Cow::Borrowed(self)
        } else {
            std::borrow::Cow::Owned(Self {
                collection_hint: None,
                ..self.clone()
            })
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct Contracts {
    pub discovery: DiscoverySchema,
    pub collection_details: CollectionDetails,
    pub artwork: Artwork,
    pub naming_templates: NamingTemplates,
    pub identified_source: IdentifiedSource,
    pub artifact: Artifact,
    pub collection: Collection,
    pub release: Release,
    pub resolved_release: ResolvedRelease,
    pub provider_request: ProviderRequest,
    pub provider_manifest: ProviderManifest,
    pub job: Job,
    pub subscription: Subscription,
    pub destination: Destination,
    pub event: Event,
    pub problem: Problem,
}

#[derive(Debug, thiserror::Error)]
pub enum DomainError {
    #[error(
        "The provider changed the approved output identity, content, or authority. Prepare a new acquisition."
    )]
    PlanChanged,
    #[error("{0}")]
    Invalid(String),
}

pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Portable, UTF-8 byte-bounded display name. Identity is supplied separately.
pub fn path_segment(value: &str, fallback: &str) -> String {
    let value: String = value
        .chars()
        .map(|c| {
            if c.is_control() || "<>:\"/\\|?*".contains(c) {
                '_'
            } else {
                c
            }
        })
        .collect();
    let mut result = value.trim_matches([' ', '.']).to_string();
    while result.len() > 120 {
        result.pop();
    }
    result = result.trim_end_matches([' ', '.']).to_string();
    let stem = result.split('.').next().unwrap_or("").to_ascii_uppercase();
    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit())
    {
        result.insert(0, '_');
    }
    if result.is_empty() {
        fallback.into()
    } else {
        result
    }
}

pub fn validate_provider_result(
    provider: &ProviderManifest,
    request: &ProviderRequest,
    value: &serde_json::Value,
) -> std::result::Result<(), DomainError> {
    type Checked<T> = std::result::Result<T, DomainError>;
    fn invalid() -> DomainError {
        DomainError::Invalid("The source result violates the normalized provider contract".into())
    }
    fn reference(provider: &ProviderManifest, r: &SourceRef) -> Checked<()> {
        if r.provider != provider.id || r.validate().is_err() {
            Err(invalid())
        } else {
            Ok(())
        }
    }
    fn canonical(provider: &ProviderManifest, value: &str) -> Checked<()> {
        let url = url::Url::parse(value).map_err(|_| invalid())?;
        if url.port_or_known_default() != Some(443)
            || url.fragment().is_some()
            || url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || !provider
                .source_hosts
                .iter()
                .any(|h| url.host_str() == Some(h))
        {
            Err(invalid())
        } else {
            Ok(())
        }
    }
    fn collection(provider: &ProviderManifest, c: &Collection) -> Checked<()> {
        reference(provider, &c.reference)?;
        canonical(provider, &c.canonical_url)?;
        if let Some(summary) = &c.summary {
            summary.validate()?;
            let mut section_ids = std::collections::BTreeSet::new();
            if summary.sections.len() > 12 {
                return Err(invalid());
            }
            for section in &summary.sections {
                reference(provider, &section.reference)?;
                if section.label.is_empty()
                    || section.label.len() > 100
                    || !section_ids.insert(&section.reference.id)
                {
                    return Err(invalid());
                }
            }
            for url in summary.banner_url.iter().chain(summary.avatar_url.iter()) {
                let parsed = url::Url::parse(url).map_err(|_| invalid())?;
                if parsed.scheme() != "https"
                    || parsed.host_str().is_none()
                    || !parsed.username().is_empty()
                    || parsed.password().is_some()
                    || url.len() > 8192
                {
                    return Err(invalid());
                }
            }
            for creator in &summary.creator_links {
                let link = &creator.collection;
                reference(provider, &link.reference)?;
                canonical(provider, &link.canonical_url)?;
                if creator.role.is_empty()
                    || creator.role.len() > 100
                    || link.title.is_empty()
                    || link.title.len() > 2048
                    || link.reference == c.reference
                {
                    return Err(invalid());
                }
            }
            if let Some(parent) = &summary.parent {
                reference(provider, &parent.reference)?;
                canonical(provider, &parent.canonical_url)?;
                if parent.reference == c.reference
                    || parent.title.is_empty()
                    || parent.title.len() > 2048
                {
                    return Err(invalid());
                }
            }
        }
        if c.title.is_empty()
            || c.title.len() > 2048
            || c.description.as_ref().is_some_and(|s| s.len() > 128 * 1024)
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn release(provider: &ProviderManifest, r: &Release) -> Checked<()> {
        reference(provider, &r.reference)?;
        reference(provider, &r.collection)?;
        canonical(provider, &r.canonical_url)?;
        if let Some(preview) = &r.preview {
            collection(provider, preview)?;
            if preview.reference != r.reference {
                return Err(invalid());
            }
        }
        if r.title.is_empty()
            || r.title.len() > 2048
            || r.chapter.as_ref().is_some_and(|c| c.len() > 512)
            || r.position > 9_007_199_254_740_991
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn parse<T: serde::de::DeserializeOwned>(value: &serde_json::Value) -> Checked<T> {
        serde_json::from_value(value.clone()).map_err(|_| invalid())
    }
    match request.operation.as_str() {
        "discovery" => {
            let schema: DiscoverySchema = parse(value)?;
            schema.validate()?;
        }
        "details" => {
            let details: CollectionDetails = parse(value)?;
            reference(provider, &details.reference)?;
            if request.reference.as_ref() != Some(&details.reference) {
                return Err(invalid());
            }
            details.validate()?;
        }
        "artwork" => {
            let page: Page<Artwork> = parse(value)?;
            if page.items.len() > request.page_size as usize
                || page.next_cursor.as_ref().is_some_and(|s| s.len() > 8192)
            {
                return Err(invalid());
            }
            for item in page.items {
                item.validate()?;
            }
        }
        "identify" => {
            let identified: IdentifiedSource = parse(value)?;
            match identified {
                IdentifiedSource::Collection { reference: r }
                | IdentifiedSource::Release { reference: r } => reference(provider, &r)?,
            }
        }
        "collection" => {
            let c: Collection = parse(value)?;
            collection(provider, &c)?;
            if request.reference.as_ref() != Some(&c.reference) {
                return Err(invalid());
            }
        }
        "search" | "browse" | "related" | "recommendations" => {
            let page: Page<Collection> = parse(value)?;
            if page.items.len() > request.page_size as usize
                || page.next_cursor.as_ref().is_some_and(|s| s.len() > 8192)
            {
                return Err(invalid());
            }
            for c in &page.items {
                collection(provider, c)?;
            }
        }
        "releases" => {
            let page: Page<Release> = parse(value)?;
            if page.items.len() > request.page_size as usize
                || page.next_cursor.as_ref().is_some_and(|s| s.len() > 8192)
            {
                return Err(invalid());
            }
            for r in &page.items {
                release(provider, r)?;
                if request.reference.as_ref() != Some(&r.collection) {
                    return Err(invalid());
                }
            }
        }
        "resolve" => {
            let resolved: ResolvedRelease = parse(value)?;
            release(provider, &resolved.release)?;
            collection(provider, &resolved.collection)?;
            if resolved.release.collection != resolved.collection.reference
                || request.reference.as_ref() != Some(&resolved.release.reference)
                || resolved.resources.len() > 20_000
            {
                return Err(invalid());
            }
            let mut ids = std::collections::BTreeSet::new();
            for resource in &resolved.resources {
                if resource.id.is_empty()
                    || resource.id.len() > 8192
                    || !ids.insert(&resource.id)
                    || resource
                        .expected_sha256
                        .as_ref()
                        .is_some_and(|s| s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()))
                {
                    return Err(invalid());
                }
                let (Locator::Http {
                    url, permission, ..
                }
                | Locator::Media {
                    url, permission, ..
                }) = &resource.locator;
                if matches!(resource.locator, Locator::Media { .. }) && !provider.media_tools {
                    return Err(invalid());
                }

                {
                    let grant = provider
                        .grants
                        .iter()
                        .find(|g| &g.id == permission)
                        .ok_or(invalid())?;
                    validate_broker_url(&url::Url::parse(url).map_err(|_| invalid())?, grant)
                        .map_err(|_| invalid())?;
                }
            }
        }
        _ => return Err(invalid()),
    }
    Ok(())
}

/// URL authority validation shared by runtime brokers and author conformance.
/// Address resolution and public-network enforcement remain in omd-network.
pub fn validate_broker_url(url: &url::Url, grant: &HostGrant) -> Result<(), DomainError> {
    let host = url.host_str().unwrap_or("");
    if url.scheme() != "https"
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || host.parse::<std::net::IpAddr>().is_ok()
        || host.starts_with('[')
        || !grant.hosts.iter().any(|h| host_matches(h, host))
    {
        return Err(DomainError::Invalid(
            "The source URL exceeds its declared authority".into(),
        ));
    }
    Ok(())
}
pub fn host_matches(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        suffix.contains('.')
            && host.ends_with(&format!(".{suffix}"))
            && host.len() > suffix.len() + 1
    } else {
        pattern == host
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan() -> Plan {
        serde_json::from_str(include_str!("../../../tests/fixtures/v2-plan.json")).unwrap()
    }
    #[test]
    fn refresh_matches_stable_identity_after_array_reordering() {
        let original = plan();
        let mut refreshed = original.clone();
        refreshed.outputs.reverse();
        if let Locator::Http { url, .. } = &mut refreshed.outputs[0].locator {
            *url = "https://example.com/refreshed-b.png".into();
        }
        let result = original.refresh(&refreshed).unwrap();
        assert_eq!(result.outputs[0], original.outputs[0]);
        assert_eq!(result.outputs[1].id, "page-b");
        assert_eq!(result.outputs[1].relative_path, "00002.png");
    }
    #[test]
    fn refresh_rejects_changed_identity_integrity_and_authority() {
        let original = plan();
        for change in 0..4 {
            let mut next = original.clone();
            match change {
                0 => next.outputs[0].id = "new".into(),
                1 => next.outputs[0].expected_size = Some(100),
                2 => next.outputs[0].position = 1,
                _ => {
                    if let Locator::Http { permission, .. } = &mut next.outputs[0].locator {
                        *permission = "other".into();
                    }
                }
            }
            assert!(original.refresh(&next).is_err());
        }
    }
    #[test]
    fn names_are_portable_and_byte_bounded() {
        assert_eq!(path_segment("CON.txt", "item"), "_CON.txt");
        assert_eq!(path_segment("a/b:c?", "item"), "a_b_c_");
        assert!(path_segment(&"章".repeat(100), "item").len() <= 120);
    }
    /// Sources built before the collection hint existed receive exactly the
    /// payload they always did unless the engine has a hint to give, and the
    /// worker still accepts a request written without the field.
    #[test]
    fn the_collection_hint_is_optional_on_the_wire() {
        let earlier = serde_json::json!({
            "release_order": null, "discovery": null, "credential_profile": null,
            "operation": "resolve",
            "reference": {"provider": "org.example.source", "id": "item-1"},
            "query": null, "url": null, "cursor": null, "page_size": 200,
            "policy": SelectionPolicy::default(), "now": "2026-01-01T00:00:00Z"
        });
        let request: ProviderRequest = serde_json::from_value(earlier.clone()).unwrap();
        assert_eq!(request.collection_hint, None);
        assert_eq!(serde_json::to_value(&request).unwrap(), earlier);
        let listed = SourceRef {
            provider: "org.example.source".into(),
            id: "results:demo".into(),
        };
        let hinted = ProviderRequest {
            collection_hint: Some(listed.clone()),
            ..request
        };
        let wire = serde_json::to_value(&hinted).unwrap();
        assert_eq!(
            wire["collection_hint"],
            serde_json::to_value(&listed).unwrap()
        );
        let back: ProviderRequest = serde_json::from_value(wire).unwrap();
        assert_eq!(back.collection_hint, Some(listed));
    }
    /// A source receives the hint only when its manifest asks for it; every
    /// other source gets the exact bytes an earlier engine sent, so one that
    /// validates its input against the earlier closed schema keeps working.
    #[test]
    fn only_a_source_that_declares_the_capability_receives_the_hint() {
        let policy = serde_json::to_string(&SelectionPolicy::default()).unwrap();
        let earlier = format!(
            "{{\"release_order\":null,\"discovery\":null,\"credential_profile\":null,\
             \"operation\":\"resolve\",\"reference\":{{\"provider\":\"org.example.source\",\
             \"id\":\"item-1\"}},\"query\":null,\"url\":null,\"cursor\":null,\"page_size\":200,\
             \"policy\":{policy},\"now\":\"2026-01-01T00:00:00Z\"}}"
        );
        let unhinted: ProviderRequest = serde_json::from_str(&earlier).unwrap();
        let listed = SourceRef {
            provider: "org.example.source".into(),
            id: "results:demo".into(),
        };
        let hinted = ProviderRequest {
            collection_hint: Some(listed.clone()),
            ..unhinted.clone()
        };
        let mut manifest: ProviderManifest = serde_json::from_value(serde_json::json!({
            "api": "omd:provider@2.0.0", "id": "org.example.source", "name": "Example",
            "version": "1", "description": "Synthetic", "source_hosts": ["example.org"],
            "capabilities": ["resolve"], "grants": []
        }))
        .unwrap();
        assert!(!manifest.accepts_collection_hint());
        for request in [&unhinted, &hinted] {
            let sent = serde_json::to_string(&request.for_source(&manifest)).unwrap();
            assert_eq!(sent, earlier);
        }
        manifest
            .capabilities
            .insert(COLLECTION_HINT_CAPABILITY.into());
        assert!(manifest.accepts_collection_hint());
        assert_eq!(
            serde_json::to_string(&unhinted.for_source(&manifest)).unwrap(),
            earlier
        );
        let sent: serde_json::Value =
            serde_json::to_value(hinted.for_source(&manifest).as_ref()).unwrap();
        assert_eq!(
            sent["collection_hint"],
            serde_json::to_value(&listed).unwrap()
        );
    }
    #[test]
    fn identity_is_namespaced() {
        assert_ne!(
            SourceRef {
                provider: "a".into(),
                id: "x".into()
            }
            .key(),
            SourceRef {
                provider: "b".into(),
                id: "x".into()
            }
            .key()
        );
    }
}
