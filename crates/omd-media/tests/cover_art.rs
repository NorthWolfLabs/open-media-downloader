#![cfg(any(target_os = "macos", target_os = "linux", windows))]
//! Every audio output (MP3, M4A, Opus) is rebuilt by a confined stream copy of
//! its audio. Only engine-selected plain-text tags and at most one still cover,
//! decoded and re-encoded by the managed FFmpeg, are written back; no other
//! source metadata, picture (exposed as an attached_pic stream or not),
//! chapter or attachment is published. The audio packets must be identical
//! before and after, and the engine checks the container structure, tags and
//! picture bytes. Moving video is still rejected.
//!
//! The managed tools come from OMD_TEST_MEDIA_TOOLS (a verified tools-v2.json;
//! relative paths resolve against its folder). The managed FFmpeg encodes the
//! audio. The tests add covers (ID3v2 APIC, MP4 `covr`, Ogg picture comments),
//! tags and the video track at the byte level. A managed FFmpeg with the JPEG
//! and PNG codecs keeps a re-encoded JPEG/PNG cover in MP3 and M4A; an older
//! one without image codecs removes every cover (see `keeps_covers`).
use omd_domain::{MediaSelection, Plan, Recipe};
use omd_media::{Media, Tool, Tools};
use serde_json::json;
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;

/// A complete 1x1 PNG. No managed tool decodes it; ffprobe identifies it.
const PNG: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
    0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x60, 0x60, 0x60, 0xf8,
    0x0f, 0x00, 0x01, 0x04, 0x01, 0x00, 0x5f, 0xe5, 0xc3, 0x4b, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45,
    0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
];
const SECONDS: u32 = 3;

fn manifest() -> (Tools, PathBuf) {
    let path = PathBuf::from(
        std::env::var_os("OMD_TEST_MEDIA_TOOLS")
            .expect("Set OMD_TEST_MEDIA_TOOLS to the verified native tool manifest"),
    );
    let mut tools: Tools = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let base = path.parent().unwrap();
    let absolute = |tool: &mut Tool| {
        if tool.path.is_relative() {
            tool.path = base.join(&tool.path);
        }
    };
    absolute(&mut tools.yt_dlp);
    for tool in [&mut tools.ffmpeg, &mut tools.ffprobe, &mut tools.node] {
        tool.as_mut().map(absolute);
    }
    let ffmpeg = tools.ffmpeg.as_ref().expect("managed FFmpeg").path.clone();
    (tools, ffmpeg)
}
fn media(tools: Tools, work: &Path) -> Media {
    Media {
        revoked: CancellationToken::new(),
        tools,
        network: omd_network::Network::new(0),
        work_root: work.into(),
    }
}
fn plan(recipe: Recipe, tools: &Tools, duration_ms: u64) -> Plan {
    let mut plan: Plan =
        serde_json::from_str(include_str!("../../../tests/fixtures/v2-plan.json")).unwrap();
    plan.recipe = recipe;
    plan.outputs = serde_json::from_value(json!([{
        "id": "audio:main", "position": 0, "relative_path": format!("media.{}", recipe.extension()),
        "role": "media", "media_type": null, "expected_size": null, "expected_sha256": null,
        "locator": {"kind": "media", "url": "https://cdn.fixture.test/episode.mp3",
                    "permission": "media", "credential_profile": null}
    }]))
    .unwrap();
    plan.media = Some(MediaSelection {
        source_signature: "fixture".into(),
        selected_height: None,
        duration_ms: Some(duration_ms),
        format_ids: vec!["mpeg".into()],
        subtitles: vec![],
        yt_dlp_digest: tools.yt_dlp.sha256.clone(),
        ffmpeg_digest: tools.ffmpeg.as_ref().unwrap().sha256.clone(),
        ffprobe_digest: tools.ffprobe.as_ref().unwrap().sha256.clone(),
        node_digest: tools.node.as_ref().map(|t| t.sha256.clone()),
    });
    plan
}

/// Mono 16-bit PCM with a square tone, for the managed FFmpeg's WAV demuxer.
fn wav() -> Vec<u8> {
    let rate = 8000u32;
    let samples: Vec<u8> = (0..rate * SECONDS)
        .flat_map(|i| (if (i / 10) % 2 == 0 { 6000i16 } else { -6000 }).to_le_bytes())
        .collect();
    let mut out = Vec::new();
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&(36 + samples.len() as u32).to_le_bytes());
    out.extend_from_slice(b"WAVEfmt ");
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes()); // PCM
    out.extend_from_slice(&1u16.to_le_bytes()); // mono
    out.extend_from_slice(&rate.to_le_bytes());
    out.extend_from_slice(&(rate * 2).to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&16u16.to_le_bytes());
    out.extend_from_slice(b"data");
    out.extend_from_slice(&(samples.len() as u32).to_le_bytes());
    out.extend_from_slice(&samples);
    out
}
/// Encode the tone with the managed FFmpeg; `options` precede the output.
fn encode(ffmpeg: &Path, dir: &Path, options: &[&str], output: &str) -> Vec<u8> {
    let input = dir.join("tone.wav");
    std::fs::write(&input, wav()).unwrap();
    let out = dir.join(output);
    let status = std::process::Command::new(ffmpeg)
        .args(["-nostdin", "-hide_banner", "-loglevel", "error", "-y", "-i"])
        .arg(&input)
        .args(options)
        .arg(&out)
        .status()
        .unwrap();
    assert!(status.success(), "managed FFmpeg failed for {output}");
    std::fs::read(out).unwrap()
}

/// An ID3v2.3 tag with one APIC frame per (MIME label, payload), as podcast
/// publishers write. The label is whatever the publisher claims.
fn id3_pictures(pictures: &[(&str, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    for (index, (mime, picture)) in pictures.iter().enumerate() {
        let mut frame = vec![0u8]; // ISO-8859-1 text
        frame.extend_from_slice(mime.as_bytes());
        frame.push(0);
        frame.push(if index == 0 { 3 } else { 0 }); // front cover, then "other"
        frame.extend_from_slice(format!("Cover {index}\0").as_bytes());
        frame.extend_from_slice(picture);
        body.extend_from_slice(b"APIC");
        body.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&frame);
    }
    let size = body.len() as u32;
    let mut tag = b"ID3\x03\x00\x00".to_vec();
    tag.extend((0..4).rev().map(|i| ((size >> (7 * i)) & 0x7f) as u8));
    tag.extend_from_slice(&body);
    tag
}
fn id3_cover(picture: &[u8]) -> Vec<u8> {
    id3_pictures(&[("image/png", picture)])
}

fn mp4_box(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut out = ((payload.len() + 8) as u32).to_be_bytes().to_vec();
    out.extend_from_slice(kind);
    out.extend_from_slice(payload);
    out
}
fn full_box(kind: &[u8; 4], version_flags: u32, payload: &[u8]) -> Vec<u8> {
    let mut body = version_flags.to_be_bytes().to_vec();
    body.extend_from_slice(payload);
    mp4_box(kind, &body)
}
/// Top-level boxes as (offset, size, kind).
fn boxes(bytes: &[u8], mut offset: usize, end: usize) -> Vec<(usize, usize, [u8; 4])> {
    let mut out = vec![];
    while offset + 8 <= end {
        let size = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        assert!(size >= 8 && offset + size <= end, "unexpected MP4 layout");
        out.push((
            offset,
            size,
            bytes[offset + 4..offset + 8].try_into().unwrap(),
        ));
        offset += size;
    }
    out
}
/// Append `child` to the trailing `moov` box. FFmpeg writes `moov` after
/// `mdat` (no faststart), so no chunk offset moves.
fn append_to_moov(file: &mut Vec<u8>, child: &[u8]) {
    let (offset, size, kind) = *boxes(file, 0, file.len()).last().unwrap();
    assert_eq!(&kind, b"moov", "moov must be the last top-level box");
    assert_eq!(offset + size, file.len());
    file.extend_from_slice(child);
    file[offset..offset + 4].copy_from_slice(&((size + child.len()) as u32).to_be_bytes());
}
/// iTunes-style cover art: moov/udta/meta/ilst/covr, as M4A publishers write.
fn mp4_cover(picture: &[u8]) -> Vec<u8> {
    mp4_typed_cover(14, picture) // well-known type 14: PNG
}
/// `kind` is the iTunes data type: 13 JPEG, 14 PNG, 12 GIF, 27 BMP.
fn mp4_typed_cover(kind: u32, picture: &[u8]) -> Vec<u8> {
    let mut data = kind.to_be_bytes().to_vec();
    data.extend_from_slice(&0u32.to_be_bytes());
    data.extend_from_slice(picture);
    let covr = mp4_box(b"covr", &mp4_box(b"data", &data));
    let mut handler = vec![0u8; 4];
    handler.extend_from_slice(b"mdirappl");
    handler.extend_from_slice(&[0; 9]);
    let mut meta = full_box(b"hdlr", 0, &handler);
    meta.extend_from_slice(&mp4_box(b"ilst", &covr));
    mp4_box(b"udta", &full_box(b"meta", 0, &meta))
}
/// A 16x16 H.264 track whose one sample is `sample` bytes at `offset`
/// (the sample content is never decoded).
fn mp4_video_track(offset: u32, sample: u32, duration_ms: u32) -> Vec<u8> {
    const MATRIX: [u32; 9] = [0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x4000_0000];
    let be = |values: &[u32]| {
        values
            .iter()
            .flat_map(|v| v.to_be_bytes())
            .collect::<Vec<_>>()
    };
    let mut tkhd = be(&[0, 0, 2, 0, duration_ms, 0, 0, 0, 0]);
    tkhd.extend_from_slice(&be(&MATRIX));
    tkhd.extend_from_slice(&be(&[16 << 16, 16 << 16]));
    let mdhd = [be(&[0, 0, 1000, duration_ms]), vec![0x55, 0xc4, 0, 0]].concat();
    let hdlr = [be(&[0]), b"vide".to_vec(), vec![0; 12], b"Video\0".to_vec()].concat();
    let mut entry = vec![0u8; 6];
    entry.extend_from_slice(&1u16.to_be_bytes()); // data reference index
    entry.extend_from_slice(&[0; 16]);
    entry.extend_from_slice(&[0, 16, 0, 16]); // width, height
    entry.extend_from_slice(&be(&[0x48_0000, 0x48_0000, 0]));
    entry.extend_from_slice(&1u16.to_be_bytes()); // frame count
    entry.extend_from_slice(&[0; 32]);
    entry.extend_from_slice(&[0, 0x18, 0xff, 0xff]);
    // Baseline SPS (16x16, one macroblock) and PPS, so ffprobe reads the
    // track parameters without a decoder.
    const SPS: [u8; 6] = [0x67, 0x42, 0xc0, 0x0a, 0xf4, 0xf2];
    const PPS: [u8; 4] = [0x68, 0xce, 0x38, 0x80];
    let avcc = [
        &[1, 0x42, 0xc0, 0x0a, 0xff, 0xe1, 0, SPS.len() as u8][..],
        &SPS,
        &[1, 0, PPS.len() as u8],
        &PPS,
    ]
    .concat();
    entry.extend_from_slice(&mp4_box(b"avcC", &avcc));
    let stbl = [
        full_box(b"stsd", 0, &[be(&[1]), mp4_box(b"avc1", &entry)].concat()),
        full_box(b"stts", 0, &be(&[1, 1, duration_ms])),
        full_box(b"stsc", 0, &be(&[1, 1, 1, 1])),
        full_box(b"stsz", 0, &be(&[0, 1, sample])),
        full_box(b"stco", 0, &be(&[1, offset])),
    ]
    .concat();
    let dinf = mp4_box(
        b"dinf",
        &full_box(b"dref", 0, &[be(&[1]), full_box(b"url ", 1, &[])].concat()),
    );
    let minf = [full_box(b"vmhd", 1, &[0; 8]), dinf, mp4_box(b"stbl", &stbl)].concat();
    let mdia = [
        full_box(b"mdhd", 0, &mdhd),
        full_box(b"hdlr", 0, &hdlr),
        mp4_box(b"minf", &minf),
    ]
    .concat();
    mp4_box(
        b"trak",
        &[full_box(b"tkhd", 3, &tkhd), mp4_box(b"mdia", &mdia)].concat(),
    )
}
fn m4a(ffmpeg: &Path, dir: &Path) -> Vec<u8> {
    // bitexact and no global metadata: FFmpeg writes no udta of its own.
    encode(
        ffmpeg,
        dir,
        &[
            "-c:a",
            "aac",
            "-b:a",
            "64k",
            "-fflags",
            "+bitexact",
            "-map_metadata",
            "-1",
        ],
        "plain.m4a",
    )
}

/// Verify `bytes` as the recipe's output in the real confined helper; returns
/// the verification result and the file it leaves for publication.
async fn verify(
    tools: &Tools,
    recipe: Recipe,
    bytes: &[u8],
) -> (Result<(), omd_domain::Problem>, Vec<u8>) {
    let work = tempfile::tempdir().unwrap();
    let path = work.path().join(format!("media.{}", recipe.extension()));
    std::fs::write(&path, bytes).unwrap();
    let result = media(tools.clone(), work.path())
        .verify(
            &plan(recipe, tools, u64::from(SECONDS) * 1000),
            work.path(),
            &CancellationToken::new(),
        )
        .await;
    // Nothing but the output may remain (no temporary remux file).
    let names: Vec<_> = std::fs::read_dir(work.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(
        names,
        [format!("media.{}", recipe.extension())],
        "{names:?}"
    );
    (result, std::fs::read(path).unwrap())
}
/// Verify and require success, a result whose audio packets are exactly the
/// input's, copied, and the streams `published` expects.
async fn verified(
    tools: &Tools,
    recipe: Recipe,
    bytes: &[u8],
    codec: &str,
    cover: Option<&str>,
) -> Vec<u8> {
    let output = published(tools, recipe, bytes, codec, cover).await;
    assert_eq!(
        audio_packets(tools, &output, recipe.extension()),
        audio_packets(tools, bytes, recipe.extension()),
        "{recipe:?}: the audio packets changed"
    );
    output
}
/// Verify, require success and one audio stream, plus one attached picture of
/// codec `cover` when the managed FFmpeg keeps covers (`keeps_covers`) and
/// nothing else; return the published file.
async fn published(
    tools: &Tools,
    recipe: Recipe,
    bytes: &[u8],
    codec: &str,
    cover: Option<&str>,
) -> Vec<u8> {
    let (result, output) = verify(tools, recipe, bytes).await;
    result.unwrap_or_else(|p| panic!("{recipe:?}: {}: {}", p.code, p.message));
    let mut expected = vec![("audio", codec, 0)];
    if let Some(cover) = cover.filter(|_| keeps_covers(tools)) {
        expected.push(("video", cover, 1));
    }
    assert_eq!(
        streams(tools, &output, recipe.extension()),
        kinds(&expected),
        "{recipe:?}: only the audio and a re-encoded cover may be published"
    );
    assert_eq!(
        kept_picture(&output).is_some(),
        expected.len() == 2,
        "{recipe:?}: picture bytes"
    );
    output
}
/// Whether the managed FFmpeg decodes and re-encodes JPEG and PNG pictures,
/// so a verified still cover is kept.
fn keeps_covers(tools: &Tools) -> bool {
    let output = std::process::Command::new(&tools.ffmpeg.as_ref().unwrap().path)
        .args(["-hide_banner", "-encoders"])
        .output()
        .unwrap();
    let listing = String::from_utf8(output.stdout).unwrap();
    ["mjpeg", "png"].iter().all(|codec| {
        listing
            .lines()
            .any(|line| line.split_whitespace().nth(1) == Some(codec))
    })
}
/// The leading ID3v2.4 tag of a published MP3 as (frame id, body) pairs, and
/// the bytes after it (the audio).
/// ID3v2 frames as (frame id, body).
type Frames = Vec<([u8; 4], Vec<u8>)>;
fn id3v24(bytes: &[u8]) -> (Frames, &[u8]) {
    if !bytes.starts_with(b"ID3\x04") {
        return (vec![], bytes);
    }
    let syncsafe = |b: &[u8]| b.iter().fold(0usize, |n, &b| n << 7 | usize::from(b));
    let end = 10 + syncsafe(&bytes[6..10]);
    let mut frames = vec![];
    let mut at = 10;
    while at + 10 <= end && bytes[at] != 0 {
        let size = syncsafe(&bytes[at + 4..at + 8]);
        frames.push((
            bytes[at..at + 4].try_into().unwrap(),
            bytes[at + 10..at + 10 + size].to_vec(),
        ));
        at += 10 + size;
    }
    (frames, &bytes[end..])
}
/// The kept cover's bytes: the APIC picture of an MP3, or the `covr` data of
/// an M4A.
fn kept_picture(bytes: &[u8]) -> Option<Vec<u8>> {
    if let Some((_, apic)) = id3v24(bytes).0.into_iter().find(|(id, _)| id == b"APIC") {
        // UTF-8, MIME type, picture type, empty description.
        let mime = apic[1..].iter().position(|&b| b == 0).unwrap();
        return Some(apic[1 + mime + 3..].to_vec());
    }
    let at = bytes.windows(4).position(|w| w == b"covr")?;
    let size = u32::from_be_bytes(bytes[at - 4..at].try_into().unwrap()) as usize;
    Some(bytes[at + 20..at - 4 + size].to_vec())
}
/// The kept tags as the managed ffprobe reads them (container and audio
/// stream tags; keys in lower case), without the MP4 structure fields that
/// ffprobe also reports as tags (brands, handler and language).
fn tags(tools: &Tools, bytes: &[u8], ext: &str) -> std::collections::BTreeMap<String, String> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(format!("probe.{ext}"));
    std::fs::write(&path, bytes).unwrap();
    let output = std::process::Command::new(&tools.ffprobe.as_ref().unwrap().path)
        .args(["-v", "error", "-select_streams", "a:0", "-show_entries"])
        .args(["format_tags:stream_tags", "-of", "json"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    [&value["format"]["tags"], &value["streams"][0]["tags"]]
        .into_iter()
        .filter_map(|tags| tags.as_object())
        .flatten()
        .map(|(k, v)| (k.to_lowercase(), v.as_str().unwrap().to_owned()))
        .filter(|(k, _)| {
            ![
                "major_brand",
                "minor_version",
                "compatible_brands",
                "handler_name",
                "language",
                "vendor_id",
            ]
            .contains(&k.as_str())
        })
        .collect()
}
fn has(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}
/// Size and hash of every audio packet, as the managed ffprobe reads them.
fn audio_packets(tools: &Tools, bytes: &[u8], ext: &str) -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(format!("probe.{ext}"));
    std::fs::write(&path, bytes).unwrap();
    let output = std::process::Command::new(&tools.ffprobe.as_ref().unwrap().path)
        .args(["-v", "error", "-select_streams", "a:0", "-show_entries"])
        .args([
            "packet=size,data_hash",
            "-show_data_hash",
            "sha256",
            "-of",
            "csv=p=0",
        ])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Size and payload hash only; later columns are side data.
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| line.splitn(3, ',').take(2).collect::<Vec<_>>().join(","))
        .collect()
}
/// What the managed ffprobe reports for the fixture: (codec_type, codec_name, attached_pic).
fn streams(tools: &Tools, bytes: &[u8], ext: &str) -> Vec<(String, String, u64)> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(format!("probe.{ext}"));
    std::fs::write(&path, bytes).unwrap();
    let output = std::process::Command::new(&tools.ffprobe.as_ref().unwrap().path)
        .args(["-v", "error", "-show_entries"])
        .arg("stream=codec_type,codec_name:stream_disposition=attached_pic")
        .args(["-of", "json"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    value["streams"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            (
                s["codec_type"].as_str().unwrap().into(),
                s["codec_name"].as_str().unwrap_or("").into(),
                s["disposition"]["attached_pic"].as_u64().unwrap(),
            )
        })
        .collect()
}
fn kinds(list: &[(&str, &str, u64)]) -> Vec<(String, String, u64)> {
    list.iter()
        .map(|(a, b, c)| (a.to_string(), b.to_string(), *c))
        .collect()
}

fn mp3(ffmpeg: &Path, dir: &Path) -> Vec<u8> {
    // No FFmpeg ID3 tag: the publisher's tag added by each test is the only one.
    encode(
        ffmpeg,
        dir,
        &["-c:a", "libmp3lame", "-b:a", "64k", "-id3v2_version", "0"],
        "plain.mp3",
    )
}
/// A valid two-frame animated GIF (black, then white), as in the review.
const TWO_FRAME_GIF: &[u8] = &[
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x21, 0xf9, 0x04, 0x00, 0x0a, 0x00,
    0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x4c, 0x01,
    0x00, 0x3b,
];
/// CRC-32 as PNG uses it.
fn png_crc(bytes: &[u8]) -> u32 {
    !bytes.iter().fold(!0u32, |crc, &byte| {
        (0..8).fold(crc ^ u32::from(byte), |crc, _| {
            if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            }
        })
    })
}
/// A PNG chunk; the CRC is not checked by the probe and is left zero.
fn png_chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
    [&(data.len() as u32).to_be_bytes()[..], kind, data, &[0; 4]].concat()
}
/// An APNG: the 1x1 PNG with an animation control chunk for two frames.
fn apng() -> Vec<u8> {
    let ihdr_end = 8 + 25;
    let mut actl = 2u32.to_be_bytes().to_vec();
    actl.extend_from_slice(&0u32.to_be_bytes());
    [
        &PNG[..ihdr_end],
        &png_chunk(b"acTL", &actl),
        &PNG[ihdr_end..],
    ]
    .concat()
}
/// An animated WebP header (VP8X with the animation flag, ANIM, one ANMF).
fn animated_webp() -> Vec<u8> {
    let chunk = |kind: &[u8; 4], data: &[u8]| {
        let mut out = kind.to_vec();
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(data);
        if data.len() % 2 == 1 {
            out.push(0);
        }
        out
    };
    let body = [
        b"WEBP".to_vec(),
        chunk(b"VP8X", &[0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        chunk(b"ANIM", &[0; 6]),
        chunk(b"ANMF", &[0; 16]),
        chunk(b"ANMF", &[0; 16]),
    ]
    .concat();
    [
        b"RIFF".to_vec(),
        (body.len() as u32).to_le_bytes().to_vec(),
        body,
    ]
    .concat()
}

#[tokio::test]
#[ignore = "requires OMD_TEST_MEDIA_TOOLS and native helper confinement"]
async fn mp3_with_a_still_cover_keeps_a_re_encoded_cover() {
    let (tools, ffmpeg) = manifest();
    let dir = tempfile::tempdir().unwrap();
    let audio = mp3(&ffmpeg, dir.path());
    let covered = [id3_cover(PNG), audio.clone()].concat();
    assert_eq!(
        streams(&tools, &covered, "mp3"),
        kinds(&[("audio", "mp3", 0), ("video", "png", 1)])
    );
    // A file without pictures or tags is still rebuilt without any tag.
    let plain = verified(&tools, Recipe::Mp3, &audio, codec_of(Recipe::Mp3), None).await;
    assert!(!has(&plain, b"ID3"));
    // The PNG is decoded and written anew as the front cover; the source's
    // picture description ("Cover 0") is not kept.
    let output = verified(&tools, Recipe::Mp3, &covered, "mp3", Some("png")).await;
    assert!(!has(&output, b"Cover 0"));
    if let Some(picture) = kept_picture(&output) {
        assert!(picture.starts_with(b"\x89PNG") && picture != PNG);
    } else {
        assert!(!has(&output, &PNG[..16]) && !has(&output, b"APIC"));
    }
}

#[tokio::test]
#[ignore = "requires OMD_TEST_MEDIA_TOOLS and native helper confinement"]
async fn m4a_with_a_still_cover_keeps_only_a_re_encoded_still_cover() {
    let (tools, ffmpeg) = manifest();
    let dir = tempfile::tempdir().unwrap();
    let audio = m4a(&ffmpeg, dir.path());
    // A file without pictures is still rebuilt: same audio packets.
    verified(&tools, Recipe::M4a, &audio, codec_of(Recipe::M4a), None).await;
    // A still PNG is kept, re-encoded. An animated GIF falsely typed as BMP or
    // as JPEG (the MP4 demuxer exposes only these three cover types) is not a
    // decodable JPEG/PNG, so it is removed.
    for (kind, picture, kept) in [
        (14, PNG.to_vec(), Some("png")),
        (27, TWO_FRAME_GIF.to_vec(), None),
        (13, TWO_FRAME_GIF.to_vec(), None),
    ] {
        let mut covered = audio.clone();
        append_to_moov(&mut covered, &mp4_typed_cover(kind, &picture));
        let found = streams(&tools, &covered, "m4a");
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!((found[1].0.as_str(), found[1].2), ("video", 1), "{found:?}");
        let output = verified(&tools, Recipe::M4a, &covered, "aac", kept).await;
        match kept_picture(&output) {
            Some(cover) => assert!(cover.starts_with(b"\x89PNG") && cover != picture),
            None => assert!(!has(&output, &picture[..12]) && !has(&output, b"covr")),
        }
    }
}

/// Ogg CRC-32 (polynomial 0x04c11db7, no reflection, zero initial value).
fn ogg_crc(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0u32, |crc, &byte| {
        (0..8).fold(crc ^ (u32::from(byte) << 24), |crc, _| {
            if crc & 0x8000_0000 != 0 {
                (crc << 1) ^ 0x04c1_1db7
            } else {
                crc << 1
            }
        })
    })
}
fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        for i in 0..4 {
            out.push(if i <= chunk.len() {
                TABLE[(n >> (18 - 6 * i) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    out
}
/// Add a FLAC-style METADATA_BLOCK_PICTURE comment to the OpusTags packet of
/// an FFmpeg-written Ogg Opus file (the second page holds the whole packet).
fn opus_with_picture(file: &[u8], mime: &str, picture: &[u8]) -> Vec<u8> {
    let mut block = Vec::new();
    for value in [3u32, mime.len() as u32] {
        block.extend_from_slice(&value.to_be_bytes());
    }
    block.extend_from_slice(mime.as_bytes());
    for value in [0u32, 1, 1, 24, 0, picture.len() as u32] {
        block.extend_from_slice(&value.to_be_bytes());
    }
    block.extend_from_slice(picture);
    opus_with_comments(
        file,
        &[format!("METADATA_BLOCK_PICTURE={}", base64(&block))],
    )
}
/// Add comments to the OpusTags packet of an FFmpeg-written Ogg Opus file.
fn opus_with_comments(file: &[u8], comments: &[String]) -> Vec<u8> {
    let page = |offset: usize| {
        assert_eq!(&file[offset..offset + 4], b"OggS");
        let segments = file[offset + 26] as usize;
        let body: usize = file[offset + 27..offset + 27 + segments]
            .iter()
            .map(|&n| n as usize)
            .sum();
        (offset + 27 + segments, offset + 27 + segments + body)
    };
    let (_, first_end) = page(0);
    let (tags_start, tags_end) = page(first_end);
    let tags = &file[tags_start..tags_end];
    assert_eq!(&tags[..8], b"OpusTags");
    let vendor = u32::from_le_bytes(tags[8..12].try_into().unwrap()) as usize;
    let count_at = 12 + vendor;
    let count = u32::from_le_bytes(tags[count_at..count_at + 4].try_into().unwrap());
    let mut packet = tags[..count_at].to_vec();
    packet.extend_from_slice(&(count + comments.len() as u32).to_le_bytes());
    packet.extend_from_slice(&tags[count_at + 4..]);
    for comment in comments {
        packet.extend_from_slice(&(comment.len() as u32).to_le_bytes());
        packet.extend_from_slice(comment.as_bytes());
    }
    assert!(
        packet.len() < 255 * 255,
        "keep the picture packet on one page"
    );
    let mut lacing = vec![255u8; packet.len() / 255];
    lacing.push((packet.len() % 255) as u8);
    let mut header = file[first_end..first_end + 26].to_vec();
    header[22..26].fill(0);
    let mut new_page = [header, vec![lacing.len() as u8], lacing, packet].concat();
    let crc = ogg_crc(&new_page);
    new_page[22..26].copy_from_slice(&crc.to_le_bytes());
    [&file[..first_end], &new_page[..], &file[tags_end..]].concat()
}

#[tokio::test]
#[ignore = "requires OMD_TEST_MEDIA_TOOLS and native helper confinement"]
async fn opus_with_a_cover_picture_downloads_as_an_audio_only_file() {
    let (tools, ffmpeg) = manifest();
    let dir = tempfile::tempdir().unwrap();
    let audio = encode(
        &ffmpeg,
        dir.path(),
        &[
            "-c:a",
            "libopus",
            "-b:a",
            "32k",
            "-fflags",
            "+bitexact",
            "-map_metadata",
            "-1",
        ],
        "plain.opus",
    );
    // A file without pictures is still rebuilt: same audio packets.
    verified(&tools, Recipe::Opus, &audio, codec_of(Recipe::Opus), None).await;
    // FFmpeg's Ogg muxer cannot store a picture, so an Opus cover is removed.
    for (mime, picture) in [
        ("image/png", PNG.to_vec()),
        ("image/gif", TWO_FRAME_GIF.to_vec()),
    ] {
        let covered = opus_with_picture(&audio, mime, &picture);
        let found = streams(&tools, &covered, "opus");
        assert_eq!(found.len(), 2, "{mime}: {found:?}");
        assert_eq!((found[1].0.as_str(), found[1].2), ("video", 1), "{found:?}");
        let output = verified(&tools, Recipe::Opus, &covered, "opus", None).await;
        assert!(!has(&output, &base64_needle(&picture, mime)));
        assert!(
            !output.windows(22).any(|w| w == b"METADATA_BLOCK_PICTURE"),
            "{mime}: the picture comment must not be copied back"
        );
    }
}

/// The review's counterexamples and their relatives: a label never proves a
/// still image. Each output is published, never rejected: with at most one
/// cover, which is a still picture decoded and written anew.
#[tokio::test]
#[ignore = "requires OMD_TEST_MEDIA_TOOLS and native helper confinement"]
async fn untrusted_or_unbounded_pictures_are_removed_or_re_encoded() {
    let (tools, ffmpeg) = manifest();
    let dir = tempfile::tempdir().unwrap();
    let audio = mp3(&ffmpeg, dir.path());
    let not_an_image = b"These bytes are not an image at all.\n".repeat(2);
    let oversized = [&[0xff, 0xd8, 0xff, 0xe0][..], &vec![0u8; 17 * 1024 * 1024]].concat();
    let five: Vec<(&str, &[u8])> = vec![("image/png", PNG); 5];
    let (apng, webp) = (apng(), animated_webp());
    // A 16000x16000 PNG header: decoding it would allocate about 1 GB. The
    // decoders' pixel budget refuses it before any allocation.
    let mut bomb = PNG.to_vec();
    bomb[16..24].copy_from_slice(&[0, 0, 0x3e, 0x80, 0, 0, 0x3e, 0x80]);
    let crc = png_crc(&bomb[12..29]);
    bomb[29..33].copy_from_slice(&crc.to_be_bytes());
    // (case, APIC frames as (MIME label, payload), codec ffprobe reports,
    // the kept cover's codec). The PNG decoder reads an APNG's default image
    // only, so its animation cannot survive the re-encoding.
    type Case<'a> = (&'a str, Vec<(&'a str, &'a [u8])>, &'a str, Option<&'a str>);
    let cases: Vec<Case> = vec![
        (
            "animated GIF",
            vec![("image/gif", TWO_FRAME_GIF)],
            "gif",
            None,
        ),
        (
            "non-image bytes labelled PNG",
            vec![("image/png", not_an_image.as_slice())],
            "png",
            None,
        ),
        (
            "APNG labelled PNG",
            vec![("image/png", apng.as_slice())],
            "png",
            Some("png"),
        ),
        (
            "animated WebP",
            vec![("image/webp", webp.as_slice())],
            "webp",
            None,
        ),
        (
            "17 MiB picture labelled JPEG",
            vec![("image/jpeg", oversized.as_slice())],
            "mjpeg",
            None,
        ),
        ("five covers", five, "png", Some("png")),
        (
            "16000x16000 PNG",
            vec![("image/png", bomb.as_slice())],
            "png",
            None,
        ),
    ];
    for (case, pictures, codec, kept) in cases {
        let covered = [id3_pictures(&pictures), audio.clone()].concat();
        let found = streams(&tools, &covered, "mp3");
        assert_eq!(found.len(), 1 + pictures.len(), "{case}: {found:?}");
        assert!(
            found[1..]
                .iter()
                .all(|(kind, name, attached)| kind == "video" && name == codec && *attached == 1),
            "{case}: {found:?}"
        );
        let output = published(&tools, Recipe::Mp3, &covered, "mp3", kept).await;
        assert_eq!(
            audio_packets(&tools, &output, "mp3"),
            audio_packets(&tools, &audio, "mp3"),
            "{case}: audio changed"
        );
        let (frames, rest) = id3v24(&output);
        let cover = kept_picture(&output);
        for (_, payload) in &pictures {
            // A distinctive slice of each payload (past the all-zero padding).
            let marker = &payload[..payload.len().min(12)];
            assert!(!has(rest, marker), "{case}: payload bytes survive");
            assert!(cover.as_deref() != Some(*payload), "{case}: picture copied");
        }
        assert!(
            cover
                .as_ref()
                .is_none_or(|c| !has(c, b"acTL") && !has(c, b"fcTL")),
            "{case}: animation survives"
        );
        // Nothing but the one re-encoded picture is in the tag.
        assert!(
            frames.iter().all(|(id, _)| id == b"APIC") && frames.len() <= 1,
            "{case}: {:?}",
            frames.iter().map(|(id, _)| id).collect::<Vec<_>>()
        );
        assert!(
            !has(rest, b"APIC") && !has(rest, b"ID3"),
            "{case}: a tag survives"
        );
    }
}

#[tokio::test]
#[ignore = "requires OMD_TEST_MEDIA_TOOLS and native helper confinement"]
async fn an_audio_output_with_a_real_video_track_is_still_rejected() {
    let (tools, ffmpeg) = manifest();
    let dir = tempfile::tempdir().unwrap();
    let mut file = m4a(&ffmpeg, dir.path());
    // The video sample points at the first bytes of the existing mdat payload.
    let (mdat, _, _) = boxes(&file, 0, file.len())
        .into_iter()
        .find(|(_, _, kind)| kind == b"mdat")
        .unwrap();
    append_to_moov(
        &mut file,
        &mp4_video_track(mdat as u32 + 8, 16, SECONDS * 1000),
    );
    // Also carry a cover: the picture must not excuse the video track.
    append_to_moov(&mut file, &mp4_cover(PNG));
    let found = streams(&tools, &file, "m4a");
    assert!(
        found.contains(&("video".into(), "h264".into(), 0)),
        "{found:?}"
    );
    let problem = verify(&tools, Recipe::M4a, &file).await.0.unwrap_err();
    assert_eq!(problem.code, "media_verification");
    assert_eq!(
        problem.message,
        "The audio output unexpectedly contains video."
    );
}

/// A live public podcast MP3 with embedded cover art, downloaded through the
/// real broker and confined yt-dlp, then verified. The operator supplies the
/// episode: OMD_TEST_LIVE_EPISODE_URL (a direct HTTPS enclosure URL) and
/// OMD_TEST_LIVE_EPISODE_HOSTS (comma-separated granted hosts, wildcards
/// allowed, covering any redirect). Core names no publisher.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live public download; requires OMD_TEST_MEDIA_TOOLS, OMD_TEST_LIVE_EPISODE_URL/_HOSTS and native helper confinement"]
async fn live_podcast_episode_with_cover_art_downloads_as_mp3() {
    let (tools, _) = manifest();
    let url = std::env::var("OMD_TEST_LIVE_EPISODE_URL").expect("OMD_TEST_LIVE_EPISODE_URL");
    let hosts = std::env::var("OMD_TEST_LIVE_EPISODE_HOSTS")
        .expect("OMD_TEST_LIVE_EPISODE_HOSTS")
        .split(',')
        .map(|h| h.trim().to_owned())
        .filter(|h| !h.is_empty())
        .collect();
    let work = tempfile::tempdir().unwrap();
    let media = media(tools, work.path());
    let grants = vec![omd_domain::HostGrant {
        request_intervals: Default::default(),
        id: "media".into(),
        hosts,
        methods: vec!["GET".into()],
        credential: false,
    }];
    let resolved: omd_domain::ResolvedRelease = serde_json::from_value(json!({
        "release": {
            "reference": {"provider": "fixture-source", "id": "episode"},
            "collection": {"provider": "fixture-source", "id": "show"},
            "title": "Episode", "canonical_url": url,
            "chapter": null, "volume": null, "language": "en", "group": null,
            "published_at": null, "revision": null,
            "availability": "available", "unavailable_reason": null, "position": 1
        },
        "collection": {
            "reference": {"provider": "fixture-source", "id": "show"},
            "title": "Show", "kind": "playlist", "canonical_url": url,
            "description": null, "artwork_url": null
        },
        "resources": [{
            "id": "audio", "position": 0, "role": "media", "media_type": "audio/mpeg",
            "expected_size": null, "expected_sha256": null,
            "locator": {"kind": "media", "url": url, "permission": "media", "credential_profile": null}
        }],
        "expires_at": null
    }))
    .unwrap();
    let cancel = CancellationToken::new();
    let plan = media
        .prepare(
            omd_media::Preparation {
                resolved,
                recipe: Recipe::Mp3,
                policy: Default::default(),
                provider_digest: "fixture".into(),
                credential_profile: None,
            },
            &grants,
            &cancel,
        )
        .await
        .unwrap_or_else(|p| panic!("prepare: {} {}", p.code, p.message));
    let staging = tempfile::tempdir_in(work.path()).unwrap();
    let (progress, _) = tokio::sync::watch::channel(json!({}));
    media
        .download(
            omd_media::Download {
                plan: &plan,
                grants: &grants,
                work: staging.path(),
                progress,
            },
            &cancel,
        )
        .await
        .unwrap_or_else(|p| panic!("download: {} {}", p.code, p.message));
    let bytes = std::fs::read(staging.path().join("media.mp3")).unwrap();
    let found = streams(&media.tools, &bytes, "mp3");
    // The episode's audio, and at most the publisher's cover re-encoded.
    assert_eq!(found[0], ("audio".into(), "mp3".into(), 0), "{found:?}");
    assert!(
        found[1..] == kinds(&[("video", "mjpeg", 1)])
            || found[1..] == kinds(&[("video", "png", 1)])
            || found.len() == 1,
        "{found:?}"
    );
}

fn codec_of(recipe: Recipe) -> &'static str {
    match recipe {
        Recipe::Mp3 => "mp3",
        Recipe::M4a => "aac",
        _ => "opus",
    }
}
/// A real 16x16 baseline JPEG (from the ENGINE-FIX-2 verification review).
fn red_jpeg() -> Vec<u8> {
    const HEX: &str = "ffd8ffe000104a46494600010100004800480000ffe1004c4578696600004d4d002a00000008000187690004000000010000001a000000000003a00100030000000100010000a00200040000000100000008a0030004000000010000000800000000ffed003850686f746f73686f7020332e30003842494d04040000000000003842494d0425000000000010d41d8cd98f00b204e9800998ecf8427effc00011080008000803012200021101031101ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffc4001f0100030101010101010101010000000000000102030405060708090a0bffc400b51100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffdb004300020202020202030202030503030305060505050506080606060606080a0808080808080a0a0a0a0a0a0a0a0c0c0c0c0c0c0e0e0e0e0e0f0f0f0f0f0f0f0f0f0fffdb00430102020204040407040407100b090b1010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010ffdd00040001ffda000c03010002110311003f00f90e8a28afc2cff550ffd9";
    (0..HEX.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&HEX[i..i + 2], 16).unwrap())
        .collect()
}
/// An APEv2 tag with a binary "Cover Art (Front)" item, appended to an MP3.
fn ape_cover(name: &str, picture: &[u8]) -> Vec<u8> {
    let value = [name.as_bytes(), &[0], picture].concat();
    let mut item = (value.len() as u32).to_le_bytes().to_vec();
    item.extend_from_slice(&2u32.to_le_bytes()); // binary item
    item.extend_from_slice(b"Cover Art (Front)\0");
    item.extend_from_slice(&value);
    let mut tag = item.clone();
    tag.extend_from_slice(b"APETAGEX");
    tag.extend_from_slice(&2000u32.to_le_bytes());
    tag.extend_from_slice(&((item.len() + 32) as u32).to_le_bytes());
    tag.extend_from_slice(&1u32.to_le_bytes());
    tag.extend_from_slice(&0u32.to_le_bytes());
    tag.extend_from_slice(&[0; 8]);
    tag
}
/// The picture as it appears inside a base64 Ogg comment (an aligned slice).
fn base64_needle(picture: &[u8], mime: &str) -> Vec<u8> {
    // The picture starts at block offset 32 + mime length.
    let skip = (3 - (32 + mime.len()) % 3) % 3;
    let aligned = &picture[skip..skip + 3 * ((picture.len() - skip) / 3)];
    base64(aligned).into_bytes()
}
fn opus_audio(ffmpeg: &Path, dir: &Path) -> Vec<u8> {
    encode(
        ffmpeg,
        dir,
        &[
            "-c:a",
            "libopus",
            "-b:a",
            "32k",
            "-fflags",
            "+bitexact",
            "-map_metadata",
            "-1",
        ],
        "plain.opus",
    )
}

/// Pictures the FFmpeg demuxer does not expose as a stream (unknown or odd
/// MIME labels, APEv2 covers, M4A cover types it ignores). They used to be
/// published byte for byte; the rebuild must remove every one of them.
#[tokio::test]
#[ignore = "requires OMD_TEST_MEDIA_TOOLS and native helper confinement"]
async fn pictures_the_demuxer_does_not_expose_are_never_published() {
    let (tools, ffmpeg) = manifest();
    let dir = tempfile::tempdir().unwrap();
    let mp3 = mp3(&ffmpeg, dir.path());
    let m4a = m4a(&ffmpeg, dir.path());
    let opus = opus_audio(&ffmpeg, dir.path());
    let jpeg = red_jpeg();
    let svg = b"<svg xmlns='http://www.w3.org/2000/svg'><script>REVIEW-SVG</script></svg>".to_vec();
    let with_covr = |kind: u32, picture: &[u8]| {
        let mut file = m4a.clone();
        append_to_moov(&mut file, &mp4_typed_cover(kind, picture));
        file
    };
    type Case = (&'static str, Recipe, Vec<u8>, Vec<u8>);
    let cases: Vec<Case> = vec![
        (
            "mp3 APIC image/x-unknown + GIF",
            Recipe::Mp3,
            [
                id3_pictures(&[("image/x-unknown", TWO_FRAME_GIF)]),
                mp3.clone(),
            ]
            .concat(),
            b"GIF89a".to_vec(),
        ),
        (
            "mp3 APIC empty MIME + GIF",
            Recipe::Mp3,
            [id3_pictures(&[("", TWO_FRAME_GIF)]), mp3.clone()].concat(),
            b"GIF89a".to_vec(),
        ),
        (
            "mp3 APIC image/svg+xml + SVG",
            Recipe::Mp3,
            [id3_pictures(&[("image/svg+xml", &svg)]), mp3.clone()].concat(),
            b"REVIEW-SVG".to_vec(),
        ),
        (
            "mp3 APIC image/jpeg; charset=x + JPEG",
            Recipe::Mp3,
            [
                id3_pictures(&[("image/jpeg; charset=x", &jpeg)]),
                mp3.clone(),
            ]
            .concat(),
            b"JFIF".to_vec(),
        ),
        (
            "mp3 APEv2 Cover Art (Front) cover.gif",
            Recipe::Mp3,
            [mp3.clone(), ape_cover("cover.gif", TWO_FRAME_GIF)].concat(),
            b"GIF89a".to_vec(),
        ),
        (
            "mp3 APEv2 Cover Art (Front) payload.bin",
            Recipe::Mp3,
            [mp3.clone(), ape_cover("payload.bin", TWO_FRAME_GIF)].concat(),
            b"GIF89a".to_vec(),
        ),
        (
            "m4a covr type 12 (GIF)",
            Recipe::M4a,
            with_covr(12, TWO_FRAME_GIF),
            b"GIF89a".to_vec(),
        ),
        (
            "m4a covr type 0 (implicit) + JPEG",
            Recipe::M4a,
            with_covr(0, &jpeg),
            b"JFIF".to_vec(),
        ),
        (
            "opus METADATA_BLOCK_PICTURE image/x-unknown + GIF",
            Recipe::Opus,
            opus_with_picture(&opus, "image/x-unknown", TWO_FRAME_GIF),
            base64_needle(TWO_FRAME_GIF, "image/x-unknown"),
        ),
    ];
    for (case, recipe, bytes, needle) in cases {
        assert!(has(&bytes, &needle), "{case}: fixture lacks its payload");
        let output = published(&tools, recipe, &bytes, codec_of(recipe), None).await;
        // The audio is the clean source's, packet for packet (an APEv2 tag
        // read as a trailing "packet" is not audio and is cut).
        let clean = match recipe {
            Recipe::Mp3 => &mp3,
            Recipe::M4a => &m4a,
            _ => &opus,
        };
        assert_eq!(
            audio_packets(&tools, &output, recipe.extension()),
            audio_packets(&tools, clean, recipe.extension()),
            "{case}: audio changed"
        );
        for marker in [
            &needle[..],
            b"APETAGEX",
            b"covr",
            b"METADATA_BLOCK_PICTURE",
            b"APIC",
        ] {
            assert!(
                !has(&output, marker),
                "{case}: {:?} survives",
                String::from_utf8_lossy(marker)
            );
        }
    }
}

/// Content after the audio that the stream copy carries along (an APEv2
/// cover, arbitrary bytes) is cut at the last whole MPEG frame; content
/// between frames (junk, a stitched-in ID3 tag with a picture) cannot be
/// removed safely, so the download fails instead of publishing it.
#[tokio::test]
#[ignore = "requires OMD_TEST_MEDIA_TOOLS and native helper confinement"]
async fn mp3_data_outside_the_audio_frames_is_cut_or_refused() {
    let (tools, ffmpeg) = manifest();
    let dir = tempfile::tempdir().unwrap();
    let audio = mp3(&ffmpeg, dir.path());
    let tag = id3_pictures(&[("image/gif", TWO_FRAME_GIF)]);
    let marker = b"REVIEW-PAYLOAD-MARKER-".repeat(200);
    let reference = audio_packets(&tools, &audio, "mp3");
    for (case, bytes, needle) in [
        (
            "APIC + trailing APEv2 PNG",
            [tag.clone(), audio.clone(), ape_cover("cover.png", PNG)].concat(),
            PNG,
        ),
        (
            "APIC + trailing bytes",
            [tag.clone(), audio.clone(), marker.clone()].concat(),
            &marker[..],
        ),
        (
            "ID3v1 trailer",
            [
                audio.clone(),
                b"TAG".to_vec(),
                b"V1-PAYLOAD".repeat(12),
                vec![0; 5],
            ]
            .concat(),
            &b"V1-PAYLOAD"[..],
        ),
    ] {
        let output = published(&tools, Recipe::Mp3, &bytes, "mp3", None).await;
        // An ID3v1 tag's fields are text tags: its title, artist, album,
        // year and genre may be kept as the rebuild's own ID3v2.4 text
        // frames, nothing else.
        let (frames, rest) = id3v24(&output);
        assert!(
            frames
                .iter()
                .all(|(id, _)| [b"TIT2", b"TPE1", b"TALB", b"TDRC", b"TCON"].contains(&id)),
            "{case}: {frames:?}"
        );
        assert!(
            !has(rest, needle) && !has(&output, b"GIF89a"),
            "{case}: payload survives"
        );
        assert!(
            !has(&output, b"APETAGEX") && !has(rest, b"ID3") && !has(rest, b"TAG"),
            "{case}: a tag survives"
        );
        assert_eq!(
            audio_packets(&tools, &output, "mp3"),
            reference,
            "{case}: audio changed"
        );
    }
    // The frame boundary nearest the middle, as ffprobe reports it.
    let half = {
        let path = dir.path().join("frames.mp3");
        std::fs::write(&path, &audio).unwrap();
        let out = std::process::Command::new(&tools.ffprobe.as_ref().unwrap().path)
            .args([
                "-v",
                "error",
                "-show_entries",
                "packet=pos",
                "-of",
                "csv=p=0",
            ])
            .arg(&path)
            .output()
            .unwrap();
        let positions: Vec<usize> = String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect();
        positions[positions.len() / 2]
    };
    for (case, bytes) in [
        (
            "bytes between audio frames",
            [&audio[..half], &marker, &audio[half..]].concat(),
        ),
        (
            "second ID3 tag with APIC mid-file (stitched ad)",
            [
                &tag[..],
                &audio[..half],
                &id3_pictures(&[("image/png", PNG)]),
                &audio[half..],
            ]
            .concat(),
        ),
    ] {
        let (result, _) = verify(&tools, Recipe::Mp3, &bytes).await;
        let problem = result.expect_err(case);
        assert_eq!(problem.code, "media_verification", "{case}");
        // Deterministic: a retry would download the same bytes again.
        assert!(!problem.retryable && problem.actions.is_empty(), "{case}");
        assert!(
            problem.message.contains("between its audio frames"),
            "{case}"
        );
    }
}

/// A real camera JPEG cover (EXIF and Photoshop segments) with bytes smuggled
/// after its end marker and an ICC profile, in MP3 and M4A. The cover is kept
/// only as pixels re-encoded by the managed encoder: no source segment, side
/// data (ICC/EXIF) or trailing byte survives.
#[tokio::test]
#[ignore = "requires OMD_TEST_MEDIA_TOOLS and native helper confinement"]
async fn a_real_jpeg_cover_keeps_only_its_re_encoded_pixels() {
    let (tools, ffmpeg) = manifest();
    let dir = tempfile::tempdir().unwrap();
    let source = red_jpeg();
    // An ICC profile segment after the JFIF segment, then a trailing payload.
    let icc = [&b"ICC_PROFILE\0\x01\x01"[..], &b"SMUGGLED-ICC-".repeat(20)].concat();
    let app2 = [
        &[0xff, 0xe2][..],
        &((icc.len() + 2) as u16).to_be_bytes(),
        &icc,
    ]
    .concat();
    let jpeg = [&source[..20], &app2, &source[20..], b"SMUGGLED-AFTER-EOI"].concat();
    let covered = [
        id3_pictures(&[("image/jpeg", &jpeg)]),
        mp3(&ffmpeg, dir.path()),
    ]
    .concat();
    assert_eq!(
        streams(&tools, &covered, "mp3"),
        kinds(&[("audio", "mp3", 0), ("video", "mjpeg", 1)])
    );
    let clean = |output: &[u8]| {
        for marker in [&b"SMUGGLED"[..], b"Exif", b"Photoshop", b"ICC_PROFILE"] {
            assert!(
                !has(output, marker),
                "{:?} survives",
                String::from_utf8_lossy(marker)
            );
        }
    };
    let output = verified(&tools, Recipe::Mp3, &covered, "mp3", Some("mjpeg")).await;
    clean(&output);
    let mut covered = m4a(&ffmpeg, dir.path());
    append_to_moov(&mut covered, &mp4_typed_cover(13, &jpeg));
    let output = verified(&tools, Recipe::M4a, &covered, "aac", Some("mjpeg")).await;
    clean(&output);
    if let Some(cover) = kept_picture(&output) {
        assert!(cover.starts_with(&[0xff, 0xd8]) && cover.ends_with(&[0xff, 0xd9]));
    } else {
        assert!(!has(&output, b"covr"));
    }
}

/// Apple HE-AAC and HE-AAC v2 (`afconvert -d aach/aacp`, 3.00 s; provenance in
/// tests/fixtures/media/README.md). The source's edit list includes a final
/// padding-only packet that the rebuilt file's edit list leaves out; with the
/// edit list honoured, the comparison wrongly refused these files.
#[tokio::test]
#[ignore = "requires OMD_TEST_MEDIA_TOOLS and native helper confinement"]
async fn apple_he_aac_m4a_is_published_with_every_packet() {
    let (tools, _) = manifest();
    for (name, bytes) in [
        (
            "HE-AAC",
            &include_bytes!("../../../tests/fixtures/media/apple-he-aac-3s.m4a")[..],
        ),
        (
            "HE-AAC v2",
            &include_bytes!("../../../tests/fixtures/media/apple-he-aac-v2-3s.m4a")[..],
        ),
    ] {
        let (result, output) = verify(&tools, Recipe::M4a, bytes).await;
        result.unwrap_or_else(|p| panic!("{name}: {}: {}", p.code, p.message));
        assert_eq!(
            streams(&tools, &output, "m4a"),
            kinds(&[("audio", "aac", 0)]),
            "{name}"
        );
        assert_eq!(
            stored_packets(&tools, &output),
            stored_packets(&tools, bytes),
            "{name}: every stored packet, padding included, is kept"
        );
    }
}
/// Every stored M4A sample, edit list ignored (size and hash).
fn stored_packets(tools: &Tools, bytes: &[u8]) -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("probe.m4a");
    std::fs::write(&path, bytes).unwrap();
    let output = std::process::Command::new(&tools.ffprobe.as_ref().unwrap().path)
        .args([
            "-v",
            "error",
            "-ignore_editlist",
            "1",
            "-select_streams",
            "a:0",
        ])
        .args([
            "-show_entries",
            "packet=size,data_hash",
            "-show_data_hash",
            "sha256",
        ])
        .args(["-of", "csv=p=0"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| line.splitn(3, ',').take(2).collect::<Vec<_>>().join(","))
        .collect()
}

/// About 40 hours of synthetic 8 kbit/s MPEG-2.5 Layer III silence (2 million
/// 72-byte frames; 144 MB), well beyond the roughly 1.5 million packets that
/// an in-memory listing once allowed. The packet listings are streamed from
/// temporary files, so it verifies and publishes with every packet, and no
/// listing is left behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires OMD_TEST_MEDIA_TOOLS and native helper confinement; writes about 300 MB"]
async fn audio_longer_than_ten_hours_is_verified_in_bounded_memory() {
    let (tools, _) = manifest();
    let mut frame = vec![0xff, 0xe3, 0x18, 0xc0];
    frame.resize(72, 0);
    let frames = 2_000_000;
    let bytes = frame.repeat(frames);
    let work = tempfile::tempdir().unwrap();
    let path = work.path().join("media.mp3");
    std::fs::write(&path, &bytes).unwrap();
    drop(bytes);
    // 576 samples at 8 kHz: 72 ms per frame.
    let plan = plan(Recipe::Mp3, &tools, frames as u64 * 72);
    media(tools.clone(), work.path())
        .verify(&plan, work.path(), &CancellationToken::new())
        .await
        .unwrap_or_else(|p| panic!("{}: {}", p.code, p.message));
    let names: Vec<_> = std::fs::read_dir(work.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, ["media.mp3"]);
    let output = std::process::Command::new(&tools.ffprobe.as_ref().unwrap().path)
        .args(["-v", "error", "-select_streams", "a:0", "-count_packets"])
        .args(["-show_entries", "stream=nb_read_packets", "-of", "csv=p=0"])
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        frames.to_string()
    );
}

/// MPEG-1 Layer II frames in a ".mp3": they probe as audio, but the MP3 muxer
/// refuses them, so the rebuild fails. Its temporary file must not remain.
#[tokio::test]
#[ignore = "requires OMD_TEST_MEDIA_TOOLS and native helper confinement"]
async fn a_failed_rebuild_leaves_no_temporary_file() {
    let (tools, _) = manifest();
    // 128 kbit/s, 44.1 kHz, stereo: 417 bytes per frame, 1152 samples.
    let mut frame = vec![0xff, 0xfd, 0x80, 0x04];
    frame.resize(417, 0);
    let bytes = frame.repeat(115);
    assert_eq!(
        streams(&tools, &bytes, "mp3"),
        kinds(&[("audio", "mp2", 0)])
    );
    // `verify` asserts that nothing but media.mp3 is left in the work folder.
    let (result, _) = verify(&tools, Recipe::Mp3, &bytes).await;
    assert_eq!(result.unwrap_err().code, "media_verification");
}

/// Optional corpus run: every .mp3/.m4a/.opus file in the folders listed in
/// OMD_TEST_AUDIO_CORPUS (separated by the platform path separator) goes
/// through the real confined verify. Each must publish one audio stream whose
/// packets equal the source's (MP3: a prefix, as trailing data may be cut),
/// unless its file name is listed in OMD_TEST_AUDIO_CORPUS_REFUSED.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires OMD_TEST_MEDIA_TOOLS, OMD_TEST_AUDIO_CORPUS and native helper confinement"]
async fn audio_corpus_publishes_audio_only_without_false_rejections() {
    let (tools, _) = manifest();
    let folders = std::env::var_os("OMD_TEST_AUDIO_CORPUS").expect("OMD_TEST_AUDIO_CORPUS");
    let refused: Vec<String> = std::env::var("OMD_TEST_AUDIO_CORPUS_REFUSED")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    let mut failures = vec![];
    let (mut published, mut expected_refusals) = (0, 0);
    for folder in std::env::split_paths(&folders) {
        let mut names: Vec<_> = std::fs::read_dir(&folder)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        for name in names {
            let recipe = match name.rsplit('.').next() {
                Some("mp3") => Recipe::Mp3,
                Some("m4a") => Recipe::M4a,
                Some("opus") => Recipe::Opus,
                _ => continue,
            };
            let bytes = std::fs::read(folder.join(&name)).unwrap();
            let work = tempfile::tempdir().unwrap();
            let path = work.path().join(format!("media.{}", recipe.extension()));
            std::fs::write(&path, &bytes).unwrap();
            let mut plan = plan(recipe, &tools, 0);
            plan.media.as_mut().unwrap().duration_ms = None;
            let result = media(tools.clone(), work.path())
                .verify(&plan, work.path(), &CancellationToken::new())
                .await;
            let expected_refusal = refused.contains(&name);
            match result {
                Err(problem) if expected_refusal => {
                    expected_refusals += 1;
                    eprintln!(
                        "CORPUS refused (expected) {name}: {} {}",
                        problem.code, problem.message
                    );
                }
                Err(problem) => {
                    failures.push(format!("{name}: {} {}", problem.code, problem.message))
                }
                Ok(()) => {
                    let output = std::fs::read(&path).unwrap();
                    let found = streams(&tools, &output, recipe.extension());
                    let (source, kept) = if recipe == Recipe::M4a {
                        (
                            stored_packets(&tools, &bytes),
                            stored_packets(&tools, &output),
                        )
                    } else {
                        (
                            audio_packets(&tools, &bytes, recipe.extension()),
                            audio_packets(&tools, &output, recipe.extension()),
                        )
                    };
                    let same = if recipe == Recipe::Mp3 {
                        !kept.is_empty()
                            && kept.len() <= source.len()
                            && kept[..kept.len() - 1] == source[..kept.len() - 1]
                    } else {
                        kept == source
                    };
                    let picture = |s: &(String, String, u64)| {
                        s.0 == "video" && s.2 == 1 && ["mjpeg", "png"].contains(&s.1.as_str())
                    };
                    let shape = found.first().is_some_and(|s| s.0 == "audio")
                        && (found.len() == 1 || (found.len() == 2 && picture(&found[1])));
                    if !shape || !same {
                        failures.push(format!("{name}: published {found:?}, packets kept {same}"));
                    } else if expected_refusal {
                        failures.push(format!("{name}: expected a refusal, was published"));
                    } else {
                        published += 1;
                    }
                }
            }
        }
    }
    eprintln!("CORPUS published {published}, refused as expected {expected_refusals}");
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Bytes appended to the OpusHead packet are not codec setup: the stream
/// copy would carry them into the published file, so it is refused.
#[tokio::test]
#[ignore = "requires OMD_TEST_MEDIA_TOOLS and native helper confinement"]
async fn a_payload_appended_to_the_opus_head_is_refused() {
    let (tools, ffmpeg) = manifest();
    let dir = tempfile::tempdir().unwrap();
    let audio = opus_audio(&ffmpeg, dir.path());
    // The first page holds exactly the 19-byte OpusHead packet.
    assert_eq!(&audio[..4], b"OggS");
    let segments = audio[26] as usize;
    assert_eq!((segments, audio[27]), (1, 19));
    let head = &audio[28..47];
    assert!(head.starts_with(b"OpusHead"));
    let packet = [head, &b"OPUSHEAD-PAYLOAD".repeat(10)[..]].concat();
    let mut page = audio[..26].to_vec();
    page[22..26].fill(0);
    page.push(1);
    page.push(packet.len() as u8);
    page.extend_from_slice(&packet);
    let crc = ogg_crc(&page);
    page[22..26].copy_from_slice(&crc.to_le_bytes());
    let bytes = [&page[..], &audio[47..]].concat();
    assert_eq!(
        streams(&tools, &bytes, "opus"),
        kinds(&[("audio", "opus", 0)])
    );
    let (result, _) = verify(&tools, Recipe::Opus, &bytes).await;
    let problem = result.unwrap_err();
    assert_eq!(problem.code, "media_verification");
    assert!(!problem.retryable);
    // The same file without the payload is published.
    verified(&tools, Recipe::Opus, &audio, "opus", None).await;
}

/// Text tags of every recipe: the engine keeps title, artist, track and the
/// other plain-text fields it lists, written anew; private frames, lyrics,
/// comments, encoder strings, freeform items and pictures that are not a
/// decodable JPEG/PNG never reach the published file.
#[tokio::test]
#[ignore = "requires OMD_TEST_MEDIA_TOOLS and native helper confinement"]
async fn only_plain_text_tags_are_kept_for_every_recipe() {
    let (tools, ffmpeg) = manifest();
    let dir = tempfile::tempdir().unwrap();
    let expected: std::collections::BTreeMap<String, String> = [
        ("title", "Épisode One"),
        ("artist", "Fixture Artist"),
        ("track", "3/12"),
    ]
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .into();
    let secret = |output: &[u8], case: &str| {
        assert!(!has(output, b"SECRET"), "{case}: a dropped tag survives");
    };
    // MP3: an ID3v2.3 tag as publishers write it (ISO-8859-1 text frames).
    let frame = |id: &[u8; 4], body: &[u8]| {
        [&id[..], &(body.len() as u32).to_be_bytes(), &[0, 0], body].concat()
    };
    let body = [
        frame(b"TIT2", b"\0\xc9pisode One"),
        frame(b"TPE1", b"\0Fixture Artist"),
        frame(b"TRCK", b"\x003/12"),
        frame(b"TXXX", b"\0note\0SECRET-TXXX"),
        frame(b"PRIV", b"owner.example\0SECRET-PRIV"),
        frame(b"COMM", b"\0eng\0SECRET-COMMENT"),
        frame(b"USLT", b"\0eng\0SECRET-LYRICS"),
        frame(
            b"GEOB",
            b"\0application/octet-stream\0f.bin\0\0SECRET-OBJECT",
        ),
        frame(b"TSSE", b"\0SECRET-ENCODER"),
    ]
    .concat();
    let size = body.len() as u32;
    let mut tag = b"ID3\x03\x00\x00".to_vec();
    tag.extend((0..4).rev().map(|i| ((size >> (7 * i)) & 0x7f) as u8));
    tag.extend_from_slice(&body);
    let source = [tag, mp3(&ffmpeg, dir.path())].concat();
    let output = verified(&tools, Recipe::Mp3, &source, "mp3", None).await;
    secret(&output, "mp3");
    assert_eq!(tags(&tools, &output, "mp3"), expected);
    let (frames, _) = id3v24(&output);
    assert_eq!(
        frames.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        [*b"TIT2", *b"TPE1", *b"TRCK"]
    );
    // M4A: iTunes items, including a freeform item and an encoder string.
    let item = |kind: &[u8; 4], class: u32, value: &[u8]| {
        let data = [&class.to_be_bytes()[..], &[0; 4], value].concat();
        mp4_box(kind, &mp4_box(b"data", &data))
    };
    let freeform = mp4_box(
        b"----",
        &[
            full_box(b"mean", 0, b"com.example"),
            full_box(b"name", 0, b"note"),
            mp4_box(b"data", b"\0\0\0\x01\0\0\0\0SECRET-FREEFORM"),
        ]
        .concat(),
    );
    let ilst = [
        item(b"\xa9nam", 1, "Épisode One".as_bytes()),
        item(b"\xa9ART", 1, b"Fixture Artist"),
        item(b"trkn", 0, &[0, 0, 0, 3, 0, 12, 0, 0]),
        item(b"\xa9too", 1, b"SECRET-ENCODER"),
        item(b"\xa9lyr", 1, b"SECRET-LYRICS"),
        freeform,
    ]
    .concat();
    let mut handler = vec![0u8; 4];
    handler.extend_from_slice(b"mdirappl");
    handler.extend_from_slice(&[0; 9]);
    let meta = [full_box(b"hdlr", 0, &handler), mp4_box(b"ilst", &ilst)].concat();
    let mut source = m4a(&ffmpeg, dir.path());
    append_to_moov(&mut source, &mp4_box(b"udta", &full_box(b"meta", 0, &meta)));
    let output = verified(&tools, Recipe::M4a, &source, "aac", None).await;
    secret(&output, "m4a");
    assert_eq!(tags(&tools, &output, "m4a"), expected);
    // Opus: Vorbis comments, with field names in any letter case.
    let source = opus_with_comments(
        &opus_audio(&ffmpeg, dir.path()),
        &[
            "TITLE=Épisode One".into(),
            "artist=Fixture Artist".into(),
            "TRACKNUMBER=3/12".into(),
            "LYRICS=SECRET-LYRICS".into(),
            "ENCODER=SECRET-ENCODER".into(),
            "COVERART=SECRET-COVER".into(),
        ],
    );
    let output = verified(&tools, Recipe::Opus, &source, "opus", None).await;
    secret(&output, "opus");
    assert_eq!(tags(&tools, &output, "opus"), expected);
}
