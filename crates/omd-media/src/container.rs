//! Byte-level structure checks of rebuilt audio outputs. They parse only
//! container framing (MPEG audio frame headers, MP4 boxes, Ogg pages), the
//! engine-selected text tags and the framing of one re-encoded cover picture;
//! no audio or image payload is decoded. Anything outside the expected
//! structure is reported, so a published audio file holds only audio, its
//! minimal framing, plain-text tags and at most one still JPEG/PNG cover in
//! exactly the form FFmpeg's own encoders write.
use std::io::{self, Read, Seek, SeekFrom};

/// What a check found wrong. The message is internal; callers report a fixed
/// user-facing problem.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Violation(pub &'static str);
impl From<io::Error> for Violation {
    fn from(_: io::Error) -> Self {
        Violation("unreadable output")
    }
}
/// The largest non-audio tail of an MP3 that is inspected and removed.
const MAX_TAIL: u64 = 64 * 1024 * 1024;
/// The largest MP4 `moov` box that is read.
const MAX_MOOV: u64 = 64 * 1024 * 1024;
/// The largest Ogg header packet (OpusHead/OpusTags) that is assembled.
const MAX_HEADER_PACKET: usize = 1024 * 1024;
/// MP4 boxes nest at most this deep below `moov` (FFmpeg writes 5 levels).
const MAX_MP4_DEPTH: u32 = 8;
/// The largest MP4 sample description (`stsd`) box: codec setup only.
const MAX_STSD: usize = 1024;
/// Reported when an MP3 has data between audio frames.
pub(crate) const BETWEEN_FRAMES: Violation = Violation("non-audio data between audio frames");
/// The longest kept text tag value, in UTF-8 bytes.
pub(crate) const MAX_TEXT: usize = 1024;
/// The largest side of a kept cover picture, in pixels. The decoders get the
/// matching pixel budget, so a larger picture is never decoded.
pub(crate) const MAX_PICTURE_SIDE: u32 = 4096;
/// The largest leading ID3v2 tag of a rebuilt MP3 (text tags and one cover).
const MAX_ID3: u64 = 32 * 1024 * 1024;

/// The text tags an audio rebuild may keep, as (FFmpeg key, ID3v2.4 frame,
/// iTunes item, Vorbis comment field). Nothing else is written back.
pub(crate) const TAGS: [(&str, &[u8; 4], &[u8; 4], &str); 10] = [
    ("title", b"TIT2", b"\xa9nam", "TITLE"),
    ("artist", b"TPE1", b"\xa9ART", "ARTIST"),
    ("album", b"TALB", b"\xa9alb", "ALBUM"),
    ("album_artist", b"TPE2", b"aART", "ALBUMARTIST"),
    ("composer", b"TCOM", b"\xa9wrt", "COMPOSER"),
    ("genre", b"TCON", b"\xa9gen", "GENRE"),
    ("date", b"TDRC", b"\xa9day", "DATE"),
    ("track", b"TRCK", b"trkn", "TRACKNUMBER"),
    ("disc", b"TPOS", b"disk", "DISCNUMBER"),
    ("copyright", b"TCOP", b"cprt", "COPYRIGHT"),
];
/// A kept text value: 1 to `MAX_TEXT` bytes of UTF-8 without control
/// characters (no NUL, line breaks or escapes).
pub(crate) fn plain_text(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.len() <= MAX_TEXT
        && std::str::from_utf8(bytes).is_ok_and(|text| !text.chars().any(char::is_control))
}

const MPEG1_BITRATES: [[u32; 15]; 3] = [
    [
        0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448,
    ],
    [
        0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384,
    ],
    [
        0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320,
    ],
];
const MPEG2_BITRATES: [[u32; 15]; 2] = [
    [
        0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256,
    ],
    [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],
];
/// The length of the MPEG audio frame whose 4-byte header is `h`, if valid.
/// Free-format (bitrate index 0) and reserved values are not valid.
fn mpeg_frame(h: [u8; 4]) -> Option<u64> {
    if h[0] != 0xff || h[1] & 0xe0 != 0xe0 {
        return None;
    }
    let version = match (h[1] >> 3) & 3 {
        3 => 1, // MPEG-1
        2 => 2, // MPEG-2
        0 => 3, // MPEG-2.5
        _ => return None,
    };
    let layer = match (h[1] >> 1) & 3 {
        3 => 1,
        2 => 2,
        1 => 3,
        _ => return None,
    };
    let bitrate_index = (h[2] >> 4) as usize;
    let rate_index = ((h[2] >> 2) & 3) as usize;
    if bitrate_index == 0 || bitrate_index == 15 || rate_index == 3 {
        return None;
    }
    let padding = u64::from((h[2] >> 1) & 1);
    let kbps = if version == 1 {
        MPEG1_BITRATES[layer - 1][bitrate_index]
    } else {
        MPEG2_BITRATES[usize::from(layer != 1)][bitrate_index]
    };
    let bitrate = u64::from(kbps) * 1000;
    const RATES: [[u64; 3]; 3] = [
        [44100, 48000, 32000],
        [22050, 24000, 16000],
        [11025, 12000, 8000],
    ];
    let rate = RATES[version - 1][rate_index];
    Some(match layer {
        1 => (12 * bitrate / rate + padding) * 4,
        3 if version != 1 => 72 * bitrate / rate + padding,
        _ => 144 * bitrate / rate + padding,
    })
}
fn read_at<F: Read + Seek>(file: &mut F, offset: u64, buffer: &mut [u8]) -> io::Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(buffer)
}
/// A tag header that a player may read: ID3v2 ("ID3", version 2-4, revision
/// 0, no undefined flags, a syncsafe size) or an APEv2 footer/header.
fn tag_at(bytes: &[u8], i: usize) -> bool {
    let id3 = bytes[i..].starts_with(b"ID3")
        && bytes.len() >= i + 10
        && (2..=4).contains(&bytes[i + 3])
        && bytes[i + 4] == 0
        && bytes[i + 5] & 0x0f == 0
        && bytes[i + 6..i + 10].iter().all(|b| b & 0x80 == 0);
    id3 || bytes[i..].starts_with(b"APETAGEX")
}

/// Check an MP3 written by the audio rebuild: at most the rebuild's own
/// leading ID3v2.4 tag (see `id3v24`), then contiguous MPEG audio frames.
/// Returns where the audio ends. Bytes after the last whole frame (an APEv2 or
/// ID3v1 tag, junk, a partial frame) may be cut there; but bytes between
/// frames, such as a stitched-in ID3 tag, cannot be removed safely and are a
/// violation.
pub(crate) fn mp3<F: Read + Seek>(file: &mut F, len: u64) -> Result<u64, Violation> {
    let start = leading_id3(file, len)?;
    let mut end = start;
    let mut frames = 0u64;
    let mut header = [0u8; 4];
    while end + 4 <= len {
        read_at(file, end, &mut header)?;
        match mpeg_frame(header) {
            Some(size) if end + size <= len => {
                end += size;
                frames += 1;
            }
            _ => break,
        }
    }
    if frames == 0 {
        return Err(Violation("no MPEG audio frames"));
    }
    let tail = len - end;
    if tail > MAX_TAIL {
        return Err(Violation("too much data after the audio"));
    }
    let mut rest = vec![0u8; tail as usize];
    read_at(file, end, &mut rest)?;
    // Three consecutive whole frames after the stop mean audio continues: the
    // stop was mid-stream. (Two match too often by chance in megabytes of
    // compressed trailing data; three almost never do.)
    let whole_frame = |at: u64| -> Option<u64> {
        let start = usize::try_from(at).ok()?;
        let header: [u8; 4] = rest.get(start..start.checked_add(4)?)?.try_into().ok()?;
        let next = at.checked_add(mpeg_frame(header)?)?;
        (next <= tail).then_some(next)
    };
    for at in 0..tail {
        if whole_frame(at)
            .and_then(whole_frame)
            .and_then(whole_frame)
            .is_some()
        {
            return Err(BETWEEN_FRAMES);
        }
    }
    // Inside the frames, no tag header may appear either.
    scan(file, start, end, tag_at)?;
    Ok(end)
}
/// The length of the rebuild's leading ID3v2.4 tag (0 without one), after
/// checking it with `id3v24`.
fn leading_id3<F: Read + Seek>(file: &mut F, len: u64) -> Result<u64, Violation> {
    let mut header = [0u8; 10];
    if len < 10 {
        return Ok(0);
    }
    read_at(file, 0, &mut header)?;
    if &header[..3] != b"ID3" {
        return Ok(0);
    }
    if header[3..6] != [4, 0, 0] {
        return Err(Violation("unexpected ID3 tag header"));
    }
    let size = syncsafe(&header[6..10]).ok_or(Violation("unexpected ID3 tag header"))?;
    let total = 10 + u64::from(size);
    if total > len.min(MAX_ID3) {
        return Err(Violation("oversized ID3 tag"));
    }
    let mut body = vec![0u8; size as usize];
    read_at(file, 10, &mut body)?;
    id3v24(&body)?;
    Ok(total)
}
/// A 28-bit ID3v2 syncsafe integer.
fn syncsafe(bytes: &[u8]) -> Option<u32> {
    bytes
        .iter()
        .try_fold(0u32, |n, &b| (b < 0x80).then_some(n << 7 | u32::from(b)))
}
/// The body of an ID3v2.4 tag as FFmpeg writes it for the rebuild: no
/// extended header, unsynchronisation or footer; only the engine's text
/// frames (UTF-8, one value each) and at most one front-cover APIC frame with
/// an empty description; then zero padding.
fn id3v24(body: &[u8]) -> Result<(), Violation> {
    let mut at = 0;
    let mut seen: Vec<[u8; 4]> = vec![];
    while at < body.len() {
        if body[at] == 0 {
            // Padding runs to the end of the tag.
            return if body[at..].iter().all(|&b| b == 0) {
                Ok(())
            } else {
                Err(Violation("data in the ID3 padding"))
            };
        }
        let header = body
            .get(at..at + 10)
            .ok_or(Violation("truncated ID3 frame"))?;
        let id: [u8; 4] = header[..4].try_into().expect("4 bytes");
        let size = syncsafe(&header[4..8]).ok_or(Violation("invalid ID3 frame size"))? as usize;
        let frame = body
            .get(at + 10..at + 10 + size)
            .filter(|f| !f.is_empty())
            .ok_or(Violation("invalid ID3 frame size"))?;
        if header[8..10] != [0, 0] {
            return Err(Violation("ID3 frame flags"));
        }
        if seen.contains(&id) {
            return Err(Violation("repeated ID3 frame"));
        }
        seen.push(id);
        if &id == b"APIC" {
            apic(frame)?;
        } else if TAGS.iter().any(|(_, frame_id, _, _)| **frame_id == id) {
            // UTF-8, the value, and FFmpeg's terminating NUL.
            let text = frame[1..].strip_suffix(&[0]).unwrap_or(&frame[1..]);
            if frame[0] != 3 || !plain_text(text) {
                return Err(Violation("ID3 text frame"));
            }
        } else {
            return Err(Violation("unexpected ID3 frame"));
        }
        at += 10 + size;
    }
    Ok(())
}
/// An APIC frame: UTF-8, a JPEG/PNG MIME type, the front-cover type, an empty
/// description, and a picture whose kind matches the MIME type.
fn apic(frame: &[u8]) -> Result<(), Violation> {
    let invalid = || Violation("ID3 picture frame");
    let (&encoding, rest) = frame.split_first().ok_or_else(invalid)?;
    let mime_end = rest.iter().position(|&b| b == 0).ok_or_else(invalid)?;
    let (mime, rest) = (&rest[..mime_end], &rest[mime_end + 1..]);
    // Picture type 3 (front cover), then the empty description's NUL.
    let picture = rest.strip_prefix(&[3, 0]).ok_or_else(invalid)?;
    if encoding != 3 {
        return Err(invalid());
    }
    match mime {
        b"image/jpeg" => jpeg(picture).map(|_| ()),
        b"image/png" => png(picture).map(|_| ()),
        _ => Err(invalid()),
    }
}

/// Check a baseline JPEG exactly as FFmpeg's encoder writes a re-encoded cover
/// (bit-exact, side data removed): SOI; an optional JFIF APP0 without a
/// thumbnail; quantisation and Huffman tables; one SOF0; an optional restart
/// interval and FFmpeg's fixed colour-space comment; one scan whose entropy
/// data holds only stuffed bytes and restart markers; and EOI as the last two
/// bytes. EXIF, ICC, XMP and every other segment are violations. Returns the
/// picture's (width, height).
pub(crate) fn jpeg(bytes: &[u8]) -> Result<(u32, u32), Violation> {
    let invalid = |what| Err(Violation(what));
    if !bytes.starts_with(&[0xff, 0xd8]) {
        return invalid("not a JPEG");
    }
    let mut at = 2;
    let mut size = None;
    let (mut app0, mut tables) = (false, false);
    loop {
        let (Some(0xff), Some(&marker)) = (bytes.get(at), bytes.get(at + 1)) else {
            return invalid("JPEG segment");
        };
        let length = bytes
            .get(at + 2..at + 4)
            .map(|b| usize::from(u16::from_be_bytes([b[0], b[1]])))
            .filter(|n| *n >= 2)
            .ok_or(Violation("JPEG segment"))?;
        let body = bytes
            .get(at + 4..at + 2 + length)
            .ok_or(Violation("truncated JPEG segment"))?;
        match marker {
            0xe0 if !app0 && size.is_none() => {
                // JFIF 1.02, density only, no thumbnail.
                if body.len() != 14 || !body.starts_with(b"JFIF\0\x01\x02") || body[12..] != [0, 0]
                {
                    return invalid("JPEG APP0");
                }
                app0 = true;
            }
            0xdb | 0xc4 => tables = true,
            0xdd if body.len() == 2 => {}
            0xfe if body == b"CS=ITU601\0" => {}
            0xc0 if size.is_none() => {
                // Precision 8, dimensions, then 1 or 3 three-byte components.
                let components = usize::from(*body.get(5).unwrap_or(&0));
                if body.len() != 6 + 3 * components || body[0] != 8 || ![1, 3].contains(&components)
                {
                    return invalid("JPEG frame header");
                }
                let height = u32::from(u16::from_be_bytes([body[1], body[2]]));
                let width = u32::from(u16::from_be_bytes([body[3], body[4]]));
                size = Some(picture_size(width, height)?);
            }
            0xda if size.is_some() && tables => {
                at += 2 + length;
                break;
            }
            _ => return invalid("unexpected JPEG segment"),
        }
        at += 2 + length;
    }
    // Entropy-coded data: 0xff is followed only by a stuffed zero or a
    // restart marker, until EOI ends the file.
    while at < bytes.len() {
        if bytes[at] == 0xff {
            match bytes.get(at + 1) {
                Some(0x00 | 0xd0..=0xd7) => at += 2,
                Some(0xd9) if at + 2 == bytes.len() => return Ok(size.expect("frame header")),
                _ => return invalid("data after the JPEG scan"),
            }
        } else {
            at += 1;
        }
    }
    invalid("JPEG without end marker")
}
fn picture_size(width: u32, height: u32) -> Result<(u32, u32), Violation> {
    if (1..=MAX_PICTURE_SIDE).contains(&width) && (1..=MAX_PICTURE_SIDE).contains(&height) {
        Ok((width, height))
    } else {
        Err(Violation("picture size"))
    }
}
/// PNG chunks FFmpeg's encoder writes for a still picture without side data:
/// colour information, the palette and transparency, pixel aspect and image
/// data. Text, EXIF, ICC and animation chunks are violations.
const PNG_CHUNKS: [&[u8; 4]; 9] = [
    b"PLTE", b"tRNS", b"pHYs", b"sRGB", b"gAMA", b"cHRM", b"cICP", b"sBIT", b"IDAT",
];
/// Check a still PNG as FFmpeg's encoder writes a re-encoded cover: the
/// signature, a non-interlaced IHDR, only `PNG_CHUNKS` (each ancillary chunk
/// once, image data contiguous), every CRC correct, and IEND as the last
/// bytes. Returns the picture's (width, height).
pub(crate) fn png(bytes: &[u8]) -> Result<(u32, u32), Violation> {
    let invalid = |what| Err(Violation(what));
    let Some(mut rest) = bytes.strip_prefix(b"\x89PNG\r\n\x1a\n") else {
        return invalid("not a PNG");
    };
    let mut seen: Vec<[u8; 4]> = vec![];
    let mut size = None;
    loop {
        let length = rest
            .get(..4)
            .map(|b| u32::from_be_bytes(b.try_into().expect("4 bytes")) as usize)
            .ok_or(Violation("truncated PNG chunk"))?;
        let chunk = rest
            .get(4..8 + length)
            .ok_or(Violation("truncated PNG chunk"))?;
        let crc = rest
            .get(8 + length..12 + length)
            .ok_or(Violation("truncated PNG chunk"))?;
        if crc32(chunk).to_be_bytes() != crc {
            return invalid("PNG chunk checksum");
        }
        let kind: [u8; 4] = chunk[..4].try_into().expect("4 bytes");
        let data = &chunk[4..];
        rest = &rest[12 + length..];
        match &kind {
            b"IHDR" if size.is_none() => {
                // Width, height, depth, colour type, compression 0, filter 0,
                // no interlacing.
                if data.len() != 13 || data[10..] != [0, 0, 0] {
                    return invalid("PNG header");
                }
                let width = u32::from_be_bytes(data[..4].try_into().expect("4 bytes"));
                let height = u32::from_be_bytes(data[4..8].try_into().expect("4 bytes"));
                size = Some(picture_size(width, height)?);
            }
            b"IEND" if size.is_some() && seen.contains(b"IDAT") => {
                return if data.is_empty() && rest.is_empty() {
                    Ok(size.expect("header"))
                } else {
                    invalid("data after the PNG end")
                };
            }
            b"IDAT" if size.is_some() && seen.last() == Some(b"IDAT") => {}
            kind if size.is_some() && PNG_CHUNKS.contains(&kind) && !seen.contains(kind) => {}
            _ => return invalid("unexpected PNG chunk"),
        }
        seen.push(kind);
    }
}
/// CRC-32 (ISO 3309, as PNG uses it).
fn crc32(bytes: &[u8]) -> u32 {
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

/// Call `found` at every offset of `[start, end)`, with enough lookahead for a
/// 10-byte pattern; fail on the first match.
fn scan<F: Read + Seek>(
    file: &mut F,
    start: u64,
    end: u64,
    found: impl Fn(&[u8], usize) -> bool,
) -> Result<(), Violation> {
    const CHUNK: usize = 1024 * 1024;
    const OVERLAP: usize = 16;
    let mut offset = start;
    let mut buffer = vec![0u8; CHUNK + OVERLAP];
    while offset < end {
        let size = (end - offset).min((CHUNK + OVERLAP) as u64) as usize;
        read_at(file, offset, &mut buffer[..size])?;
        let chunk = &buffer[..size];
        let last = if offset + size as u64 == end {
            size
        } else {
            CHUNK
        };
        if (0..last).any(|i| found(chunk, i)) {
            return Err(Violation("tag data inside the audio"));
        }
        offset += last as u64;
    }
    Ok(())
}

/// One MP4 box: (type, header length, total length).
fn mp4_box<F: Read + Seek>(
    file: &mut F,
    at: u64,
    end: u64,
) -> Result<([u8; 4], u64, u64), Violation> {
    let invalid = || Violation("invalid MP4 box size");
    let mut head = [0u8; 8];
    if at.checked_add(8).is_none_or(|next| next > end) {
        return Err(Violation("truncated MP4 box"));
    }
    read_at(file, at, &mut head)?;
    let kind: [u8; 4] = head[4..].try_into().expect("4 bytes");
    let (header, size) = match u32::from_be_bytes(head[..4].try_into().expect("4 bytes")) {
        0 => (8, end - at),
        1 => {
            if at + 16 > end {
                return Err(invalid());
            }
            let mut large = [0u8; 8];
            read_at(file, at + 8, &mut large)?;
            (16, u64::from_be_bytes(large))
        }
        n => (8, u64::from(n)),
    };
    // Checked: a 64-bit size near 2^64 must not wrap.
    if size < header || at.checked_add(size).is_none_or(|next| next > end) {
        return Err(invalid());
    }
    Ok((kind, header, size))
}
/// Check an M4A written by the audio rebuild: only `ftyp`, `free`, one `moov`
/// and `mdat` at the top; `moov` holds one track and at most an iTunes
/// metadata list of the engine's text items and one checked cover (`covr`);
/// no metadata anywhere else.
pub(crate) fn m4a<F: Read + Seek>(file: &mut F, len: u64) -> Result<(), Violation> {
    let mut at = 0;
    let mut moov = None;
    let mut mdat = 0;
    while at < len {
        let (kind, header, size) = mp4_box(file, at, len)?;
        match &kind {
            b"ftyp" | b"free" => {}
            b"mdat" => mdat += 1,
            b"moov" if moov.is_none() => moov = Some((at + header, at + size)),
            _ => return Err(Violation("unexpected top-level MP4 box")),
        }
        at += size;
    }
    let (start, end) = moov.ok_or(Violation("no moov box"))?;
    if mdat != 1 || end - start > MAX_MOOV {
        return Err(Violation("unexpected MP4 layout"));
    }
    let mut body = vec![0u8; (end - start) as usize];
    read_at(file, start, &mut body)?;
    let mut tracks = 0;
    walk(&body, b"moov", 0, &mut tracks)?;
    if tracks != 1 {
        return Err(Violation("not exactly one MP4 track"));
    }
    Ok(())
}
/// Walk the children of an in-memory container box, at most `MAX_MP4_DEPTH`
/// levels deep (an error, never unbounded recursion).
fn walk(body: &[u8], parent: &[u8; 4], depth: u32, tracks: &mut u32) -> Result<(), Violation> {
    if depth > MAX_MP4_DEPTH {
        return Err(Violation("MP4 boxes nested too deeply"));
    }
    let mut cursor = io::Cursor::new(body);
    let end = body.len() as u64;
    let mut at = 0;
    while at < end {
        let (kind, header, size) = mp4_box(&mut cursor, at, end)?;
        let inner = &body[(at + header) as usize..(at + size) as usize];
        let allowed = match parent {
            b"moov" => matches!(&kind, b"mvhd" | b"trak" | b"udta"),
            b"udta" => &kind == b"meta",
            b"meta" => matches!(&kind, b"hdlr" | b"ilst"),
            _ => &kind != b"covr" && &kind != b"udta" && &kind != b"meta",
        };
        if !allowed {
            return Err(Violation("unexpected MP4 metadata box"));
        }
        let deeper = depth + 1;
        match &kind {
            b"trak" => {
                *tracks += 1;
                walk(inner, &kind, deeper, tracks)?;
            }
            b"mdia" | b"minf" | b"stbl" | b"dinf" | b"edts" | b"udta" => {
                walk(inner, &kind, deeper, tracks)?
            }
            // A full box: version and flags precede the children.
            b"meta" => walk(
                inner.get(4..).ok_or(Violation("short meta box"))?,
                &kind,
                deeper,
                tracks,
            )?,
            b"ilst" => metadata_items(inner)?,
            b"stsd" => sample_description(inner)?,
            _ => {}
        }
        at += size;
    }
    Ok(())
}
/// The items of an iTunes metadata list (`ilst`) as FFmpeg writes them for the
/// rebuild: each at most once, each holding exactly one `data` box with the
/// default locale. Text items are UTF-8 (`plain_text`); track and disc
/// numbers have FFmpeg's fixed binary layout; a cover is one JPEG or PNG.
fn metadata_items(body: &[u8]) -> Result<(), Violation> {
    let invalid = |what| Err(Violation(what));
    let mut cursor = io::Cursor::new(body);
    let end = body.len() as u64;
    let mut at = 0;
    let mut seen: Vec<[u8; 4]> = vec![];
    while at < end {
        let (kind, header, size) = mp4_box(&mut cursor, at, end)?;
        let item = &body[(at + header) as usize..(at + size) as usize];
        if seen.contains(&kind) {
            return invalid("repeated MP4 metadata item");
        }
        seen.push(kind);
        let (data_kind, data_header, data_size) =
            mp4_box(&mut io::Cursor::new(item), 0, item.len() as u64)?;
        if &data_kind != b"data" || data_size != item.len() as u64 || data_size < data_header + 8 {
            return invalid("MP4 metadata value");
        }
        let data = &item[data_header as usize..];
        let (class, locale, value) = (
            u32::from_be_bytes(data[..4].try_into().expect("4 bytes")),
            &data[4..8],
            &data[8..],
        );
        if locale != [0; 4] {
            return invalid("MP4 metadata value");
        }
        let valid = match &kind {
            b"covr" => match class {
                13 => jpeg(value).is_ok(),
                14 => png(value).is_ok(),
                _ => false,
            },
            // Reserved, number, count, reserved (trkn); disk has no padding.
            b"trkn" => {
                class == 0 && value.len() == 8 && value[..2] == [0, 0] && value[6..] == [0, 0]
            }
            b"disk" => class == 0 && value.len() == 6 && value[..2] == [0, 0],
            kind if TAGS.iter().any(|(_, _, item, _)| *item == kind) => {
                class == 1 && plain_text(value)
            }
            _ => return invalid("unexpected MP4 metadata item"),
        };
        if !valid {
            return invalid("MP4 metadata value");
        }
        at += size;
    }
    Ok(())
}
/// A sample description holds codec setup only: it is small, and an AAC
/// decoder configuration (`esds`) carries no bytes beyond what its fields use.
fn sample_description(body: &[u8]) -> Result<(), Violation> {
    if body.len() > MAX_STSD {
        return Err(Violation("oversized MP4 sample description"));
    }
    // Version/flags, entry count, then the entries.
    let mut cursor = io::Cursor::new(body);
    let end = body.len() as u64;
    let mut at = 8;
    while at < end {
        let (kind, header, size) = mp4_box(&mut cursor, at, end)?;
        let entry = &body[(at + header) as usize..(at + size) as usize];
        if &kind == b"mp4a" {
            // Audio sample entry v0: 28 bytes, then child boxes.
            let children = entry
                .get(28..)
                .ok_or(Violation("short audio sample entry"))?;
            let mut inner = io::Cursor::new(children);
            let inner_end = children.len() as u64;
            let mut child = 0;
            while child < inner_end {
                let (kind, header, size) = mp4_box(&mut inner, child, inner_end)?;
                if &kind == b"esds" {
                    let esds = &children[(child + header) as usize..(child + size) as usize];
                    if let Some(asc) = esds.get(4..).and_then(audio_specific_config)
                        && has_payload_after(asc, asc_bits(asc))
                    {
                        return Err(Violation("data after the AAC decoder configuration"));
                    }
                }
                child += size;
            }
        }
        at += size;
    }
    Ok(())
}
/// One MPEG-4 descriptor: (tag, body, rest after it).
fn descriptor(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, mut rest) = bytes.split_first()?;
    let mut length = 0usize;
    for _ in 0..4 {
        let (&b, next) = rest.split_first()?;
        rest = next;
        length = (length << 7) | usize::from(b & 0x7f);
        if b & 0x80 == 0 {
            return (length <= rest.len()).then(|| (tag, &rest[..length], &rest[length..]));
        }
    }
    None
}
/// The AudioSpecificConfig inside an `esds` ES_Descriptor, for MPEG-4 audio.
fn audio_specific_config(es: &[u8]) -> Option<&[u8]> {
    let (tag, body, _) = descriptor(es)?;
    if tag != 3 {
        return None;
    }
    let flags = *body.get(2)?;
    let mut offset = 3;
    if flags & 0x80 != 0 {
        offset += 2;
    }
    if flags & 0x40 != 0 {
        offset += 1 + usize::from(*body.get(offset)?);
    }
    if flags & 0x20 != 0 {
        offset += 2;
    }
    let (tag, config, _) = descriptor(body.get(offset..)?)?;
    // MPEG-4 audio object type indication.
    if tag != 4 || *config.first()? != 0x40 {
        return None;
    }
    let (tag, asc, _) = descriptor(config.get(13..)?)?;
    (tag == 5).then_some(asc)
}
struct Bits<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl Bits<'_> {
    fn get(&mut self, n: usize) -> Option<u32> {
        let mut value = 0u32;
        for _ in 0..n {
            let byte = *self.bytes.get(self.at / 8)?;
            value = (value << 1) | u32::from((byte >> (7 - self.at % 8)) & 1);
            self.at += 1;
        }
        Some(value)
    }
    fn peek(&self, n: usize) -> Option<u32> {
        Bits {
            bytes: self.bytes,
            at: self.at,
        }
        .get(n)
    }
    fn left(&self) -> usize {
        (self.bytes.len() * 8).saturating_sub(self.at)
    }
}
/// The bits an AudioSpecificConfig's fields use (ISO/IEC 14496-3 1.6.2),
/// including SBR/PS signalling. `None` when the configuration is one this
/// check does not model (for example a program config element); such a
/// configuration is never rejected.
fn asc_bits(asc: &[u8]) -> Option<usize> {
    let mut b = Bits { bytes: asc, at: 0 };
    let object_type = |b: &mut Bits| -> Option<u32> {
        let t = b.get(5)?;
        if t == 31 {
            Some(32 + b.get(6)?)
        } else {
            Some(t)
        }
    };
    let frequency = |b: &mut Bits| -> Option<()> {
        if b.get(4)? == 15 {
            b.get(24)?;
        }
        Some(())
    };
    let mut aot = object_type(&mut b)?;
    frequency(&mut b)?;
    let channels = b.get(4)?;
    let mut explicit_sbr = false;
    if aot == 5 || aot == 29 {
        explicit_sbr = true;
        frequency(&mut b)?;
        aot = object_type(&mut b)?;
    }
    // GASpecificConfig for the AAC object types without error resilience.
    if !matches!(aot, 1 | 2 | 3 | 4 | 6 | 7) || channels == 0 {
        return None;
    }
    b.get(1)?; // frameLengthFlag
    if b.get(1)? == 1 {
        b.get(14)?; // coreCoderDelay
    }
    let extension = b.get(1)?;
    if aot == 6 {
        b.get(3)?; // layerNr
    }
    if extension == 1 {
        return None; // version-3 extension fields are not modelled
    }
    // Backward-compatible SBR/PS signalling (sync extension 0x2b7).
    if !explicit_sbr && b.left() >= 16 && b.peek(11)? == 0x2b7 {
        b.get(11)?;
        match object_type(&mut b)? {
            5 => {
                if b.get(1)? == 1 {
                    frequency(&mut b)?;
                    if b.left() >= 12 && b.peek(11)? == 0x548 {
                        b.get(11)?;
                        b.get(1)?;
                    }
                }
            }
            _ => return None,
        }
    }
    Some(b.at)
}
/// Whether `bytes` holds any non-zero bit after the first `used` bits. Zero
/// padding carries nothing; anything else is not part of the codec setup.
fn has_payload_after(bytes: &[u8], used: Option<usize>) -> bool {
    let Some(used) = used else {
        return false;
    };
    let mut bits = Bits { bytes, at: used };
    while bits.left() > 0 {
        if bits.get(1) != Some(0) {
            return true;
        }
    }
    false
}

/// Check an Ogg Opus file written by the audio rebuild: contiguous Ogg pages
/// of one logical stream to the last byte, starting with OpusHead and an
/// OpusTags packet that holds only the engine's text comments (so no picture
/// or other metadata) and nothing after them.
pub(crate) fn ogg_opus<F: Read + Seek>(file: &mut F, len: u64) -> Result<(), Violation> {
    let mut at = 0u64;
    let mut serial = None;
    let mut packets: Vec<Vec<u8>> = vec![vec![]];
    let mut header = [0u8; 27];
    while at < len {
        if at + 27 > len {
            return Err(Violation("truncated Ogg page"));
        }
        read_at(file, at, &mut header)?;
        if &header[..4] != b"OggS" || header[4] != 0 {
            return Err(Violation("non-Ogg data"));
        }
        let page_serial = u32::from_le_bytes(header[14..18].try_into().expect("4 bytes"));
        if *serial.get_or_insert(page_serial) != page_serial {
            return Err(Violation("more than one Ogg stream"));
        }
        let mut lacing = vec![0u8; header[26] as usize];
        read_at(file, at + 27, &mut lacing)?;
        let body = lacing.iter().map(|&n| u64::from(n)).sum::<u64>();
        let start = at + 27 + lacing.len() as u64;
        if start + body > len {
            return Err(Violation("truncated Ogg page"));
        }
        // Assemble the first two packets (OpusHead, OpusTags) only.
        if packets.len() <= 2 {
            let mut data = vec![0u8; body as usize];
            read_at(file, start, &mut data)?;
            let mut offset = 0;
            for &n in &lacing {
                if packets.len() <= 2 {
                    let current = packets.last_mut().expect("one packet");
                    current.extend_from_slice(&data[offset..offset + n as usize]);
                    if current.len() > MAX_HEADER_PACKET {
                        return Err(Violation("oversized Ogg header packet"));
                    }
                }
                offset += n as usize;
                if n < 255 {
                    packets.push(vec![]);
                }
            }
        }
        at = start + body;
    }
    let (head, tags) = match &packets[..] {
        [head, tags, ..] => (head, tags),
        _ => return Err(Violation("missing Opus headers")),
    };
    if !head.starts_with(b"OpusHead") || !tags.starts_with(b"OpusTags") || tags.len() < 16 {
        return Err(Violation("missing Opus headers"));
    }
    // RFC 7845 5.1: 19 bytes, plus 2 and one byte per channel for a channel
    // mapping family other than 0. Anything further is not codec setup.
    let used = match (head.get(9), head.get(18)) {
        (Some(_), Some(0)) => 19,
        (Some(&channels), Some(_)) => 21 + usize::from(channels),
        _ => return Err(Violation("short OpusHead")),
    };
    if head.len() > used && has_payload_after(head, Some(used * 8)) {
        return Err(Violation("data after the OpusHead fields"));
    }
    opus_comments(&tags[8..])
}
/// The vendor string and comment list of an OpusTags packet: at most one of
/// each engine field (`TAGS`, any letter case) with a `plain_text` value, and
/// no bytes after the list.
fn opus_comments(tags: &[u8]) -> Result<(), Violation> {
    let malformed = Violation("malformed OpusTags");
    let mut at = 0usize;
    let mut field = || -> Result<&[u8], Violation> {
        let length = tags
            .get(at..at + 4)
            .map(|b| u32::from_le_bytes(b.try_into().expect("4 bytes")) as usize)
            .ok_or(Violation("malformed OpusTags"))?;
        let value = tags
            .get(at + 4..at + 4 + length)
            .ok_or(Violation("malformed OpusTags"))?;
        at += 4 + length;
        Ok(value)
    };
    field()?; // vendor
    let count = tags
        .get(at..at + 4)
        .map(|b| u32::from_le_bytes(b.try_into().expect("4 bytes")) as usize)
        .ok_or(malformed)?;
    at += 4;
    if count > TAGS.len() {
        return Err(Violation("Opus comments"));
    }
    let mut seen: Vec<&str> = vec![];
    for _ in 0..count {
        let length = tags
            .get(at..at + 4)
            .map(|b| u32::from_le_bytes(b.try_into().expect("4 bytes")) as usize)
            .ok_or(Violation("malformed OpusTags"))?;
        let comment = tags
            .get(at + 4..at + 4 + length)
            .ok_or(Violation("malformed OpusTags"))?;
        at += 4 + length;
        let split = comment.iter().position(|&b| b == b'=');
        let (name, value) = split
            .map(|i| (&comment[..i], &comment[i + 1..]))
            .ok_or(Violation("Opus comments"))?;
        let Some((_, _, _, known)) = TAGS.iter().find(|(key, _, _, field)| {
            name.eq_ignore_ascii_case(field.as_bytes()) || name.eq_ignore_ascii_case(key.as_bytes())
        }) else {
            return Err(Violation("Opus comments"));
        };
        if seen.contains(known) || !plain_text(value) {
            return Err(Violation("Opus comments"));
        }
        seen.push(known);
    }
    if at != tags.len() {
        return Err(Violation("data after the Opus comments"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    /// MPEG-1 Layer III, 128 kbit/s, 44.1 kHz: 417 bytes (418 padded).
    fn frame(padded: bool) -> Vec<u8> {
        let mut f = vec![0xff, 0xfb, 0x90 | if padded { 2 } else { 0 }, 0x64];
        f.resize(if padded { 418 } else { 417 }, 0x55);
        f
    }
    fn audio(n: usize) -> Vec<u8> {
        (0..n).flat_map(|i| frame(i % 3 == 0)).collect()
    }
    fn check_mp3(bytes: &[u8]) -> Result<u64, Violation> {
        mp3(&mut Cursor::new(bytes), bytes.len() as u64)
    }
    #[test]
    fn mpeg_frame_lengths_follow_the_header() {
        assert_eq!(mpeg_frame([0xff, 0xfb, 0x90, 0x64]), Some(417));
        assert_eq!(mpeg_frame([0xff, 0xfb, 0x92, 0x64]), Some(418));
        // MPEG-2 Layer III, 64 kbit/s, 22.05 kHz.
        assert_eq!(mpeg_frame([0xff, 0xf3, 0x80, 0x64]), Some(208));
        // MPEG-1 Layer I, 32 kbit/s, 44.1 kHz.
        assert_eq!(mpeg_frame([0xff, 0xff, 0x10, 0x00]), Some(32));
        for invalid in [
            [0xff, 0xfb, 0x00, 0x00], // free format
            [0xff, 0xfb, 0xf0, 0x00], // bad bitrate
            [0xff, 0xfb, 0x9c, 0x00], // reserved rate
            [0xff, 0xe9, 0x90, 0x00], // reserved layer
            [0xff, 0xeb, 0x90, 0x00], // reserved version
            [0x49, 0x44, 0x33, 0x03], // "ID3"
        ] {
            assert_eq!(mpeg_frame(invalid), None, "{invalid:02x?}");
        }
    }
    #[test]
    fn clean_mp3_frames_pass_and_trailing_tags_are_cut() {
        let clean = audio(20);
        assert_eq!(check_mp3(&clean), Ok(clean.len() as u64));
        let mut ape = b"APEPAYLOAD".repeat(30);
        ape.extend_from_slice(b"APETAGEX");
        ape.extend_from_slice(&[0; 24]);
        let id3v1 = [b"TAG".to_vec(), vec![b' '; 125]].concat();
        let partial = frame(false)[..200].to_vec();
        for tail in [ape, id3v1, b"junk".repeat(50), partial, vec![0xff]] {
            let bytes = [clean.clone(), tail].concat();
            assert_eq!(check_mp3(&bytes), Ok(clean.len() as u64));
        }
    }
    #[test]
    fn data_between_mp3_frames_or_tags_inside_them_are_violations() {
        let clean = audio(20);
        // The end of frame 7 (frames 0, 3 and 6 are padded).
        let boundary = (0..7)
            .map(|i| if i % 3 == 0 { 418 } else { 417 })
            .sum::<usize>();
        let id3 = [b"ID3\x03\x00\x00\x00\x00\x01\x00".to_vec(), vec![0; 128]].concat();
        for junk in [b"JUNK-BETWEEN-FRAMES".to_vec(), id3] {
            let bytes = [&clean[..boundary], &junk, &clean[boundary..]].concat();
            assert!(check_mp3(&bytes).is_err(), "{:?}", &junk[..4]);
        }
        // A tag header hidden inside a frame payload.
        let mut hidden = clean.clone();
        hidden[500..510].copy_from_slice(b"ID3\x04\x00\x00\x00\x00\x00\x10");
        assert_eq!(
            check_mp3(&hidden),
            Err(Violation("tag data inside the audio"))
        );
        let mut ape = clean.clone();
        ape[900..908].copy_from_slice(b"APETAGEX");
        assert!(check_mp3(&ape).is_err());
        // A leading tag is not allowed either: the rebuild writes none.
        let leading = [b"ID3\x03\x00\x00\x00\x00\x00\x00".to_vec(), clean.clone()].concat();
        assert!(check_mp3(&leading).is_err());
        assert!(check_mp3(b"not audio at all").is_err());
        assert!(check_mp3(&[]).is_err());
    }

    fn bx(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        [
            &((payload.len() + 8) as u32).to_be_bytes()[..],
            kind,
            payload,
        ]
        .concat()
    }
    fn m4a_file(udta: Option<Vec<u8>>, extra_top: Option<Vec<u8>>) -> Vec<u8> {
        let stbl = bx(
            b"stbl",
            &[bx(b"stsd", &[0; 8]), bx(b"stco", &[0; 8])].concat(),
        );
        let trak = bx(
            b"trak",
            &[
                bx(b"tkhd", &[0; 84]),
                bx(
                    b"mdia",
                    &[bx(b"mdhd", &[0; 24]), bx(b"minf", &stbl)].concat(),
                ),
            ]
            .concat(),
        );
        let moov = bx(
            b"moov",
            &[bx(b"mvhd", &[0; 100]), trak, udta.unwrap_or_default()].concat(),
        );
        [
            bx(b"ftyp", b"M4A \0\0\0\0"),
            moov,
            bx(b"free", &[]),
            extra_top.unwrap_or_default(),
            bx(b"mdat", &[1; 64]),
        ]
        .concat()
    }
    fn meta(ilst: &[u8]) -> Vec<u8> {
        bx(
            b"udta",
            &bx(
                b"meta",
                &[&[0u8; 4][..], &bx(b"hdlr", &[0; 25]), &bx(b"ilst", ilst)].concat(),
            ),
        )
    }
    fn check_m4a(bytes: &[u8]) -> Result<(), Violation> {
        m4a(&mut Cursor::new(bytes), bytes.len() as u64)
    }
    #[test]
    fn m4a_allows_only_audio_framing_and_checked_metadata() {
        check_m4a(&m4a_file(None, None)).unwrap();
        check_m4a(&m4a_file(Some(meta(&[])), None)).unwrap();
        let covr = bx(
            b"covr",
            &bx(b"data", &[0, 0, 0, 13, 0, 0, 0, 0, 0xff, 0xd8]),
        );
        let title = bx(b"\xa9nam", &bx(b"data", b"\0\0\0\x01\0\0\0\0Title"));
        check_m4a(&m4a_file(Some(meta(&title)), None)).unwrap();
        for bad in [
            m4a_file(Some(meta(&covr)), None),
            m4a_file(None, Some(bx(b"uuid", &[0; 32]))),
            m4a_file(None, Some(bx(b"moov", &[]))),
            m4a_file(Some(bx(b"udta", &bx(b"covr", &[0; 8]))), None),
            m4a_file(Some(bx(b"udta", &bx(b"chpl", &[0; 8]))), None),
            [m4a_file(None, None), b"trailing".to_vec()].concat(),
        ] {
            assert!(check_m4a(&bad).is_err());
        }
    }

    fn page(serial: u32, packets: &[&[u8]]) -> Vec<u8> {
        let mut lacing = vec![];
        for packet in packets {
            lacing.extend(std::iter::repeat_n(255u8, packet.len() / 255));
            lacing.push((packet.len() % 255) as u8);
        }
        let mut out = b"OggS\0\0".to_vec();
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(&serial.to_le_bytes());
        out.extend_from_slice(&[0; 8]);
        out.push(lacing.len() as u8);
        out.extend_from_slice(&lacing);
        for packet in packets {
            out.extend_from_slice(packet);
        }
        out
    }
    fn tags(comments: &[&str]) -> Vec<u8> {
        let mut out = b"OpusTags".to_vec();
        out.extend_from_slice(&6u32.to_le_bytes());
        out.extend_from_slice(b"ffmpeg");
        out.extend_from_slice(&(comments.len() as u32).to_le_bytes());
        for c in comments {
            out.extend_from_slice(&(c.len() as u32).to_le_bytes());
            out.extend_from_slice(c.as_bytes());
        }
        out
    }
    fn check_ogg(bytes: &[u8]) -> Result<(), Violation> {
        ogg_opus(&mut Cursor::new(bytes), bytes.len() as u64)
    }
    #[test]
    fn ogg_opus_allows_one_stream_with_only_engine_comments() {
        let head = b"OpusHead\x01\x01\0\0\0\0\0\0\0\0\0";
        let clean = [
            page(7, &[head]),
            page(7, &[&tags(&[])]),
            page(7, &[&[1; 300], &[2; 40]]),
        ]
        .concat();
        check_ogg(&clean).unwrap();
        check_ogg(&[page(7, &[head]), page(7, &[&tags(&["title=x"])])].concat()).unwrap();
        let picture = format!("METADATA_BLOCK_PICTURE={}", "A".repeat(600));
        for bad in [
            [page(7, &[head]), page(7, &[&tags(&[&picture])])].concat(),
            [page(7, &[head]), page(7, &[&tags(&["COVERART=AAAA"])])].concat(),
            [clean.clone(), page(8, &[&[1; 10]])].concat(),
            [clean.clone(), b"APETAGEX".to_vec()].concat(),
            [page(7, &[b"Vorbis"]), page(7, &[&tags(&[])])].concat(),
            clean[..clean.len() - 5].to_vec(),
        ] {
            assert!(check_ogg(&bad).is_err());
        }
    }

    /// The ENGINE-FIX-3 review's crashers: deep `mdia` nesting overflowed the
    /// stack; a 64-bit box size near 2^64 wrapped (endless loop at the top
    /// level, a panic inside `moov`). All must be plain errors now.
    #[test]
    fn hostile_mp4_box_trees_are_errors_not_aborts_or_loops() {
        let mut nested = bx(b"stbl", &[]);
        for _ in 0..20_000 {
            nested = bx(b"mdia", &nested);
        }
        let moov = bx(
            b"moov",
            &[bx(b"mvhd", &[0; 100]), bx(b"trak", &nested)].concat(),
        );
        let deep = [bx(b"ftyp", b"M4A \0\0\0\0"), moov, bx(b"mdat", &[0; 8])].concat();
        // Run on a 2 MiB stack, like the blocking pool.
        let result = std::thread::Builder::new()
            .stack_size(2 * 1024 * 1024)
            .spawn(move || check_m4a(&deep))
            .unwrap()
            .join()
            .expect("no stack overflow");
        assert_eq!(result, Err(Violation("MP4 boxes nested too deeply")));
        let huge = |kind: &[u8; 4]| {
            let mut b = 1u32.to_be_bytes().to_vec();
            b.extend_from_slice(kind);
            b.extend_from_slice(&(u64::MAX - 7).to_be_bytes());
            b
        };
        for bad in [
            [
                bx(b"ftyp", b"M4A \0\0\0\0"),
                huge(b"free"),
                bx(b"mdat", &[0; 8]),
            ]
            .concat(),
            [
                bx(b"ftyp", b"M4A \0\0\0\0"),
                bx(b"moov", &[bx(b"mvhd", &[0; 100]), huge(b"trak")].concat()),
                bx(b"mdat", &[0; 8]),
            ]
            .concat(),
            // A large size whose 16-byte header itself is truncated.
            [
                bx(b"ftyp", b"M4A \0\0\0\0"),
                vec![0, 0, 0, 1, b'f', b'r', b'e', b'e', 0],
            ]
            .concat(),
        ] {
            let started = std::time::Instant::now();
            assert!(check_m4a(&bad).is_err());
            assert!(started.elapsed() < std::time::Duration::from_secs(2));
        }
    }
    /// Deterministic pseudo-random bytes (xorshift), standing in for
    /// compressed trailing data.
    fn noise(n: usize, mut seed: u64) -> Vec<u8> {
        (0..n)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed as u8
            })
            .collect()
    }
    #[test]
    fn large_random_trailing_data_is_cut_not_mistaken_for_audio() {
        let clean = audio(20);
        // The review saw 9 of 40 such 10 MB tails refused under the
        // two-frame rule; three consecutive frames do not match by chance.
        for seed in 1..=6u64 {
            let bytes = [clean.clone(), noise(10 * 1024 * 1024, seed)].concat();
            assert_eq!(check_mp3(&bytes), Ok(clean.len() as u64), "seed {seed}");
        }
        // Three real frames after junk are still audio continuing.
        let bytes = [clean.clone(), b"JUNK".to_vec(), audio(3)].concat();
        assert_eq!(check_mp3(&bytes), Err(BETWEEN_FRAMES));
    }
    #[test]
    fn opus_head_carries_nothing_beyond_its_fields() {
        let tags_page = page(7, &[&tags(&[])]);
        let stereo = b"OpusHead\x01\x02\0\0\x80\xbb\0\0\0\0\0".to_vec();
        let surround = [
            b"OpusHead\x01\x06\0\0\x80\xbb\0\0\0\0\x01".to_vec(),
            vec![4, 2, 0, 4, 1, 2, 3, 5],
        ]
        .concat();
        for head in [
            stereo.clone(),
            surround.clone(),
            [stereo.clone(), vec![0; 8]].concat(),
        ] {
            check_ogg(&[page(7, &[&head]), tags_page.clone()].concat()).unwrap();
        }
        for head in [
            [stereo.clone(), b"PAYLOAD".repeat(1200)].concat(),
            [surround, vec![1]].concat(),
        ] {
            assert_eq!(
                check_ogg(&[page(7, &[&head]), tags_page.clone()].concat()),
                Err(Violation("data after the OpusHead fields"))
            );
        }
        assert!(check_ogg(&[page(7, &[b"OpusHead\x01\x02"]), tags_page].concat()).is_err());
    }
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    /// AudioSpecificConfigs from the review's legitimate M4A corpus.
    const REAL_ASCS: [&str; 10] = [
        "1210",           // AAC-LC (Apple, FFmpeg aac_at, ADTS source)
        "1190",           // AAC-LC 48 kHz (Apple fragmented)
        "121056e500",     // FFmpeg aac: explicit "no SBR"
        "158856e500",     // FFmpeg aac, 8 kHz mono
        "119056e500",     // FFmpeg aac, 48 kHz
        "138856e500",     // FFmpeg aac, 22.05 kHz mono
        "139056e5a0",     // Apple HE-AAC (SBR, backward compatible)
        "138856e5a54880", // Apple HE-AAC v2 (SBR + PS)
        "2b920800000000000000000000000000000000000000000000", // streamed HE-AAC (zero padded)
        "12100000000000000000000000000000", // streamed AAC-LC (zero padded)
    ];
    fn esds(asc: &[u8]) -> Vec<u8> {
        let tag = |t: u8, body: &[u8]| [&[t, body.len() as u8][..], body].concat();
        let decoder = tag(
            4,
            &[
                &[0x40, 0x15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0][..],
                &tag(5, asc),
            ]
            .concat(),
        );
        let es = tag(3, &[&[0, 1, 0][..], &decoder, &tag(6, &[2])].concat());
        [&[0u8; 4][..], &es].concat()
    }
    fn stsd(asc: &[u8]) -> Vec<u8> {
        let entry = bx(
            b"mp4a",
            &[&[0u8; 28][..], &bx(b"esds", &esds(asc))].concat(),
        );
        [&[0, 0, 0, 0, 0, 0, 0, 1][..], &entry].concat()
    }
    #[test]
    fn aac_configurations_carry_nothing_beyond_their_fields() {
        for asc in REAL_ASCS {
            let asc = hex(asc);
            assert_eq!(audio_specific_config(&esds(&asc)[4..]), Some(&asc[..]));
            sample_description(&stsd(&asc)).unwrap_or_else(|v| panic!("{asc:02x?}: {v:?}"));
        }
        assert_eq!(asc_bits(&hex("1210")), Some(16));
        assert_eq!(asc_bits(&hex("121056e500")), Some(33));
        assert_eq!(asc_bits(&hex("139056e5a0")), Some(37));
        assert_eq!(asc_bits(&hex("138856e5a54880")), Some(49));
        assert_eq!(asc_bits(&hex("2b920800")), Some(25));
        for asc in REAL_ASCS {
            let payload = [hex(asc), b"PAYLOAD".repeat(1000)].concat();
            let config = esds(&payload[..payload.len().min(100)]);
            assert!(
                has_payload_after(
                    audio_specific_config(&config[4..]).unwrap(),
                    asc_bits(&payload)
                ),
                "{asc}"
            );
        }
        // Inside a real sample description, and an oversized one.
        let small = [hex("1210"), b"PAYLOAD".repeat(10)].concat();
        assert_eq!(
            sample_description(&stsd(&small)),
            Err(Violation("data after the AAC decoder configuration"))
        );
        let big = bx(
            b"mp4a",
            &[&[0u8; 28][..], &bx(b"btrt", &[1; 1200])].concat(),
        );
        assert_eq!(
            sample_description(&[&[0, 0, 0, 0, 0, 0, 0, 1][..], &big].concat()),
            Err(Violation("oversized MP4 sample description"))
        );
        // Configurations this check does not model are never rejected.
        assert_eq!(asc_bits(&hex("1200ffff")), None); // program config element
        assert!(!has_payload_after(
            &hex("1200ffff"),
            asc_bits(&hex("1200ffff"))
        ));
    }
    /// What the managed FFmpeg writes when it re-encodes covers (bit-exact,
    /// side data removed): an 8x8 baseline JPEG and a 2x2 RGBA PNG.
    const COVER_JPEG: &str = "ffd8ffe000104a46494600010200004800480000ffdb0043000804040404040505050505050606060606060606060606060607070708080807070706060707080808080909090808080809090a0a0a0c0c0b0b0e0e0e111114ffc4004c0001010000000000000000000000000000000601010100000000000000000000000000000507100100000000000000000000000000000000110100000000000000000000000000000000ffc00011080008000803012200021100031100ffda000c03010002110311003f00900012aaffd9";
    const COVER_PNG: &str = "89504e470d0a1a0a0000000d494844520000000200000002080600000072b60d240000000970485973000000000000000100847917730000001549444154789c63fccfc0f09f91e17f230b031400002f3503855b7c145d0000000049454e44ae426082";
    /// `bytes` with `insert` placed at `at`.
    fn spliced(bytes: &[u8], at: usize, insert: &[u8]) -> Vec<u8> {
        [&bytes[..at], insert, &bytes[at..]].concat()
    }
    fn png_chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let body = [&kind[..], data].concat();
        [
            &(data.len() as u32).to_be_bytes()[..],
            &body,
            &crc32(&body).to_be_bytes(),
        ]
        .concat()
    }
    #[test]
    fn only_re_encoded_still_pictures_pass() {
        let jpg = hex(COVER_JPEG);
        let pic = hex(COVER_PNG);
        assert_eq!(jpeg(&jpg), Ok((8, 8)));
        assert_eq!(png(&pic), Ok((2, 2)));
        // After the 18-byte JFIF segment; before IEND (12 bytes from the end).
        let segment = |marker: u8, body: &[u8]| {
            [
                &[0xff, marker][..],
                &((body.len() + 2) as u16).to_be_bytes(),
                body,
            ]
            .concat()
        };
        let mut huge = jpg.clone();
        let sof = (0..huge.len())
            .find(|&i| huge[i..].starts_with(&[0xff, 0xc0]))
            .unwrap();
        huge[sof + 5..sof + 7].copy_from_slice(&5000u16.to_be_bytes());
        let scan_end = jpg.len() - 2;
        for (case, bad) in [
            (
                "trailing bytes",
                [jpg.clone(), b"SMUGGLED".to_vec()].concat(),
            ),
            (
                "EXIF",
                spliced(&jpg, 20, &segment(0xe1, b"Exif\0\0MM\0*SMUGGLED")),
            ),
            (
                "ICC",
                spliced(&jpg, 20, &segment(0xe2, b"ICC_PROFILE\0\x01\x01SMUGGLED")),
            ),
            ("comment", spliced(&jpg, 20, &segment(0xfe, b"SMUGGLED"))),
            ("progressive", {
                let mut b = jpg.clone();
                b[sof + 1] = 0xc2;
                b
            }),
            (
                "marker in the scan",
                spliced(&jpg, scan_end, &[0xff, 0xfe, 0, 4, 1, 2]),
            ),
            ("no end marker", jpg[..scan_end].to_vec()),
            ("oversized", huge),
            (
                "camera JPEG",
                hex("ffd8ffe000104a46494600010100004800480000ffe1004c4578696600004d4d002a"),
            ),
            ("PNG bytes", pic.clone()),
        ] {
            assert!(jpeg(&bad).is_err(), "{case}");
        }
        let iend = pic.len() - 12;
        let mut header = pic.clone();
        header[8 + 8 + 12] = 1; // interlaced
        let crc = crc32(&header[12..12 + 17]);
        header[12 + 17..12 + 21].copy_from_slice(&crc.to_be_bytes());
        let mut checksum = pic.clone();
        checksum[iend - 1] ^= 1;
        for (case, bad) in [
            (
                "trailing bytes",
                [pic.clone(), b"SMUGGLED".to_vec()].concat(),
            ),
            (
                "text",
                spliced(&pic, iend, &png_chunk(b"tEXt", b"Comment\0SMUGGLED")),
            ),
            (
                "ICC",
                spliced(&pic, 33, &png_chunk(b"iCCP", b"p\0\0SMUGGLED")),
            ),
            (
                "EXIF",
                spliced(&pic, 33, &png_chunk(b"eXIf", b"MM\0*SMUGGLED")),
            ),
            (
                "animation",
                spliced(&pic, 33, &png_chunk(b"acTL", &[0, 0, 0, 2, 0, 0, 0, 0])),
            ),
            (
                "private chunk",
                spliced(&pic, iend, &png_chunk(b"smGL", b"SMUGGLED")),
            ),
            ("repeated pHYs", spliced(&pic, 33, &pic[33..33 + 21])),
            ("interlaced", header),
            ("checksum", checksum),
            ("no end", pic[..iend].to_vec()),
            ("JPEG bytes", jpg.clone()),
        ] {
            assert!(png(&bad).is_err(), "{case}");
        }
    }
    fn syncsafe_bytes(n: usize) -> [u8; 4] {
        [3, 2, 1, 0].map(|i| ((n >> (7 * i)) & 0x7f) as u8)
    }
    /// An ID3v2.4 tag as the rebuild writes it, with `padding` zero bytes.
    fn id3_tag(frames: &[(&[u8; 4], Vec<u8>)], padding: usize) -> Vec<u8> {
        let mut body = vec![];
        for (id, data) in frames {
            body.extend_from_slice(*id);
            body.extend_from_slice(&syncsafe_bytes(data.len()));
            body.extend_from_slice(&[0, 0]);
            body.extend_from_slice(data);
        }
        body.resize(body.len() + padding, 0);
        [&b"ID3\x04\0\0"[..], &syncsafe_bytes(body.len()), &body].concat()
    }
    fn text(value: &str) -> Vec<u8> {
        [&[3][..], value.as_bytes(), &[0]].concat()
    }
    fn picture(mime: &str, kind: u8, bytes: &[u8]) -> Vec<u8> {
        [&[3][..], mime.as_bytes(), &[0, kind, 0], bytes].concat()
    }
    #[test]
    fn mp3_keeps_only_its_own_text_tags_and_one_re_encoded_cover() {
        let clean = audio(20);
        let jpg = hex(COVER_JPEG);
        let cover = picture("image/jpeg", 3, &jpg);
        let good = id3_tag(
            &[
                (b"TIT2", text("Épisode One")),
                (b"TRCK", text("3/12")),
                (b"APIC", cover.clone()),
            ],
            10,
        );
        let bytes = [good.clone(), clean.clone()].concat();
        assert_eq!(check_mp3(&bytes), Ok(bytes.len() as u64));
        let png_cover = id3_tag(&[(b"APIC", picture("image/png", 3, &hex(COVER_PNG)))], 0);
        check_mp3(&[png_cover, clean.clone()].concat()).unwrap();
        // The audio after the tag is still checked frame by frame.
        let after_tag = [
            good.clone(),
            clean[..500].to_vec(),
            b"JUNK".to_vec(),
            clean.clone(),
        ]
        .concat();
        assert!(check_mp3(&after_tag).is_err());
        let mut v23 = good.clone();
        v23[3] = 3;
        let mut flagged = good.clone();
        flagged[5] = 0x40; // extended header
        let mut padded = good.clone();
        let last = padded.len() - 1;
        padded[last] = 1;
        for (case, tag) in [
            ("ID3v2.3", v23),
            ("tag flags", flagged),
            ("data in the padding", padded),
            ("TXXX", id3_tag(&[(b"TXXX", text("x\0y"))], 0)),
            ("PRIV", id3_tag(&[(b"PRIV", b"owner\0SECRET".to_vec())], 0)),
            ("GEOB", id3_tag(&[(b"GEOB", b"\0\0\0\0SECRET".to_vec())], 0)),
            ("lyrics", id3_tag(&[(b"USLT", text("la"))], 0)),
            (
                "repeated",
                id3_tag(&[(b"TIT2", text("a")), (b"TIT2", text("b"))], 0),
            ),
            (
                "UTF-16",
                id3_tag(&[(b"TIT2", [&[1][..], b"\xff\xfea\0"].concat())], 0),
            ),
            ("control character", id3_tag(&[(b"TIT2", text("a\nb"))], 0)),
            ("two values", id3_tag(&[(b"TIT2", text("a\0b"))], 0)),
            (
                "too long",
                id3_tag(&[(b"TIT2", text(&"a".repeat(MAX_TEXT + 1)))], 0),
            ),
            (
                "GIF label",
                id3_tag(&[(b"APIC", picture("image/gif", 3, &jpg))], 0),
            ),
            (
                "mismatched label",
                id3_tag(&[(b"APIC", picture("image/png", 3, &jpg))], 0),
            ),
            (
                "not the front cover",
                id3_tag(&[(b"APIC", picture("image/jpeg", 0, &jpg))], 0),
            ),
            (
                "picture with a payload",
                id3_tag(
                    &[(b"APIC", [cover.clone(), b"SMUGGLED".to_vec()].concat())],
                    0,
                ),
            ),
            (
                "two pictures",
                id3_tag(&[(b"APIC", cover.clone()), (b"APIC", cover.clone())], 0),
            ),
        ] {
            assert!(check_mp3(&[tag, clean.clone()].concat()).is_err(), "{case}");
        }
    }
    fn item(kind: &[u8; 4], class: u32, value: &[u8]) -> Vec<u8> {
        bx(
            kind,
            &bx(
                b"data",
                &[&class.to_be_bytes()[..], &[0; 4], value].concat(),
            ),
        )
    }
    #[test]
    fn m4a_metadata_holds_only_engine_items_and_one_re_encoded_cover() {
        let good = [
            item(b"\xa9nam", 1, "Épisode One".as_bytes()),
            item(b"trkn", 0, &[0, 0, 0, 3, 0, 12, 0, 0]),
            item(b"disk", 0, &[0, 0, 0, 1, 0, 2]),
            item(b"covr", 13, &hex(COVER_JPEG)),
        ]
        .concat();
        check_m4a(&m4a_file(Some(meta(&good)), None)).unwrap();
        check_m4a(&m4a_file(
            Some(meta(&item(b"covr", 14, &hex(COVER_PNG)))),
            None,
        ))
        .unwrap();
        let mut locale = item(b"\xa9ART", 1, b"Artist");
        locale[23] = 1;
        for (case, items) in [
            ("JPEG typed as PNG", item(b"covr", 14, &hex(COVER_JPEG))),
            (
                "camera JPEG",
                item(
                    b"covr",
                    13,
                    &hex("ffd8ffe000104a46494600010100004800480000ffe1004c"),
                ),
            ),
            ("GIF cover", item(b"covr", 12, b"GIF89a")),
            ("lyrics", item(b"\xa9lyr", 1, b"la")),
            ("encoder", item(b"\xa9too", 1, b"Lavf")),
            (
                "freeform",
                bx(
                    b"----",
                    &[
                        bx(b"mean", b"\0\0\0\0com.example"),
                        bx(b"name", b"\0\0\0\0x"),
                    ]
                    .concat(),
                ),
            ),
            (
                "repeated",
                [item(b"\xa9nam", 1, b"a"), item(b"\xa9nam", 1, b"b")].concat(),
            ),
            ("binary title", item(b"\xa9nam", 0, b"a")),
            ("control character", item(b"\xa9nam", 1, b"a\x07")),
            ("locale", locale),
            ("short track", item(b"trkn", 0, &[0, 0, 0, 3])),
            (
                "two values",
                bx(
                    b"\xa9nam",
                    &[
                        bx(b"data", b"\0\0\0\x01\0\0\0\0a"),
                        bx(b"data", b"\0\0\0\x01\0\0\0\0b"),
                    ]
                    .concat(),
                ),
            ),
        ] {
            assert!(
                check_m4a(&m4a_file(Some(meta(&items)), None)).is_err(),
                "{case}"
            );
        }
    }
    #[test]
    fn opus_comments_are_only_engine_text_fields() {
        let head = b"OpusHead\x01\x01\0\0\0\0\0\0\0\0\0";
        let file =
            |packet: &[u8]| [page(7, &[head]), page(7, &[packet]), page(7, &[&[1; 30]])].concat();
        check_ogg(&file(&tags(&[
            "title=Épisode One",
            "ALBUMARTIST=A",
            "TRACKNUMBER=3",
        ])))
        .unwrap();
        let too_many: Vec<String> = (0..=TAGS.len()).map(|i| format!("title{i}=x")).collect();
        let too_many: Vec<&str> = too_many.iter().map(String::as_str).collect();
        for (case, packet) in [
            ("picture", tags(&["METADATA_BLOCK_PICTURE=AAAA"])),
            ("unknown field", tags(&["LYRICS=la"])),
            ("encoder", tags(&["encoder=Lavf"])),
            ("repeated field", tags(&["title=a", "TITLE=b"])),
            ("no separator", tags(&["title"])),
            ("control character", tags(&["title=a\nb"])),
            ("empty value", tags(&["title="])),
            ("too many", tags(&too_many)),
            (
                "data after the list",
                [tags(&["title=a"]), b"\x01SMUGGLED".to_vec()].concat(),
            ),
            ("short", b"OpusTags\x06\0\0\0ffm".to_vec()),
        ] {
            assert!(check_ogg(&file(&packet)).is_err(), "{case}");
        }
    }
}
