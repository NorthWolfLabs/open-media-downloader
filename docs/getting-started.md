# Use OMD

OMD needs a source plugin to discover or download content. There is no bundled
catalog or plugin marketplace: you choose which source plugins to install, and
each plugin is a separate package with its own author and terms. A small podcast
plugin is maintained separately as a worked example for plugin authors; it is not
included with OMD releases.

## Desktop workflow

The separate desktop app starts its packaged engine and manages its connection.
Choose a destination, then import a trusted plugin package in Sources. Read the
permission review before approving it. OMD binds approval to the exact reviewed
package bytes; changed code or grants require a new review.

Use Explore to browse the sources you installed or search using their supported
filters. Open an item to inspect its releases. Choose a destination and output
format, review the selected files, then download. Source capabilities differ:
one podcast feed may expose one show containing hundreds of episodes.

Each item is saved in its own folder. A folder name gets a `[copy …]` suffix only
when that name is already taken, for example by a new version of an earlier
download or by another output format of the same item. Names that differ only in
letter case or Unicode form (such as a precomposed and a decomposed "é") count
as the same name.

MP4 video downloads prefer H.264, HEVC or AV1 video. They use VP9 video only when
the source offers no other MP4 video known to fit the chosen maximum resolution,
because many players, including QuickTime and Photos, do not play VP9 in MP4. WebM and MKV downloads can keep VP9 video.
When OMD cannot verify a finished download's container or streams, it does
not save the file. Trying again would fetch the same file, so OMD asks you to
prepare the item again and choose another format.

Audio downloads (MP3, M4A, Opus) contain one audio stream, a few plain-text tags
and, for MP3 and M4A, at most one still cover picture. OMD chooses the source audio
and converts it to the chosen format only when its codec and container differ; a
file extension alone does not decide this. OMD then rebuilds every audio file
before saving it: it copies the audio packets unchanged into a new file and writes
back only:
- the source's title, artist, album, album artist, composer, genre, date, track,
  disc and copyright tags, when each is plain text of at most 1024 bytes;
- only where the source has no usable title, artist or date tag: the title from
  the release title, the artist from the release's creators or else, for a
  channel, the channel title (your edited titles take the place of the
  source's), and the date from the release's published time when it is a valid
  calendar date, as YYYY-MM-DD. OMD never replaces a tag the source has and never adds an album or
  album artist;
- one JPEG or PNG cover of at most 4096 pixels per side, preferring the one marked
  as the front cover. OMD decodes the picture and encodes it again, so only its
  pixels are kept: no EXIF, colour profile, animation or hidden bytes.

Everything else is left out: other pictures (GIF, WebP and other formats, or a
picture that does not decode), comments, lyrics, private and other tags, chapters
and attachments. Opus files keep their tags but no cover, because the Ogg writer
cannot store one. A runtime whose FFmpeg has no image codecs removes every cover.
OMD checks that the audio packets are identical before and after. It also checks
the file's structure:
- an MP3 is MPEG audio frames, after at most OMD's own ID3v2.4 tag holding only
  those text frames and one picture;
- an M4A has one audio track, a metadata list with only those items, and an AAC
  setup with nothing after its fields;
- an Opus file is one Ogg stream whose comments are only those tags, with an Opus
  header with nothing after its fields;
- a cover is a baseline JPEG or a PNG exactly as the encoder writes it, with no
  metadata segments or chunks and nothing after its end.

A cover that fails these checks is dropped and the file is rebuilt without it.
Data after the last MP3 audio frame, such as a trailing tag, is cut. If an MP3
has data between its audio frames (for example a tag stitched into the middle), or
any other check fails, the download fails and no file is saved. Retrying would
fail the same way, so OMD does not offer it. A real video track in an audio
download is also an error. Title and other details are also saved next to the file
in `metadata.json`.

Verification streams its audio packet lists through temporary files, so memory use
does not grow with length. It covers up to 40 million packets: roughly 290 hours of
MP3, 250 hours of AAC or 220 hours of Opus. While it runs it needs about 45 bytes
of temporary disk space per packet (about 6 MB per hour of MP3) for each of up to
three lists. A longer file is not saved, and OMD says that it is too long to verify.

Two kinds of data can't be checked without re-encoding the audio:
- Bytes hidden inside the audio frames themselves (MP3 ancillary data, for
  example) count as audio.
- AAC setups this check does not model (a program config element, or
  error-resilient object types) are kept as they are. Trailing zero bytes are
  accepted, because some services pad the AAC setup with them.

Subscriptions can notify you about new matches or download them automatically.
Choose that behavior explicitly. Downloads, history and destination-file operations
remain engine-owned. A preview/preparation does not itself start a download.

Keep background operation off unless you want work to continue after the
desktop app closes: with it off, quitting the app stops OMD, and unfinished
downloads continue the next time you open it. Settings explains its startup
integration. Accounts are optional and
source-specific, and many sources need none.

## Engine and CLI

For a headless Ubuntu 24.04 installation, follow the [Linux runtime guide](linux-runtime.md)
first; it installs the scoped guardian policy. MCP clients attaching to an installed
desktop engine do not need a second engine installation.

Start a packaged runtime with its supplied launcher and a private profile path,
or follow the source-build instructions in the root README. The profile contains
private state and `instance.json`; never share it or put it in Git. The CLI attaches
to an already running engine:

```sh
omd --instance /absolute/private/omd-profile/instance.json status
omd --instance /absolute/private/omd-profile/instance.json sources
omd --instance /absolute/private/omd-profile/instance.json install /absolute/my-source.omdp
```

The last command returns a permission review. After inspecting it, repeat with
`--approve` and the **engine-returned approval digest**, not the file's SHA-256.
Use `omd --help` and each subcommand's `--help` for exact options. Account imports
use stdin rather than secret command-line arguments.

Each `omd` command holds a client lease only while it runs, and asks the
engine to finish its downloads after it leaves. With background operation off,
an engine that no client holds stops about a minute after it starts. When the
last client to leave was the CLI or an MCP server, the engine stays for about a
minute after that client left, so separate `omd` commands keep reaching the same
engine, and it first finishes every queued and running download: a download
submitted from the CLI finishes, then the engine stops at its next check (within
seconds) once that minute has passed. Downloads queued behind a
destination's storage operation, and paused or failed downloads, do not keep it
running; they continue the next time the engine starts. When the desktop app is
the last to leave, the engine stops without waiting, as quitting the app
intends.

## Agents and troubleshooting

[MCP](mcp.md) provides the same engine workflows through typed tools, along with
built-in operating and plugin-authoring guides. Use `get_guidance` with
`{"topic":"workflows"}` to start. Restart an MCP connection after an engine restart.

If a source is missing, import its package. If permissions are missing, review the
specific grant rather than granting unrelated access. If a destination is offline
or unavailable, reconnect it and inspect the engine's recovery action. If a source
changes its feed or hosts, its plugin may need an update. The [OpenAPI contract](../schemas/v2/openapi.json)
is authoritative for programmatic callers; do not invent endpoints or filters.

## Updating the engine runtime

Stop the engine before replacing a runtime directory, including when background
operation is enabled:

```sh
omd-engine --profile /absolute/private-profile --prepare-update
```

This authenticates to that profile's engine, suspends only its startup registration
and waits for shutdown. A missing profile is left untouched. Do not replace files
if this command fails. Install all runtime binaries from the same release together,
then start the new engine with the same profile. Settings, sources, subscriptions,
history and downloaded files are retained. The background preference is retained;
the next interactive launch restores its startup registration. `--identity` prints
the executable's version, API and SHA-256 without opening a profile.

Before applying pending database migrations, the engine saves a private consistent
`pre-migration-…sqlite3` snapshot beside the database, including committed WAL data.
It refuses databases with newer or unknown migrations. The snapshot is a database
recovery aid, not a backup of credentials, plugins or downloaded media. Keep a full
profile backup before upgrading; never force a downgrade by editing
migration records or replacing a running database.
