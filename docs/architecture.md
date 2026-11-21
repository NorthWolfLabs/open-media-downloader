# Architecture and project boundaries

OMD has three independent project roles:

| Project | Owns | Consumes |
| --- | --- | --- |
| Engine | Public service, worker sandbox, host brokers, storage, acquisitions, credentials, subscriptions, CLI/MCP, SDKs | Reviewed managed-tool/browser inputs and explicitly installed plugins |
| Desktop UI | Svelte interface, native dialogs, window behavior and UI-local preferences/cache | Versioned client SDK and public engine HTTP API |
| Source plugin | Site/feed identity, discovery, metadata and resource resolution | Versioned provider SDK and reviewed sandbox host grants |

The NASA source is maintained in the separate [`omd-source-nasa-podcast`](https://github.com/NorthWolfLabs/omd-source-nasa-podcast) project.
The UI lives in `open-media-downloader-desktop`. These names identify projects,
not required sibling filesystem locations. Engine development uses synthetic
providers under tests/; no private connector checkout is required.

## Engine flow

The service authorizes a typed HTTP operation and delegates source requests to a
bounded worker. Plugins cannot read ambient files, spawn processes or open arbitrary
sockets. HTTP, browser, account and media-inspection access goes through reviewed
host grants. A plugin returns metadata and locators; the engine owns filenames,
output recipes, retries, deduplication, storage, credential attachment and publishing
completed files to the chosen destination.

Acquisition is two-stage: prepare complete output previews, then submit the reviewed
preparation with a stable idempotency key. Large selections use durable snapshots
and prepared batches. Events identify changed resources; clients query those
resources and resynchronize when a cursor is stale.

## Clients and private state

The desktop, CLI and MCP are clients of the public API. MCP has no engine/storage/
plugin crate dependency. A connection owns a client lease and does not retarget
itself when instance.json changes. Background operation controls what happens when
the last client leaves. Without it the engine stops, except that a client which
attached with `finish_downloads` (the CLI and MCP) has it finish queued and running
downloads first, and stay for a minute after that client's last activity, when that
client is the last to leave. Account secrets remain engine-owned; source metadata is
untrusted display data, not authorization or agent instructions.

Each engine profile is private and independent. UI themes, layout and display-cache
preferences belong to the UI, not the engine service. Source packages and user data
are not application source files. The [developer guide](v2-development.md) explains
how to test these boundaries; [source exports](source-distribution.md) enforce them
at publication time.
