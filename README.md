# Open Media Downloader engine

OMD discovers media through source plugins and turns reviewed selections into
portable files you control. This project owns the local service, downloads,
permissions, accounts, storage, subscriptions, CLI and MCP server. It has no
built-in sources, reader or player.

The desktop UI (`open-media-downloader-desktop`) and a worked-example podcast
source plugin ([`omd-source-nasa-podcast`](https://github.com/NorthWolfLabs/omd-source-nasa-podcast)) are separate projects. Neither is
required to build this engine, and the example plugin is not part of any release.
The provider SDK and public client SDK live here and are consumed as versioned
packages by those projects.

## Start here

- **Users:** [use the engine or desktop](docs/getting-started.md).
- **Agents:** [MCP setup and workflows](docs/mcp.md). The server includes plugin
  authoring guidance and the exact matching SDK contracts.
- **Developers:** [build and test](docs/v2-development.md), then read the
  [architecture and project boundaries](docs/architecture.md).
- **Plugin authors:** [provider SDK](sdk/provider/README.md) and the
  [authoring skill](.agents/skills/omd-plugin-authoring/SKILL.md).
- **Release maintainers:** [source exports](docs/source-distribution.md),
  [native materials](docs/materials-contract.md), [macOS signing](docs/macos-signing.md)
  and [Windows signing](docs/windows-signing.md).

## Run from source

Use Rust 1.93.0. Node 24.20.0, Vite+ 0.2.8 and UV are development/build tools;
installed users do not need them. Put build output and test profiles outside
source directories when preparing a release.

```sh
cargo build --locked --workspace --bins
cargo run --locked --bin omd-engine -- --profile /absolute/private/omd-profile
```

In another terminal:

```sh
cargo run --locked --bin omd -- --instance /absolute/private/omd-profile/instance.json status
```

The service listens on literal loopback and writes its endpoint and private
bearer authorities to that profile. Keep the whole profile private. This minimal
source launch does not include managed media/browser tools: use the verified
runtime manifests described in the developer guide for acquisition/sign-in.

For a trusted local agent, run the native MCP executable against the same profile:

```sh
cargo run --locked --bin omd-mcp -- --instance /absolute/private/omd-profile/instance.json --access full --print-config
```

The printed host configuration contains paths, not tokens. The running MCP server
exposes 95 engine tools plus a guidance tool, including plugin review/install,
browse/search, downloads and subscriptions. It never silently starts an engine.

## Source map

| Directory | Responsibility |
| --- | --- |
| `crates/` | Engine domains, persistence, workers, service, CLI and MCP |
| `sdk/provider/` | Sandboxed TypeScript source-plugin SDK and tooling |
| `sdk/client/` | Versioned public HTTP client SDK |
| `schemas/v2/` | Generated domain and OpenAPI contracts |
| `adapters/browser/` | Managed browser broker adapter |
| `tests/` | Synthetic providers and public contract checks |
| `scripts/`, `distribution/` | Explicit build, source, runtime and materials packaging |

Project code is [MIT licensed](LICENSE). Dependencies and managed runtime tools
retain their own terms. Source preparation and passing tests do not establish
signed installer or native-platform release acceptance. Nothing is published
by the build/export commands in this repository.
