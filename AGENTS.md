# Working on the OMD engine

Read README.md, docs/architecture.md and docs/v2-development.md first. For source
plugins use .agents/skills/omd-plugin-authoring/SKILL.md and the matching SDK.

- Keep site-specific behavior in separate plugin projects. Keep UI implementation
  in the separate desktop project. Expose engine behavior through its typed public
  HTTP contract; update generated SDK/MCP contracts when changing that contract.
- Use UV for Python and Vite+ for JavaScript/TypeScript. Respect the checked-in
  toolchain pins and lockfiles. Build synthetic provider components before Rust
  acceptance tests; the developer guide gives the order.
- Write agent reports, screenshots, logs and scratch output under
  .local/agent-reports/<task>/ or an explicit directory outside the project.
  Maintained documentation belongs in docs/. Do not add local evidence to source.
- Never commit profiles, instance authorities, accounts, cookies, downloaded media,
  private plugins or signing credentials. Do not point tests at a user's profile.
- Keep approved vendor assets and the snapshot WASM build input. Do not treat
  license/source materials or immutable release evidence as disposable caches.
- Each project owns its public source policy. Export only this project using
  scripts/export-public-source.py; another checkout is not a source-export input.
- Run checks appropriate to the change. Native/platform acceptance is separate
  from fixture, emulated and CI results; describe those limits accurately.
