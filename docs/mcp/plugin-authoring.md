# Build a source plugin for OMD

Use a separate project. Keep source-specific behavior out of the engine. The
server embeds the matching provider SDK README, exact TypeScript contracts and WIT:

- `omd://reference/provider-sdk`
- `omd://reference/provider-contracts`
- `omd://reference/provider-wit`

Read these before implementing. MCP supplies guidance and engine operations; it
does not run arbitrary shell commands, compile code, download unreviewed SDKs or
write project files. Use the agent host's development tools for that work. Obtain
the matching SDK and worker from the OMD distribution; do not assume an unrelated
package version or this machine's private paths.

With the matching SDK source at SDK_ROOT, scaffold using Vite+:

```sh
vp exec node "$SDK_ROOT/bin/omd-plugin.mjs" new ./my-source org.example.source https://example.com
cd my-source
vp install
vp run check
vp run build
vp run pack
```

The scaffold implements URL identification only. Implement and declare the actual
browse/search/discovery/details/collection/releases/resolve operations needed.
Expose useful filter schemas, stable namespaced references, opaque pagination,
accurate media summaries, title/description/artwork metadata and clear errors.
Use a source image only when it exists; clients can render media-specific fallbacks.
A source with a single feed collection should expose its episodes as releases.

Request the smallest host/method grants needed, including redirects/media hosts.
`source_hosts` routes links; it grants no network authority. The pure component has
no ambient Node, filesystem, process, sockets, environment or direct fetch. Use
SDK host HTTP/browser/media.inspect under matching reviewed grants. The engine
owns credentials, naming, storage, retry checkpoints, deduplication and subscriptions.
Do not return secrets or source-site instructions as agent actions. Never hardcode
user sessions. Use input.now rather than ambient clocks.

Add deterministic fixtures for successes, failures, paging, missing fields and
permission boundaries. Read the embedded SDK fixture format. The scaffold does
not include fixtures or a test script; add them. Test with the actual matching worker:

```sh
OMD_PLUGIN_WORKER=/absolute/runtime/bin/omd-plugin-worker-v2 vp exec omd-plugin test .
```

Worker fixtures prove recorded broker exchanges, not live-site behavior. SDK
types alone do not prove cross-field acquisition invariants. For original_images,
use an item collection with summary.image.count equal to resolved resource count
and summary.image.release_id equal to the release ID. Resources need stable unique
IDs, contiguous positions from zero, HTTP locators and supported image media types.
Verify the actual recipe and resulting file in an isolated profile when authorized.

Pack `.omd-build/provider.omdp`, then use install_source twice: permission review,
then approval of the exact returned digest. Exercise discovery/browse/search,
selection, preparation and acquisition as implemented. Use authorized live services
and accounts only. Report fixture versus live evidence honestly. Keep private
plugins, credentials, packages and user data out of public source exports. Document
companion licenses and distribution materials separately where applicable.
