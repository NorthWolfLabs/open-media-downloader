# OMD TypeScript provider SDK

This is the single v2 source-authoring path. Provider code compiles to a pure
ComponentizeJS component; the engine executes it in a bounded Wasmtime worker.
Node is a build dependency for authors, never a plugin execution fallback.

```sh
omd-plugin new ./my-source org.example.source https://example.com
omd-plugin check ./my-source
omd-plugin build ./my-source
omd-plugin watch ./my-source
omd-plugin pack ./my-source
```

Install a versioned SDK tarball with Vite+ when developing against an unpublished
release. The source repository itself does not need an engine sibling checkout.
The scaffold implements URL identification only. Add `search`, `browse`,
`collection`, `releases`, and `resolve` as needed, and declare only implemented
operations in the manifest. Unsupported operations produce a structured error.

`http.json`, `http.text`, and `http.html` use named manifest network grants.
HTML parsing and CSS selectors are bundled, with no page scripts or DOM globals.
Return stable source and page identities; a locator URL is not a filename.
The engine owns names, files, retry checkpoints, subscriptions, and deduplication.
Use `input.now` rather than ambient clocks. Host processes, files, sockets,
environment variables, and direct `fetch` are unavailable to a pure component.

Types are generated from the Rust schema, and the build checks provider types
before compilation. Author errors become structured source failures. The SDK
rejects common ambient APIs and Node imports with build-time diagnostics.

Unexpected author errors return a bounded generic error to application clients.
The actual Wasmtime fixture runner additionally returns `diagnostics`, containing
TypeScript `source`, `line`, and `column` locations. `omd-plugin test` includes
these locations when an expected-success fixture fails. Expected `SourceError`
failures retain their explicit recovery message and actions.

Maps are local build artifacts, verified against both the component hash and map
hash in `.omd-build/build.json`. A missing or mismatched map yields no locations;
it never points at stale source. Maps contain no source text, symbol names or
absolute developer paths, and packages do not require source maps at runtime.
Only numeric generated locations leave the component. Unexpected exception text
and raw stacks are excluded because they can contain source response contents.

The `.omdp` format is `OMDP2\0`, a little-endian u32 manifest length, UTF-8 manifest
JSON, and the component bytes. It contains no archive paths to extract. Installation
reviews the digest of the normalized manifest and component together. New bytes
require new approval even when the version string is unchanged.

## Current acceptance limits

The conformance component proves broker imports, HTML extraction, author errors,
and execution limits. SDK tests cover scaffolding and ambient-API diagnostics.
Fixture recording/redaction, operation tracing, and source-mapped author errors
are included. ComponentizeJS 0.19.3 and Jco 1.17.9 are pinned because
the newer toolchain pulled in vulnerable optional archive-extraction dependencies.
The bundled WASI snapshot transformer fixes build-time entropy before Wizer runs.
Tests reproduce identical components and packages in separate directories, and
the transformed components pass actual Wasmtime conformance. See
[build-tool/README.md](build-tool/README.md) for the pinned transformation and
remaining cross-platform reproducibility checks. Authors do not need Rust.

### Test the real component with fixtures

`omd-plugin test .` builds the source and replays every JSON file in `fixtures/`
through the OMD Wasmtime worker. Set `OMD_PLUGIN_WORKER` to the worker executable
from the engine distribution when it is not on PATH. No Cargo toolchain is
needed by the author, and there is no live-network fallback in fixture runs.

A fixture has `input` (a source operation), `exchanges` (ordered
`{operation, request, response}` broker calls), and either `result` (the exact
normalized output) or `error` (an expected source error code). The worker also
checks successful outputs against the same Rust contract used by the engine.
Unexpected network authority, calls, missing responses, and oversized or stalled
operations fail the test. For generated long-feed cases, import `harness` from
`@northwolf/omd-provider/testing`, build once, and call
`await runtime.invoke(input, (operation, request) => fixtureResponse)`.
The return value includes the structured broker trace and source result.

For example, an identify-only fixture in `fixtures/identify.json` can contain:

```json
{
  "input": {"operation": "identify", "url": "https://example.com/collection/demo"},
  "exchanges": [],
  "result": {
    "kind": "collection",
    "reference": {"id": "demo", "provider": "org.example.source"}
  }
}
```

Make the expected result match your implementation. HTTP fixtures use broker
operation `http`. Its request includes `url`, `permission` (the grant ID),
`method`, `headers` and `body`; a successful response contains `status` and
`body`. For `http.json`, the response body is a JSON-encoded string, not an
object. Use the recording helper for exact exchanges, then independently check
the recorded result rather than assuming recorded behavior is correct.

The scaffold has no test script or fixtures. After adding fixtures, run
`OMD_PLUGIN_WORKER=/absolute/path/to/omd-plugin-worker-v2 vp exec omd-plugin test .`.
Installing build dependencies may require registry access even though fixture
execution makes no live source requests.

For the `original_images` acquisition recipe, return an `item` collection with
`summary.image.count` matching the resolved resource count and
`summary.image.release_id` matching the release reference ID. Resources require
unique stable IDs, contiguous zero-based positions, HTTP locators and supported
image media types. Passing worker fixtures does not establish that media bytes
can be acquired; verify a real acquisition separately when the task permits it.

Build commands own their compiler descendants and enforce time and output budgets.
Diagnostic capture preserves UTF-8 across pipe boundaries. On Unix, each build
uses an owned process group; on Windows 10+, the SDK uses Windows PowerShell to
create a kernel kill-on-close Job Object atomically with its child. There is no
fallback to an unowned Windows compiler process. These are build-time lifecycle
controls, separate from the engine's runtime plugin/native-helper confinement.
Windows execution evidence is tracked separately from the macOS authoring tests.

Scaffolding vendors an immutable copy of the exact installed SDK and references
that local archive. Run `vp install` in the new project. Authoring does not depend
on a sibling checkout or a registry publication of a development SDK version.

Conformance brokers can throw `new BrokerFailure(problem)` (from
`@northwolf/omd-provider/testing`) to exercise a real engine denial, expiration or
rate-limit response inside the component. Other callback exceptions remain test
failures. JSON fixtures accept an `error` object on a broker exchange.

`recordFixture(runtime, input, broker, output, {secrets})` executes the real
component and records the exchanges plus its result as a replayable fixture. Use
an engine-brokered recording callback; the runner provides no ambient live-network
fallback. Recording redacts authorization/cookie fields, token query parameters,
URL credentials, nested JSON credentials, and the explicit source-specific secret
values. Review recorded HTML before committing it: automatic redaction cannot
recognize every secret embedded in arbitrary markup. Files are created privately
and recording never overwrites an existing fixture.

## Managed media inspection

A source that declares `media_tools: true` can call
`media.inspect(url, cursor, pageSize)`. The engine runs its managed media tool
through the network broker, using the source's grants and account, and returns
`MediaInfo`. That is a fixed set of metadata fields. Formats, transport URLs,
headers, cookies, file paths and helper diagnostics are never included. The
engine uses the same generic tool options for every source and offers no way
to pass extractor-specific arguments.

- `pageSize` is 1–200. Pass `next_cursor` back unchanged to read the next page.
- Collection entries come from a flat listing: each one has only what the
  extractor reports without opening that item. An entry's raw tool `url` is
  never returned or turned into `webpage_url`, because it may be a signed media
  URL or contain credentials. Ordinary flat entries lack `formats`, so they
  also lack `accessible`; when an extractor supplies formats, the engine derives
  `accessible` from those reported formats as it does for a single item.
- Your source owns navigation. Build an entry's page URL from its `id` and the
  URL you inspected. Inspecting one item returns `webpage_url` when its
  extractor reports one.
- If a site shows dates only on item pages, flat entries may have no
  `timestamp` or `upload_date`. Inspect those items one at a time, read them
  with your own granted requests, or leave `published_at` empty.

Earlier development engines rebuilt entry page URLs and requested approximate
listing dates for one site. Both site-specific fallbacks were removed; sources
that relied on them must follow the steps above.

## Bounded source browsers and isolated sign-in

Use `http.html` for pages that work without scripts. A source that requires rendered
content may declare `browser: true` and use a scoped browser:

```ts
import {withBrowser} from '@northwolf/omd-provider';
const page = await withBrowser(url, async browser => {
  await browser.wait('.chapter-list');
  return browser.snapshot();
});
```

The engine owns the pinned Node/Playwright/Chromium package, session lifetime,
network broker, file confinement and resource limits. The component receives only
bounded text/link snapshots. Check `truncated` before treating a snapshot as
complete. Navigation, waits and interactions use the same manifest grants as
HTTP requests; redirects, subresources, websockets and downloads cannot bypass
the broker. There is no arbitrary evaluation, process launch, cookie export or
ambient browser API. The scope closes on success and failure. Fixtures can replay
`browser.open`, `browser.action` and `browser.close` through the real component.

Interactive sign-in is a separate manifest capability:

```json
"sign_in": {
  "url": "https://source.example/account",
  "grants": [{
    "id": "identity", "hosts": ["identity.example"],
    "methods": ["GET", "POST"], "credential": true
  }]
}
```

Declare only additional identity hosts in `sign_in.grants`. These permissions are
reviewed during installation but are never available to source operations. A source
can offer sign-in with `browser: false`. The frontend attaches a client-owned
sign-in session; the engine exports approved source cookies directly into its OS
credential vault. Identity-provider cookies are discarded at completion. Neither
plugin results nor diagnostic logs receive credentials. Account selection and
expiration are managed by the engine; provider authors need no credential code.

Clients choose where the person signs in: the engine's isolated browser, or a
native window that uses the operating system's own web view (`window: "native"`).
Some sites reject automated browsers; a native window is an ordinary system web
view and passes those checks, but its page uses the normal network connection
instead of the broker. Either way the engine keeps only cookies, with their real
attributes, and page local storage for HTTPS origins covered by the source's
credential grants, then restores both before page scripts run in later source
browser sessions. Declare `completion_cookies` so a native window can finish by
itself; without them the person finishes by closing the window once signed in.

### Account connection preference (0.11.0)

A manifest may set `account_mode` to `browser`, `cookies`, or `header` to select
its initial connection method in the reference UI. This is a preference, not a
permission grant. `browser` requires `sign_in`; any explicit mode requires a
credential grant. The engine rejects unknown modes and incompatible declarations.
Omitting the field preserves manifest compatibility: the reference UI chooses
browser sign-in if declared, otherwise header import, irrespective of media tools.

Imports are saved without asserting authentication. Neither cookie names nor a
successful browse operation verify an imported account. There is no plugin-defined
import verification protocol in this version. Browser sign-in retains the existing
engine-owned, expiring completion check. `sign_in.completion_cookies` applies only
to that browser workflow. Hosts still come exclusively from credential grants;
this preference conveys no hosts or secrets. Independently maintained connectors
that previously relied on private UI dispatch must declare their preferred mode.

### Collection hint on resolve (0.12.0)

One release can be listed in several collections: search results, a playlist
and its own series, for example. When a person downloads releases selected from
a collection, the engine resolves each release again and refuses the download
with `selection_changed` unless the resolved release's `collection` is the
collection it was listed under.

To be told that collection, declare the `collection_hint` capability in
`omd-plugin.json` next to `resolve`:

```json
"capabilities": ["search", "collection", "releases", "resolve", "collection_hint"]
```

On those calls `resolve` then receives `input.collection_hint`, the collection
the release was listed under. Declaring the capability also applies the check to
subscriptions that download automatically: the release must resolve under the
followed collection (a release that resolves as its own `item` collection, an
image post for example, keeps that identity). Sources that don't declare it keep
the earlier subscription behavior and may file a followed release elsewhere. When a download refreshes expired transport
locations, it is the collection of the approved plan, and the engine requires the
same collection back. If the release still belongs to the hinted collection,
return that collection as both `release.collection` and `collection.reference`,
with its own title and canonical URL:

```ts
resolve(input) {
  const item = loadItem(input.reference!);
  const hint = input.collection_hint;
  const parent = hint && listsItem(hint, item) ? listedCollection(hint) : seriesOf(item);
  return {release: {...toRelease(item), collection: parent.reference},
    collection: parent, resources: toResources(item), expires_at: null};
}
```

Keep release IDs stable. Don't encode the listed collection into a release ID:
that breaks duplicate detection. The hint grants nothing. It is engine-owned,
absent on every other call (including direct preparations and client-requested
operations), and the engine still requires exactly the listed collection back.

A source that does not declare the capability never receives the field: its
requests are byte-for-byte what earlier engines sent, so a source that validates
its input against the earlier closed request schema keeps working. Engines
before the capability existed refuse to install a manifest that declares it. The
fixture harness refuses a fixture `input` with `collection_hint` unless the
manifest declares the capability, and plugin workers from earlier engines reject
that field, so test it with the worker from a matching engine.
