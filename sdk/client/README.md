# OMD engine client

The SDK ships `openapi.json`, generated operation types, and a typed HTTP client.
Its normal client is generated from the same authorization table as the engine;
installation, activation and shutdown require a separate administrative client.

```ts
import {EngineClient} from '@northwolf/omd-engine-client';
const engine = new EngineClient(connection); // private profile descriptor
const lease = await engine.attach();
const {data} = await engine.api.GET('/v2/groups', {
  params: {query: {q: 'series', limit: 100}}
});
await engine.api.POST('/v2/groups/{id}/{action}', {
  params: {path: {id: 'group-id', action: 'pause'}}
});
```

Read the per-profile `instance.json` through your native shell adapter. Keep its
tokens in memory, never browser storage or URLs. Construct `EngineClient` with
the loopback endpoint and normal token. Supply `admin_token` only to a trusted
shell that offers explicit source-package permission review. Administrative
operations require `engine.administrativeApi()`; they are absent from `engine.api`.
Engine errors throw `EngineError` with status, code, retryability and recovery actions.

Call `attach()` and heartbeat at the returned interval. Detach when your client
closes. With background operation disabled, the last client's departure allows
the engine to checkpoint and stop; unfinished downloads continue at its next
start. A client that submits downloads and then leaves, such as a command-line
tool or an agent, calls `attach({finish_downloads: true})` instead: when it is
the last client to leave, the engine first finishes queued and running
downloads. A restarted engine publishes a new endpoint and tokens; reopen its
instance file instead of retrying obsolete credentials.

For event synchronization, read `/v2/service` to obtain an event cursor **before**
loading resource lists, then subscribe from that cursor. Replayed invalidations
make changes during those reads visible. `events()` handles bearer headers,
Last-Event-ID, framing, and bounded reconnect backoff. When `onResync` runs, take
a fresh cursor and reload the relevant snapshots before opening a new stream.
The server retains at least the latest 100,000 events; expired or impossible
cursors return HTTP 409 `resync_required` rather than silently skipping changes.

Every unbounded response is paginated. Continue with `next_cursor` until null;
retain search/filter parameters on subsequent pages. `createApi(connection)` is
the standalone typed transport; `createAdministrativeApi(connection)` is its
explicit privileged counterpart. Both use HTTP only and reject off-profile
non-loopback endpoints and redirects.

Folder selection and external opening belong in native shell adapters; direct
database access and local file mutations do not. This SDK is an attachment
contract, not evidence that all packaged release platforms passed acceptance.
