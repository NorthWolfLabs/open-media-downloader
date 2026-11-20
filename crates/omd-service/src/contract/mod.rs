//! Operation schemas and authorization are exported together. Adding a route
//! without a shape fails contract generation instead of publishing an empty schema.
pub mod models;
use super::*;
use models::*;
use schemars::JsonSchema;
#[derive(Default)]
struct Schemas(serde_json::Map<String, Value>);
impl Schemas {
    fn schema<T: JsonSchema>(&mut self) -> Value {
        let mut schema =
            serde_json::to_value(schemars::schema_for!(T)).expect("Rust schema serializes");
        let definitions = schema.as_object_mut().unwrap().remove("$defs");
        schema.as_object_mut().unwrap().remove("$schema");
        fn references(value: &mut Value) {
            match value {
                Value::Object(map) => {
                    if let Some(Value::String(reference)) = map.get_mut("$ref") {
                        *reference = reference.replace("#/$defs/", "#/components/schemas/");
                    }
                    for value in map.values_mut() {
                        references(value);
                    }
                }
                Value::Array(items) => {
                    for value in items {
                        references(value);
                    }
                }
                _ => {}
            }
        }
        if let Some(Value::Object(definitions)) = definitions {
            for (name, mut definition) in definitions {
                references(&mut definition);
                self.insert(name, definition);
            }
        }
        references(&mut schema);
        let name = T::schema_name().into_owned();
        self.insert(name.clone(), schema);
        json!({"$ref":format!("#/components/schemas/{name}")})
    }
    fn insert(&mut self, name: String, mut schema: Value) {
        // Root schemas have an informational title that nested definitions omit.
        if let Some(object) = schema.as_object_mut() {
            object.remove("title");
        }
        if let Some(previous) = self.0.get(&name) {
            assert_eq!(previous, &schema, "Conflicting schema name: {name}");
        } else {
            self.0.insert(name, schema);
        }
    }
    fn query<T: JsonSchema>(&mut self) -> Vec<Value> {
        self.schema::<T>();
        let schema = &self.0[T::schema_name().as_ref()];
        let required = schema["required"].as_array().cloned().unwrap_or_default();
        schema["properties"].as_object().unwrap().iter().map(|(name,value)|json!({"name":name,"in":"query","required":required.contains(&json!(name)),"schema":value})).collect()
    }
}
struct Shape {
    id: &'static str,
    body: Option<Value>,
    response: Value,
    query: Vec<Value>,
    actions: Option<&'static [&'static str]>,
    binary: bool,
    events: bool,
}
fn shape(s: &mut Schemas, method: &str, path: &str) -> Shape {
    macro_rules! response {
        ($id:literal,$ty:ty) => {
            Shape {
                id: $id,
                body: None,
                response: s.schema::<$ty>(),
                query: vec![],
                actions: None,
                binary: false,
                events: false,
            }
        };
    }
    macro_rules! body {
        ($id:literal,$request:ty,$response:ty) => {{
            let mut value = response!($id, $response);
            value.body = Some(s.schema::<$request>());
            value
        }};
    }
    macro_rules! page {
        ($id:literal,$ty:ty) => {{
            let mut value = response!($id, Page<$ty>);
            value.query = s.query::<List>();
            value
        }};
    }
    macro_rules! action {($id:literal,$ty:ty,$($action:literal),+)=>{{let mut value=response!($id,$ty);value.actions=Some(&[$($action),+]);value}};}
    match (method, path) {
        ("GET", "/v2/browser-tools/status") => {
            response!("getBrowserToolStatus", browsers::BrowserStatus)
        }
        ("GET", "/v2/browser-tools") => page!("listBrowserTools", omd_browser::packages::Installed),
        ("GET", "/v2/browser-tools/{id}") => {
            response!("getBrowserTool", omd_browser::packages::Installed)
        }
        ("POST", "/v2/browser-tools/install") => body!(
            "installBrowserTools",
            browsers::InstallBrowser,
            browsers::BrowserInstallation
        ),
        ("POST", "/v2/browser-tools/{id}/activate") => {
            response!("activateBrowserTools", omd_browser::packages::Installed)
        }
        ("POST", "/v2/browser-tools/{id}/remove") => body!(
            "removeBrowserTools",
            browsers::RemoveBrowser,
            browsers::BrowserRemoval
        ),
        ("POST", "/v2/browser-tools/{id}/cleanup") => {
            response!("retryBrowserToolCleanup", omd_browser::packages::Installed)
        }
        ("POST", "/v2/sources/{id}/sign-ins") => body!(
            "startSourceSignIn",
            browsers::StartSignIn,
            browsers::SignInSession
        ),
        ("POST", "/v2/sign-ins/{id}/actions") => body!(
            "interactWithSignIn",
            browsers::SignInAction,
            browsers::SignInReply
        ),
        ("POST", "/v2/sign-ins/{id}/status") => body!(
            "sourceSignInStatus",
            browsers::SignInOwner,
            browsers::SignInReply
        ),
        ("POST", "/v2/sign-ins/{id}/complete") => {
            body!("completeSourceSignIn", browsers::SignInOwner, AccountSaved)
        }
        ("POST", "/v2/sign-ins/{id}/close") => body!(
            "closeSourceSignIn",
            browsers::SignInOwner,
            browsers::SignInClosed
        ),
        ("GET", "/v2/tools") => page!("listToolSets", omd_tools::Installed),
        ("GET", "/v2/tools/status") => response!("getToolStatus", tools::Status),
        ("GET", "/v2/tools/{id}") => response!("getToolSet", omd_tools::Installed),
        ("POST", "/v2/tools/install") => {
            body!("installToolSet", tools::Install, tools::Installation)
        }
        ("POST", "/v2/tools/{id}/activate") => response!("activateToolSet", omd_tools::Installed),
        ("POST", "/v2/tools/{id}/remove") => body!("removeToolSet", tools::Remove, tools::Removal),
        ("POST", "/v2/tools/{id}/retry-cleanup") => {
            response!("retryToolCleanup", omd_tools::Installed)
        }
        ("GET", "/v2/notifications") => {
            response!("getNotificationStatus", omd_notifications::Status)
        }
        ("PUT", "/v2/notifications") => body!(
            "configureNotifications",
            omd_notifications::Settings,
            omd_notifications::Status
        ),
        ("POST", "/v2/notifications/test") => {
            response!("testNotification", notifications::Accepted)
        }
        ("GET", "/v2/notifications/history") => {
            page!("listNotificationHistory", omd_notifications::Batch)
        }
        ("POST", "/v2/notifications/history/{id}/{action}") => action!(
            "controlNotification",
            omd_notifications::Status,
            "retry",
            "dismiss"
        ),
        ("GET", "/v2/openapi.json") => {
            let mut value = response!("getContract", serde_json::Value);
            value.response =
                json!({"type":"object","description":"The OpenAPI 3.1 document for this service."});
            value
        }
        ("GET", "/v2/operations") => response!("listOperations", Vec<Operation>),
        ("GET", "/v2/service") => response!("getService", Service),
        ("GET", "/v2/summary") => response!("getSummary", Summary),
        ("POST", "/v2/service/shutdown") => {
            let mut value = response!("shutdownService", Shutdown);
            value.query = s.query::<ShutdownQuery>();
            value
        }
        ("POST", "/v2/clients") => {
            let mut value = response!("attachClient", ClientLease);
            value.query = s.query::<AttachQuery>();
            value
        }
        ("POST", "/v2/clients/{id}") => response!("heartbeatClient", ClientHeartbeat),
        ("DELETE", "/v2/clients/{id}") => response!("detachClient", ClientDetached),
        ("GET", "/v2/sources") => page!("listSources", Source),
        ("POST", "/v2/sources/{id}/remove") => body!(
            "removeSource",
            source_removals::RemoveSource,
            source_removals::SourceRemovalResponse
        ),
        ("GET", "/v2/source-removals") => page!(
            "listSourceRemovals",
            omd_store::source_removals::SourceRemoval
        ),
        ("GET", "/v2/source-removals/{id}") => response!(
            "getSourceRemoval",
            omd_store::source_removals::SourceRemoval
        ),
        ("GET", "/v2/source-removals/{id}/entries") => page!(
            "listSourceRemovalEntries",
            omd_store::source_removals::SourceRemovalEntry
        ),
        ("POST", "/v2/source-removals/{id}/retry") => response!(
            "retrySourceRemoval",
            omd_store::source_removals::SourceRemoval
        ),
        ("POST", "/v2/sources/install") => body!("installSource", Install, InstallResult),
        ("POST", "/v2/sources/{id}/invoke") => {
            body!("invokeSource", SourceInvocation, SourceResult)
        }
        ("GET", "/v2/sources/{id}/versions") => page!("listSourceVersions", SourceVersion),
        ("POST", "/v2/sources/{id}/activate") => {
            body!("activateSource", ActivateSource, SourceActivated)
        }
        ("GET", "/v2/sources/{id}/artwork") => {
            let mut v = response!("getArtwork", String);
            v.query = s.query::<ArtworkQuery>();
            v.binary = true;
            v
        }
        ("GET", "/v2/sources/{id}/credentials") => page!("listSourceAccounts", SourceAccount),
        ("PUT", "/v2/sources/{id}/credentials/{profile}") => {
            body!("saveSourceAccount", SaveCredentials, AccountSaved)
        }
        ("DELETE", "/v2/sources/{id}/credentials/{profile}") => {
            response!("revokeSourceAccount", AccountRevoked)
        }
        ("GET", "/v2/source-catalog") => page!("listSourceCatalog", catalog::CatalogEntry),
        ("POST", "/v2/destinations/default") => response!("ensureDefaultDestination", Destination),
        ("GET", "/v2/destinations") => page!("listDestinations", Destination),
        ("POST", "/v2/destinations/{id}/check") => {
            response!("checkDestination", omd_storage::checks::DestinationCheck)
        }
        ("GET", "/v2/destination-checks") => page!(
            "listDestinationChecks",
            omd_storage::checks::DestinationCheck
        ),
        ("GET", "/v2/destination-checks/{id}") => {
            response!("getDestinationCheck", omd_storage::checks::DestinationCheck)
        }
        ("GET", "/v2/destination-checks/{id}/files") => page!(
            "listDestinationCheckFiles",
            omd_storage::checks::DestinationCheckFile
        ),
        ("POST", "/v2/destination-checks/{id}/{action}") => action!(
            "controlDestinationCheck",
            omd_storage::checks::DestinationCheck,
            "pause",
            "resume",
            "retry",
            "cancel"
        ),
        ("POST", "/v2/destinations") => body!("addDestination", AddDestination, Destination),
        ("GET", "/v2/destinations/{id}") => response!("getDestination", Destination),
        ("POST", "/v2/destinations/{id}/reconnect") => {
            body!("reconnectDestination", ReconnectDestination, Destination)
        }
        ("POST", "/v2/destinations/{id}/relocate") => body!(
            "relocateDestination",
            storage::Relocate,
            omd_storage::Operation
        ),
        ("GET", "/v2/relocations") => page!("listRelocations", omd_storage::Operation),
        ("GET", "/v2/relocations/{id}") => response!("getRelocation", omd_storage::Operation),
        ("GET", "/v2/relocations/{id}/files") => {
            page!("listRelocationFiles", omd_storage::FileEntry)
        }
        ("POST", "/v2/relocations/{id}/{action}") => action!(
            "controlRelocation",
            omd_storage::Operation,
            "start",
            "retry",
            "cancel"
        ),
        ("POST", "/v2/jobs/{id}/file-operations") => body!(
            "createFileOperation",
            maintenance::Request,
            omd_storage::maintenance::FileOperation
        ),
        ("GET", "/v2/file-operations") => page!(
            "listFileOperations",
            omd_storage::maintenance::FileOperation
        ),
        ("GET", "/v2/file-operations/{id}") => {
            response!("getFileOperation", omd_storage::maintenance::FileOperation)
        }
        ("GET", "/v2/file-operations/{id}/files") => page!(
            "listFileOperationEntries",
            omd_storage::maintenance::FileEntry
        ),
        ("POST", "/v2/file-operations/{id}/{action}") => action!(
            "controlFileOperation",
            omd_storage::maintenance::FileOperation,
            "start",
            "retry",
            "cancel"
        ),
        ("POST", "/v2/snapshots") => body!(
            "createSnapshot",
            selections::SnapshotRequest,
            omd_store::selections::SelectionTask
        ),
        ("GET", "/v2/selections") => page!("listSelections", omd_store::selections::SelectionTask),
        ("GET", "/v2/selections/{id}") => {
            response!("getSelection", omd_store::selections::SelectionTask)
        }
        ("POST", "/v2/selections/{id}/{action}") => action!(
            "controlSelection",
            omd_store::selections::SelectionTask,
            "retry",
            "cancel"
        ),
        ("GET", "/v2/snapshots/{id}/releases") => page!("listSnapshotReleases", Release),
        ("POST", "/v2/batches") => body!(
            "prepareBatch",
            selections::BatchRequest,
            omd_store::selections::SelectionTask
        ),
        ("GET", "/v2/batches/{id}/items") => page!("listBatchItems", Preview),
        ("POST", "/v2/preparations") => body!("prepareAcquisition", Prepare, Preparation),
        ("GET", "/v2/groups") => page!("listGroups", omd_store::groups::JobGroup),
        ("GET", "/v2/groups/{id}") => response!("getGroup", omd_store::groups::JobGroup),
        ("GET", "/v2/groups/{id}/jobs") => page!("listGroupJobs", Job),
        ("POST", "/v2/groups/{id}/{action}") => action!(
            "controlGroup",
            omd_store::groups::GroupAction,
            "pause",
            "cancel",
            "resume",
            "retry"
        ),
        ("POST", "/v2/acquisitions/status") => body!(
            "lookupAcquisitions",
            StatusLookup,
            Vec<omd_store::history::AcquisitionStatus>
        ),
        ("GET", "/v2/jobs") => page!("listJobs", Job),
        ("POST", "/v2/jobs") => body!("enqueueAcquisition", Enqueue, EnqueueResult),
        ("GET", "/v2/jobs/{id}") => response!("getJob", Job),
        ("GET", "/v2/jobs/{id}/files") => page!("listArtifacts", Artifact),
        ("GET", "/v2/jobs/{id}/files/{artifact}") => response!("getArtifact", Artifact),
        ("POST", "/v2/jobs/{id}/{action}") => {
            action!("controlJob", Job, "pause", "cancel", "resume", "retry")
        }
        ("GET", "/v2/settings") => response!("getSettings", Settings),
        ("PATCH", "/v2/settings") => body!("updateSettings", Preferences, Preferences),
        ("GET", "/v2/subscriptions") => page!("listSubscriptions", Subscription),
        ("POST", "/v2/subscriptions") => {
            body!("createSubscription", SubscribeRequest, Subscription)
        }
        ("PATCH", "/v2/subscriptions/{id}") => {
            body!("updateSubscription", SubscribeRequest, Subscription)
        }
        ("POST", "/v2/subscriptions/{id}/{action}") => action!(
            "controlSubscription",
            Subscription,
            "pause",
            "resume",
            "check"
        ),
        ("GET", "/v2/inbox") => page!("listInbox", InboxItem),
        ("POST", "/v2/inbox/{id}/{action}") => {
            action!("controlInboxItem", Updated, "read", "retry")
        }
        ("GET", "/v2/metadata/{kind}/{provider}") => {
            let mut v = response!("getMetadataOverride", MetadataOverride);
            v.query = s.query::<presentation::MetadataQuery>();
            v
        }
        ("PUT", "/v2/metadata/{kind}") => body!(
            "setMetadataOverride",
            presentation::MetadataWrite,
            MetadataOverride
        ),
        ("GET", "/v2/naming") => response!("getNamingTemplates", NamingTemplates),
        ("PUT", "/v2/naming") => body!("setNamingTemplates", NamingTemplates, NamingTemplates),
        ("GET", "/v2/events") => {
            let mut v = response!("followEvents", Event);
            v.query = s.query::<EventQuery>();
            v.events = true;
            v
        }
        _ => panic!("Operation is missing its public contract: {method} {path}"),
    }
}

pub fn document() -> Value {
    static DOCUMENT: std::sync::LazyLock<Value> = std::sync::LazyLock::new(build_document);
    DOCUMENT.clone()
}
fn build_document() -> Value {
    let mut schemas = Schemas::default();
    let problem = schemas.schema::<Problem>();
    let snapshot = schemas.schema::<selections::SnapshotRequest>();
    let batch = schemas.schema::<selections::BatchRequest>();
    let mut paths = serde_json::Map::<String, Value>::new();
    for operation in OPERATIONS {
        let mut shape = shape(&mut schemas, operation.method, operation.path);
        if operation.path != "/v2/jobs" && operation.path != "/v2/groups" {
            shape.query.retain(|p| p["name"] != "state");
        }
        for part in operation.path.split('/') {
            if let Some(name) = part.strip_prefix('{').and_then(|p| p.strip_suffix('}')) {
                let mut schema = json!({"type":"string"});
                if name == "action" {
                    schema["enum"] = json!(shape.actions.expect("Action enum required"));
                }
                if name == "kind" {
                    schema["enum"] = json!(["collection", "release"]);
                }
                shape
                    .query
                    .push(json!({"name":name,"in":"path","required":true,"schema":schema}));
            }
        }
        if operation.method == "POST" && operation.path == "/v2/jobs" {
            shape.query.push(json!({"name":"Idempotency-Key","in":"header","required":true,"schema":{"type":"string","minLength":1,"maxLength":200},"description":"Replay is checked before preparation expiration. Reusing a key with another request returns 409."}));
        }
        if shape.events {
            shape.query.push(json!({"name":"Last-Event-ID","in":"header","required":false,"schema":{"type":"integer","minimum":0},"description":"Last applied event cursor. Takes precedence over the query cursor. A 409 or resync_required event requires a new service snapshot and resource queries."}));
        }
        let content = if shape.binary {
            json!({"image/*":{"schema":{"type":"string","format":"binary"}}})
        } else if shape.events {
            json!({"text/event-stream":{"schema":{"type":"string"},"x-omd-event-schema":shape.response}})
        } else {
            json!({"application/json":{"schema":shape.response}})
        };
        let mut value = json!({"operationId":shape.id,"parameters":shape.query,"x-omd-scope":operation.scope,"security":if operation.scope=="admin"{json!([{"adminClient":[]}])}else{json!([{"normalClient":[]},{"adminClient":[]}])},"responses":{"200":{"description":"Success","content":content},"default":{"description":"Structured engine error. Follow its recovery actions; retain stale UI data where applicable.","content":{"application/json":{"schema":problem}}}}});
        if let Some(body) = shape.body {
            value["requestBody"] =
                json!({"required":true,"content":{"application/json":{"schema":body}}});
        }
        paths.entry(operation.path).or_insert_with(|| json!({}))[operation.method.to_lowercase()] =
            value;
    }
    // A durable task is always either an enumeration request or a prepared
    // acquisition batch; expose that union rather than opaque database JSON.
    schemas
        .0
        .get_mut("SelectionTask")
        .expect("Selection task schema")["properties"]["request"] =
        json!({"anyOf":[snapshot,batch]});
    // Utoipa owns the OpenAPI envelope. Preserve Schemars' complete JSON Schema
    // 2020-12 vocabulary (including boolean schemas) without a lossy conversion
    // through a smaller schema AST.
    let mut document = serde_json::to_value(utoipa::openapi::OpenApi::new(
        utoipa::openapi::Info::new("OMD acquisition engine", "2.0.0"),
        utoipa::openapi::path::Paths::new(),
    ))
    .expect("OpenAPI envelope serializes");
    document["info"]["description"] = json!(
        "One service per user profile. Read the private instance descriptor, attach a lease, and use the normal token for ordinary workflows. Heartbeat every 15 seconds. Native folder pickers and external opening belong to the shell; the engine owns file changes. Snapshot event_cursor before querying resources, then reconnect from the last applied event. Collections use server-side cursor pagination; always follow next_cursor until null."
    );
    document["paths"] = json!(paths);
    document["components"] = json!({"schemas":schemas.0,"securitySchemes":{"normalClient":{"type":"http","scheme":"bearer","description":"Profile normal-client token: read and manage operations."},"adminClient":{"type":"http","scheme":"bearer","description":"Profile administration token: installation, activation and service shutdown. Keep out of ordinary frontend network requests."}}});
    document
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_authorized_operation_has_a_resolvable_contract_and_stable_identifier() {
        let document = document();
        let mut ids = BTreeSet::new();
        for operation in OPERATIONS {
            let schema = &document["paths"][operation.path][operation.method.to_lowercase()];
            assert_eq!(schema["x-omd-scope"], operation.scope);
            assert!(ids.insert(schema["operationId"].as_str().unwrap()));
            assert!(schema["responses"]["200"]["content"].is_object());
        }
        fn walk(value: &Value, root: &Value) {
            if let Some(reference) = value.get("$ref").and_then(Value::as_str) {
                let pointer = reference
                    .strip_prefix('#')
                    .expect("Published schemas are self-contained");
                assert!(
                    root.pointer(pointer).is_some(),
                    "Missing schema {reference}"
                );
            }
            match value {
                Value::Object(map) => {
                    for value in map.values() {
                        walk(value, root)
                    }
                }
                Value::Array(items) => {
                    for value in items {
                        walk(value, root)
                    }
                }
                _ => {}
            }
        }
        walk(&document, &document);
        assert!(
            document["components"]["schemas"]["SourceInvocation"]["properties"]
                .get("now")
                .is_none()
        );
        assert_eq!(
            document["components"]["schemas"]["SourceInvocation"]["properties"]["page_size"]["default"],
            100
        );
        assert_ne!(
            document["components"]["schemas"]["Page_Release"],
            document["components"]["schemas"]["Page_Collection"]
        );
    }
}
