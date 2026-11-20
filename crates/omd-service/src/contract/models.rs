//! Named HTTP response shapes. Domain payloads retain their Rust-owned schemas.
use omd_domain::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct Source {
    pub manifest: ProviderManifest,
    pub digest: String,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct SourceVersion {
    pub manifest: ProviderManifest,
    pub digest: String,
    pub active: bool,
    pub installed_at: String,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct SourceReview {
    pub review_required: bool,
    pub digest: String,
    pub manifest: ProviderManifest,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct SourceInstalled {
    pub installed: bool,
    pub digest: String,
    pub manifest: ProviderManifest,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum InstallResult {
    Review(SourceReview),
    Installed(SourceInstalled),
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct SourceActivated {
    pub activated: bool,
    pub digest: String,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct SourceAccount {
    pub profile: String,
    pub label: String,
    pub updated_at: String,
    pub status: String,
    pub issue: Option<Problem>,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct AccountSaved {
    pub profile: String,
    pub saved: bool,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct AccountRevoked {
    pub revoked: bool,
}
// Unknown parameters are ignored, as they were before this query existed.
#[derive(Default, Serialize, Deserialize, JsonSchema)]
pub struct AttachQuery {
    /// When this client is the last to leave and background operation is off,
    /// keep the engine running until no download is queued or running, then
    /// stop. Without it, the engine stops soon after the last client leaves and
    /// unfinished downloads continue at its next start. Command-line and agent
    /// clients that submit work and leave set it; an interactive application
    /// whose window close should stop downloads leaves it unset.
    #[serde(default)]
    pub finish_downloads: bool,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ClientLease {
    pub id: String,
    pub heartbeat_seconds: u32,
    pub lease_seconds: u32,
    /// Whether the engine recorded `finish_downloads` for this client. Absent
    /// on engines released before that attach option.
    pub finish_downloads: Option<bool>,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ClientHeartbeat {
    pub id: String,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ClientDetached {
    pub detached: bool,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct Shutdown {
    pub state: String,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct Updated {
    pub updated: bool,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct Summary {
    pub active_jobs: u64,
    pub acquired: u64,
    pub following: u64,
    pub attention: u64,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ToolIdentity {
    pub name: String,
    pub version: String,
    pub sha256: String,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct MediaTools {
    pub configured: bool,
    pub complete: bool,
    pub tools: Vec<ToolIdentity>,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct Service {
    pub api: String,
    pub version: String,
    /// Absent on engines released before manual-update handover support.
    pub executable_sha256: Option<String>,
    pub event_cursor: i64,
    pub scopes: Vec<String>,
    pub capabilities: Vec<String>,
    pub recipes: Vec<Recipe>,
    pub media_tools: Option<MediaTools>,
}
#[derive(Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShutdownQuery {
    /// Suspend this profile's startup registration for replacement/uninstall.
    /// The background preference is preserved and restored on the next launch.
    #[serde(default)]
    pub for_update: bool,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct Startup {
    pub enabled: bool,
    pub issue: Option<Problem>,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct Settings {
    pub background: bool,
    pub languages: Vec<String>,
    #[serde(default)]
    pub bandwidth_bytes_per_second: u64,
    #[serde(default)]
    pub onboarding_complete: bool,
    pub startup: Startup,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct Preview {
    pub plan: Plan,
    pub outcome: IntentOutcome,
    pub files: Vec<String>,
    pub estimated_bytes: Option<u64>,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct Preparation {
    pub id: String,
    pub expires_at: String,
    pub destination: Destination,
    pub items: Vec<Preview>,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct EnqueuedItem {
    pub job: Job,
    pub created: bool,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct Enqueued {
    pub group_id: String,
    pub items: Vec<EnqueuedItem>,
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct EnqueuedBatch {
    pub group_id: String,
    pub created: u64,
    pub existing: u64,
    pub total: u64,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum EnqueueResult {
    Explicit(Enqueued),
    Batch(EnqueuedBatch),
}
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct InboxItem {
    pub id: String,
    pub subscription_id: String,
    pub release: Release,
    pub state: String,
    pub job_id: Option<String>,
    pub issue: Option<Problem>,
    pub created_at: String,
    pub read_at: Option<String>,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum SourceResult {
    Discovery(DiscoverySchema),
    Details(CollectionDetails),
    Artwork(Page<Artwork>),
    Collections(Page<Collection>),
    Releases(Page<Release>),
    Collection(Box<Collection>),
    Resolved(Box<ResolvedRelease>),
    Identified(IdentifiedSource),
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IntentOutcome {
    Download,
    NewVersion,
    AlreadyAcquired,
    ExistingJob,
}
/// Frontends describe a source operation. The engine supplies its clock and all
/// execution authority; clients need not construct the worker's internal request.
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceInvocation {
    #[serde(default)]
    pub release_order: Option<ReleaseOrder>,
    #[serde(default)]
    pub discovery: Option<DiscoveryQuery>,
    pub operation: SourceOperation,
    pub reference: Option<SourceRef>,
    pub query: Option<String>,
    pub url: Option<String>,
    pub cursor: Option<String>,
    #[serde(default = "page_size")]
    pub page_size: u32,
    #[serde(default)]
    pub policy: SelectionPolicy,
    pub credential_profile: Option<String>,
}
fn page_size() -> u32 {
    100
}
impl SourceInvocation {
    pub fn into_worker(self) -> ProviderRequest {
        ProviderRequest {
            release_order: self.release_order,
            discovery: self.discovery,
            operation: self.operation.name().into(),
            reference: self.reference,
            query: self.query,
            url: self.url,
            cursor: self.cursor,
            page_size: self.page_size,
            policy: self.policy,
            credential_profile: self.credential_profile,
            now: omd_store::now(),
            // Engine-owned: set only when the engine resolves a listed release again.
            collection_hint: None,
        }
    }
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceOperation {
    Discovery,
    Details,
    Artwork,
    Related,
    Recommendations,
    Search,
    Browse,
    Collection,
    Releases,
    Resolve,
    Identify,
}
impl SourceOperation {
    fn name(self) -> &'static str {
        match self {
            Self::Discovery => "discovery",
            Self::Details => "details",
            Self::Artwork => "artwork",
            Self::Related => "related",
            Self::Recommendations => "recommendations",
            Self::Search => "search",
            Self::Browse => "browse",
            Self::Collection => "collection",
            Self::Releases => "releases",
            Self::Resolve => "resolve",
            Self::Identify => "identify",
        }
    }
}

#[cfg(test)]
mod source_operation_tests {
    use super::*;
    #[test]
    fn related_titles_pass_the_public_request_contract() {
        let operation: SourceOperation =
            serde_json::from_value(serde_json::json!("related")).unwrap();
        assert_eq!(operation.name(), "related");
        let schema = serde_json::to_value(schemars::schema_for!(SourceOperation)).unwrap();
        assert!(
            schema["enum"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("related"))
        );
    }
}
