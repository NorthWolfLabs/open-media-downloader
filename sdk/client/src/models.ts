/* Generated from the Rust domain schema. Do not edit by hand. */

/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "FileStatus".
 */
export type FileStatus = "present" | "missing" | "modified" | "detached" | "destination_unavailable";
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "CollectionKind".
 */
export type CollectionKind = ("manga" | "playlist" | "channel") | "item";
/**
 * Source-provided artwork geometry and collection navigation.
 *
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "ArtworkLayout".
 */
export type ArtworkLayout = "portrait" | "landscape" | "square" | "banner";
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "CollectionSectionKind".
 */
export type CollectionSectionKind = "releases" | "collections";
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "IdentifiedSource".
 */
export type IdentifiedSource =
  | {
      kind: "collection";
      reference: SourceRef;
    }
  | {
      kind: "release";
      reference: SourceRef;
    };
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "Locator".
 */
export type Locator =
  | {
      credential_profile?: string | null;
      headers?: {
        [k: string]: string;
      };
      kind: "http";
      permission: string;
      url: string;
    }
  | {
      credential_profile?: string | null;
      kind: "media";
      permission: string;
      url: string;
    };
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "Recipe".
 */
export type Recipe = "cbz" | "image_folder" | "original_images" | "mp4" | "mkv" | "webm" | "m4a" | "mp3" | "opus";
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "Availability".
 */
export type Availability = "available" | "external" | "authentication_required" | "unavailable" | "unknown";
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "JobState".
 */
export type JobState =
  "queued" | "resolving" | "transferring" | "verifying" | "publishing" | "completed" | "paused" | "failed" | "canceled";
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "AccountMode".
 */
export type AccountMode = "browser" | "cookies" | "header";
/**
 * Explicit chapter browsing order. Absent for complete acquisition/subscription scans.
 *
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "ReleaseOrder".
 */
export type ReleaseOrder = "asc" | "desc";
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "ActionPolicy".
 */
export type ActionPolicy = "notify" | "download";

export interface Contracts {
  artifact: Artifact;
  artwork: Artwork;
  collection: Collection;
  collection_details: CollectionDetails;
  destination: Destination;
  discovery: DiscoverySchema;
  event: Event;
  identified_source: IdentifiedSource;
  job: Job;
  naming_templates: NamingTemplates;
  problem: Problem;
  provider_manifest: ProviderManifest;
  provider_request: ProviderRequest;
  release: Release;
  resolved_release: ResolvedRelease;
  subscription: Subscription;
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "Artifact".
 */
export interface Artifact {
  id: string;
  job_id: string;
  media_type: string;
  relative_path: string;
  sha256: string;
  size: number;
  status: FileStatus;
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "Artwork".
 */
export interface Artwork {
  id: string;
  label: string;
  locale?: string | null;
  url: string;
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "Collection".
 */
export interface Collection {
  artwork_url?: string | null;
  canonical_url: string;
  description?: string | null;
  kind: CollectionKind;
  reference: SourceRef;
  summary?: CollectionSummary | null;
  title: string;
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "SourceRef".
 */
export interface SourceRef {
  id: string;
  provider: string;
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "CollectionSummary".
 */
export interface CollectionSummary {
  artwork_layout?: ArtworkLayout | null;
  avatar_url?: string | null;
  banner_url?: string | null;
  content_rating?: string | null;
  content_rating_appearance?: LabelAppearance | null;
  creator_links?: CreatorLink[];
  creators?: string[];
  /**
   * Duration and audience facts supplied by a media source, including flat listings.
   */
  duration_seconds?: number | null;
  followers?: number | null;
  handle?: string | null;
  image?: ImageSummary | null;
  languages?: string[];
  original_language?: string | null;
  /**
   * The containing collection, such as the channel that published a video.
   */
  parent?: CollectionLink | null;
  profile?: string | null;
  /**
   * Source display text (for example “2 hours ago”); never treated as an exact date.
   */
  published_label?: string | null;
  rating?: number | null;
  rating_max?: number | null;
  sections?: CollectionSection[];
  status?: string | null;
  status_appearance?: LabelAppearance | null;
  tag_appearances?: {
    [k: string]: LabelAppearance;
  };
  tags?: string[];
  video_count_label?: string | null;
  view_count?: number | null;
  year?: number | null;
}
/**
 * A source's label color, never arbitrary CSS or executable presentation.
 *
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "LabelAppearance".
 */
export interface LabelAppearance {
  color: string;
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "CreatorLink".
 */
export interface CreatorLink {
  collection: CollectionLink;
  role: string;
}
/**
 * Small, source-provided discovery facts. No executable presentation or social actions.
 *
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "CollectionLink".
 */
export interface CollectionLink {
  canonical_url: string;
  kind: CollectionKind;
  reference: SourceRef;
  title: string;
}
/**
 * A downloadable image post. One release contains every image in the post.
 *
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "ImageSummary".
 */
export interface ImageSummary {
  bytes?: number | null;
  count: number;
  format?: string | null;
  height?: number | null;
  previews?: string[];
  release_id: string;
  width?: number | null;
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "CollectionSection".
 */
export interface CollectionSection {
  kind: CollectionSectionKind;
  label: string;
  reference: SourceRef;
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "CollectionDetails".
 */
export interface CollectionDetails {
  alternative_titles: {
    [k: string]: string[];
  };
  creators: MetadataField[];
  description?: string | null;
  facts: MetadataField[];
  languages: string[];
  /**
   * Honest explanation of source-provided or similarity-based recommendations.
   */
  recommendation_basis?: string | null;
  reference: SourceRef;
  tags: DiscoveryOption[];
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "MetadataField".
 */
export interface MetadataField {
  appearance?: LabelAppearance | null;
  label: string;
  values: string[];
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "DiscoveryOption".
 */
export interface DiscoveryOption {
  appearance?: LabelAppearance | null;
  id: string;
  label: string;
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "Destination".
 */
export interface Destination {
  available: boolean;
  id: string;
  label: string;
  root: string;
  storage_operation?: string | null;
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "DiscoverySchema".
 */
export interface DiscoverySchema {
  feeds: DiscoveryOption[];
  filters: DiscoveryFilter[];
  sorts: DiscoveryOption[];
  /**
   * Query this discovery operation with a query (including empty for popular tags).
   */
  tag_search?: boolean;
  tags?: DiscoveryOption[];
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "DiscoveryFilter".
 */
export interface DiscoveryFilter {
  id: string;
  label: string;
  multiple: boolean;
  options: DiscoveryOption[];
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "Event".
 */
export interface Event {
  created_at: string;
  id: number;
  kind: string;
  resource_id: string;
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "Job".
 */
export interface Job {
  acquisition_key: string;
  attempt: number;
  bytes_done: number;
  bytes_total?: number | null;
  created_at: string;
  destination_id: string;
  group_id?: string | null;
  id: string;
  issue?: Problem | null;
  plan: Plan;
  state: JobState;
  title: string;
  updated_at: string;
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "Problem".
 */
export interface Problem {
  actions: string[];
  code: string;
  message: string;
  retryable: boolean;
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "Plan".
 */
export interface Plan {
  collection: Collection;
  credential_profile?: string | null;
  expires_at?: string | null;
  final_relative_path: string;
  /**
   * Artifact-set version, assigned by the engine before confirmation.
   */
  generation?: number;
  media?: MediaSelection | null;
  metadata?: OutputMetadata;
  outputs: LogicalOutput[];
  policy: SelectionPolicy;
  provider_digest: string;
  recipe: Recipe;
  release: Release;
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "MediaSelection".
 */
export interface MediaSelection {
  duration_ms?: number | null;
  ffmpeg_digest: string;
  ffprobe_digest: string;
  format_ids: string[];
  node_digest?: string | null;
  selected_height?: number | null;
  source_signature: string;
  subtitles: string[];
  yt_dlp_digest: string;
}
export interface OutputMetadata {
  collection?: MetadataOverride;
  release?: MetadataOverride1;
}
export interface MetadataOverride {
  chapter?: string | null;
  description?: string | null;
  title?: string | null;
  volume?: string | null;
}
export interface MetadataOverride1 {
  chapter?: string | null;
  description?: string | null;
  title?: string | null;
  volume?: string | null;
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "LogicalOutput".
 */
export interface LogicalOutput {
  expected_sha256?: string | null;
  expected_size?: number | null;
  id: string;
  locator: Locator;
  media_type?: string | null;
  position: number;
  relative_path: string;
  role: string;
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "SelectionPolicy".
 */
export interface SelectionPolicy {
  automatic_subtitles?: boolean;
  groups?: string[];
  languages?: string[];
  max_height?: number;
  subtitle_languages?: string[];
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "Release".
 */
export interface Release {
  availability: Availability;
  canonical_url: string;
  chapter?: string | null;
  collection: SourceRef;
  group?: string | null;
  language?: string | null;
  position: number;
  /**
   * Metadata for browsing the release without fetching each item's details.
   */
  preview?: Collection | null;
  published_at?: string | null;
  reference: SourceRef;
  revision?: string | null;
  title: string;
  unavailable_reason?: string | null;
  volume?: string | null;
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "NamingTemplates".
 */
export interface NamingTemplates {
  collection?: string;
  release?: string;
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "ProviderManifest".
 */
export interface ProviderManifest {
  /**
   * Preferred reference-UI connection method. Imports store credentials without
   * asserting authentication; browser completion remains engine-owned.
   */
  account_mode?: AccountMode | null;
  api: string;
  browser?: boolean;
  /**
   * The operations this source implements (such as `search`, `releases`
   * and `resolve`), plus `collection_hint` when its `resolve` reads the
   * request's `collection_hint`.
   */
  capabilities: string[];
  description: string;
  grants: HostGrant[];
  id: string;
  media_tools?: boolean;
  name: string;
  /**
   * Used only by the interactive engine-owned sign-in browser. These grants
   * are never handed to source HTTP, media, or browser broker operations.
   */
  sign_in?: SignIn | null;
  source_hosts: string[];
  version: string;
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "HostGrant".
 */
export interface HostGrant {
  credential: boolean;
  hosts: string[];
  id: string;
  methods: string[];
  /**
   * Additional pacing for upstream endpoints with a stricter limit than ordinary browsing.
   */
  request_intervals?: {
    [k: string]: number;
  };
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "SignIn".
 */
export interface SignIn {
  /**
   * Cookie names required before saving an authenticated source session.
   * Values stay inside the engine and are never exposed to plugins or clients.
   */
  completion_cookies?: string[];
  grants: HostGrant[];
  url: string;
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "ProviderRequest".
 */
export interface ProviderRequest {
  /**
   * Sent only to a source whose manifest declares the `collection_hint`
   * capability, and only on `resolve`, when the engine resolves a release
   * again for a download: the collection the release was listed under when
   * it was selected (for example a search-results or playlist collection),
   * or the collection of an approved plan being refreshed. A source that
   * files a release under more than one collection may return this
   * collection as the release's collection while the release still belongs
   * to it. The engine still requires the returned collection to match.
   * Absent otherwise: a source that does not declare the capability gets
   * requests without this field.
   */
  collection_hint?: SourceRef | null;
  credential_profile?: string | null;
  cursor?: string | null;
  discovery?: DiscoveryQuery | null;
  now: string;
  operation: string;
  page_size: number;
  policy: SelectionPolicy;
  query?: string | null;
  reference?: SourceRef | null;
  release_order?: ReleaseOrder | null;
  url?: string | null;
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "DiscoveryQuery".
 */
export interface DiscoveryQuery {
  feed?: string | null;
  filters?: {
    [k: string]: string[];
  };
  sort?: string | null;
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "ResolvedRelease".
 */
export interface ResolvedRelease {
  collection: Collection;
  expires_at?: string | null;
  release: Release;
  resources: Resource[];
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "Resource".
 */
export interface Resource {
  expected_sha256?: string | null;
  expected_size?: number | null;
  id: string;
  locator: Locator;
  media_type?: string | null;
  position: number;
  role: string;
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "Subscription".
 */
export interface Subscription {
  current_check?: ObservationProgress | null;
  enabled: boolean;
  id: string;
  initialized: boolean;
  issue?: Problem | null;
  last_success?: string | null;
  next_check: string;
  request: SubscribeRequest;
  /**
   * Cached source collection title with any user title override applied.
   */
  title?: string | null;
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "ObservationProgress".
 */
export interface ObservationProgress {
  processed: number;
  source_digest: string;
  started_at: string;
  state: string;
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "SubscribeRequest".
 */
export interface SubscribeRequest {
  action: ActionPolicy;
  credential_profile?: string | null;
  destination_id: string;
  include_existing: boolean;
  interval_minutes: number;
  /**
   * Optional name shown in subscriptions, independent of the source title.
   */
  name?: string | null;
  policy: SelectionPolicy;
  recipe: Recipe;
  /**
   * Saved discovery input. Search subscriptions observe matching items, not their releases.
   */
  search?: SubscriptionSearch | null;
  target: SourceRef;
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "SubscriptionSearch".
 */
export interface SubscriptionSearch {
  discovery?: DiscoveryQuery | null;
  query: string;
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "MetadataOverride".
 */
export interface MetadataOverride2 {
  chapter?: string | null;
  description?: string | null;
  title?: string | null;
  volume?: string | null;
}
/**
 * This interface was referenced by `Contracts`'s JSON-Schema
 * via the `definition` "OutputMetadata".
 */
export interface OutputMetadata1 {
  collection?: MetadataOverride;
  release?: MetadataOverride1;
}
