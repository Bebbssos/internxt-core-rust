use serde::{Deserialize, Serialize};

/// Persisted credentials (our own format; stored AES-encrypted like the node CLI).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Credentials {
    /// JWT used as Bearer for the drive API (the node CLI's `newToken`).
    pub token: String,
    pub user: UserInfo,
    /// Active workspace context (set by `workspaces use`), if any. When present,
    /// all drive/network operations are scoped to this workspace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<WorkspaceContext>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserInfo {
    pub email: String,
    /// Plain (decrypted) mnemonic.
    pub mnemonic: String,
    pub bucket: String,
    pub bridge_user: String,
    pub user_id: String,
    pub root_folder_id: String,
    /// Decrypted ecc (OpenPGP) private key, base64(armored). Needed to decrypt
    /// workspace mnemonics. Optional: only present for key-aware logins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecc_private_key: Option<String>,
    /// Decrypted kyber private key, base64(raw). Optional (hybrid workspaces only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kyber_private_key: Option<String>,
}

/// Persisted active-workspace context. Mirrors the node CLI's stored `workspace`
/// (credentials + decrypted workspace mnemonic).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WorkspaceContext {
    /// Workspace uuid (used in `/workspaces/{id}/...` routes and the web link).
    pub id: String,
    pub name: String,
    /// `x-internxt-workspace` header value (WorkspaceCredentialsDetails.tokenHeader).
    pub token: String,
    pub bucket: String,
    /// Network (bridge) basic-auth user/pass for workspace transfers.
    pub network_user: String,
    pub network_pass: String,
    /// Decrypted workspace mnemonic (WorkspaceUser.key after hybrid decrypt).
    pub mnemonic: String,
    /// Workspace root folder uuid (default browse/upload target).
    pub root_folder_id: String,
}

impl Credentials {
    /// Network basic-auth user: workspace network user when a workspace is active,
    /// else the personal bridge user.
    pub fn net_user(&self) -> &str {
        match &self.workspace {
            Some(w) => &w.network_user,
            None => &self.user.bridge_user,
        }
    }

    /// Network basic-auth password source (sha256'd downstream): workspace network
    /// pass when active, else the personal userId.
    pub fn net_pass(&self) -> &str {
        match &self.workspace {
            Some(w) => &w.network_pass,
            None => &self.user.user_id,
        }
    }

    /// Active bucket: workspace bucket when active, else personal bucket.
    pub fn bucket(&self) -> &str {
        match &self.workspace {
            Some(w) => &w.bucket,
            None => &self.user.bucket,
        }
    }

    /// Active mnemonic for file-key derivation: workspace mnemonic when active.
    pub fn mnemonic(&self) -> &str {
        match &self.workspace {
            Some(w) => &w.mnemonic,
            None => &self.user.mnemonic,
        }
    }

    /// Default root folder: workspace root when active, else personal root.
    pub fn root_folder(&self) -> &str {
        match &self.workspace {
            Some(w) => &w.root_folder_id,
            None => &self.user.root_folder_id,
        }
    }

    /// Active workspace uuid, if any.
    pub fn workspace_id(&self) -> Option<&str> {
        self.workspace.as_ref().map(|w| w.id.as_str())
    }
}

/// Space usage breakdown (`GET /users/usage`). Bytes.
#[derive(Deserialize, Debug, Clone, Default)]
pub struct SpaceUsage {
    #[serde(default)]
    pub drive: u64,
    #[serde(default)]
    pub backups: u64,
    #[serde(default)]
    pub total: u64,
}

// ---- Network (bridge) DTOs ----

#[derive(Deserialize, Debug)]
pub struct StartUploadResponse {
    pub uploads: Vec<UploadSlot>,
}

#[derive(Deserialize, Debug)]
pub struct UploadSlot {
    pub uuid: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub urls: Option<Vec<String>>,
    #[serde(rename = "UploadId", default)]
    pub upload_id: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct FinishUploadResponse {
    pub id: String,
}

#[derive(Deserialize, Debug)]
pub struct DownloadLinksResponse {
    pub index: String,
    pub shards: Vec<DownloadShard>,
    #[serde(default)]
    pub version: Option<u32>,
    pub size: u64,
}

#[derive(Deserialize, Debug, Clone)]
pub struct DownloadShard {
    pub index: i64,
    pub url: String,
    /// Ciphertext byte length of this shard. Shards concatenate (ordered by
    /// `index`) into one continuous CTR stream, so this lets a range request
    /// skip whole shards and byte-range the boundary ones.
    #[serde(default)]
    pub size: u64,
}

// ---- Drive DTOs ----

#[derive(Deserialize, Debug, Clone)]
pub struct DriveFileData {
    pub uuid: String,
    #[serde(default)]
    pub bucket: String,
    #[serde(rename = "fileId", default)]
    pub file_id: Option<String>,
    #[serde(default)]
    pub size: SizeField,
    #[serde(rename = "plainName", default)]
    pub plain_name: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(rename = "type", default)]
    pub file_type: Option<String>,
    /// Whether the caller has this file marked as a favorite. Added to the
    /// backend DTOs alongside the favorites API (og sdk 1.20.x); absent from
    /// older responses, where it decodes as `false`.
    #[serde(rename = "isFavorite", default)]
    pub is_favorite: bool,
    /// Uuid of the folder the file sits in. Present on the reads that return a
    /// file from outside a folder listing (`/files/recents`, `/files/meta`),
    /// which is what makes it possible to say *where* such a file lives.
    #[serde(rename = "folderUuid", default)]
    pub folder_uuid: Option<String>,
    /// The file's own modification time (client-supplied, preserved across
    /// upload and replace) — not the record's. This is the timestamp change
    /// detection compares against; prefer [`Self::modified_at`], which falls
    /// back to `updated_at` when a response omits it.
    #[serde(rename = "modificationTime", default)]
    pub modification_time: Option<String>,
    /// The file's own creation time, as opposed to when the record was written.
    #[serde(rename = "creationTime", default)]
    pub creation_time: Option<String>,
    /// When the *record* was created server-side.
    #[serde(rename = "createdAt", default)]
    pub created_at: Option<String>,
    /// When the *record* last changed server-side (a rename or a move bumps
    /// this without touching [`Self::modification_time`]).
    #[serde(rename = "updatedAt", default)]
    pub updated_at: Option<String>,
    /// Lifecycle state: `EXISTS`, `TRASHED` or `DELETED`. Some responses omit
    /// it — see [`Self::is_live`] for the reading that treats an absent status
    /// the way the folder listings do.
    #[serde(default)]
    pub status: Option<String>,
    /// Thumbnails registered for this file. The folder listing, the folder tree
    /// and `/files/recents` carry them; `/files/{uuid}/meta` omits the key
    /// entirely, so an empty vec means "not reported here", not "none exist".
    #[serde(default)]
    pub thumbnails: Vec<ThumbnailMeta>,
    /// The parent folder, inlined. Only `/files/recents` populates it — the
    /// folder listing, `/files/{uuid}/meta` and the folder tree all send the
    /// key as `null` and offer [`Self::folder_uuid`] instead.
    #[serde(default)]
    pub folder: Option<FileParentFolder>,
}

impl DriveFileData {
    /// The file's modification time, falling back to the record's `updatedAt`
    /// when the response omits it.
    ///
    /// Change detection wants this rather than either field alone:
    /// `modificationTime` is the client-supplied one that survives an upload,
    /// but not every read returns it.
    pub fn modified_at(&self) -> Option<&str> {
        self.modification_time
            .as_deref()
            .or(self.updated_at.as_deref())
    }

    /// Whether the file counts as present: `status` is `EXISTS`, empty or
    /// absent.
    ///
    /// Absent reads as live because the responses that omit `status` only ever
    /// carry live items — the same rule the folder listings apply.
    pub fn is_live(&self) -> bool {
        !matches!(self.status.as_deref(), Some(s) if !s.is_empty() && s != "EXISTS")
    }

    /// Full filename: `plainName` plus the `type` extension when there is one.
    pub fn full_name(&self) -> Option<String> {
        let plain = self.plain_name.as_deref().or(self.name.as_deref())?;
        match self.file_type.as_deref() {
            Some(t) if !t.is_empty() => Some(format!("{plain}.{t}")),
            _ => Some(plain.to_string()),
        }
    }
}

/// The parent folder as `/files/recents` inlines it under `folder`. Only the
/// identifying fields are typed — the rest of that object repeats what a folder
/// read already returns.
#[derive(Deserialize, Debug, Clone)]
pub struct FileParentFolder {
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(rename = "plainName", default)]
    pub plain_name: Option<String>,
    /// Encrypted name; `plain_name` is the readable one.
    #[serde(default)]
    pub name: Option<String>,
    #[serde(rename = "parentUuid", default)]
    pub parent_uuid: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
}

/// A thumbnail as returned inside a folder-content file listing (`files[].thumbnails[]`
/// of `/folders/content/{uuid}/files`; the `/meta` endpoint omits it). Enough to
/// download it (bucket + network file id) and describe it.
#[derive(Deserialize, Debug, Clone)]
pub struct ThumbnailMeta {
    #[serde(default)]
    pub id: u64,
    #[serde(rename = "bucket_id", default)]
    pub bucket_id: String,
    #[serde(rename = "bucket_file", default)]
    pub bucket_file: String,
    #[serde(rename = "type", default)]
    pub thumbnail_type: String,
    #[serde(default)]
    pub size: SizeField,
    #[serde(rename = "max_width", default)]
    pub max_width: u32,
    #[serde(rename = "max_height", default)]
    pub max_height: u32,
}

/// Response of `POST /files/thumbnail` (og `Thumbnail`). We only need it to
/// deserialize successfully; the useful bits are the network `bucket_file` and id.
#[derive(Deserialize, Debug)]
pub struct Thumbnail {
    #[serde(default)]
    pub id: u64,
    #[serde(rename = "file_id", default)]
    pub file_id: u64,
    #[serde(rename = "bucket_file", default)]
    pub bucket_file: String,
    #[serde(rename = "type", default)]
    pub thumbnail_type: String,
    #[serde(default)]
    pub size: SizeField,
}

/// Size comes back as a number or a numeric string depending on endpoint.
#[derive(Debug, Default, Clone)]
pub struct SizeField(pub u64);

impl<'de> Deserialize<'de> for SizeField {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let v = serde_json::Value::deserialize(d)?;
        let n = match v {
            serde_json::Value::Number(n) => n.as_u64().unwrap_or(0),
            serde_json::Value::String(s) => s.parse().map_err(D::Error::custom)?,
            serde_json::Value::Null => 0,
            _ => return Err(D::Error::custom("invalid size")),
        };
        Ok(SizeField(n))
    }
}

/// Folder metadata as returned by `GET /folders/meta?path=...`
/// (og `storageClient.getFolderByPath`).
///
/// This endpoint answers in **snake_case** (`plain_name`, `parent_uuid`, ...),
/// unlike `/folders/{uuid}/meta` and every other folder route, which use
/// camelCase — so it needs its own struct rather than reusing the folder value
/// shape. The asymmetry is real, not a guess: confirmed against the live API,
/// where the sibling `GET /files/meta?path=` *does* answer in camelCase and
/// deserializes straight into [`DriveFileData`].
#[derive(Deserialize, Debug, Clone)]
pub struct FolderPathMeta {
    pub uuid: String,
    #[serde(default)]
    pub id: u64,
    #[serde(default)]
    pub plain_name: Option<String>,
    /// Encrypted name (the on-wire `name`); `plain_name` is the readable one.
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub parent_id: Option<u64>,
    #[serde(default)]
    pub parent_uuid: Option<String>,
    #[serde(default)]
    pub bucket: Option<String>,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default)]
    pub removed: bool,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub creation_time: Option<String>,
    #[serde(default)]
    pub modification_time: Option<String>,
}

/// Another user's public keys (`GET /users/public-key/{email}`).
///
/// Needed to encrypt something *to* that user — the sharing-invite flow wraps
/// the item key to the recipient's key. Two are returned: the OpenPGP `ecc` key
/// every account has, and the post-quantum `kyber` key that hybrid accounts add.
#[derive(Deserialize, Debug, Clone, Default)]
pub struct UserPublicKeys {
    /// base64 of the armored OpenPGP public key.
    #[serde(default)]
    pub ecc: Option<String>,
    /// base64 of the raw Kyber public key. Absent for ecc-only accounts.
    #[serde(default)]
    pub kyber: Option<String>,
}

/// Response of `GET /users/public-key/{email}`.
#[derive(Deserialize, Debug, Clone, Default)]
pub struct UserPublicKeyResponse {
    /// The ecc key repeated at the top level, for older clients that predate
    /// the hybrid `keys` object. Same value as `keys.ecc`.
    #[serde(rename = "publicKey", default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub keys: UserPublicKeys,
}

/// Per-plan versioning limits, nested inside [`FileLimits`].
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct VersioningLimits {
    /// Whether the plan may keep file versions at all.
    ///
    /// Note this reports the *plan's* entitlement. On the account this was
    /// verified against it read `true` while no version was ever actually
    /// minted — see [`crate::api::DriveApi::get_file_versions`].
    #[serde(default)]
    pub enabled: bool,
    /// Largest file, in bytes, eligible to be versioned.
    #[serde(rename = "maxFileSize", default)]
    pub max_file_size: u64,
    /// How long a version is kept before the retention policy drops it.
    #[serde(rename = "retentionDays", default)]
    pub retention_days: u32,
    /// How many versions are kept per file.
    #[serde(rename = "maxVersions", default)]
    pub max_versions: u32,
}

/// Response of `GET /files/limits` (og `storageClient.getFileVersionLimits`).
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct FileLimits {
    #[serde(default)]
    pub versioning: VersioningLimits,
    /// Largest single upload the plan allows, in bytes. `None` when the plan
    /// sets no per-file cap (field null or absent).
    #[serde(rename = "maxUploadFileSize", default)]
    pub max_upload_file_size: Option<u64>,
    /// Whether the account may use Internxt Photos. Undocumented when this was
    /// first observed in the live response; og's OpenAPI schema declares it as
    /// a required `boolean` since sdk 1.20.x. Still decoded leniently, so a
    /// `false` from an older backend means "unknown or no", not proof the
    /// feature is off.
    #[serde(rename = "photosAccess", default)]
    pub photos_access: bool,
}

/// One historical version of a file (`GET /files/{uuid}/versions`).
///
/// Versions are minted server-side — no client in og creates one explicitly,
/// and drive-web presents them as "autosave versions". See
/// [`crate::api::DriveApi::get_file_versions`] for what that means in practice.
#[derive(Deserialize, Debug, Clone)]
pub struct FileVersion {
    /// Version id — the `{versionId}` of the delete/restore routes.
    pub id: String,
    /// Owning file's numeric id. Nullable in the schema.
    #[serde(rename = "fileId", default)]
    pub file_id: Option<String>,
    /// Network (bridge) object holding this version's bytes. Downloading a
    /// version is an ordinary download of this id from the file's bucket —
    /// there is no version-specific download route.
    #[serde(rename = "networkFileId", default)]
    pub network_file_id: String,
    #[serde(default)]
    pub size: SizeField,
    /// `EXISTS` or `DELETED`.
    #[serde(default)]
    pub status: Option<String>,
    /// When the file was last modified *before* this version was created.
    #[serde(rename = "modificationTime", default)]
    pub modification_time: Option<String>,
    #[serde(rename = "createdAt", default)]
    pub created_at: Option<String>,
    #[serde(rename = "updatedAt", default)]
    pub updated_at: Option<String>,
    /// When the retention policy drops this version.
    #[serde(rename = "expiresAt", default)]
    pub expires_at: Option<String>,
}

/// Aggregate counts for a folder subtree (`GET /folders/{uuid}/stats`).
///
/// The two `*_exact` flags matter: for large folders the backend answers with
/// an estimate and clears them. Observed exact on a 31-file folder and
/// **inexact on a ~1000-file one**, so never present these as precise without
/// checking the flag.
#[derive(Deserialize, Debug, Clone, Default)]
pub struct FolderStats {
    #[serde(rename = "fileCount", default)]
    pub file_count: u64,
    #[serde(rename = "totalSize", default)]
    pub total_size: u64,
    #[serde(rename = "isFileCountExact", default)]
    pub is_file_count_exact: bool,
    #[serde(rename = "isTotalSizeExact", default)]
    pub is_total_size_exact: bool,
}

/// One node of `GET /folders/{uuid}/tree` — a folder with its files and,
/// recursively, its subfolders. The whole subtree arrives in a single request.
#[derive(Deserialize, Debug, Clone)]
pub struct FolderTree {
    pub uuid: String,
    #[serde(default)]
    pub id: u64,
    #[serde(rename = "plainName", default)]
    pub plain_name: Option<String>,
    /// Encrypted name; `plain_name` is the readable one.
    #[serde(default)]
    pub name: Option<String>,
    #[serde(rename = "parentUuid", default)]
    pub parent_uuid: Option<String>,
    #[serde(rename = "parentId", default)]
    pub parent_id: Option<u64>,
    #[serde(default)]
    pub status: Option<String>,
    /// Files directly in this folder.
    #[serde(default)]
    pub files: Vec<DriveFileData>,
    /// Subfolders, each a full subtree of its own.
    #[serde(default)]
    pub children: Vec<FolderTree>,
}

impl FolderTree {
    /// Total number of files in this subtree, including every descendant.
    pub fn total_files(&self) -> usize {
        self.files.len() + self.children.iter().map(|c| c.total_files()).sum::<usize>()
    }

    /// Total number of folders below this node.
    pub fn total_folders(&self) -> usize {
        self.children.len() + self.children.iter().map(|c| c.total_folders()).sum::<usize>()
    }
}

/// One hit from the fuzzy global search (`POST /fuzzy/{search}`, og
/// `storageClient.getGlobalSearchItems`).
///
/// `item_type` is `"file"` or `"folder"` and `item_id` is that item's uuid —
/// the handle to follow up with [`crate::api::DriveApi::get_file_meta`] or
/// `get_folder_meta`. The search index carries only enough of the record to
/// rank and label a hit, so `item` (the partial record: bucket, fileId, size,
/// type) is kept as raw JSON and may be absent entirely.
#[derive(Deserialize, Debug, Clone)]
pub struct SearchResult {
    pub id: String,
    #[serde(rename = "itemId")]
    pub item_id: String,
    /// `"file"` or `"folder"`.
    #[serde(rename = "itemType")]
    pub item_type: String,
    /// Plain (decrypted) item name, as indexed.
    pub name: String,
    /// Postgres full-text rank. Null for a hit found only by trigram
    /// similarity, so this is an `Option`, unlike og's type.
    #[serde(default)]
    pub rank: Option<f64>,
    /// Trigram similarity of `name` against the query, 0.0..=1.0.
    #[serde(default)]
    pub similarity: f64,
    /// The partial item record the backend attaches to a hit, when it does.
    #[serde(default)]
    pub item: Option<serde_json::Value>,
}

/// Optional filters for [`crate::api::DriveApi::global_search`], sent as the
/// JSON body of `POST /fuzzy/{search}`.
///
/// og moved this endpoint from `GET .../fuzzy/{search}?offset=N` to a POST with
/// this body in sdk 1.20.x, which is also where the filters below appeared.
/// Every field is optional and they combine with AND (within `types`, the
/// extensions combine with OR).
#[derive(Serialize, Debug, Clone, Default)]
pub struct SearchFilters {
    /// Pagination offset. The page size is the backend's, not ours to set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
    /// File extensions without the dot (`["jpg", "pdf"]`), plus the reserved
    /// value `"folder"` to include folders in the results.
    #[serde(rename = "type", skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<String>,
    /// Smallest file size to return, in bytes. Excludes folders when set.
    #[serde(rename = "minSize", skip_serializing_if = "Option::is_none")]
    pub min_size: Option<u64>,
    /// Largest file size to return, in bytes. Excludes folders when set.
    #[serde(rename = "maxSize", skip_serializing_if = "Option::is_none")]
    pub max_size: Option<u64>,
    /// ISO 8601 timestamp; only items modified after it are returned.
    #[serde(rename = "modifiedAfter", skip_serializing_if = "Option::is_none")]
    pub modified_after: Option<String>,
    /// ISO 8601 timestamp; only items modified before it are returned.
    #[serde(rename = "modifiedBefore", skip_serializing_if = "Option::is_none")]
    pub modified_before: Option<String>,
}

/// A role a shared item's recipient can hold (`GET /sharings/roles`).
/// Observed live: `EDITOR`, `READER`, `TEAM_MANAGER`.
#[derive(Deserialize, Debug, Clone)]
pub struct SharingRole {
    pub id: String,
    /// Uppercase role name, e.g. `READER`.
    pub name: String,
    #[serde(rename = "createdAt", default)]
    pub created_at: Option<String>,
    #[serde(rename = "updatedAt", default)]
    pub updated_at: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The shape `/files/recents` answers with — the only read that inlines the
    /// parent folder. Field names and nesting are taken from a live response.
    #[test]
    fn drive_file_data_decodes_a_recents_record() {
        let f: DriveFileData = serde_json::from_value(json!({
            "uuid": "file-uuid",
            "fileId": "network-file-id",
            "bucket": "bucket-id",
            "plainName": "notes",
            "type": "txt",
            "size": "1234",
            "folderUuid": "parent-uuid",
            "creationTime": "2026-01-02T03:04:05.000Z",
            "modificationTime": "2026-02-03T04:05:06.000Z",
            "createdAt": "2026-01-02T03:04:05.678Z",
            "updatedAt": "2026-02-03T04:05:06.789Z",
            "status": "EXISTS",
            "folder": {
                "uuid": "parent-uuid",
                "plainName": "Documents",
                "parentUuid": "grandparent-uuid",
                "status": "EXISTS",
                // Fields we deliberately don't type must not break decoding.
                "userId": 42,
                "encryptVersion": "03-aes"
            }
        }))
        .unwrap();

        assert_eq!(f.size.0, 1234);
        assert_eq!(f.folder_uuid.as_deref(), Some("parent-uuid"));
        assert_eq!(f.modified_at(), Some("2026-02-03T04:05:06.000Z"));
        assert_eq!(f.full_name().as_deref(), Some("notes.txt"));
        assert!(f.is_live());
        let parent = f.folder.expect("recents inlines the parent folder");
        assert_eq!(parent.plain_name.as_deref(), Some("Documents"));
    }

    /// Every added field is optional: the older, narrower shape still decodes.
    #[test]
    fn drive_file_data_decodes_a_record_without_any_of_the_new_fields() {
        let f: DriveFileData = serde_json::from_value(json!({
            "uuid": "file-uuid",
            "plainName": "archive",
            "type": "",
            "size": 0
        }))
        .unwrap();

        assert!(f.modification_time.is_none());
        assert!(f.folder.is_none());
        assert!(f.thumbnails.is_empty());
        assert_eq!(f.modified_at(), None);
        // An empty `type` must not produce a trailing dot.
        assert_eq!(f.full_name().as_deref(), Some("archive"));
        // No status at all reads as live, like the folder listings treat it.
        assert!(f.is_live());
    }

    #[test]
    fn modified_at_falls_back_to_updated_at_and_status_gates_liveness() {
        let no_mtime: DriveFileData = serde_json::from_value(json!({
            "uuid": "u",
            "updatedAt": "2026-02-03T04:05:06.789Z",
            "status": "TRASHED"
        }))
        .unwrap();
        assert_eq!(no_mtime.modified_at(), Some("2026-02-03T04:05:06.789Z"));
        assert!(!no_mtime.is_live());

        let deleted: DriveFileData =
            serde_json::from_value(json!({ "uuid": "u", "status": "DELETED" })).unwrap();
        assert!(!deleted.is_live());

        let blank: DriveFileData =
            serde_json::from_value(json!({ "uuid": "u", "status": "" })).unwrap();
        assert!(blank.is_live());
    }

    /// The tree's file objects are the listing's, so a caller taking files
    /// straight from a subtree gets the same timestamps and thumbnails.
    #[test]
    fn folder_tree_files_carry_the_timestamps_change_detection_needs() {
        let tree: FolderTree = serde_json::from_value(json!({
            "uuid": "root-uuid",
            "plainName": "root",
            "status": "EXISTS",
            "files": [{
                "uuid": "file-uuid",
                "fileId": "network-file-id",
                "bucket": "bucket-id",
                "plainName": "report",
                "type": "pdf",
                "size": 9001,
                "modificationTime": "2026-02-03T04:05:06.000Z",
                "updatedAt": "2026-02-03T04:05:06.789Z",
                "status": "EXISTS",
                "thumbnails": [{
                    "id": 7,
                    "bucket_id": "thumb-bucket",
                    "bucket_file": "thumb-file",
                    "type": "png",
                    "size": 512,
                    "max_width": 300,
                    "max_height": 300
                }]
            }],
            "children": []
        }))
        .unwrap();

        let f = &tree.files[0];
        assert_eq!(f.modified_at(), Some("2026-02-03T04:05:06.000Z"));
        assert_eq!(f.size.0, 9001);
        assert_eq!(f.thumbnails.len(), 1);
        assert_eq!(f.thumbnails[0].bucket_file, "thumb-file");
    }
}
