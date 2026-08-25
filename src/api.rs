//! Drive REST API client (DRIVE_NEW_API_URL). Mirrors og/sdk auth + storage.

use anyhow::{anyhow, Result};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use serde_json::{json, Value};
use std::time::Duration;

use crate::config;
use crate::models::{Credentials, DriveFileData, FileLimits, FileVersion, FolderPathMeta, FolderStats, FolderTree, SearchFilters, SearchResult, SharingRole, UserPublicKeyResponse};

/// Connecting to a reachable API host should be fast; anything slower almost
/// certainly means a dead peer or a firewalled black hole rather than a slow
/// server, so we don't let it hang indefinitely.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Every [`DriveApi`] call is a small metadata/JSON request (auth, folder
/// listings, file entry CRUD, ...) — never a large file body (those go
/// through [`crate::network::NetworkApi`] to presigned storage URLs). So it's
/// safe, and desirable, to cap the *total* request duration here — unlike the
/// network client, which streams large bodies and must not be capped this way.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeouts for [`DriveApi`]'s HTTP client.
#[derive(Clone, Copy, Debug)]
pub struct DriveTimeouts {
    pub connect: Duration,
    pub request: Duration,
}

impl Default for DriveTimeouts {
    fn default() -> Self {
        DriveTimeouts {
            connect: DEFAULT_CONNECT_TIMEOUT,
            request: DEFAULT_REQUEST_TIMEOUT,
        }
    }
}

pub struct DriveApi {
    client: Client,
    base: String,
    /// Active workspace as (uuid, token). When set, requests carry the
    /// `x-internxt-workspace` header and folder/trash/file-entry calls route to
    /// the `/workspaces/{id}/...` endpoints.
    workspace: Option<(String, String)>,
}

fn base_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    if let Ok(v) = HeaderValue::from_str(&config::client_version()) {
        h.insert("internxt-version", v);
    }
    if let Ok(v) = HeaderValue::from_str(&config::client_name()) {
        h.insert("internxt-client", v);
    }
    if let Ok(v) = HeaderValue::from_str(&config::desktop_header()) {
        h.insert("x-internxt-desktop-header", v);
    }
    h
}

/// Percent-encode a single URL path segment, `/` included.
///
/// Unlike [`encode_path`], nothing is kept literal: the value is one segment,
/// so a `/` inside it (legal in a search term) must not be allowed to split the
/// path. og interpolates the raw string into the URL and has that bug.
fn encode_segment(segment: &str) -> String {
    encode_path(segment).replace('/', "%2F")
}

/// Percent-encode a Drive path for use in a query string, keeping `/` literal.
///
/// Everything outside the RFC 3986 unreserved set (plus `/`) is escaped, so a
/// space becomes `%20` rather than `+`: the `+`-for-space convention belongs to
/// form encoding, and only `%20` was verified against the live endpoint.
fn encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for b in path.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

impl DriveApi {
    pub fn new() -> Self {
        Self::with_timeouts(DriveTimeouts::default())
    }

    /// Same as [`Self::new`], with caller-adjustable timeouts (e.g. so
    /// `internxt-cli-rust` can widen them via a flag/env var).
    pub fn with_timeouts(timeouts: DriveTimeouts) -> Self {
        let client = Client::builder()
            .connect_timeout(timeouts.connect)
            .timeout(timeouts.request)
            .build()
            .unwrap_or_default();
        DriveApi {
            client,
            base: config::drive_api_url(),
            workspace: None,
        }
    }

    /// Build a client scoped to the credentials' active workspace (if any), so
    /// every request carries the workspace header and routes appropriately.
    pub fn for_credentials(creds: &Credentials) -> Self {
        let mut api = Self::new();
        if let Some(w) = &creds.workspace {
            api.workspace = Some((w.id.clone(), w.token.clone()));
        }
        api
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    /// URL for the `?path=` metadata lookups (`/files/meta`, `/folders/meta`).
    ///
    /// The Drive path is percent-encoded before it goes into the query string.
    /// og interpolates it raw, which breaks on any name containing `&`, `#`,
    /// `?` or `%` — ordinary characters in a filename. `/` is deliberately left
    /// literal: it's the path separator the endpoint is parsing, not data.
    fn meta_by_path_url(&self, kind: &str, path: &str) -> String {
        format!("{}?path={}", self.url(&format!("/{kind}/meta")), encode_path(path))
    }

    /// `true` when this client is scoped to an active workspace. Backups have
    /// no workspace-scoped variant, so callers use this to skip/reject
    /// backup-device lookups while a workspace is active.
    pub fn is_workspace(&self) -> bool {
        self.workspace.is_some()
    }

    /// Authenticated headers, including `x-internxt-workspace` when a workspace
    /// is active (mirrors node SdkManager.init with a workspaceToken).
    fn auth_headers(&self, token: &str) -> Result<HeaderMap> {
        let mut h = base_headers();
        h.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {token}"))?);
        if let Some((_, ws_token)) = &self.workspace {
            h.insert("x-internxt-workspace", HeaderValue::from_str(ws_token)?);
        }
        Ok(h)
    }

    async fn check(resp: reqwest::Response, ctx: &str) -> Result<Value> {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(anyhow!("{ctx} failed: HTTP {status}: {text}"));
        }
        if text.is_empty() {
            return Ok(Value::Null);
        }
        Ok(serde_json::from_str(&text)?)
    }

    /// POST /auth/login -> (encrypted_salt (sKey), tfa_enabled)
    pub async fn security_details(&self, email: &str) -> Result<(String, bool)> {
        let resp = self
            .client
            .post(self.url("/auth/login"))
            .headers(base_headers())
            .json(&json!({ "email": email }))
            .send()
            .await?;
        let v = Self::check(resp, "securityDetails").await?;
        let skey = v["sKey"]
            .as_str()
            .ok_or_else(|| anyhow!("no sKey in response: {v}"))?
            .to_string();
        let tfa = v["tfa"].as_bool().unwrap_or(false) || v["tfa"].is_string();
        Ok((skey, tfa))
    }

    /// POST /auth/login/access (no keys) -> full response json (newToken, user, ...)
    pub async fn login_access(
        &self,
        email: &str,
        encrypted_password_hash: &str,
        tfa: Option<&str>,
    ) -> Result<Value> {
        let body = json!({
            "email": email,
            "password": encrypted_password_hash,
            "tfa": tfa,
        });
        let resp = self
            .client
            .post(self.url("/auth/login/access"))
            .headers(base_headers())
            .json(&body)
            .send()
            .await?;
        Self::check(resp, "loginAccess").await
    }

    /// GET /users/refresh -> new session token (refreshUserCredentials).
    /// Returns the `newToken`; the rest of the user identity is unchanged.
    pub async fn refresh_user_token(&self, token: &str) -> Result<String> {
        let v = self.refresh_user_credentials(token).await?;
        v["newToken"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("no newToken in refresh response: {v}"))
    }

    /// GET /users/refresh -> full `{ user, token, newToken }` (RefreshUserTokensDto).
    /// Used by the SSO login flow to fetch the user identity, since the
    /// universal link only carries the mnemonic, token and ecc private key.
    ///
    /// The node CLI hits `/users/cli/refresh`, but that path is tier-gated by the
    /// backend (`402 "CLI access not allowed for this user tier"` on non-Ultimate
    /// plans). `/users/refresh` is the first-party GUI endpoint (drive-web /
    /// drive-desktop) and returns the identical `RefreshUserTokensDto`, so we use
    /// it to work on every plan. See config `client_name` note on the gate.
    pub async fn refresh_user_credentials(&self, token: &str) -> Result<serde_json::Value> {
        let resp = self
            .client
            .get(self.url("/users/refresh"))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "refreshUserCredentials").await
    }

    /// GET /users/usage -> space used, split drive / backups / total (bytes).
    /// Mirrors og `storageClient.spaceUsageV2()`.
    pub async fn space_usage(&self, token: &str) -> Result<crate::models::SpaceUsage> {
        let resp = self
            .client
            .get(self.url("/users/usage"))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        let v = Self::check(resp, "spaceUsage").await?;
        Ok(serde_json::from_value(v)?)
    }

    /// GET /users/limit -> the plan's total space limit in bytes (`maxSpaceBytes`).
    /// Mirrors og `storageClient.spaceLimitV2()`.
    pub async fn space_limit(&self, token: &str) -> Result<u64> {
        let resp = self
            .client
            .get(self.url("/users/limit"))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        let v = Self::check(resp, "spaceLimit").await?;
        Ok(v.get("maxSpaceBytes").and_then(|m| m.as_u64()).unwrap_or(0))
    }

    /// GET /files/limits -> the plan's file limits: the per-upload size cap and
    /// the versioning entitlement. Mirrors og
    /// `storageClient.getFileVersionLimits()`.
    ///
    /// og's node CLI reads only `maxUploadFileSize` from this (to reject an
    /// oversized upload before spending bandwidth on it); the versioning block
    /// is what drive-web gates its version-history UI on.
    ///
    /// There is no separate size-precheck endpoint to pair with this: og's SDK
    /// declares `POST /files/check-size-limit`, but it answers 404 on the live
    /// API, so this is the only way to learn the cap.
    pub async fn get_file_limits(&self, token: &str) -> Result<FileLimits> {
        let resp = self
            .client
            .get(self.url("/files/limits"))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        let v = Self::check(resp, "getFileLimits").await?;
        Ok(serde_json::from_value(v)?)
    }

    /// GET {payments}/products/tier -> the plan's human `label` (e.g. "Pro").
    /// Best-effort (separate API, og cli never calls it). **Unreliable for
    /// legacy plans**: those come back `label:"free"` regardless, so callers
    /// must corroborate with [`Self::user_subscription`] before trusting it.
    pub async fn user_tier(&self, token: &str) -> Result<Option<String>> {
        let url = format!("{}/products/tier", config::payments_api_url());
        let mut headers = base_headers();
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {token}"))?);
        let resp = self.client.get(url).headers(headers).send().await?;
        let v = Self::check(resp, "userTier").await?;
        Ok(v.get("label")
            .and_then(|l| l.as_str())
            .map(|s| s.to_string()))
    }

    /// GET {payments}/subscriptions -> the billing `type`: `free`, `lifetime`,
    /// or `subscription`. This is the authoritative plan signal (legacy lifetime
    /// accounts report `lifetime` here even while the tier endpoint mislabels
    /// them `free`). Best-effort; `None` on error/absent. Not workspace-scoped.
    pub async fn user_subscription(&self, token: &str) -> Result<Option<String>> {
        let url = format!("{}/subscriptions", config::payments_api_url());
        let mut headers = base_headers();
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {token}"))?);
        let resp = self.client.get(url).headers(headers).send().await?;
        let v = Self::check(resp, "userSubscription").await?;
        Ok(v.get("type").and_then(|t| t.as_str()).map(|s| s.to_string()))
    }

    /// GET /files/{uuid}/meta
    pub async fn get_file_meta(&self, token: &str, uuid: &str) -> Result<DriveFileData> {
        let resp = self
            .client
            .get(self.url(&format!("/files/{uuid}/meta")))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        let v = Self::check(resp, "getFileMeta").await?;
        Ok(serde_json::from_value(v)?)
    }

    /// GET /files/{uuid}/meta — raw JSON (keeps fields absent from
    /// [`DriveFileData`], e.g. `folderUuid`, needed to reconstruct a file's path).
    pub async fn get_file_meta_value(&self, token: &str, uuid: &str) -> Result<Value> {
        let resp = self
            .client
            .get(self.url(&format!("/files/{uuid}/meta")))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "getFileMeta").await
    }

    /// GET /files/meta?path=... — resolve an absolute Drive path to a file in a
    /// **single** request, instead of walking one listing per path component.
    /// Mirrors og `storageClient.getFileByPath`, which the node CLI uses for
    /// every WebDAV resource lookup.
    ///
    /// Path rules, confirmed against the live API:
    /// * the leading `/` is **required** — without it the server answers
    ///   `400 Invalid path provided`;
    /// * the file **extension is part of the path** (`/dir/notes.txt`, not
    ///   `/dir/notes`) — the bare stem answers `404 File not found`;
    /// * a missing file is a `404`, surfaced here as an `Err`.
    ///
    /// Not workspace-aware: og exposes no workspace-scoped variant, and this
    /// account had no workspace to verify one against, so callers holding a
    /// workspace-scoped client must keep using component-wise resolution.
    pub async fn get_file_by_path(&self, token: &str, path: &str) -> Result<DriveFileData> {
        let resp = self
            .client
            .get(self.meta_by_path_url("files", path))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        let v = Self::check(resp, "getFileByPath").await?;
        Ok(serde_json::from_value(v)?)
    }

    /// GET /folders/meta?path=... — the folder counterpart of
    /// [`Self::get_file_by_path`]; same path rules (leading `/` required, a
    /// trailing `/` is tolerated, missing is a `404`).
    ///
    /// Returns [`FolderPathMeta`] rather than the usual folder value because
    /// this endpoint alone answers in snake_case — see that type's note.
    pub async fn get_folder_by_path(&self, token: &str, path: &str) -> Result<FolderPathMeta> {
        let resp = self
            .client
            .get(self.meta_by_path_url("folders", path))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        let v = Self::check(resp, "getFolderByPath").await?;
        Ok(serde_json::from_value(v)?)
    }

    /// GET /users/public-key/{email} -> that user's public keys. Mirrors og
    /// `usersClient.getPublicKey`.
    ///
    /// This is the lookup any "share with someone" flow starts from: the item
    /// key gets wrapped to the recipient's key. Both are returned — the OpenPGP
    /// `ecc` key every account has, and the post-quantum `kyber` key hybrid
    /// accounts add (absent for ecc-only accounts).
    ///
    /// The email is percent-encoded, so a `+`-tagged address survives the round
    /// trip.
    pub async fn get_user_public_key(
        &self,
        token: &str,
        email: &str,
    ) -> Result<UserPublicKeyResponse> {
        let resp = self
            .client
            .get(self.url(&format!("/users/public-key/{}", encode_path(email))))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        let v = Self::check(resp, "getUserPublicKey").await?;
        Ok(serde_json::from_value(v)?)
    }

    /// GET /files/{uuid}/versions -> the file's version history, newest first.
    /// Mirrors og `storageClient.getFileVersions`.
    ///
    /// **Nothing observed on the live API actually creates a version.** The
    /// endpoint is real and answers correctly (`200 []` for a known file, `404
    /// File not found` otherwise), and `GET /files/limits` reports
    /// `versioning.enabled: true` — but replacing a file twice via
    /// `PUT /files/{uuid}` (with and without `modificationTime`, polled for 12s
    /// after each, on a file far under the 20 MB versioning cap) left the list
    /// empty. No og client creates versions either: drive-web only reads,
    /// restores and deletes them, labelling them "autosave versions". So
    /// version creation is server-side and appears to be deployed-but-dark.
    ///
    /// Consequence: this returns real data if the backend ever starts minting
    /// versions, but the field shapes come from og's OpenAPI schema rather than
    /// an observed non-empty response, and [`Self::restore_file_version`] /
    /// [`Self::delete_file_version`] could not be exercised against a real
    /// version. Treat all three as unverified beyond their error paths.
    pub async fn get_file_versions(&self, token: &str, uuid: &str) -> Result<Vec<FileVersion>> {
        let resp = self
            .client
            .get(self.url(&format!("/files/{uuid}/versions")))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        let v = Self::check(resp, "getFileVersions").await?;
        Ok(serde_json::from_value(v)?)
    }

    /// DELETE /files/{uuid}/versions/{version_id} — drop one stored version.
    /// The file's current content is untouched. Mirrors og
    /// `storageClient.deleteFileVersion`. See [`Self::get_file_versions`] for
    /// why this is unverified against a real version.
    pub async fn delete_file_version(
        &self,
        token: &str,
        uuid: &str,
        version_id: &str,
    ) -> Result<()> {
        let resp = self
            .client
            .delete(self.url(&format!("/files/{uuid}/versions/{version_id}")))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "deleteFileVersion").await?;
        Ok(())
    }

    /// POST /files/{uuid}/versions/{version_id}/restore — make a stored version
    /// the file's current content, keeping its uuid. Returns the updated file.
    /// Mirrors og `storageClient.restoreFileVersion`. See
    /// [`Self::get_file_versions`] for why this is unverified against a real
    /// version.
    pub async fn restore_file_version(
        &self,
        token: &str,
        uuid: &str,
        version_id: &str,
    ) -> Result<DriveFileData> {
        let resp = self
            .client
            .post(self.url(&format!("/files/{uuid}/versions/{version_id}/restore")))
            .headers(self.auth_headers(token)?)
            .json(&json!({}))
            .send()
            .await?;
        let v = Self::check(resp, "restoreFileVersion").await?;
        Ok(serde_json::from_value(v)?)
    }

    /// GET /folders/{uuid}/tree -> the folder's entire subtree (files plus
    /// recursively nested subfolders) in one request. Mirrors og
    /// `storageClient.getFolderTree`.
    ///
    /// This replaces a breadth-first walk that costs one paginated listing per
    /// folder — worth a lot for whole-tree work like sync or compare.
    ///
    /// **Only safe for bounded subtrees.** The backend builds the whole tree
    /// eagerly and gives up on big ones: verified working on a 31-file folder
    /// (nesting confirmed several levels deep), but the same call against a
    /// ~1000-file, 37 GB account root answered **HTTP 520** — an upstream
    /// failure, not a normal error body. Callers must be ready to fall back to
    /// paginated listing, and shouldn't reach for this on an arbitrary folder.
    /// [`Self::get_folder_stats`] is a cheap way to gauge size beforehand.
    pub async fn get_folder_tree(&self, token: &str, uuid: &str) -> Result<FolderTree> {
        let resp = self
            .client
            .get(self.url(&format!("/folders/{uuid}/tree")))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        let v = Self::check(resp, "getFolderTree").await?;
        // The subtree is wrapped: `{ "tree": { ... } }`.
        let tree = v
            .get("tree")
            .cloned()
            .ok_or_else(|| anyhow!("getFolderTree: no `tree` in response"))?;
        Ok(serde_json::from_value(tree)?)
    }

    /// GET /folders/{uuid}/stats -> file count and total size for a subtree.
    /// Mirrors og `storageClient.getFolderStats`.
    ///
    /// Check [`FolderStats::is_file_count_exact`] /
    /// [`FolderStats::is_total_size_exact`] before presenting the numbers as
    /// precise — the backend estimates for large folders and clears the flags.
    pub async fn get_folder_stats(&self, token: &str, uuid: &str) -> Result<FolderStats> {
        let resp = self
            .client
            .get(self.url(&format!("/folders/{uuid}/stats")))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        let v = Self::check(resp, "getFolderStats").await?;
        Ok(serde_json::from_value(v)?)
    }

    /// POST /folders/content/{uuid}/files/existence -> those of `files` that
    /// already exist in the folder. Mirrors og
    /// `storageClient.checkDuplicatedFiles`.
    ///
    /// `files` is a list of `(plain_name, file_type)` pairs, where the type is
    /// the extension without the dot (`("notes", "txt")`). Answers with the
    /// full records of the ones that collide, so a caller can go straight to
    /// replacing them; an empty result means every name is free.
    ///
    /// Cheaper and more direct than listing the folder to look for collisions,
    /// which is what upload paths do today.
    pub async fn check_duplicate_files(
        &self,
        token: &str,
        folder_uuid: &str,
        files: &[(&str, &str)],
    ) -> Result<Vec<DriveFileData>> {
        let payload: Vec<Value> = files
            .iter()
            .map(|(name, ty)| json!({ "plainName": name, "type": ty }))
            .collect();
        let resp = self
            .client
            .post(self.url(&format!("/folders/content/{folder_uuid}/files/existence")))
            .headers(self.auth_headers(token)?)
            .json(&json!({ "files": payload }))
            .send()
            .await?;
        let v = Self::check(resp, "checkDuplicateFiles").await?;
        let list = v
            .get("existentFiles")
            .cloned()
            .unwrap_or_else(|| Value::Array(vec![]));
        Ok(serde_json::from_value(list)?)
    }

    /// POST /folders/content/{uuid}/folders/existence -> those of `names` that
    /// already exist as subfolders. Mirrors og
    /// `storageClient.checkDuplicatedFolders`.
    ///
    /// Returns the raw records rather than a typed folder struct: core has no
    /// camelCase folder DTO yet, and the other folder reads here
    /// (`get_folder_meta`, the content listings) likewise hand back [`Value`].
    pub async fn check_duplicate_folders(
        &self,
        token: &str,
        folder_uuid: &str,
        names: &[&str],
    ) -> Result<Vec<Value>> {
        let resp = self
            .client
            .post(self.url(&format!("/folders/content/{folder_uuid}/folders/existence")))
            .headers(self.auth_headers(token)?)
            .json(&json!({ "plainNames": names }))
            .send()
            .await?;
        let v = Self::check(resp, "checkDuplicateFolders").await?;
        Ok(v.get("existentFolders")
            .and_then(|f| f.as_array())
            .cloned()
            .unwrap_or_default())
    }

    /// GET /files/recents?limit=N -> the account's most recently modified
    /// files, newest first, across every folder. Mirrors og
    /// `storageClient.getRecentFiles`.
    ///
    /// Entries carry `folderUuid`, so a caller can resolve where each file
    /// lives; [`DriveFileData`] keeps only the fields core needs, so reach for
    /// [`Self::get_file_meta_value`] if the raw record is wanted.
    pub async fn get_recent_files(&self, token: &str, limit: u32) -> Result<Vec<DriveFileData>> {
        let resp = self
            .client
            .get(self.url(&format!("/files/recents?limit={limit}")))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        let v = Self::check(resp, "getRecentFiles").await?;
        Ok(serde_json::from_value(v)?)
    }

    /// GET /users/me/upload-status -> whether the account has ever uploaded a
    /// file. Mirrors og `storageClient.hasUploadedFiles`, which drive-web uses
    /// to tell a genuinely empty account from a still-loading one.
    pub async fn has_uploaded_files(&self, token: &str) -> Result<bool> {
        let resp = self
            .client
            .get(self.url("/users/me/upload-status"))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        let v = Self::check(resp, "hasUploadedFiles").await?;
        Ok(v.get("hasUploadedFiles")
            .and_then(|h| h.as_bool())
            .unwrap_or(false))
    }

    /// POST /fuzzy/{search} -> items whose name fuzzy-matches `query`, ranked
    /// best first. Mirrors og `storageClient.getGlobalSearchItems`.
    ///
    /// og moved this off `GET .../fuzzy/{search}?offset=N` in sdk 1.20.x: the
    /// parameters now travel as a JSON body ([`SearchFilters`]) so the new
    /// extension/size/date filters have somewhere to live. Pass
    /// [`SearchFilters::default()`] for an unfiltered first page.
    ///
    /// Workspace-aware: with a workspace active this searches that workspace's
    /// drive (`/workspaces/{id}/fuzzy/{search}`) rather than the personal one.
    /// The search term is percent-encoded, so a term containing `/`, `?` or `#`
    /// can't corrupt the path.
    pub async fn global_search(
        &self,
        token: &str,
        query: &str,
        filters: &SearchFilters,
    ) -> Result<Vec<SearchResult>> {
        let search = encode_segment(query);
        let path = match &self.workspace {
            Some((id, _)) => format!("/workspaces/{id}/fuzzy/{search}"),
            None => format!("/fuzzy/{search}"),
        };
        let resp = self
            .client
            .post(self.url(&path))
            .headers(self.auth_headers(token)?)
            .json(filters)
            .send()
            .await?;
        let v = Self::check(resp, "globalSearch").await?;
        let list = v
            .get("data")
            .cloned()
            .unwrap_or_else(|| Value::Array(vec![]));
        Ok(serde_json::from_value(list)?)
    }

    /// PUT /favorites/{item_type}/{uuid} -> mark a file or folder as a
    /// favorite. `item_type` is `"file"` or `"folder"`.
    ///
    /// Idempotent: favoriting an already-favorited item succeeds and creates no
    /// duplicate. Returns the item's resulting favorite state — the endpoint
    /// answers `{ "favorited": true }`, but is documented as a bodiless 200, so
    /// an empty response is read as success.
    pub async fn mark_favorite(&self, token: &str, item_type: &str, uuid: &str) -> Result<bool> {
        let resp = self
            .client
            .put(self.url(&format!("/favorites/{item_type}/{uuid}")))
            .headers(self.auth_headers(token)?)
            .json(&json!({}))
            .send()
            .await?;
        let v = Self::check(resp, "markFavorite").await?;
        Ok(v.get("favorited").and_then(|f| f.as_bool()).unwrap_or(true))
    }

    /// DELETE /favorites/{item_type}/{uuid} -> drop a file or folder from the
    /// favorites. Idempotent like [`Self::mark_favorite`]: unfavoriting an item
    /// that isn't favorited is a successful no-op. Returns the resulting
    /// favorite state (`false` when the response carries no body).
    pub async fn unmark_favorite(&self, token: &str, item_type: &str, uuid: &str) -> Result<bool> {
        let resp = self
            .client
            .delete(self.url(&format!("/favorites/{item_type}/{uuid}")))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        let v = Self::check(resp, "unmarkFavorite").await?;
        Ok(v.get("favorited").and_then(|f| f.as_bool()).unwrap_or(false))
    }

    /// GET /favorites?type=…&limit=…&offset=… -> one page of the account's
    /// favorited files *or* folders — the endpoint returns one kind per call,
    /// chosen by `item_type` (`"file"` or `"folder"`).
    ///
    /// `sort` is `uuid`, `plainName` or `updatedAt` and `order` is `ASC` or
    /// `DESC`; both are optional and left to the backend's default when `None`.
    /// Records come back raw: folders have no camelCase DTO in core (same
    /// reasoning as [`Self::check_duplicate_folders`]). For files, prefer the
    /// typed [`Self::get_favorite_files`].
    pub async fn get_favorites(
        &self,
        token: &str,
        item_type: &str,
        limit: u32,
        offset: u32,
        sort: Option<&str>,
        order: Option<&str>,
    ) -> Result<Vec<Value>> {
        let mut path = format!("/favorites?type={item_type}&limit={limit}&offset={offset}");
        if let Some(sort) = sort {
            path.push_str(&format!("&sort={sort}"));
        }
        if let Some(order) = order {
            path.push_str(&format!("&order={order}"));
        }
        let resp = self
            .client
            .get(self.url(&path))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        let v = Self::check(resp, "getFavorites").await?;
        Ok(v.as_array().cloned().unwrap_or_default())
    }

    /// [`Self::get_favorites`] for files, decoded into [`DriveFileData`] — the
    /// same shape the folder listings hand back, so a favorites page can feed
    /// straight into a download.
    pub async fn get_favorite_files(
        &self,
        token: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<DriveFileData>> {
        let list = self
            .get_favorites(token, "file", limit, offset, None, None)
            .await?;
        Ok(serde_json::from_value(Value::Array(list))?)
    }

    /// GET folder ancestors — the chain from the folder itself (first element) up
    /// to the account/workspace root (last element, `parentUuid: null`). Each entry
    /// carries `uuid`/`plainName`/`parentUuid`. Workspace-aware
    /// (`/workspaces/{id}/folders/{uuid}/ancestors`).
    pub async fn get_folder_ancestors(&self, token: &str, uuid: &str) -> Result<Value> {
        let path = match &self.workspace {
            Some((id, _)) => format!("/workspaces/{id}/folders/{uuid}/ancestors"),
            None => format!("/folders/{uuid}/ancestors"),
        };
        let resp = self
            .client
            .get(self.url(&path))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "getFolderAncestors").await
    }

    /// POST /files (createFileEntryByUuid), or POST /workspaces/{id}/files when a
    /// workspace is active. The workspace variant omits `creationTime` and adds a
    /// `date` field (mirrors og workspaceClient.createFileEntry).
    #[allow(clippy::too_many_arguments)]
    pub async fn create_file_entry(
        &self,
        token: &str,
        plain_name: &str,
        file_type: &str,
        size: u64,
        folder_uuid: &str,
        file_id: &str,
        bucket: &str,
        creation_time: &str,
        modification_time: &str,
    ) -> Result<DriveFileData> {
        let (path, body) = match &self.workspace {
            Some((id, _)) => (
                format!("/workspaces/{id}/files"),
                json!({
                    "name": plain_name,
                    "plainName": plain_name,
                    "type": file_type,
                    "size": size,
                    "folderUuid": folder_uuid,
                    "fileId": file_id,
                    "bucket": bucket,
                    "encryptVersion": "03-aes",
                    "modificationTime": modification_time,
                    "date": modification_time,
                }),
            ),
            None => (
                "/files".to_string(),
                json!({
                    "plainName": plain_name,
                    "type": file_type,
                    "size": size,
                    "folderUuid": folder_uuid,
                    "fileId": file_id,
                    "bucket": bucket,
                    "encryptVersion": "03-aes",
                    "creationTime": creation_time,
                    "modificationTime": modification_time,
                }),
            ),
        };
        let resp = self
            .client
            .post(self.url(&path))
            .headers(self.auth_headers(token)?)
            .json(&body)
            .send()
            .await?;
        let v = Self::check(resp, "createFileEntry").await?;
        Ok(serde_json::from_value(v)?)
    }

    /// PUT /files/{uuid} — replace an existing file's content in place (keeps the
    /// same uuid/name/folder, swaps `fileId` + `size`). Mirrors og
    /// storage.replaceFile; avoids the 409 that createFileEntry raises for a
    /// duplicate name in the same folder.
    pub async fn replace_file(
        &self,
        token: &str,
        uuid: &str,
        file_id: &str,
        size: u64,
    ) -> Result<DriveFileData> {
        let resp = self
            .client
            .put(self.url(&format!("/files/{uuid}")))
            .headers(self.auth_headers(token)?)
            .json(&json!({ "fileId": file_id, "size": size }))
            .send()
            .await?;
        let v = Self::check(resp, "replaceFile").await?;
        Ok(serde_json::from_value(v)?)
    }

    /// Replace a file's content, tolerating the zero-byte case.
    ///
    /// A zero-byte file has no network object behind it — nothing is uploaded,
    /// so its `fileId` is the empty string. `POST /files` accepts that happily
    /// (creating an empty file works), but `PUT /files/{uuid}` answers an empty
    /// `fileId` with a 500, so truncating an existing Drive file to zero bytes
    /// can never go through `replace_file`. Fall back to trash-then-create for
    /// that one case: the old entry is trashed (recoverable, not permanently
    /// deleted) and a fresh empty entry takes over its name.
    ///
    /// If that create fails the trash is rolled back — some plans reject
    /// empty-file creation outright (HTTP 402), and without the rollback such
    /// an account would see a truncate leave its file in the trash instead of
    /// in place. Restoring is just a move back to the parent folder, the same
    /// thing an explicit "restore from trash" does.
    ///
    /// Note the uuid is NOT preserved on that path — the returned
    /// `DriveFileData` carries the new one, so callers holding a per-file uuid
    /// must adopt it instead of reusing what they passed in.
    #[allow(clippy::too_many_arguments)]
    pub async fn replace_file_or_recreate(
        &self,
        token: &str,
        uuid: &str,
        file_id: &str,
        size: u64,
        plain_name: &str,
        file_type: &str,
        folder_uuid: &str,
        bucket: &str,
        creation_time: &str,
        modification_time: &str,
    ) -> Result<DriveFileData> {
        if !file_id.is_empty() {
            return self.replace_file(token, uuid, file_id, size).await;
        }
        self.trash_items(token, json!([{ "uuid": uuid, "type": "file" }]))
            .await?;
        let created = self
            .create_file_entry(
                token,
                plain_name,
                file_type,
                size,
                folder_uuid,
                file_id,
                bucket,
                creation_time,
                modification_time,
            )
            .await;
        match created {
            Ok(created) => Ok(created),
            Err(e) => match self.move_file(token, uuid, folder_uuid).await {
                Ok(_) => Err(e.context(
                    "could not create the empty file; the original was restored from the trash",
                )),
                Err(restore) => Err(e.context(format!(
                    "could not create the empty file, and restoring the original from the trash \
                     also failed ({restore:#}) — it is still in the trash"
                ))),
            },
        }
    }

    /// POST /files/thumbnail — register a thumbnail for a file (mirrors og
    /// storage.createThumbnailEntryWithUUID). The thumbnail bytes must already be
    /// uploaded to the network; `bucket_file` is that network file id.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_thumbnail_entry(
        &self,
        token: &str,
        file_uuid: &str,
        thumbnail_type: &str,
        size: u64,
        max_width: u32,
        max_height: u32,
        bucket: &str,
        bucket_file: &str,
    ) -> Result<crate::models::Thumbnail> {
        let body = json!({
            "fileUuid": file_uuid,
            "type": thumbnail_type,
            "size": size,
            "maxWidth": max_width,
            "maxHeight": max_height,
            "bucketId": bucket,
            "bucketFile": bucket_file,
            "encryptVersion": "03-aes",
        });
        let resp = self
            .client
            .post(self.url("/files/thumbnail"))
            .headers(self.auth_headers(token)?)
            .json(&body)
            .send()
            .await?;
        let v = Self::check(resp, "createThumbnailEntry").await?;
        Ok(serde_json::from_value(v)?)
    }

    /// GET /workspaces/ — available + pending workspaces (WorkspacesResponse).
    pub async fn get_workspaces(&self, token: &str) -> Result<Value> {
        let resp = self
            .client
            .get(self.url("/workspaces/"))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "getWorkspaces").await
    }

    /// GET /workspaces/{id}/credentials — network creds + token header for a workspace.
    pub async fn get_workspace_credentials(&self, token: &str, workspace_id: &str) -> Result<Value> {
        let resp = self
            .client
            .get(self.url(&format!("/workspaces/{workspace_id}/credentials")))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "getWorkspaceCredentials").await
    }

    // ---- Workspace administration ----
    //
    // These read the membership/quota side of a workspace, as opposed to the
    // credentials the transfer paths need. All of them hand back raw [`Value`]
    // rather than typed structs, on purpose: the account available for probing
    // belongs to **no workspace at all** (`GET /workspaces/` answers
    // `{"availableWorkspaces": [], "pendingWorkspaces": []}`), so every response
    // observed was an empty list. Typing them would mean transcribing og's
    // OpenAPI schema and presenting a guess as a contract. Raw values keep the
    // uncertainty visible, and match how the other workspace and folder reads
    // here already behave.
    //
    // Verified only in the sense that the routes exist and answer 200 with an
    // empty body: `/workspaces/`, `/workspaces/pending-setup` and
    // `/workspaces/invitations`. The `{workspace_id}`-scoped calls below could
    // not be reached at all. Anyone with a populated workspace should re-probe
    // and promote these to real types.

    /// GET /workspaces/{id} -> a single workspace's details.
    /// Unverified — see the note above.
    pub async fn get_workspace(&self, token: &str, workspace_id: &str) -> Result<Value> {
        let resp = self
            .client
            .get(self.url(&format!("/workspaces/{workspace_id}")))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "getWorkspace").await
    }

    /// GET /workspaces/{id}/members -> the workspace's members.
    /// Unverified — see the note above.
    pub async fn get_workspace_members(&self, token: &str, workspace_id: &str) -> Result<Value> {
        let resp = self
            .client
            .get(self.url(&format!("/workspaces/{workspace_id}/members")))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "getWorkspaceMembers").await
    }

    /// GET /workspaces/{id}/teams -> the workspace's teams.
    /// Unverified — see the note above.
    pub async fn get_workspace_teams(&self, token: &str, workspace_id: &str) -> Result<Value> {
        let resp = self
            .client
            .get(self.url(&format!("/workspaces/{workspace_id}/teams")))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "getWorkspaceTeams").await
    }

    /// GET /workspaces/{id}/usage -> the workspace's overall space usage.
    /// Unverified — see the note above.
    pub async fn get_workspace_usage(&self, token: &str, workspace_id: &str) -> Result<Value> {
        let resp = self
            .client
            .get(self.url(&format!("/workspaces/{workspace_id}/usage")))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "getWorkspaceUsage").await
    }

    /// GET /workspaces/{id}/usage/member -> the calling member's own usage
    /// within the workspace. Unverified — see the note above.
    pub async fn get_workspace_member_usage(
        &self,
        token: &str,
        workspace_id: &str,
    ) -> Result<Value> {
        let resp = self
            .client
            .get(self.url(&format!("/workspaces/{workspace_id}/usage/member")))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "getWorkspaceMemberUsage").await
    }

    /// GET /workspaces/pending-setup -> workspaces the caller owns that still
    /// need setting up. Answers `200 []` on an account with no workspaces.
    pub async fn get_pending_setup_workspaces(&self, token: &str) -> Result<Value> {
        let resp = self
            .client
            .get(self.url("/workspaces/pending-setup"))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "getPendingSetupWorkspaces").await
    }

    /// GET /workspaces/invitations -> workspace invitations awaiting the
    /// caller's response. Answers `200 []` on an account with none.
    pub async fn get_workspace_invitations(
        &self,
        token: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Value> {
        let resp = self
            .client
            .get(self.url(&format!(
                "/workspaces/invitations?limit={limit}&offset={offset}"
            )))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "getWorkspaceInvitations").await
    }

    // ---- Sharings (read + revoke) ----
    //
    // Covers listing what is shared, inspecting one item's sharing, and
    // stopping a share. **Creating** a share is deliberately absent: it wraps
    // the item key to the recipient (or to a link password), which needs
    // crypto this crate doesn't have yet. That belongs in its own change.
    //
    // `item_type` throughout is `"file"` or `"folder"`, matching og's routes.
    //
    // The test account had nothing shared, so the list endpoints were verified
    // answering 200 with empty collections, and the per-item ones through their
    // error paths (`404 Item is not being shared`). Only `get_sharing_roles`
    // and `get_share_domains` returned real data, and they are the only two
    // given typed results here — the rest hand back raw [`Value`] rather than a
    // schema-derived guess.

    /// GET /sharings/roles -> the roles a share recipient can be given.
    /// Observed live: `EDITOR`, `READER`, `TEAM_MANAGER`.
    pub async fn get_sharing_roles(&self, token: &str) -> Result<Vec<SharingRole>> {
        let resp = self
            .client
            .get(self.url("/sharings/roles"))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        let v = Self::check(resp, "getSharingRoles").await?;
        Ok(serde_json::from_value(v)?)
    }

    /// GET /storage/share/domains -> the domains public share links may use.
    /// Returns the bare list (the wire shape wraps it in `{ "list": [...] }`).
    pub async fn get_share_domains(&self, token: &str) -> Result<Vec<String>> {
        let resp = self
            .client
            .get(self.url("/storage/share/domains"))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        let v = Self::check(resp, "getShareDomains").await?;
        Ok(v.get("list")
            .and_then(|l| l.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|d| d.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// GET /sharings/files -> files the caller has shared. Paginated.
    /// `order_by` takes og's `field:DIRECTION` form, e.g. `createdAt:DESC`.
    pub async fn get_shared_files(
        &self,
        token: &str,
        page: u32,
        per_page: u32,
        order_by: &str,
    ) -> Result<Value> {
        self.sharings_page(token, "files", page, per_page, order_by)
            .await
    }

    /// GET /sharings/folders -> folders the caller has shared. Paginated.
    /// See [`Self::get_shared_files`] for `order_by`.
    pub async fn get_shared_folders(
        &self,
        token: &str,
        page: u32,
        per_page: u32,
        order_by: &str,
    ) -> Result<Value> {
        self.sharings_page(token, "folders", page, per_page, order_by)
            .await
    }

    async fn sharings_page(
        &self,
        token: &str,
        kind: &str,
        page: u32,
        per_page: u32,
        order_by: &str,
    ) -> Result<Value> {
        let resp = self
            .client
            .get(self.url(&format!(
                "/sharings/{kind}?page={page}&perPage={per_page}&orderBy={}",
                encode_path(order_by)
            )))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "getSharings").await
    }

    /// GET /sharings/shared-with-me/folders -> folders other people shared with
    /// the caller. Paginated.
    pub async fn get_shared_with_me_folders(
        &self,
        token: &str,
        page: u32,
        per_page: u32,
    ) -> Result<Value> {
        let resp = self
            .client
            .get(self.url(&format!(
                "/sharings/shared-with-me/folders?page={page}&perPage={per_page}"
            )))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "getSharedWithMeFolders").await
    }

    /// GET /sharings/shared-by-me/folders -> folders the caller has shared out.
    /// Paginated.
    pub async fn get_shared_by_me_folders(
        &self,
        token: &str,
        page: u32,
        per_page: u32,
    ) -> Result<Value> {
        let resp = self
            .client
            .get(self.url(&format!(
                "/sharings/shared-by-me/folders?page={page}&perPage={per_page}"
            )))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "getSharedByMeFolders").await
    }

    /// GET /sharings/invites -> sharing invitations awaiting the caller.
    pub async fn get_sharing_invites(
        &self,
        token: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Value> {
        let resp = self
            .client
            .get(self.url(&format!(
                "/sharings/invites?limit={limit}&offset={offset}"
            )))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "getSharingInvites").await
    }

    /// GET /sharings/{item_type}/{item_id}/info -> details of how one item is
    /// shared. An item that isn't shared answers `404 Item is not being
    /// shared`, surfaced here as an `Err` — that's the normal "not shared"
    /// signal, not a transport failure.
    pub async fn get_item_sharing_info(
        &self,
        token: &str,
        item_type: &str,
        item_id: &str,
    ) -> Result<Value> {
        let resp = self
            .client
            .get(self.url(&format!("/sharings/{item_type}/{item_id}/info")))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "getItemSharingInfo").await
    }

    /// GET /sharings/{item_type}/{item_id}/type -> whether the item is shared
    /// publicly or privately. Same `404` behaviour as
    /// [`Self::get_item_sharing_info`].
    pub async fn get_item_sharing_type(
        &self,
        token: &str,
        item_type: &str,
        item_id: &str,
    ) -> Result<Value> {
        let resp = self
            .client
            .get(self.url(&format!("/sharings/{item_type}/{item_id}/type")))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "getItemSharingType").await
    }

    /// GET /sharings/{item_type}/{item_id}/invites -> people invited to this
    /// item. Unlike `info`/`type`, an unshared item answers `200 []` rather
    /// than 404.
    pub async fn get_item_sharing_invites(
        &self,
        token: &str,
        item_type: &str,
        item_id: &str,
    ) -> Result<Value> {
        let resp = self
            .client
            .get(self.url(&format!("/sharings/{item_type}/{item_id}/invites")))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "getItemSharingInvites").await
    }

    /// DELETE /sharings/{item_type}/{item_id} -> stop sharing an item.
    ///
    /// **Idempotent**: revoking an item that isn't shared succeeds rather than
    /// erroring — verified live against an unshared folder. So an `Ok` here
    /// means "not shared any more", not "a share was actually removed"; check
    /// [`Self::get_item_sharing_info`] first if you need to tell those apart.
    ///
    /// Only that no-op path was exercised. Revoking a *real* share was not
    /// tested, since creating one needs the crypto this change deliberately
    /// leaves out.
    pub async fn stop_sharing(&self, token: &str, item_type: &str, item_id: &str) -> Result<()> {
        let resp = self
            .client
            .delete(self.url(&format!("/sharings/{item_type}/{item_id}")))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "stopSharing").await?;
        Ok(())
    }

    /// GET /auth/logout (best effort; invalidates the session token server-side).
    pub async fn logout(&self, token: &str) -> Result<()> {
        let resp = self
            .client
            .get(self.url("/auth/logout"))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "logout").await?;
        Ok(())
    }

    /// GET /folders/{uuid}/meta
    pub async fn get_folder_meta(&self, token: &str, uuid: &str) -> Result<Value> {
        let resp = self
            .client
            .get(self.url(&format!("/folders/{uuid}/meta")))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "getFolderMeta").await
    }

    /// One page of subfolders (returns `.folders`/`.result`). Personal endpoint is
    /// `/folders/content/{uuid}/folders/`; workspace is `/workspaces/{id}/folders/{uuid}/folders/`.
    pub async fn get_folder_subfolders(
        &self,
        token: &str,
        uuid: &str,
        offset: u32,
    ) -> Result<Value> {
        let path = match &self.workspace {
            Some((id, _)) => {
                format!("/workspaces/{id}/folders/{uuid}/folders/?offset={offset}&limit=50")
            }
            None => format!(
                "/folders/content/{uuid}/folders/?offset={offset}&limit=50&sort=plainName&order=ASC"
            ),
        };
        let resp = self
            .client
            .get(self.url(&path))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "getFolderFolders").await
    }

    /// One page of files (returns `.files`/`.result`). Personal endpoint is
    /// `/folders/content/{uuid}/files/`; workspace is `/workspaces/{id}/folders/{uuid}/files/`.
    pub async fn get_folder_subfiles(
        &self,
        token: &str,
        uuid: &str,
        offset: u32,
    ) -> Result<Value> {
        let path = match &self.workspace {
            Some((id, _)) => {
                format!("/workspaces/{id}/folders/{uuid}/files/?offset={offset}&limit=50")
            }
            None => format!(
                "/folders/content/{uuid}/files/?offset={offset}&limit=50&sort=plainName&order=ASC"
            ),
        };
        let resp = self
            .client
            .get(self.url(&path))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "getFolderFiles").await
    }

    /// Create a folder by parent uuid. Routes to `/workspaces/{id}/folders` when
    /// a workspace is active (payload uses `name` instead of `plainName`).
    pub async fn create_folder(
        &self,
        token: &str,
        plain_name: &str,
        parent_folder_uuid: &str,
    ) -> Result<Value> {
        let (path, body) = match &self.workspace {
            Some((id, _)) => (
                format!("/workspaces/{id}/folders"),
                json!({ "name": plain_name, "parentFolderUuid": parent_folder_uuid }),
            ),
            None => (
                "/folders".to_string(),
                json!({ "plainName": plain_name, "parentFolderUuid": parent_folder_uuid }),
            ),
        };
        let resp = self
            .client
            .post(self.url(&path))
            .headers(self.auth_headers(token)?)
            .json(&body)
            .send()
            .await?;
        Self::check(resp, "createFolder").await
    }

    /// PATCH /folders/{uuid} — move folder into a destination folder.
    pub async fn move_folder(&self, token: &str, uuid: &str, destination: &str) -> Result<Value> {
        let resp = self
            .client
            .patch(self.url(&format!("/folders/{uuid}")))
            .headers(self.auth_headers(token)?)
            .json(&json!({ "destinationFolder": destination }))
            .send()
            .await?;
        Self::check(resp, "moveFolder").await
    }

    /// PATCH /files/{uuid} — move file into a destination folder.
    pub async fn move_file(&self, token: &str, uuid: &str, destination: &str) -> Result<Value> {
        let resp = self
            .client
            .patch(self.url(&format!("/files/{uuid}")))
            .headers(self.auth_headers(token)?)
            .json(&json!({ "destinationFolder": destination }))
            .send()
            .await?;
        Self::check(resp, "moveFile").await
    }

    /// PUT /folders/{uuid}/meta — rename folder.
    pub async fn rename_folder(&self, token: &str, uuid: &str, plain_name: &str) -> Result<()> {
        let resp = self
            .client
            .put(self.url(&format!("/folders/{uuid}/meta")))
            .headers(self.auth_headers(token)?)
            .json(&json!({ "plainName": plain_name }))
            .send()
            .await?;
        Self::check(resp, "renameFolder").await?;
        Ok(())
    }

    /// PUT /files/{uuid}/meta — rename file (plainName + type).
    pub async fn rename_file(
        &self,
        token: &str,
        uuid: &str,
        plain_name: &str,
        file_type: &str,
    ) -> Result<()> {
        let resp = self
            .client
            .put(self.url(&format!("/files/{uuid}/meta")))
            .headers(self.auth_headers(token)?)
            .json(&json!({ "plainName": plain_name, "type": file_type }))
            .send()
            .await?;
        Self::check(resp, "renameFile").await?;
        Ok(())
    }

    /// POST /storage/trash/add — move items to trash. `items` = [{uuid,type}].
    pub async fn trash_items(&self, token: &str, items: Value) -> Result<()> {
        let resp = self
            .client
            .post(self.url("/storage/trash/add"))
            .headers(self.auth_headers(token)?)
            .json(&json!({ "items": items }))
            .send()
            .await?;
        Self::check(resp, "trashItems").await?;
        Ok(())
    }

    /// One page of trash; `kind` is "files" or "folders". Personal uses
    /// `/storage/trash/paginated`; workspace uses `/workspaces/{id}/trash` with a
    /// singular `type` (`file`/`folder`).
    pub async fn trash_paginated(&self, token: &str, kind: &str, offset: u32) -> Result<Value> {
        let path = match &self.workspace {
            Some((id, _)) => {
                let ws_type = if kind == "folders" { "folder" } else { "file" };
                format!("/workspaces/{id}/trash?offset={offset}&limit=50&type={ws_type}")
            }
            None => {
                format!("/storage/trash/paginated?limit=50&offset={offset}&type={kind}&root=true")
            }
        };
        let resp = self
            .client
            .get(self.url(&path))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "getTrashPaginated").await
    }

    /// Empty the trash permanently. Personal: DELETE /storage/trash/all;
    /// workspace: DELETE /workspaces/{id}/trash.
    pub async fn clear_trash(&self, token: &str) -> Result<()> {
        let path = match &self.workspace {
            Some((id, _)) => format!("/workspaces/{id}/trash"),
            None => "/storage/trash/all".to_string(),
        };
        let resp = self
            .client
            .delete(self.url(&path))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "clearTrash").await?;
        Ok(())
    }

    /// DELETE /files/{uuid} — permanently delete a file.
    pub async fn delete_file(&self, token: &str, uuid: &str) -> Result<()> {
        let resp = self
            .client
            .delete(self.url(&format!("/files/{uuid}")))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "deleteFile").await?;
        Ok(())
    }

    /// DELETE /folders/{uuid} — permanently delete a folder.
    pub async fn delete_folder(&self, token: &str, uuid: &str) -> Result<()> {
        let resp = self
            .client
            .delete(self.url(&format!("/folders/{uuid}")))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "deleteFolder").await?;
        Ok(())
    }

    // ---- backups ----
    //
    // The desktop app represents each backed-up device as a special Drive
    // folder ("device as folder"): `GET /backup/deviceAsFolder` lists them,
    // and browsing/downloading what's backed up is just ordinary folder
    // listing/download against that folder's uuid — no dedicated endpoints or
    // client-side decryption needed beyond what folders already require
    // (names are stored server-side plaintext, like other Drive folders).
    // Personal-account only: backups have no workspace-scoped variant.

    /// GET /backup/deviceAsFolder — list backup devices (each a Drive folder).
    pub async fn get_backup_devices(&self, token: &str) -> Result<Value> {
        let resp = self
            .client
            .get(self.url("/backup/deviceAsFolder"))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "getBackupDevices").await
    }

    /// POST /backup/deviceAsFolder — create a backup device (a new Drive
    /// folder registered as a device). Lets a headless/scripted `ixr` upload
    /// register itself as a backup device without the desktop app.
    pub async fn create_backup_device(&self, token: &str, name: &str) -> Result<Value> {
        let resp = self
            .client
            .post(self.url("/backup/deviceAsFolder"))
            .headers(self.auth_headers(token)?)
            .json(&json!({ "deviceName": name }))
            .send()
            .await?;
        Self::check(resp, "createBackupDevice").await
    }

    /// PATCH /backup/deviceAsFolder/{uuid} — rename a backup device.
    pub async fn rename_backup_device(&self, token: &str, uuid: &str, name: &str) -> Result<Value> {
        let resp = self
            .client
            .patch(self.url(&format!("/backup/deviceAsFolder/{uuid}")))
            .headers(self.auth_headers(token)?)
            .json(&json!({ "deviceName": name }))
            .send()
            .await?;
        Self::check(resp, "renameBackupDevice").await
    }

    /// DELETE /backup/deviceAsFolder/{uuid} — delete a backup device and
    /// everything backed up to it. Same call the desktop app's own "delete
    /// device" action makes; unlike Drive files/folders, backups have no
    /// trash to recover from, so this is effectively permanent.
    pub async fn delete_backup_device(&self, token: &str, uuid: &str) -> Result<()> {
        let resp = self
            .client
            .delete(self.url(&format!("/backup/deviceAsFolder/{uuid}")))
            .headers(self.auth_headers(token)?)
            .send()
            .await?;
        Self::check(resp, "deleteBackupDevice").await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{encode_path, encode_segment};
    use crate::models::{SearchFilters, SearchResult};

    #[test]
    fn encode_path_keeps_separators_and_unreserved() {
        assert_eq!(encode_path("/dir/notes.txt"), "/dir/notes.txt");
        assert_eq!(encode_path("/a-b_c.d~e/f"), "/a-b_c.d~e/f");
    }

    #[test]
    fn encode_path_escapes_space_as_percent_20_not_plus() {
        assert_eq!(
            encode_path("/TestingZone/Untitled design.zip"),
            "/TestingZone/Untitled%20design.zip"
        );
    }

    #[test]
    fn encode_path_escapes_query_breaking_characters() {
        // These are legal in a Drive filename and would otherwise truncate or
        // corrupt the query string — the bug og's raw interpolation has.
        assert_eq!(encode_path("/a&b"), "/a%26b");
        assert_eq!(encode_path("/a?b"), "/a%3Fb");
        assert_eq!(encode_path("/a#b"), "/a%23b");
        assert_eq!(encode_path("/100%"), "/100%25");
        assert_eq!(encode_path("/a+b"), "/a%2Bb");
    }

    #[test]
    fn encode_path_escapes_non_ascii_as_utf8_bytes() {
        assert_eq!(encode_path("/café"), "/caf%C3%A9");
    }

    #[test]
    fn encode_segment_escapes_slashes_too() {
        // A search term is one path segment: a `/` in it must not split the URL.
        assert_eq!(encode_segment("a/b"), "a%2Fb");
        assert_eq!(encode_segment("q1 report?"), "q1%20report%3F");
    }

    #[test]
    fn search_filters_omit_unset_fields() {
        let empty = serde_json::to_value(SearchFilters::default()).unwrap();
        assert_eq!(empty, serde_json::json!({}));

        let filters = SearchFilters {
            offset: Some(20),
            types: vec!["jpg".into(), "folder".into()],
            max_size: Some(1073741824),
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_value(filters).unwrap(),
            serde_json::json!({
                "offset": 20,
                "type": ["jpg", "folder"],
                "maxSize": 1073741824u64,
            })
        );
    }

    #[test]
    fn search_result_tolerates_null_rank_and_missing_item() {
        let hit: SearchResult = serde_json::from_value(serde_json::json!({
            "id": "1",
            "itemId": "9c3f-…",
            "itemType": "folder",
            "name": "Invoices",
            "rank": null,
            "similarity": 0.42,
        }))
        .unwrap();
        assert_eq!(hit.rank, None);
        assert!(hit.item.is_none());
        assert_eq!(hit.item_type, "folder");
    }
}
