//! VPN API client (anonymous token + available locations) and the proxy
//! server's connection details. No official CLI ports this, so there's no
//! og/cli source to mirror.
//!
//! The VPN is not a tunnel: it's a single shared, **plain HTTP** (no TLS to
//! the proxy hop itself — confirmed against the live endpoint, see
//! `config::vpn_proxy_host`, and against the official browser extension's
//! own traffic) forward proxy for every location, tunneling HTTPS traffic
//! via CONNECT same as any HTTP proxy. The location is selected
//! per-connection via the Proxy-Authorization *username*; the *password* is
//! the same Drive session token every other API call already uses (see
//! [`proxy_credentials`]). Because the hop is unencrypted, that token
//! travels in the clear on the wire — anyone on-path between the client and
//! the proxy can read it, and the token itself decodes to the account's
//! email and name. Front-ends own the actual local listener/relay that
//! speaks to this proxy — this module only supplies the endpoint and
//! credentials it needs.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use serde_json::Value;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use crate::config;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A VPN location/zone. Mirrors og/vpn's `VPNLocation` union
/// (og/vpn/src/entrypoints/popup/App.tsx) — the same code doubles as the
/// Proxy-Authorization username on the shared proxy endpoint. Availability
/// is plan-gated server-side (see [`VpnApi::available_locations`]), not
/// enforced here.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VpnLocation {
    France,
    Germany,
    Poland,
    Canada,
    UnitedKingdom,
    /// A zone code the server returned (or the user passed) that isn't one
    /// of the five above yet. Carried through as-is instead of being
    /// dropped, so a location Internxt adds server-side still shows up
    /// (usable, just without a friendly `label()`) instead of silently
    /// disappearing until this enum gets updated.
    Other(String),
}

impl VpnLocation {
    /// The wire code — proxy username and `/users` zones-list entry.
    pub fn code(&self) -> &str {
        match self {
            VpnLocation::France => "FR",
            VpnLocation::Germany => "DE",
            VpnLocation::Poland => "PL",
            VpnLocation::Canada => "CA",
            VpnLocation::UnitedKingdom => "UK",
            VpnLocation::Other(code) => code,
        }
    }

    /// A human-readable name, when known. `None` for [`VpnLocation::Other`]
    /// — there's nothing to show but the raw code.
    pub fn label(&self) -> Option<&str> {
        match self {
            VpnLocation::France => Some("France"),
            VpnLocation::Germany => Some("Germany"),
            VpnLocation::Poland => Some("Poland"),
            VpnLocation::Canada => Some("Canada"),
            VpnLocation::UnitedKingdom => Some("United Kingdom"),
            VpnLocation::Other(_) => None,
        }
    }

    /// The five locations this build knows a friendly label for. Doesn't
    /// include [`VpnLocation::Other`] — there's no fixed instance of it.
    pub const ALL: [VpnLocation; 5] = [
        VpnLocation::France,
        VpnLocation::Germany,
        VpnLocation::Poland,
        VpnLocation::Canada,
        VpnLocation::UnitedKingdom,
    ];
}

impl fmt::Display for VpnLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl FromStr for VpnLocation {
    type Err = anyhow::Error;

    /// Recognized codes map to their named variant; any other
    /// well-formed code (ASCII alphanumeric, matching what a
    /// Proxy-Authorization username / zones-list entry can actually hold)
    /// becomes [`VpnLocation::Other`] rather than failing — the server, not
    /// this list, is authoritative on what's usable.
    fn from_str(s: &str) -> Result<Self> {
        if let Some(l) = VpnLocation::ALL.into_iter().find(|l| l.code().eq_ignore_ascii_case(s)) {
            return Ok(l);
        }
        let code = s.trim().to_ascii_uppercase();
        if code.is_empty() || !code.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(anyhow!("invalid VPN location code {s:?}"));
        }
        Ok(VpnLocation::Other(code))
    }
}

/// Host/port of the shared proxy server (gost) every location connects
/// through — see [`config::vpn_proxy_host`]/[`config::vpn_proxy_port`].
#[derive(Debug, Clone)]
pub struct VpnProxyServer {
    pub host: String,
    pub port: u16,
}

pub fn proxy_server() -> VpnProxyServer {
    VpnProxyServer { host: config::vpn_proxy_host(), port: config::vpn_proxy_port() }
}

/// Builds the `Proxy-Authorization: Basic ...` header value for `location`,
/// authenticated with `token` (the same Drive session token used for every
/// other API call — mirrors og/vpn's background.ts, which sends the user's
/// Drive JWT as the proxy password).
pub fn proxy_credentials(location: &VpnLocation, token: &str) -> String {
    format!("Basic {}", B64.encode(format!("{}:{token}", location.code())))
}

pub struct VpnApi {
    client: Client,
    base: String,
}

impl Default for VpnApi {
    fn default() -> Self {
        Self::new()
    }
}

impl VpnApi {
    pub fn new() -> Self {
        let client = Client::builder()
            .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
            .timeout(DEFAULT_REQUEST_TIMEOUT)
            .build()
            .unwrap_or_default();
        VpnApi { client, base: config::vpn_api_url() }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
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

    /// GET /users/anonymous/token -> a short-lived token usable as the proxy
    /// password without a Drive login (mirrors og/vpn's pre-auth fallback).
    /// `internxt-cli-rust` doesn't need this — it's always logged in and
    /// reuses that session token instead — but an embedder without a Drive
    /// account can still get online with it.
    pub async fn anonymous_token(&self) -> Result<String> {
        let resp = self.client.get(self.url("/users/anonymous/token")).send().await?;
        let v = Self::check(resp, "vpn anonymousToken").await?;
        v["token"].as_str().map(str::to_string).ok_or_else(|| anyhow!("no token in response: {v}"))
    }

    /// GET /users (Bearer `token`) -> the zones this account's plan can use.
    /// Server-enforced (Free=FR, Premium=+DE/PL, Ultimate=+CA/UK at the time
    /// of writing, per og/vpn's dropdown grouping) — parses whatever codes
    /// come back rather than hardcoding the tier mapping, so a plan change
    /// on Internxt's side doesn't need a client update. A code this build
    /// doesn't recognize comes back as `VpnLocation::Other` rather than
    /// being dropped — see its doc comment.
    pub async fn available_locations(&self, token: &str) -> Result<Vec<VpnLocation>> {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {token}"))?);
        let resp = self.client.get(self.url("/users")).headers(headers).send().await?;
        let v = Self::check(resp, "vpn availableLocations").await?;
        let zones = v["zones"].as_array().ok_or_else(|| anyhow!("no zones in response: {v}"))?;
        Ok(zones.iter().filter_map(|z| z.as_str()).filter_map(|code| VpnLocation::from_str(code).ok()).collect())
    }
}
