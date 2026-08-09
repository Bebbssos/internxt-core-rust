# internxt-core-rust

Unofficial Rust engine for [Internxt Drive](https://internxt.com): authentication,
end-to-end crypto, the Drive REST API, and fully streaming network transfers.
Also covers the Internxt VPN (locations + proxy credentials, `vpn` feature,
off by default) — see [Features](#features).

> Not affiliated with or endorsed by Internxt.

> Written mostly by [Claude Code](https://claude.com/claude-code), porting the
> behaviour of Internxt's official Node/TypeScript packages.

This crate is the protocol-agnostic core used by
[`internxt-cli-rust`](https://github.com/Bebbssos/internxt-cli-rust). It has no
terminal, clap, or filesystem-credential dependencies, so it works equally under a CLI,
a WebDAV/FUSE server, or a GUI. Progress reporting, 2FA, browser-open, and
refresh-warning are injected as closures/traits by the caller.

## Status

Early development. The library surface is not yet stable — expect breaking changes
between `0.x` releases.

## Features

- `fs` *(default)* — native filesystem + runtime-bound transfer helpers
  (path-based upload, multipart upload, `create_folder_with_retry`). Pulls in
  `tokio::fs` / `tokio::spawn` / `tokio::time`. Disable to build only the
  reader/writer surface (crypto, api, network, and the generic streaming
  `upload_stream_to_network` / `download_file_to_writer`).
- `thumbnails` *(default)* — image thumbnail generation (decode/resize/encode a
  300×300 PNG preview). Pulls in `image`.
- `vpn` *(off)* — the Internxt VPN's locations/anonymous-token API
  (`vpn::VpnApi`) and the shared proxy server's connection details
  (`vpn::proxy_server`, `vpn::proxy_credentials`; a plain, not TLS-wrapped,
  HTTP CONNECT proxy). No extra deps — reuses the `reqwest` client already
  unconditionally present. There's no official CLI to mirror here — the VPN
  otherwise only ships as a browser extension. The actual local
  listener/relay that speaks to this proxy is a front-end concern (see
  `internxt-cli-rust`'s `vpn locations`/`vpn proxy`), not part of this
  crate.

## Crypto compatibility

Crypto is byte-for-byte compatible with the official Node implementation, checked
against reference test vectors (`cargo test`, no network).

## License

[MIT](LICENSE).
