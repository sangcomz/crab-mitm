# crab-mitm

Language: **English (default)** | [한국어](README.ko.md)

## English (Default)

`crab-mitm` is the Rust proxy engine behind Crab Proxy.
It supports standalone CLI usage and embedding via C FFI (`include/crab_mitm.h`).

## Features

- HTTP forward proxy (absolute-form requests).
- HTTPS `CONNECT` handling (tunnel or MITM based on policy).
- Rule engine:
  - Allowlist (controls HTTPS MITM targets).
  - `map_local` (replace response with local file/text).
  - `map_remote` (rewrite upstream destination by URL prefix, via FFI).
  - `status_rewrite` (rewrite upstream status code).
- Streaming upstream request/response forwarding.
- Body inspection (sample logging + optional file spool).
- Mobile certificate portal (`crab-proxy.local` and aliases).
- Runtime controls through FFI:
  - Listen address/port
  - CA load/generate
  - Rules update
  - Throttling
  - LAN client IP allowlist
  - Transparent proxy settings
- Structured log lines for integration (`CRAB_JSON ...`).

## Build

Library (for embedding/FFI):

```bash
cargo build
```

CLI binary:

```bash
cargo build --release --features cli
```

Tests:

```bash
cargo test
```

## CLI Quick Start

1. Generate CA files:

```bash
./target/release/crab-mitm ca \
  --out-cert ca.crt.pem \
  --out-key ca.key.pem
```

2. Run proxy:

```bash
./target/release/crab-mitm run \
  --listen 127.0.0.1:8080 \
  --ca-cert ca.crt.pem \
  --ca-key ca.key.pem \
  --config crab-mitm.example.toml \
  --inspect-body \
  --inspect-sample-bytes 16384
```

Notes:

- If `--ca-cert/--ca-key` are omitted, `ca.crt.pem` and `ca.key.pem` are auto-loaded from current directory when present.
- If CA is not loaded, HTTPS stays tunnel-only (no MITM/decryption).
- HTTPS MITM also requires allowlist targets. In embedded use, add allow rules via FFI (`crab_proxy_rules_add_allow`).

## Certificate Portal (Mobile CA Install)

Hosts:

- `http://crab-proxy.local/`
- `http://crab-proxy.invalid/`
- `http://proxy.crab/`

Download endpoints:

- `/ca.pem` (PEM)
- `/android.crt` or `/ca.der` (DER)
- `/ios.mobileconfig` (iOS profile)
- `/ca.crl` (CRL)

Examples:

```bash
# Portal page
curl -x http://127.0.0.1:8080 http://crab-proxy.local/

# Download PEM
curl -x http://127.0.0.1:8080 http://crab-proxy.local/ca.pem -o crab-proxy-ca.pem
```

Portal constraints:

- Supports only HTTP `GET`/`HEAD`.
- If CA is not loaded, certificate downloads return `503 Service Unavailable`.

## Rule Matching

`match` is prefix-based:

- Starts with `http://` or `https://`: full URL prefix.
- Starts with `/`: path prefix (host-independent).
- Otherwise: `authority + path` prefix (example: `example.com/api`).

### `map_local` (TOML)

Use exactly one of `file` or `text`.

```toml
[[map_local]]
match = "example.com/"
file = "./examples/local.txt"
status = 200
content_type = "text/plain; charset=utf-8"
```

### `status_rewrite` (TOML)

```toml
[[status_rewrite]]
match = "example.com/"
to = 418

[[status_rewrite]]
match = "/api"
from = 200
to = 503
```

### CLI overrides (repeatable)

```bash
./target/release/crab-mitm run --map 'example.com/=./local.txt'
./target/release/crab-mitm run --rewrite-status 'example.com/=418'
./target/release/crab-mitm run --rewrite-status 'example.com/=200:404'
```

CLI rule arguments are applied before config-file rules.

## Body Inspection and Spool

```bash
# Sample log only (16 KB per body)
./target/release/crab-mitm run --inspect-body

# Sample log + file spool
./target/release/crab-mitm run --inspect-body --inspect-spool

# Custom spool directory/size cap
./target/release/crab-mitm run \
  --inspect-body --inspect-spool \
  --inspect-spool-dir ./spool \
  --inspect-spool-max-bytes 104857600
```

`--inspect-spool` writes body data to disk. Handle disk usage and sensitive-data policy accordingly.

## C FFI Entry Points

See `include/crab_mitm.h`.
Common calls:

- `crab_proxy_create`, `crab_proxy_start`, `crab_proxy_stop`, `crab_proxy_destroy`
- `crab_proxy_load_ca`, `crab_ca_generate`, `crab_ca_generate_with_algorithm`
- `crab_proxy_rules_add_allow`, `crab_proxy_rules_add_map_local_file`, `crab_proxy_rules_add_map_remote`, `crab_proxy_rules_add_status_rewrite`
- `crab_proxy_set_throttle_*`, `crab_proxy_set_client_allowlist_enabled`
- `crab_proxy_set_transparent_enabled`, `crab_proxy_set_transparent_port`

## Security Notes

- Intended for debugging in trusted environments.
- Do not expose as an open proxy on untrusted networks.
- When using map-local file paths through FFI, paths are restricted to allowed roots (see `CRAB_MAP_LOCAL_ALLOWED_ROOTS`).
