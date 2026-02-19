# crab-mitm

언어: [English](README.md) | **한국어**

`crab-mitm`은 Crab Proxy에서 사용하는 Rust 프록시 엔진입니다.
CLI로 단독 실행할 수 있고, C FFI(`include/crab_mitm.h`)로 임베드할 수 있습니다.

## 주요 기능

- HTTP forward proxy (absolute-form 요청 지원)
- HTTPS `CONNECT` 처리(정책에 따라 tunnel 또는 MITM)
- 규칙 엔진:
  - Allowlist(HTTPS MITM 대상 제어)
  - `map_local`(로컬 파일/텍스트로 응답 대체)
  - `map_remote`(URL prefix 기준 업스트림 대상 리맵, FFI 경유)
  - `status_rewrite`(응답 status code 변경)
- 업스트림 request/response 스트리밍 전달
- 바디 인스펙션(샘플 로그 + 선택적 파일 스풀)
- 인증서 포털(`crab-proxy.local` 계열 호스트)
- FFI 런타임 제어:
  - listen address/port
  - CA 로드/생성
  - rules 갱신
  - throttling
  - LAN client IP allowlist
  - transparent proxy
- 연동용 구조화 로그(`CRAB_JSON ...`)

## 빌드

라이브러리(FFI 임베드용):

```bash
cargo build
```

CLI 바이너리:

```bash
cargo build --release --features cli
```

테스트:

```bash
cargo test
```

## CLI 빠른 시작

1. CA 생성

```bash
./target/release/crab-mitm ca \
  --out-cert ca.crt.pem \
  --out-key ca.key.pem
```

2. 프록시 실행

```bash
./target/release/crab-mitm run \
  --listen 127.0.0.1:8080 \
  --ca-cert ca.crt.pem \
  --ca-key ca.key.pem \
  --config crab-mitm.example.toml \
  --inspect-body \
  --inspect-sample-bytes 16384
```

참고:

- `--ca-cert/--ca-key` 생략 시 현재 디렉터리의 `ca.crt.pem`, `ca.key.pem` 자동 로드
- CA가 없으면 HTTPS는 tunnel-only(복호화 없음)
- HTTPS MITM은 allowlist 대상 지정도 필요
- 임베드 환경에서는 FFI `crab_proxy_rules_add_allow`로 allow rule 추가

## 인증서 포털(모바일 CA 설치)

호스트:

- `http://crab-proxy.local/`
- `http://crab-proxy.invalid/`
- `http://proxy.crab/`

다운로드 경로:

- `/ca.pem` (PEM)
- `/android.crt` 또는 `/ca.der` (DER)
- `/ios.mobileconfig` (iOS profile)
- `/ca.crl` (CRL)

예시:

```bash
# 포털 페이지
curl -x http://127.0.0.1:8080 http://crab-proxy.local/

# PEM 다운로드
curl -x http://127.0.0.1:8080 http://crab-proxy.local/ca.pem -o crab-proxy-ca.pem
```

제약:

- HTTP `GET`/`HEAD`만 지원
- CA 미로드시 인증서 다운로드는 `503 Service Unavailable`

## 룰 매칭

`match`는 prefix 기반:

- `http://` 또는 `https://` 시작: full URL prefix
- `/` 시작: path prefix(호스트 무관)
- 그 외: `authority + path` prefix (예: `example.com/api`)

### `map_local` (TOML)

`file` 또는 `text` 중 하나만 사용:

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

### CLI 오버라이드(반복 가능)

```bash
./target/release/crab-mitm run --map 'example.com/=./local.txt'
./target/release/crab-mitm run --rewrite-status 'example.com/=418'
./target/release/crab-mitm run --rewrite-status 'example.com/=200:404'
```

CLI 규칙 인자는 config-file 규칙보다 먼저 적용됩니다.

## 바디 인스펙션/스풀

```bash
# 샘플 로그만 (body 당 16 KB)
./target/release/crab-mitm run --inspect-body

# 샘플 로그 + 파일 스풀
./target/release/crab-mitm run --inspect-body --inspect-spool

# 스풀 디렉터리/최대 크기 지정
./target/release/crab-mitm run \
  --inspect-body --inspect-spool \
  --inspect-spool-dir ./spool \
  --inspect-spool-max-bytes 104857600
```

`--inspect-spool`은 바디 데이터를 디스크에 저장합니다. 디스크 사용량/민감정보 정책을 함께 고려하세요.

## C FFI 진입점

`include/crab_mitm.h` 참고.
주요 API:

- `crab_proxy_create`, `crab_proxy_start`, `crab_proxy_stop`, `crab_proxy_destroy`
- `crab_proxy_load_ca`, `crab_ca_generate`, `crab_ca_generate_with_algorithm`
- `crab_proxy_rules_add_allow`, `crab_proxy_rules_add_map_local_file`, `crab_proxy_rules_add_map_remote`, `crab_proxy_rules_add_status_rewrite`
- `crab_proxy_set_throttle_*`, `crab_proxy_set_client_allowlist_enabled`
- `crab_proxy_set_transparent_enabled`, `crab_proxy_set_transparent_port`

## 보안 참고

- 신뢰 가능한 환경에서 디버깅 목적으로 사용하는 것을 권장합니다.
- 신뢰되지 않은 네트워크에 오픈 프록시로 노출하지 마세요.
- FFI map-local 파일 경로는 허용 루트 제약이 있습니다(`CRAB_MAP_LOCAL_ALLOWED_ROOTS`).
