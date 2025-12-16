# crab-mitm

Rust로 만든 간단한 MITM 프록시(HTTP/HTTPS)입니다. 네트워크 디버깅 용도로:

- HTTP 프록시 (absolute-form 요청 지원)
- HTTPS `CONNECT` MITM (CA 필요)
- `map_local` (로컬 파일/텍스트로 응답 대체)
- `status_rewrite` (응답 status code 변경)
- CLI 기반 설정 (TOML 파일 또는 CLI 플래그)

## 설치/빌드

```bash
cargo build --release
```

## CA 생성 (HTTPS MITM용)

```bash
./target/release/crab-mitm ca --out-cert ca.crt.pem --out-key ca.key.pem
```

브라우저/OS에 `ca.crt.pem`을 **신뢰(Trusted)** 하도록 설치해야 HTTPS가 MITM 됩니다.

## 실행

```bash
./target/release/crab-mitm run \
  --listen 127.0.0.1:8080 \
  --ca-cert ca.crt.pem --ca-key ca.key.pem \
  --config crab-mitm.example.toml
```

CA를 제공하지 않으면 HTTPS는 **터널링만** 하고(MITM 아님) `map_local/status_rewrite`는 HTTPS에 적용되지 않습니다.

## 사용 예 (curl)

```bash
# HTTP
curl -x http://127.0.0.1:8080 http://example.com/

# HTTPS (MITM) - curl이 프록시가 제시하는 서버 인증서를 검증하므로 CA를 신뢰시켜야 함
curl -x http://127.0.0.1:8080 https://example.com/ --cacert ca.crt.pem
```

## 규칙 설정

규칙은 TOML 파일(`--config`) 또는 CLI 플래그로 넣을 수 있습니다.  
CLI로 지정한 규칙이 config 파일보다 **우선** 적용됩니다.

### 매칭(match) 규칙

`match`는 **prefix 매칭**입니다.

- `http://` 또는 `https://`로 시작: `scheme://authority/path?...` 전체 URL prefix 매칭
- `/`로 시작: path prefix 매칭 (호스트 무관)
- 그 외: `authority + path` prefix 매칭 (예: `example.com/api`)

### map_local (TOML)

`file` 또는 `text` 중 하나를 지정합니다.

```toml
[[map_local]]
match = "example.com/"
file = "./examples/local.txt"
status = 200
content_type = "text/plain; charset=utf-8"
```

### status_rewrite (TOML)

```toml
[[status_rewrite]]
match = "example.com/"
to = 418

[[status_rewrite]]
match = "/api"
from = 200
to = 503
```

### CLI (반복 가능)

```bash
# map_local (file)
./target/release/crab-mitm run --map 'example.com/=./local.txt'

# status rewrite
./target/release/crab-mitm run --rewrite-status 'example.com/=418'
./target/release/crab-mitm run --rewrite-status 'example.com/=200:404'
```

## 주의

- 디버깅 목적의 도구입니다. 외부에 열린 프록시로 사용하지 마세요.
- 현재 구현은 request/response body를 메모리에 수집(버퍼링)합니다. 큰 파일/스트리밍에는 적합하지 않습니다.
