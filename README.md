# crab-mitm

Rust로 만든 간단한 MITM 프록시(HTTP/HTTPS)입니다. 네트워크 디버깅 용도로:

- HTTP 프록시 (absolute-form 요청 지원)
- HTTPS `CONNECT` MITM (CA 필요)
- `map_local` (로컬 파일/텍스트로 응답 대체)
- `status_rewrite` (응답 status code 변경)
- 업스트림 request/response body 스트리밍 전달 (대용량 대응)
- 바디 인스펙션 (샘플 로그 + 선택적 파일 스풀)
- CLI 기반 설정 (TOML 파일 또는 CLI 플래그)
- 인증서 포털 (Android/iOS/PEM CA 다운로드 페이지 제공)

## 설치/빌드

```bash
cargo build --release --features cli
cargo test
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
  --config crab-mitm.example.toml \
  --inspect-body --inspect-sample-bytes 16384
```

`--ca-cert/--ca-key`를 생략해도 현재 디렉토리에 `ca.crt.pem`, `ca.key.pem`이 있으면 자동 로드됩니다.  
CA를 로드하지 못하면(옵션 미지정 + 기본 파일 없음) HTTPS는 **터널링만** 하고(MITM 아님) `map_local/status_rewrite`는 HTTPS에 적용되지 않습니다.

## 인증서 포털 (모바일 CA 설치)

프록시 실행 중 아래 HTTP 호스트로 접속하면 인증서 다운로드 페이지를 제공합니다.

- `http://crab-proxy.local/`
- `http://crab-proxy.invalid/`
- `http://proxy.crab/`

다운로드 경로:

- `/ca.pem` (PEM)
- `/android.crt` (DER, Android)
- `/ios.mobileconfig` (iOS 구성 프로파일)

```bash
# 포털 페이지 확인
curl -x http://127.0.0.1:8080 http://crab-proxy.local/

# CA PEM 다운로드
curl -x http://127.0.0.1:8080 http://crab-proxy.local/ca.pem -o crab-proxy-ca.pem
```

주의:

- 인증서 포털은 HTTP의 `GET/HEAD`만 지원합니다.
- CA가 로드되지 않은 상태에서는 다운로드 엔드포인트가 `503 Service Unavailable`을 반환합니다.

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

### 바디 인스펙션

업스트림으로 전달되는 요청/응답 바디를 스트리밍하면서 관찰할 수 있습니다.

```bash
# 샘플 로그만 (각 바디 앞 16KB)
./target/release/crab-mitm run --inspect-body

# 샘플 로그 + 파일 스풀 (임시 디렉토리에 저장)
./target/release/crab-mitm run --inspect-body --inspect-spool

# 스풀 디렉토리/최대 크기 지정
./target/release/crab-mitm run \
  --inspect-body --inspect-spool \
  --inspect-spool-dir ./spool \
  --inspect-spool-max-bytes 104857600
```

`--inspect-spool`은 바디를 파일로 저장하므로 디스크 사용량과 민감정보 보관 정책을 함께 고려하세요.

## 주의

- 디버깅 목적의 도구입니다. 외부에 열린 프록시로 사용하지 마세요.
- 업스트림 request/response는 스트리밍 전달되지만, `--inspect-spool` 사용 시 디스크 I/O가 증가할 수 있습니다.
