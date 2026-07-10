# Clustara 폐쇄망 연동 설계

## 목표

JASCA가 보관한 Trivy 원본 JSON과 Syft CycloneDX SBOM을 사내 Clustara import API로 안전하게 전송한다. 폐쇄망 런타임에서 외부 다운로드나 클라우드 호출을 추가하지 않으며, Clustara 장애가 JASCA 스캔 저장을 실패시키지 않게 한다.

## 범위

- 관리자 UI에서 Clustara URL, API 경로, 인증 방식, 기본 쿼리 값과 전송 정책을 관리한다.
- 인증 방식은 없음, `X-API-Key`, `Authorization: Bearer`를 지원한다.
- 스캔 상세에서 `cluster_id`, `scanner`, `image_digest`를 확인·수정한 뒤 Trivy 결과를 수동 전송한다.
- 자동 전송은 관리자가 활성화했고 `cluster_id`와 유효한 `sha256:` digest가 모두 있을 때만 등록한다.
- Syft가 실제 생성한 CycloneDX JSON은 임시 업로드 폴더 정리 전에 영구 보관하고 Clustara로 전송할 수 있게 한다.
- 전송 대기, 성공, 실패, 재시도 횟수, HTTP 상태와 마지막 오류를 감사 가능한 형태로 보관한다.

Clustara 데이터를 JASCA로 조회하는 역방향 연동과 Checkov, ZAP, Semgrep 결과 전송은 이번 범위에 포함하지 않는다. 제공된 Clustara 계약이 Trivy와 Syft import API만 정의하기 때문이다.

## API 계약

기본값은 제공된 curl 예시를 그대로 사용하되 관리자 UI에서 수정할 수 있다.

```text
POST {baseUrl}{scanPath}?cluster_id={clusterId}&scanner={scanner}&image_digest={imageDigest}
Content-Type: application/json
Body: JASCA에 저장된 Trivy 원본 JSON

POST {baseUrl}{sbomPath}?image_digest={imageDigest}&generator={generator}
Content-Type: application/json
Body: Syft가 생성한 CycloneDX JSON
```

기본 설정값:

- `scanPath`: `/admin/k8s/security/scans/import`
- `sbomPath`: `/admin/k8s/security/sboms`
- `scanner`: `trivy`
- `generator`: `syft`
- `timeoutSeconds`: `30`
- `maxAttempts`: `3`
- TLS 인증서 검증: 활성화

URL과 쿼리 값은 `URL`과 `URLSearchParams`로 구성해 특수문자를 안전하게 인코딩한다.

## 구성요소

### 관리자 설정

기존 `SystemSettings` 저장 방식을 재사용한다. 설정 키는 `clustara`로 하고 다음 값을 저장한다.

- 사용 여부와 자동 전송 여부
- Base URL, Scan API 경로, SBOM API 경로
- 인증 방식과 인증 비밀값
- 기본 `cluster_id`, `scanner`, `generator`
- 요청 제한시간, 최대 전송 시도 횟수, TLS 검증 여부

비밀값은 조회 API에서 반환하지 않고 `credentialConfigured`만 반환한다. 저장 요청에서 비밀값이 비어 있거나 마스킹 문자열이면 기존 값을 유지한다. 로그, 오류 응답, 실행 증거에는 비밀값을 기록하지 않는다.

### 영구 데이터

`ClustaraDelivery`는 한 건의 외부 전송을 나타낸다.

- 대상 스캔, 유형(`TRIVY` 또는 `SBOM`), 상태
- `clusterId`, `scanner`, `generator`, `imageDigest`
- 시도 횟수, HTTP 상태, 응답 요약, 마지막 오류
- 다음 재시도 시각, 성공 시각, 생성·수정 시각
- 동일 스캔·유형·클러스터·digest 조합의 중복 방지 키

`ScanArtifact`는 보존된 SBOM 파일을 나타낸다.

- 대상 스캔, 유형 `CYCLONEDX_JSON`
- 파일 경로, SHA256, 생성 도구와 버전, 생성 시각

원본 Trivy JSON은 기존 `ScanResult.rawResult`와 `resultFilePath`를 그대로 사용한다.

### 전송 처리

스캔 완료 경로에서는 Clustara HTTP 요청을 직접 기다리지 않는다. 조건이 충족되면 `PENDING` 전송 레코드만 만든다. 주기 작업이 대기 건을 가져와 전송하고 성공 또는 실패 상태를 기록한다.

재시도는 최대 설정 횟수까지 수행하며 다음 시도는 1분, 5분 간격으로 예약한다. `4xx` 인증·검증 오류는 자동 재시도하지 않고, `408`, `429`, `5xx`, 네트워크 및 제한시간 오류만 재시도한다. 관리자는 실패 건을 수동 재전송할 수 있다.

### Digest 결정

다음 순서로 digest를 결정한다.

1. 스캔 요청에 명시된 `imageDigest`
2. Trivy `Metadata.RepoDigests`의 `sha256:` 값
3. Trivy `Metadata.ImageID`의 `sha256:` 값

값은 `sha256:` 뒤에 64자리 16진수가 있는 경우에만 인정한다. 업로드 파일 자체의 SHA256은 OCI 이미지 digest로 대체하지 않는다. digest가 없으면 자동 전송하지 않고 UI에 이유를 표시한다.

### SBOM 보존

`syft-sbom` 전략 또는 자동 보강에서 Syft가 생성한 CycloneDX JSON을 스캔 서비스가 결과와 함께 반환한다. 스캔 저장이 성공하면 `SCAN_RESULT_DIR/artifacts/{scanId}.cdx.json`에 저장하고 `ScanArtifact`를 생성한다. 저장 완료 후에만 임시 업로드 폴더를 정리한다.

SBOM이 생성되지 않은 직접 Trivy 스캔은 Trivy JSON만 전송한다. 이번 범위에서는 전송만을 위해 Syft를 추가 실행하지 않는다.

## UI

### 관리자 → Clustara 연동

- 연결 활성화와 자동 전송 토글
- Base URL과 두 API 경로
- 인증 방식 선택과 비밀값 입력
- 기본 cluster ID, scanner, generator
- 제한시간, 최대 시도 횟수, TLS 검증
- 저장, 연결 테스트, 전송 이력 새로고침
- 최근 전송 목록과 실패 사유, 재전송 작업

연결 테스트는 실제 import API에 가짜 결과를 넣지 않는다. Base URL의 DNS, TCP, TLS 연결까지만 검사하고, Clustara가 비파괴 상태 API를 제공하지 않는 현재 계약에서는 인증 검증 여부를 별도로 표시한다.

### 스캔 상세

Trivy 스캔에만 Clustara 패널을 표시한다. 기본 설정을 채운 전송 폼에서 `cluster_id`, `scanner`, `image_digest`를 수정할 수 있다. 유효하지 않은 digest는 제출 전에 차단한다. 저장된 SBOM이 있으면 Trivy 결과와 SBOM을 각각 선택해 전송할 수 있다.

## 권한

- 연동 설정 조회·수정과 전체 전송 이력: `SYSTEM_ADMIN`, `SECURITY_ADMIN`
- 스캔 상세 수동 전송: `PROJECT_ADMIN`, `ORG_ADMIN`, `SECURITY_ADMIN`, `SYSTEM_ADMIN`
- 일반 사용자는 전송 상태만 조회한다.
- 기존 조직 및 프로젝트 접근 검사를 모든 스캔 단위 API에 적용한다.

## 오류 처리와 운영 안전성

- Clustara 오류는 JASCA 스캔 결과와 정책 평가를 롤백하지 않는다.
- 응답 본문은 최대 1,000자만 저장하고 HTML과 인증정보를 노출하지 않는다.
- 동시 작업자가 같은 전송을 처리하지 않도록 원자적으로 상태를 `SENDING`으로 변경한다.
- 프로세스 중단으로 오래 남은 `SENDING` 건은 다음 기동 시 `PENDING`으로 복구한다.
- 파일이 삭제된 SBOM 전송은 HTTP 요청 전에 실패 처리한다.
- TLS 검증 해제는 관리자 UI에 경고를 표시하고 기본값으로 사용하지 않는다.

## 폐쇄망 배포

- 런타임 외부 다운로드를 수행하지 않는다.
- JASCA 컨테이너에서 Clustara 도메인의 DNS 해석과 443/TCP 연결이 가능해야 한다.
- 사내 CA 파일은 컨테이너에 읽기 전용 마운트하고 Node 신뢰 저장소에 추가한다.
- Docker 및 Kubernetes 배포 예시에 Clustara API 비밀값과 CA 마운트 방법을 추가한다.

## 검증 기준

- 없음, X-API-Key, Bearer 인증 요청 헤더가 각각 정확하다.
- API 경로와 쿼리 값 변경이 실제 요청 URL에 반영된다.
- Trivy 원본 JSON과 CycloneDX 원본 JSON이 변환 없이 전송된다.
- 잘못된 digest와 접근 권한은 HTTP 요청 전에 거부된다.
- `2xx` 성공, `4xx` 영구 실패, `5xx` 및 제한시간 재시도가 구분된다.
- 중복 전송 요청은 기존 전송 건을 반환한다.
- Clustara가 중단돼도 JASCA 스캔은 저장되고 실패 이력이 남는다.
- Syft SBOM 파일은 업로드 임시 폴더 삭제 후에도 다운로드·전송 가능하다.
- 관리자 설정과 스캔 상세 UI를 브라우저에서 검증한다.
- API 및 Web 빌드, 단위 테스트, Prisma 마이그레이션, `linux/amd64` 모놀리식 Docker 빌드를 통과한다.
