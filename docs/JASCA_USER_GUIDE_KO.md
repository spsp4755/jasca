# JASCA 사용자 가이드

이 문서는 JASCA 일반 사용자가 로그인, 프로젝트 조회, 스캔 업로드, 취약점 처리, 라이선스 확인, 정책 확인, API 연동까지 수행할 수 있도록 작성된 사용자 설명서입니다.

## 1. JASCA 개요

JASCA는 Trivy 스캔 결과를 중앙에서 수집하고, 프로젝트별 취약점과 라이선스 위험을 추적하며, 정책과 워크플로우를 통해 조치 상태를 관리하는 보안 취약점 관리 시스템입니다.

JASCA에서 할 수 있는 주요 작업은 다음과 같습니다.

- Trivy JSON 또는 SARIF 결과 파일 업로드
- 검사 대상 파일을 직접 업로드해 서버에서 Trivy 검사 실행
- 프로젝트별 스캔 이력과 취약점 현황 확인
- 취약점 상태 변경, 담당자 지정, 댓글 기록
- 라이선스 검출 결과 확인
- 정책 위반 여부 확인
- Trivy DB 상태 확인
- API 토큰을 이용한 CI/CD 또는 외부 시스템 연동
- 알림과 개인 설정 관리

## 2. 기본 접속과 로그인

### 2.1 접속

브라우저에서 운영 URL로 접속합니다.

예시:

```text
https://jasca.example.com
```

폐쇄망 배포 환경에서 포트가 직접 노출된 경우 다음과 같은 형태일 수 있습니다.

```text
http://서버주소:3005
```

### 2.2 로그인

1. 로그인 화면에서 이메일과 비밀번호를 입력합니다.
2. SSO가 활성화된 환경이면 SSO 버튼을 사용합니다.
3. MFA가 활성화된 계정은 인증 앱의 6자리 코드를 입력합니다.
4. 로그인 후 `/dashboard`로 이동합니다.

### 2.3 회원가입

1. 회원가입 화면으로 이동합니다.
2. 조직을 선택하거나 관리자로부터 받은 초대 코드를 입력합니다.
3. 이름, 이메일, 비밀번호를 입력합니다.
4. 관리자가 승인 또는 초대 기반 가입을 사용하는 경우 조직 정책에 따라 접근 권한이 부여됩니다.

## 3. 화면 구성

사용자 화면의 기본 메뉴는 다음과 같습니다.

| 메뉴 | 경로 | 설명 |
| --- | --- | --- |
| 대시보드 | `/dashboard` | 전체 취약점, 프로젝트, 최근 스캔, 주요 지표 요약 |
| 프로젝트 | `/dashboard/projects` | 프로젝트 목록과 프로젝트 상세 현황 |
| 스캔 결과 | `/dashboard/scans` | 업로드/검사된 스캔 결과 목록 |
| 취약점 | `/dashboard/vulnerabilities` | 전체 취약점 검색, 필터, 상태 관리 |
| 라이선스 | `/dashboard/licenses` | 패키지 라이선스 검출 결과와 위험 분류 |
| Trivy DB | `/dashboard/trivy-db` | Trivy DB 상태 확인과 DB 파일 관리 기능 |
| 정책 | `/dashboard/policies` | 적용 정책과 정책 위반 결과 확인 |
| API 토큰 | `/dashboard/api-tokens` | 외부 연동용 API 토큰 생성 및 삭제 |
| 연동 가이드 | `/dashboard/guide` | CI/CD 및 API 연동 예시 |
| 알림 | `/dashboard/notifications` | 사용자 알림 목록과 읽음 처리 |
| 설정 | `/dashboard/settings` | 개인 프로필, 대시보드, 알림 설정 |
| 프로필 | `/dashboard/profile` | 계정 정보, 비밀번호, MFA, 세션 관리 |
| 알림 설정 | `/dashboard/settings/notifications` | 개인 알림 수신 조건 관리 |
| Trivy 명령 가이드 | `/dashboard/settings/trivy-guide` | 환경별 Trivy 명령 생성과 실행 예시 |
| 사이트맵 | `/dashboard/sitemap` | 사용자 메뉴 전체 구조 확인 |

일부 메뉴는 역할에 따라 보이지 않을 수 있습니다.

## 4. 대시보드 사용법

대시보드는 JASCA에 로그인했을 때 가장 먼저 확인하는 화면입니다.

### 4.1 주요 지표

대시보드에서 다음 항목을 확인합니다.

- 전체 취약점 수
- 심각도별 취약점 수
- 미해결 취약점 수
- 프로젝트 수
- 최근 스캔 결과
- 최근 Critical/High 취약점
- 취약점 추세

### 4.2 빠른 작업

대시보드 또는 상단/사이드 메뉴에서 다음 작업으로 이동할 수 있습니다.

- 새 스캔 시작
- 취약점 목록 조회
- 프로젝트 목록 조회
- 리포트 확인
- 설정 변경

### 4.3 검색

상단 검색 또는 검색 입력창에서 다음 키워드로 조회할 수 있습니다.

- CVE ID
- 패키지명
- 프로젝트명
- 이미지명
- 취약점 제목

## 5. 프로젝트 사용법

프로젝트는 JASCA에서 스캔 결과와 취약점을 묶는 기본 단위입니다.

### 5.1 프로젝트 목록

`프로젝트` 메뉴에서 다음 정보를 확인합니다.

- 프로젝트 이름
- 소속 조직
- 최근 스캔 일시
- 취약점 수
- 심각도별 분포
- 라이선스 현황
- 위험도 요약

### 5.2 프로젝트 상세

프로젝트를 선택하면 프로젝트 상세 화면으로 이동합니다.

상세 화면에서 확인할 수 있는 항목은 다음과 같습니다.

- 프로젝트 기본 정보
- 최근 스캔 결과
- 취약점 목록
- 심각도 분포
- 스캔 추세
- 정책 적용 결과
- 라이선스 현황

### 5.3 프로젝트 생성

일반 사용자는 권한에 따라 직접 프로젝트를 생성하지 못할 수 있습니다. 스캔 업로드 화면에서 `새 프로젝트`를 선택하면 권한이 있는 경우 프로젝트를 자동 생성하면서 스캔을 저장할 수 있습니다.

필요 정보:

- 프로젝트 이름
- 조직
- 설명
- 스캔 대상 또는 Trivy 결과 파일

## 6. 스캔 결과 사용법

스캔 결과 메뉴는 업로드된 모든 스캔 이력을 확인하는 화면입니다.

### 6.1 스캔 결과 목록

`스캔 결과` 메뉴에서 다음 정보를 확인합니다.

- 대상 파일 또는 이미지명
- 프로젝트
- 상태
- 취약점 수
- 출처
- 스캔 일시
- 심각도 요약

목록에서 검색과 필터를 사용할 수 있습니다.

- 스캔 대상 검색
- 프로젝트명 검색
- 상태 필터
- 출처 필터
- 심각도 필터
- 기간 필터

### 6.2 새 스캔 시작

`스캔 결과 > 스캔 업로드` 또는 `/dashboard/scans/new`로 이동합니다.

스캔 방식은 두 가지입니다.

| 방식 | 설명 | 사용 상황 |
| --- | --- | --- |
| 검사 대상 업로드 | 파일을 업로드하면 JASCA 서버가 Trivy를 실행하고 결과를 저장 | 폐쇄망 서버에서 직접 검사하고 싶을 때 |
| 결과 파일 업로드 | 이미 생성된 Trivy JSON/SARIF 파일을 업로드 | CI/CD나 별도 서버에서 Trivy를 실행한 결과를 가져올 때 |

### 6.3 검사 대상 업로드

1. `검사 대상 업로드` 모드를 선택합니다.
2. 기존 프로젝트를 선택하거나 새 프로젝트 정보를 입력합니다.
3. 검사할 파일을 선택합니다.
4. Scan mode를 선택합니다.
5. Scanner 옵션을 확인합니다.
6. `검사 시작`을 클릭합니다.
7. 검사 중 필요하면 `검사 중지`를 클릭합니다.
8. 완료 후 스캔 상세 화면으로 이동해 결과를 확인합니다.

### 6.4 지원 파일 예시

JASCA는 Trivy가 지원하는 대상과 JASCA helper 로직을 조합해 다음 파일을 처리합니다.

| 파일/대상 | 권장 Scan mode | 설명 |
| --- | --- | --- |
| 소스 디렉터리 압축 zip/tar/tar.gz | fs | package-lock.json, pom.xml, requirements.txt 등 manifest 검사 |
| Linux rootfs tar/tar.gz | rootfs | `/etc/os-release`, `/var/lib/rpm`, `/var/lib/dpkg/status`가 있는 OS 파일시스템 |
| Docker save tar | image | `docker save`로 생성한 image archive |
| OCI archive | image | `oci-layout`, `index.json`, `blobs/sha256` 구조 |
| RPM 파일 | rpm | rpm2cpio/cpio로 payload를 풀고 fs 검사 |
| SBOM 파일 | sbom | CycloneDX 또는 SPDX SBOM 검사 |
| VM 이미지 | vm | qcow2, vmdk, vhd, raw img 등 |
| 단일 manifest 파일 | fs | package-lock.json, pom.xml, Dockerfile 등 |

### 6.5 Scan mode 설명

| 모드 | 설명 | 운영 권장 |
| --- | --- | --- |
| fs | 파일시스템/소스/manifest 검사 | 일반 소스 압축, 단일 파일 기본값 |
| rootfs | Linux root filesystem 검사 | OS 패키지 취약점까지 보고 싶을 때 |
| image | Docker/OCI image archive 검사 | Docker save tar, OCI archive |
| repo | 소스 저장소 archive 검사 | Git repository 형태 검사 |
| sbom | SBOM 파일 검사 | Syft 등으로 만든 SBOM 검사 |
| vm | VM 이미지 검사 | VM 디스크 이미지 검사 |
| rpm | RPM helper 검사 | RPM 패키지 내부 payload 검사 |
| auto | 파일 구조를 보고 자동 판단 | 명확하지 않은 대상에서는 수동 모드 권장 |

운영 기본값은 `fs`입니다. `Auto`는 편의 기능이며, 결과가 이상하면 대상에 맞는 명시 모드를 선택하는 것이 좋습니다.

### 6.6 Analysis strategy 설명

| 전략 | 설명 | 권장 상황 |
| --- | --- | --- |
| auto | Trivy 직접 검사 후 결과가 약하면 Syft SBOM으로 보강 | 일반 운영 기본값 |
| direct | Trivy 직접 검사만 수행 | 빠른 검사, Syft 보강이 필요 없을 때 |
| syft-sbom | Syft로 SBOM 생성 후 Trivy SBOM 검사 | Trivy 직접 검사에서 패키지 식별이 약할 때 |

### 6.7 Scanner 옵션

| 옵션 | 설명 | 기본값 |
| --- | --- | --- |
| vuln | CVE 취약점 검사 | 선택 |
| license | 라이선스 검사 | 선택 |
| misconfig | 설정 오류 검사 | 선택 가능 |
| secret | 비밀키/토큰 노출 검사 | 선택 가능 |

운영 기본값은 `vuln`, `license`입니다.

### 6.8 폐쇄망 Trivy 옵션

폐쇄망에서는 기본적으로 다음 옵션을 켜는 것을 권장합니다.

- `--offline-scan`
- `--skip-db-update`
- `--skip-java-db-update`

이 옵션은 외부 네트워크 접속 없이 로컬 Trivy DB만 사용하도록 합니다.

### 6.9 결과 파일 업로드

이미 Trivy를 실행해 JSON 또는 SARIF 파일을 만든 경우 다음 절차를 사용합니다.

1. `결과 파일 업로드` 모드를 선택합니다.
2. 프로젝트를 선택하거나 새 프로젝트를 입력합니다.
3. JSON 또는 SARIF 파일을 선택합니다.
4. 출처를 선택합니다.
5. 업로드합니다.

Trivy JSON 생성 예시:

```bash
trivy fs --format json --output trivy-result.json ./source
```

Trivy SARIF 생성 예시:

```bash
trivy fs --format sarif --output trivy-result.sarif ./source
```

### 6.10 스캔 상세 보기

스캔 상세 화면에서 다음 항목을 확인합니다.

- 스캔 대상 파일명
- 원본 위치 또는 상세 경로
- 취약점 목록
- 패키지명, 설치 버전, 수정 버전
- 심각도
- CVSS 정보
- 참고 링크
- 라이선스 결과
- 정책 위반 결과
- Trivy 실행 증적
- 실행된 명령
- 결과 요약
- Syft fallback 여부

`Trivy 검사 검증 정보`에서 실제로 어떤 모드가 사용됐는지 확인합니다.

### 6.11 스캔 비교

스캔 상세에서 비교 기능을 사용하면 이전 스캔과 현재 스캔의 차이를 볼 수 있습니다.

- 신규 발견 취약점
- 해결된 취약점
- 유지 중인 취약점
- 심각도 변화

### 6.12 정책 결과 보기

스캔 상세의 정책 결과 화면에서는 해당 스캔이 적용 정책을 통과했는지 확인합니다.

확인 항목:

- 적용된 정책
- 위반된 규칙
- 위반 대상
- 심각도
- 차단 여부
- 예외 적용 여부

정책 위반이 있으면 프로젝트 관리자 또는 보안 담당자에게 조치 계획을 공유합니다.

## 7. 취약점 사용법

취약점 메뉴는 모든 프로젝트에서 발견된 취약점을 통합 조회하는 화면입니다.

### 7.1 취약점 목록

목록에서 다음 정보를 확인합니다.

- CVE ID
- 심각도
- 패키지명
- 현재 버전
- 수정 버전
- 프로젝트
- 상태
- 담당자
- 발견 일시

### 7.2 필터와 검색

사용 가능한 필터는 다음과 같습니다.

- 프로젝트
- 심각도
- 상태
- CVE ID
- 패키지명
- 최신 스캔만 보기
- 정렬 기준

### 7.3 취약점 상태

JASCA의 취약점 상태는 다음과 같습니다.

| 상태 | 의미 |
| --- | --- |
| OPEN | 새로 발견되어 아직 처리되지 않음 |
| ASSIGNED | 담당자가 지정됨 |
| IN_PROGRESS | 조치 진행 중 |
| FIX_SUBMITTED | 수정 사항 제출됨 |
| VERIFYING | 검증 중 |
| FIXED | 수정 완료 |
| CLOSED | 종료 처리 |
| IGNORED | 무시 처리 |
| FALSE_POSITIVE | 오탐 처리 |

### 7.4 상태 변경

1. 취약점 상세로 이동합니다.
2. 현재 상태와 가능한 전환 상태를 확인합니다.
3. 적절한 상태를 선택합니다.
4. 필요하면 댓글을 남깁니다.

상태 전환은 역할과 워크플로우 정책에 따라 제한될 수 있습니다.

### 7.5 담당자 지정

1. 취약점 상세에서 담당자 영역을 찾습니다.
2. 사용자 검색 또는 선택 목록에서 담당자를 선택합니다.
3. 저장합니다.

담당자는 해당 취약점 조치 책임자로 표시됩니다.

### 7.6 댓글과 이력

취약점 상세에서 댓글을 작성할 수 있습니다.

댓글에는 다음 내용을 남기는 것을 권장합니다.

- 분석 결과
- 영향 범위
- 조치 계획
- 예외 요청 사유
- 검증 결과

이력 탭에서는 상태 변경과 댓글 기록을 확인합니다.

## 8. 라이선스 사용법

라이선스 메뉴는 Trivy license scanner 결과를 기반으로 패키지 라이선스를 보여줍니다.

### 8.1 라이선스 목록

다음 정보를 확인합니다.

- 라이선스 이름
- 분류
- 위험도
- 프로젝트
- 패키지 수
- 발견 스캔

### 8.2 라이선스 탭 의미

라이선스 탭은 취약점이 아니라 오픈소스 라이선스 준수 관점의 결과를 보여줍니다.

예시:

- MIT, Apache-2.0: 일반적으로 허용 범위가 넓은 라이선스
- GPL, AGPL: 배포/소스 공개 조건 검토 필요
- UNKNOWN: 라이선스 식별 실패로 확인 필요

### 8.3 프로젝트별 라이선스

프로젝트별 탭에서 각 프로젝트의 최신 스캔 기준 라이선스 현황을 확인합니다.

프로젝트를 선택하면 다음 정보를 볼 수 있습니다.

- 해당 프로젝트의 라이선스 분포
- 라이선스별 패키지 목록
- 위험 분류
- 최신 스캔 기준 결과

### 8.4 운영 권장

- `license` scanner가 켜져 있어야 라이선스 결과가 생성됩니다.
- 신규 라이선스나 UNKNOWN은 관리자에게 분류 요청을 합니다.
- 배포 전 GPL/AGPL 계열은 법무/오픈소스 담당자의 검토를 받습니다.

## 9. 정책 사용법

정책 메뉴에서는 조직 또는 프로젝트에 적용된 보안 기준을 확인합니다.

### 9.1 정책 목록

다음 정보를 확인합니다.

- 정책 이름
- 설명
- 활성화 여부
- 조직/프로젝트 적용 범위
- 환경
- 규칙 수

### 9.2 정책 위반 확인

스캔 상세 또는 정책 결과 화면에서 정책 위반 여부를 확인합니다.

예시 정책:

- Critical 취약점이 1개 이상이면 실패
- High 취약점이 일정 개수 이상이면 실패
- 특정 라이선스가 발견되면 실패
- 수정 버전이 있는 취약점은 일정 기간 내 조치 필요

### 9.3 예외 요청

정책상 차단되지만 업무상 예외가 필요한 경우 예외 요청을 합니다.

필수 입력:

- 예외 유형
- 대상 값
- 사유
- 만료일

예외는 관리자가 승인해야 적용됩니다.

## 10. Trivy DB 사용법

Trivy DB 메뉴는 서버에 반입된 Trivy DB 상태를 확인하는 화면입니다.

### 10.1 확인 항목

- DB 존재 여부
- DB 위치
- `metadata.json`
- `trivy.db`
- Java DB 존재 여부
- 마지막 업데이트 시간
- Trivy 버전
- 총 용량
- Health 상태

### 10.2 폐쇄망 DB 반입

폐쇄망에서는 외부에서 Trivy DB를 내려받아 서버에 반입한 뒤 JASCA 컨테이너에 mount해야 합니다.

일반적인 mount 예시:

```bash
-v /sw/dify/.cache/trivy:/app/trivy-db
```

JASCA 내부 설정의 cache dir이 `/app/trivy-db`를 바라보도록 맞춥니다.

### 10.3 DB 오류 발생 시

다음 오류가 나오면 Trivy DB가 없거나 위치가 맞지 않은 것입니다.

```text
Trivy vulnerability DB is not available. Import or bundle trivy-db before running offline scans.
```

확인 순서:

1. 서버에 `trivy.db`가 있는지 확인합니다.
2. 컨테이너에 해당 경로가 mount되었는지 확인합니다.
3. JASCA Trivy 설정의 cache dir을 확인합니다.
4. `--skip-db-update`와 `--offline-scan`을 사용 중인지 확인합니다.

## 11. API 토큰 사용법

API 토큰은 CI/CD, 자동 업로드, 외부 시스템 연동에 사용합니다.

### 11.1 토큰 생성

1. `API 토큰` 메뉴로 이동합니다.
2. `토큰 생성`을 클릭합니다.
3. 이름과 만료일을 입력합니다.
4. 권한을 선택합니다.
5. 생성된 토큰을 안전한 곳에 보관합니다.

토큰 원문은 생성 시 한 번만 표시될 수 있으므로 분실하면 재발급해야 합니다.

### 11.2 주요 권한

| 권한 | 설명 |
| --- | --- |
| scans:read 또는 scan:read | 스캔 결과 조회 |
| scans:write 또는 scan:upload | 스캔 결과 업로드 |
| projects:read 또는 project:read | 프로젝트 조회 |
| projects:write 또는 project:write | 프로젝트 생성/수정 |
| vulnerabilities:read 또는 vuln:read | 취약점 조회 |
| vulnerabilities:write 또는 vuln:write | 취약점 상태 변경 |
| reports:read 또는 report:read | 리포트 조회 |
| reports:write 또는 report:write | 리포트 생성 |
| policies:read | 정책 조회 |
| policies:write | 정책 변경 |

### 11.3 Trivy JSON 업로드 API 예시

```bash
curl -X POST "https://jasca.example.com/api/scans/upload?projectName=my-service&imageRef=my-service:1.0.0" \
  -H "Authorization: Bearer <JASCA_API_TOKEN>" \
  -H "Content-Type: application/json" \
  --data-binary @trivy-result.json
```

### 11.4 결과 파일 업로드 API 예시

```bash
curl -X POST "https://jasca.example.com/api/scans/upload/file?projectId=<PROJECT_ID>" \
  -H "Authorization: Bearer <JASCA_API_TOKEN>" \
  -F "file=@trivy-result.json" \
  -F "sourceType=TRIVY_JSON"
```

### 11.5 검사 대상 직접 업로드 API 예시

```bash
curl -X POST "https://jasca.example.com/api/scans/scan/file?projectId=<PROJECT_ID>" \
  -H "Authorization: Bearer <JASCA_API_TOKEN>" \
  -F "file=@source.tar.gz" \
  -F "scanMode=fs" \
  -F "analysisStrategy=auto" \
  -F "offlineScan=true" \
  -F "skipDbUpdate=true" \
  -F "skipJavaDbUpdate=true" \
  -F "scanners=vuln,license" \
  -F "severities=CRITICAL,HIGH,MEDIUM,LOW" \
  -F "timeout=30m"
```

## 12. 연동 가이드

연동 가이드 메뉴에서는 CI/CD 환경에서 JASCA로 스캔 결과를 업로드하는 방법을 확인합니다.

일반 흐름:

1. CI에서 Trivy 실행
2. 결과를 JSON 또는 SARIF로 저장
3. JASCA API 토큰을 사용해 업로드
4. JASCA에서 정책 평가와 취약점 추적

### 12.1 GitLab CI 예시

```yaml
trivy_scan:
  stage: security
  script:
    - trivy fs --format json --output trivy-result.json .
    - curl -X POST "$JASCA_URL/api/scans/upload/file?projectName=$CI_PROJECT_NAME" -H "Authorization: Bearer $JASCA_TOKEN" -F "file=@trivy-result.json" -F "sourceType=TRIVY_JSON"
```

### 12.2 Jenkins 예시

```groovy
sh 'trivy fs --format json --output trivy-result.json .'
sh 'curl -X POST "$JASCA_URL/api/scans/upload/file?projectName=$JOB_NAME" -H "Authorization: Bearer $JASCA_TOKEN" -F "file=@trivy-result.json" -F "sourceType=TRIVY_JSON"'
```

## 13. 리포트 사용법

리포트 메뉴에서 프로젝트별 취약점 보고서를 확인하고 다운로드할 수 있습니다.

가능한 작업:

- 리포트 목록 조회
- 유형/상태/형식/기간 필터
- 프로젝트별 취약점 리포트 생성
- CSV 다운로드
- PDF 다운로드

## 14. 알림 사용법

알림 메뉴에서는 사용자에게 전달된 시스템 알림을 확인합니다.

알림 예시:

- 새 취약점 발견
- Critical 취약점 발생
- 정책 위반
- 담당자 지정
- 예외 승인/반려
- 리포트 생성 완료

사용자는 알림을 읽음 처리할 수 있습니다.

## 15. 개인 설정

설정 메뉴에서 다음 항목을 관리합니다.

- 프로필 정보
- 비밀번호 변경
- MFA 설정
- 세션 관리
- 대시보드 위젯 표시 여부
- 알림 수신 설정

### 15.1 프로필

프로필 화면에서 계정 기본 정보를 확인하고 변경할 수 있습니다.

관리 항목:

- 이름
- 이메일
- 소속 조직
- 역할
- 비밀번호 변경
- MFA 설정
- 백업 코드
- 로그인 세션

### 15.2 알림 설정

알림 설정 화면에서 개인별 알림 수신 조건을 조정합니다.

설정 예시:

- Critical 취약점 발생 시 알림
- 담당자로 지정될 때 알림
- 예외 요청 승인/반려 알림
- 리포트 생성 완료 알림

### 15.3 Trivy 명령 가이드

Trivy 명령 가이드는 환경별로 어떤 Trivy 명령을 실행해야 하는지 확인하는 화면입니다.

활용 예시:

- 파일시스템 검사 명령 생성
- 이미지 검사 명령 생성
- SARIF 출력 명령 생성
- JSON 출력 명령 생성
- CI/CD에 넣을 명령 확인

## 16. 권장 사용 흐름

### 16.1 개발자

1. 프로젝트를 확인합니다.
2. 스캔 업로드 화면에서 `fs` 모드로 소스 또는 manifest를 검사합니다.
3. 취약점 목록에서 본인 담당 취약점을 확인합니다.
4. 조치 후 상태를 변경하고 댓글로 근거를 남깁니다.
5. 필요 시 예외 요청을 생성합니다.

### 16.2 보안 담당자

1. 대시보드에서 Critical/High 추이를 확인합니다.
2. 취약점 메뉴에서 최신 스캔 기준 필터를 적용합니다.
3. 정책 위반 프로젝트를 확인합니다.
4. 예외 요청을 검토합니다.
5. 리포트로 운영 현황을 공유합니다.

### 16.3 프로젝트 관리자

1. 프로젝트 상세에서 최신 스캔 결과를 확인합니다.
2. 담당자를 배정합니다.
3. 조치 마감과 상태를 추적합니다.
4. 배포 전 정책 위반 여부를 확인합니다.

## 17. 문제 해결

### 17.1 업로드 파일이 너무 크다고 나올 때

관리자에게 `TRIVY_UPLOAD_MAX_BYTES` 설정을 확인해 달라고 요청합니다.

예시:

```bash
TRIVY_UPLOAD_MAX_BYTES=2GB
```

### 17.2 Auto 모드 결과가 이상할 때

Auto는 파일 구조를 추정합니다. 운영에서는 대상에 맞는 명시 모드를 권장합니다.

- 일반 소스: `fs`
- OS rootfs: `rootfs`
- Docker image tar: `image`
- RPM: `rpm`
- SBOM: `sbom`

### 17.3 취약점이 발견되지 않을 때

다음을 확인합니다.

- Trivy DB가 최신인지
- `vuln` scanner가 선택되어 있는지
- 대상 파일이 실제 패키지 정보를 포함하는지
- rootfs 대상인데 `fs`로 검사하지 않았는지
- Trivy 직접 검사에서 패키지 수가 0인지
- 상세 화면의 Trivy 실행 증적에 fallback이 수행됐는지

### 17.4 AI 분석에 think 내용이 보일 때

관리자에게 AI 모델 설정 또는 응답 후처리 설정을 확인해 달라고 요청합니다. 사내 모델이 reasoning/thinking 형식의 텍스트를 그대로 반환하는 경우 UI에 노출될 수 있습니다.

### 17.5 권한 오류가 발생할 때

403 또는 접근 불가가 나오면 다음을 확인합니다.

- 현재 사용자 역할
- 소속 조직
- 프로젝트 접근 권한
- API 토큰 권한
- 조직/프로젝트 범위
