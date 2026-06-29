# JASCA - vuln-portal 연동 가이드

## 개요

JASCA는 vuln-portal의 외부 API를 호출하는 Pull 방식으로 CVE, KEV, EOL 정보를 가져옵니다.

방화벽 방향은 다음과 같습니다.

```text
출발지: JASCA 서버 IP 또는 JASCA Egress/NAT IP
도착지: vulnportal.kubagents-int.koreacb.com 또는 Ingress/LB VIP
포트: TCP 443
방향: JASCA -> vuln-portal
```

vuln-portal이 JASCA로 먼저 접속하는 구조가 아니므로 `vuln-portal -> JASCA` 방향 방화벽은 필요하지 않습니다.

## 사전 확인

JASCA 서버 또는 JASCA 컨테이너 안에서 다음 명령이 성공해야 합니다.

```bash
curl -k https://vulnportal.kubagents-int.koreacb.com/api/health

curl -k -H "X-API-Key: vp_xxxxx" \
  "https://vulnportal.kubagents-int.koreacb.com/api/v1/vulnerabilities?limit=1"
```

두 번째 명령에서 JSON 응답이 오면 JASCA 연동도 가능합니다.

## JASCA 설정

관리자 화면에서 다음 메뉴로 이동합니다.

```text
관리자 -> Vuln Portal 연동
```

설정값은 다음과 같습니다.

```text
Base URL: https://vulnportal.kubagents-int.koreacb.com
API Key: vuln-portal에서 발급한 vp_... 키
동기화 대상: CVE, KEV, EOL
동기화 주기: 기본 60분
```

저장 후 `연결 테스트`를 눌러 API 호출이 가능한지 확인합니다.

## 동기화 방식

- `즉시 동기화`: 관리자가 버튼을 눌러 바로 가져옵니다.
- `주기 동기화`: 연동 활성화가 켜져 있으면 설정된 주기로 자동 동기화합니다.
- 동기화 데이터는 JASCA의 기존 스캔 결과와 분리된 외부 인텔리전스 테이블에 저장됩니다.
- 같은 CVE가 스캔 결과에 존재하면 JASCA 취약점 상세 API에서 vuln-portal 보강 정보가 함께 내려갑니다.

## 주의사항

- vuln-portal에서 가져온 전체 CVE는 “우리 프로젝트에서 발견된 취약점”이 아닙니다.
- 따라서 JASCA는 가져온 데이터를 스캔 결과로 자동 등록하지 않습니다.
- 스캔 결과는 Trivy 또는 수동 취약점 매칭으로 생성되고, vuln-portal 데이터는 상세 설명, KEV, EPSS, 제품 정보 보강 용도로 사용합니다.
- 사내 인증서 문제로 HTTPS 연결 테스트가 실패할 때만 `TLS 인증서 검증 비활성화`를 임시로 사용하세요.

