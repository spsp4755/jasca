# JASCA v0.3.15 - ZAP 안전 실행 고도화

## 주요 변경

- ZAP 스캔 화면에서 `Baseline`과 `Active` 모드를 명확히 선택할 수 있습니다.
- `Baseline`은 URL 탐색과 Passive Alert 수집만 수행하는 기본 안전 모드입니다.
- `Active`는 관리자 설정의 허용, 사용자 확인, 허용 대상 URL 검증을 모두 만족할 때만 실행됩니다.
- 스캔마다 임시 ZAP Context를 생성해 해당 URL 범위 안에서만 Spider와 Active Scan을 수행하고 완료 후 제거합니다.
- 중지 요청 시 Spider와 Active Scan을 모두 중지합니다.
- 인증 헤더를 사용하는 ZAP 스캔은 다른 스캔과 동시에 실행되지 않도록 분리했습니다.
- 관리자 ZAP 설정과 사용자 스캔 화면의 안내 문구를 실제 동작에 맞게 수정했습니다.

## 검증

- Trivy, Checkov, ZAP, Semgrep 결과 형식 파서 테스트 57건 통과
- 실제 ZAP 2.17.0 엔진에 대한 Active Scan 완료 및 Alert 저장 확인
- API Nest 빌드 및 웹 Next.js 프로덕션 빌드 통과

## 폐쇄망 운영 참고

- ZAP 이미지는 필요한 Add-on을 사전에 포함한 이미지로 반입하세요. 기본 ZAP 이미지는 최초 기동 시 Add-on 갱신을 시도할 수 있습니다.
- Active Scan은 운영 대상에 영향을 줄 수 있으므로 별도 승인된 테스트 범위에 대해서만 사용하세요.
