# JASCA v0.3.14 릴리스 노트

## Clustara 연동

- Trivy뿐 아니라 Checkov, ZAP, Semgrep 스캔 결과도 Clustara 자동 전송 대상으로 확장했습니다.
- `image_digest`가 없는 파일, 아카이브, IaC, 웹 애플리케이션 스캔은 스캔 대상명 또는 `jasca-scan:<scan-id>`를 `image` 식별자로 전송합니다.
- 보존된 Syft SBOM도 digest 없이 같은 식별자로 전송할 수 있습니다.
- 스캔 상세의 Clustara 전송 패널을 모든 스캐너 결과에서 표시하며, 전송 이력에 실제 스캐너 또는 SBOM 생성기를 표시합니다.
- Clustara가 digest 없는 SBOM 또는 특정 스캐너 JSON을 지원하지 않으면 전송 실패 사유가 JASCA 전송 이력에 기록됩니다.

## 스캔 결과와 사용성

- Semgrep 실행 명령을 스캔 증적에 저장해 상세 화면에서 확인할 수 있습니다. 번들 규칙이 많은 경우 경로를 노출하지 않고 개수로 요약합니다.
- Checkov 프레임워크 선택 영역에 선택 개수와 선택 항목을 표시하고 선택 항목을 강조했습니다.
- 대시보드 스캐너 현황의 집계 기준을 `최근 50건`으로 명확히 표시했습니다.
- 대시보드 추이 기간에 90일 선택지를 추가했습니다.

## 검증

- Clustara 및 Semgrep 서비스 테스트 44건 통과
- API Nest 빌드 통과
- 웹 Next.js 컴파일 및 타입 검사 통과
