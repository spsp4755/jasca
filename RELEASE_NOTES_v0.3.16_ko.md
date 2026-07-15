# JASCA v0.3.16 - Harbor 연동 및 AI 보고서 내보내기

## Harbor 이미지 검사

- Harbor 이미지를 업로드하지 않고 프로젝트, 리포지토리, Digest를 선택해 Trivy `image` 검사
- Harbor `PUSH_ARTIFACT` Webhook으로 이미지 Push 후 자동 검사
- Robot Account 기반 Harbor API 조회와 읽기 전용 운영 방식 지원
- Webhook `Authorization: Bearer` 인증 및 허용 프로젝트 검증
- Digest 중복 실행 방지, 실패 재시도, stale 작업 복구
- `HarborScanJob` 신규 테이블만 추가하는 Prisma 마이그레이션 포함

## AI 분석 보고서

- AI 분석 결과를 공통 한국어 보안 보고서 템플릿으로 정리
- 표지, 메타데이터, 요약, 상세 분석, 우선순위 개선 조치, 분석 근거 포함
- AI 결과 화면과 관리자 AI 이력에서 PDF 및 DOCX 다운로드 지원
- `<think>`, `<thinking>`, reasoning 및 Markdown thinking 블록 제외
- AI 실행 소유권 검증 후 보고서 다운로드

## 검증

- API 전체 테스트: 22개 스위트, 148개 통과
- Harbor 통합 테스트 및 AI PDF/DOCX 생성 테스트 통과
- API 빌드 통과
- 웹 Next.js 빌드 및 54페이지 생성 통과

## 폐쇄망 참고

- 배포 전 Prisma 마이그레이션을 적용해야 합니다.
- Harbor에서 JASCA로 Webhook HTTPS 통신, JASCA에서 Harbor HTTPS 443 통신이 필요합니다.
- Harbor Robot Account는 프로젝트 조회와 이미지 Pull만 허용하세요.
