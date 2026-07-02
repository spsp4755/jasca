# JASCA v0.2.5 변경사항

## 주요 변경

- 스캔 결과 목록의 `대상` 표시를 Trivy 임시 검사 경로가 아니라 사용자가 업로드한 파일명 중심으로 개선했습니다.
- 스캔 상세 화면에서 `대상`과 `검사 위치`를 분리해 표시합니다.
- 압축 파일 스캔 시 목록에는 예: `NL2SQL-opencode-setup.tar.gz`, 상세에는 실제 검사 위치 예: `/tmp/jasca-trivy-uploads/.../extracted`가 표시됩니다.

## 검증 결과

- `docker build -f docker/monolith/Dockerfile -t jasca-offline:latest .` 성공
- 최신 이미지로 로컬 preview 컨테이너 재기동 성공
- `/api/scans?limit=3` 확인 결과 `targetName`은 파일명, `scanLocation`은 실제 검사 경로로 분리됨
- `/dashboard/scans` 화면 로딩 확인

## 폐쇄망 배포 참고

기존 `v0.2.4`와 동일한 방식으로 배포하면 됩니다. 기존 `/app/jasca/pgdata`, `/app/jasca/redis`는 삭제하지 말고 백업 후 그대로 마운트하세요.
