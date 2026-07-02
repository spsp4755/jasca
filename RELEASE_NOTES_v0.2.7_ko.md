# JASCA v0.2.7 릴리스 노트

## 핵심 변경

- Trivy 직접 검사에서 업로드 파일 유형에 따라 `fs`, `rootfs`, `image --input` 모드를 선택할 수 있도록 개선했습니다.
- 기본값은 `Auto`이며, 업로드 파일 구조를 보고 Docker/OCI 이미지 archive, Linux rootfs archive, 일반 filesystem 검사를 자동 판별합니다.
- RPM, DEB, APK, JAR/WAR/EAR, Python wheel/egg, Ruby gem, NuGet package 등 단일 패키지 파일 업로드 범위를 확대했습니다.
- zip, tar, tar.gz, tgz 압축파일은 안전 경로 검증 후 압축을 해제하고 검사합니다.
- Docker/OCI image tar 또는 tar.gz는 압축 해제하지 않고 `trivy image --input`으로 검사합니다.
- root filesystem 구조가 감지되면 `trivy rootfs`로 검사합니다.
- 스캔 중지 버튼이 `중지 요청 중...` 상태에 머무르지 않도록 브라우저 업로드 요청도 함께 중단하도록 개선했습니다.
- Trivy 프로세스 종료 사유를 사용자 취소, timeout, 출력 용량 초과, exit code, signal로 구분해 잘못된 "사용자 취소" 오류가 표시되지 않도록 수정했습니다.

## 운영 참고

- 폐쇄망에서 Trivy 직접 검사를 사용하려면 Trivy DB cache를 컨테이너에 마운트해야 합니다.
- 예: `-v /sw/dify/.cache/trivy:/app/trivy-db:ro`
- 컨테이너 환경변수 `TRIVY_CACHE_DIR=/app/trivy-db`를 함께 지정하는 것을 권장합니다.
- 이번 릴리스의 배포용 tar.gz는 GitHub Release asset으로 업로드하지 않고 로컬에서 별도 생성해 반입하는 방식으로 제공합니다.

## 검증

- `@jasca/api` production build 통과
- `@jasca/web` production build 통과
