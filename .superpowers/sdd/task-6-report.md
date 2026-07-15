# Task 6: Harbor 한국어 UI

## 변경 파일

- `apps/web/src/app/admin/harbor/page.tsx`
  - Harbor 관리 화면의 제목, 설명, 설정 라벨, 입력 안내, 버튼, 성공 메시지, 오류 보조 문구, 웹훅 안내를 한국어로 변경
  - Harbor, Trivy, URL, Push Artifact, Robot, HMAC, `Authorization: Bearer` 등 제품명과 기술 식별자는 유지
- `apps/web/src/app/admin/layout.tsx`
  - 관리자 내비게이션의 `Harbor Integration`을 `Harbor 연동`으로 변경
- `apps/web/src/app/dashboard/scans/new/page.tsx`
  - Harbor 수동 검사 선택, 필수값 안내, 로딩 상태, 오류 메시지를 한국어로 변경

## 검증 결과

- 영문 잔존 문구 검색: 번역 대상 문구 없음. 제품명, 이벤트명, URL 및 API 헤더 예시만 유지
- `npx.cmd tsc --noEmit`: 통과
- `npm.cmd run build`: 통과(Next.js 컴파일, 타입 검사, 54개 정적 페이지 생성 완료)
- Windows 심볼릭 링크 권한으로 standalone 파일 복사 `EPERM` 경고가 있었으나 빌드 종료 코드는 0
- `git diff --check`: 통과
