# JASCA v1.2.0

**사용자별 MCP**를 넣은 릴리스입니다. 사용자가 자기 **MCP 키**를 발급해 AI 에이전트를 연결하면, 에이전트는 그 사용자의 권한으로 JASCA를 씁니다: 조회뿐 아니라 프로젝트 만들기, 보고서 올리기, 담당자·기한 지정, 예외 요청까지 합니다. 역할에 따라 쓸 수 있는 도구가 달라져 보안 담당은 예외 승인, 관리자는 시스템 상태·서버 로그·사용자 관리 같은 **운영 도구**를 함께 씁니다. **이미지만 바꾸면 됩니다.** DB 스키마는 앱이 시작할 때 자동으로 올립니다.

## 새로 생긴 것

- **MCP 키**(오른쪽 위 사용자 메뉴 → MCP 키): 이름, **조회·변경** 또는 **읽기 전용**, 만료일(최대 1년)을 정해 만듭니다. 키 값(`jsu_…`)은 만들 때 한 번만 보이고, 키가 채워진 MCP 클라이언트 설정을 바로 복사할 수 있습니다. 같은 화면에 내 역할로 쓸 수 있는 도구가 모두 나옵니다.
  - 에이전트는 **지금의 내 권한**으로 일합니다. 역할이나 프로젝트 멤버 구성이 바뀌면 키를 다시 만들지 않아도 다음 요청부터 반영되고, 계정이 비활성화되면 키도 멈춥니다. 화면에서 할 수 없는 일은 에이전트도 할 수 없습니다.
  - 키로 한 변경은 감사 로그에 **그 사용자 이름**으로 남고 행위자 옆에 **MCP** 표시가 붙습니다.
  - 키는 계정당 20개까지. MCP 주소(`/mcp`)와 스캔 업로드에서만 받아들이고 그 밖의 API는 거부합니다.
- **역할에 따라 달라지는 도구** (모든 사용자: 조회 17개, 변경 12개):

  | 누가 | 쓸 수 있는 도구 |
  |---|---|
  | 모든 사용자 | 조회: `whoami`, `list_projects`, 기존 조회 도구 10개(`project_summary`, `list_findings`, `list_fixes` 등), `list_members`, `find_users`, `list_audit_log`, `list_advisories`, `upload_commands`. 변경: `create_project`, `update_project`, `set_member`, `set_policy`, `upload_report`, `cancel_scan`, `update_finding`, `assign_findings`, `request_exception`, `revoke_exception`, `rename_target`, `delete_target` |
  | 보안 담당 | 위 + `decide_exception`(예외 승인·반려), `create_advisory`(사내 Advisory 등록) |
  | 관리자 | 위 + `system_status`, `get_server_logs`, `list_all_scans`, `list_notifications`, `list_users`, `update_user`, `list_mcp_keys`, `revoke_mcp_key`, `get_settings`, `run_keycloak_sync`, `start_recheck`, `list_harbor_unmapped`, `assign_harbor_image` |

  - `list_findings`, `list_exceptions`, `search_packages`, `get_vulnerability`는 프로젝트를 생략하면 내가 볼 수 있는 모든 프로젝트에서 찾습니다. "내 담당 중 기한 지난 것"은 `list_findings`에 `assignee: "me"`, `overdue: true`입니다.
  - 권한이 없는 도구를 부르면 에이전트가 어느 역할이 필요한지 안내를 받습니다. 읽기 전용 키는 변경 도구를 쓰지 못합니다.
- **운영을 MCP로**(관리자): `system_status`가 버전, DB, 데이터 볼륨 남은 공간, Trivy DB 경과 일수, 스캔 대기·실패, 재평가, Keycloak 동기화, 알림 전송 상태를 한 번에 주고 조치가 필요한 것을 `problems`에 문장으로 알려 줍니다. `get_server_logs`는 서버 로그(마지막 시작 이후 최근 2,000줄)에서 검색어와 시간으로 찾습니다. `get_settings`는 설정을 비밀값 없이 보여 줍니다.
- **파일 올리기**: 소스 묶음·이미지 파일은 에이전트가 `curl`로 올립니다(`upload_commands` 도구가 명령을 줍니다. 에이전트 실행 환경에 같은 키를 `JASCA_MCP_KEY`로 넣어 둡니다). 작은 스캐너 보고서(약 4MB까지)는 `upload_report` 도구로 바로 올립니다.
- **관리 → 사용자·역할**에 전체 사용자의 **MCP 키** 표가 생겼습니다. 유출된 키를 관리자가 바로 폐기할 수 있습니다.

## 바뀐 동작

- 프로젝트 **설정 → MCP 연동**은 개인 MCP 키를 먼저 안내하고, 프로젝트 API 토큰으로 연결하는 방법은 접힌 칸으로 옮겼습니다. **프로젝트 API 토큰의 MCP(조회 도구 10개)는 그대로 동작합니다.**
- 기존 조회 도구에 더해진 것: `list_findings`의 `assignee` 필터, `project_summary`의 기한 지난 결과 수(`overdue`).
- 도구 결과의 글에서 `<`, `>`, `&`를 `<`처럼 바꿔 적지 않습니다(에이전트가 명령을 그대로 읽습니다).
- 설정 변경(SSO, SMTP, 알림 채널, AI, Harbor 연결, Trivy DB 올리기, 조치 기한, 보존 기간)과 프로젝트 삭제는 MCP에 넣지 않았습니다. 화면에서 합니다.

## 업그레이드 안내

DB 스키마가 바뀝니다(`mcp_keys` 테이블 추가). 앱이 시작할 때 자동으로 적용되고, 기존 데이터는 바뀌지 않습니다. DB 계정에는 v1.1.2와 같은 권한(스키마의 USAGE, CREATE)이면 됩니다. `DEPLOY-OFFLINE.md`의 "업그레이드"를 따르세요.

1. DB를 백업합니다.
2. `jasca-v1.2.0.tar.gz`를 워커에 반입합니다.
3. 쓰던 `jasca.yaml`의 이미지 태그만 `jasca:v1.2.0`으로 바꿔 적용합니다. 다른 값은 그대로 둡니다.
4. 로그인 화면 아래에 `JASCA v1.2.0`이 보이면 새 버전입니다. 사용자 메뉴에 **MCP 키**가 보이는지 확인합니다.

첨부한 `db.tar.gz`, `javadb.tar.gz`는 2026-11-09에 만들어진 Trivy DB입니다(v1.1.2 첨부와 같은 파일).
