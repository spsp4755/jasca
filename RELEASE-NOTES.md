# JASCA v1.1.2

**`jasca.yaml` 하나로 사내 PostgreSQL에 설치**할 수 있게 한 릴리스입니다. DB 담당자에게 받은 Host, Port, Database, User, Schema, Password를 `jasca.yaml`에 그대로 적으면 되고, `postgres.yaml`은 사내 DB가 없을 때만 씁니다. 화면과 기능은 v1.1.1과 같습니다.

## 새로 생긴 것

- **DB 접속 정보를 항목별로 적습니다.**

  | 받은 값 | `jasca.yaml`의 항목 |
  |---|---|
  | Host | `JASCA_DB_HOST` |
  | Port | `JASCA_DB_PORT` |
  | Database | `JASCA_DB_DATABASE` |
  | User | `JASCA_DB_USER` |
  | Schema | `JASCA_DB_SCHEMA` |
  | Password | `JASCA_DB_PASSWORD` (Secret `jasca-secrets`) |

  비밀번호는 받은 그대로 적습니다(URL 인코딩 불필요). 접속 암호화는 `JASCA_DB_SSLMODE`(기본 `prefer`), 최대 연결 수는 `JASCA_DB_MAX_CONNS`(기본 20)로 정합니다.
- **스키마 지정**: 테이블은 앱이 시작할 때 `JASCA_DB_SCHEMA` 안에만 자동으로 만들고, 다른 스키마(`public` 포함)는 건드리지 않습니다. 스키마는 미리 만들어져 있어야 하고, 계정에는 그 스키마의 USAGE, CREATE 권한만 있으면 됩니다. 슈퍼유저 권한이나 확장(extension)은 필요 없습니다.
- **시작 로그**에 접속한 DB가 한 줄로 나옵니다(`database <Host>:<Port>/<Database> as <User>, schema <Schema>`). 스키마가 없거나 권한이 모자라면 무엇이 문제인지 로그로 알려 줍니다.
- PostgreSQL 13~17에서 테스트했습니다.

## 사내 DB에 들어가는 것과 아닌 것

- 사내 DB: 프로젝트, 스캔 결과와 원본 보고서, 패키지 목록, 사용자, 설정, 감사 로그.
- PVC `jasca-data`: Trivy 취약점 DB와 Java DB, 대기 중인 스캔 업로드. DB를 바꿔도 Trivy DB는 다시 올릴 필요가 없습니다.

## 바뀐 동작

- 새 `jasca.yaml`은 `jasca-postgres-secrets` Secret을 참조하지 않습니다.
- v1.1.1까지의 `jasca.yaml`(`JASCA_DATABASE_URL`, `PGPASSWORD`)은 그대로 동작합니다. 두 방식을 한 파일에 함께 적으면 앱이 시작하지 않고 로그로 알려 줍니다.

## 업그레이드 안내

DB 스키마는 바뀌지 않았습니다. `DEPLOY-OFFLINE.md`를 따르세요.

- **DB를 그대로 쓸 때**: `jasca-v1.1.2.tar.gz`를 워커에 반입하고, 쓰던 `jasca.yaml`의 이미지 태그만 `jasca:v1.1.2`로 바꿔 적용합니다.
- **사내 DB로 바꾸면서 새로 시작할 때**: 새 `jasca.yaml`에 DB 접속 정보와 쓰던 값(관리자 비밀번호, Ingress 주소 등)을 적어 적용합니다. 빈 스키마에서 시작하므로 `admin` 계정이 `JASCA_BOOTSTRAP_PASSWORD`로 새로 만들어집니다.
- **사내 DB로 바꾸면서 데이터를 옮길 때**: `DEPLOY-OFFLINE.md`의 "전용 PostgreSQL에서 사내 DB로 옮기기"를 따릅니다. 옮긴 뒤 프로젝트와 결과 수를 확인하고 나서 옛 DB를 정리하세요.

로그인 화면 아래에 `JASCA v1.1.2`가 보이면 새 버전입니다.

첨부한 `db.tar.gz`, `javadb.tar.gz`는 2026-11-09에 만들어진 Trivy DB입니다(v1.1.1 첨부와 같은 파일).
