# JASCA v1.2.1 — 폐쇄망 배포 / 데이터 보존

## 가장 중요한 점

이미지와 데이터는 별개입니다. 데이터는 두 곳에 있습니다.

- **PostgreSQL**: 사용자·프로젝트·스캔 결과·취약점 상태·감사 기록·설정 전부
- **앱 PVC `jasca-data`(`/data`)**: Trivy 취약점 DB(`/data/trivy`)와 스캔 작업 폴더(`/data/work`, 스캔이 끝나면 지워짐)

이미지나 Pod만 교체하고 **같은 DB와 같은 PVC**를 연결하면 데이터가 유지됩니다. Trivy DB는 PVC에 있으므로 PVC를 잃으면 관리자 화면에서 다시 올려야 합니다.

- `data-jasca-postgres-0`: PostgreSQL 데이터 PVC. `jasca-data`: 앱 PVC. **Namespace/PVC/PV 삭제, 새 빈 PVC로 변경, DB 이름 변경 금지.**
- PostgreSQL StatefulSet은 축소/삭제 시 PVC Retain을 명시합니다. 그러나 Namespace/PVC 자체 삭제, 스토리지 장애까지 막아주지는 않습니다. 별도 백업이 필수입니다.
- 초기 관리자 비밀번호(`JASCA_BOOTSTRAP_PASSWORD`)는 빈 DB의 최초 생성에만 사용됩니다. 이미지 업데이트로 기존 관리자 암호를 초기화하지 않습니다.

## 릴리스 파일

| 파일 | 용도 |
|---|---|
| jasca-v1.2.1.tar.gz | Linux/amd64 서비스 이미지 `jasca:v1.2.1`만 포함(Trivy 0.76.1 실행 파일 포함) |
| postgres-v17.11-jasca1.tar.gz | 별도 선택 이미지 `postgres:v17.11-jasca1` (공식 17.11-bookworm 기반, 쓰지 않는 gosu·snakeoil 키 제거, root로 실행 불가) |
| jasca.yaml | Secret·ConfigMap·PVC·Deployment·Service·Ingress. 사내 PostgreSQL 접속 정보까지 이 파일 하나에 적습니다 |
| postgres.yaml | 사내 DB가 없을 때만 쓰는 전용 PostgreSQL·영구 PVC·내부 Service·NetworkPolicy |
| db.tar.gz, javadb.tar.gz | 릴리스 날짜 기준 Trivy 취약점 DB와 Java DB. 설치 뒤 **관리 → Trivy DB**에서 올립니다(아래 "Trivy DB 오프라인 갱신"). 시간이 지났으면 새로 받으세요 |
| DEPLOY-OFFLINE.md | 이 문서 |
| RELEASE-NOTES.md | 이번 버전의 변경 사항 |
| SHA256SUMS | 반입 파일 무결성 검사 |

운영 데이터, 운영 암호, 테스트 계정, **Trivy 취약점 DB**는 이미지에 포함하지 않습니다. 사내 PostgreSQL을 쓰면 `postgres.yaml`과 PostgreSQL 이미지는 필요 없습니다.

## 이미지 반입

폐쇄망 Linux 서버에서 실행합니다.

```sh
sha256sum -c --ignore-missing SHA256SUMS # 이번에 반입한 파일 검증
podman load -i jasca-v1.2.1.tar.gz
podman load -i postgres-v17.11-jasca1.tar.gz # postgres.yaml을 쓸 때만
podman image inspect jasca:v1.2.1 --format '{{.Os}}/{{.Architecture}}'
```

**Podman load만으로 Kubernetes containerd에 이미지가 등록되지는 않습니다.** 실행 가능한 모든 워커의 실제 CRI에 반입하세요.

```sh
# 일반 containerd
sudo ctr -n k8s.io images import jasca-v1.2.1.tar.gz
sudo ctr -n k8s.io images import postgres-v17.11-jasca1.tar.gz # postgres.yaml을 쓸 때만
# k3s는 sudo k3s ctr images import, RKE2는 해당 런타임의 socket/ctr 사용.
```

사내 레지스트리를 쓰면 이미지를 push한 뒤 `jasca.yaml`의 `image:` 경로를 바꾸세요. `IfNotPresent`는 이미지가 없으면 pull을 시도하므로 사전 반입이 필수입니다.

## 신규 설치

Namespace `jasca`는 미리 생성되어 있다고 가정합니다(`kubectl create namespace jasca`). YAML은 namespace/IngressClass/StorageClass를 만들거나 고정하지 않습니다.

`jasca.yaml` 하나만 고쳐서 적용합니다. PostgreSQL은 사내 DB를 씁니다.

1. `JASCA_BOOTSTRAP_PASSWORD`를 12~72자 ASCII로 변경(기본값 `CHANGE_ME`는 12자 미만이라 앱이 시작하지 않습니다).
2. DB 담당자에게 받은 접속 정보를 적습니다.

   | 받은 값 | `jasca.yaml`의 항목 |
   |---|---|
   | Host | `JASCA_DB_HOST` |
   | Port | `JASCA_DB_PORT` |
   | Database | `JASCA_DB_DATABASE` |
   | User | `JASCA_DB_USER` |
   | Schema | `JASCA_DB_SCHEMA` |
   | Password | `JASCA_DB_PASSWORD` (Secret `jasca-secrets`) |

   - 스키마는 미리 만들어져 있어야 하고, 계정에 그 스키마의 `USAGE`, `CREATE` 권한이 있어야 합니다. 테이블은 앱이 시작할 때 그 스키마 안에 자동으로 만들고, 다른 스키마(`public` 포함)는 건드리지 않습니다. 슈퍼유저 권한이나 확장(extension)은 필요 없습니다.
   - 비밀번호는 받은 그대로 적습니다. URL 인코딩은 필요 없고, YAML 큰따옴표 안에서 `"`와 `\`만 앞에 `\`를 붙입니다.
   - `JASCA_DB_SSLMODE`는 기본 `prefer`(DB가 TLS를 받으면 암호화, 아니면 평문)입니다. 암호화를 강제하려면 `require`, 서버 인증서까지 검증하려면 `verify-full`로 바꾸고 CA 파일을 마운트해 환경 변수 `PGSSLROOTCERT`로 경로를 알려 주세요.
   - `JASCA_DB_MAX_CONNS`(기본 20)는 앱이 여는 최대 연결 수입니다. 계정의 연결 한도보다 작게 두세요.
   - PostgreSQL 13 이상에서 동작합니다(13~17에서 테스트).
3. Ingress host(`jasca.example.internal`)를 실제 사내 주소로 변경하고, 필요하면 `ingressClassName`을 지정.
4. 기본 StorageClass가 없으면 PVC `jasca-data`(기본 30Gi)의 `storageClassName`을 지정. ReadWriteOnce 하나면 됩니다(replicas 1).
5. Ingress TLS 항목은 생략했습니다. 사내 앞단/LB/Ingress 공용 인증서로 **HTTPS**를 제공하세요.
6. 스캔 파일 업로드 상한은 기본 2GiB입니다. Ingress의 `proxy-body-size`(예: `2100m`, 상한보다 조금 크게)와 읽기·쓰기 제한 시간(600초)이 이 값 이상이어야 합니다. `proxy-request-buffering: "off"`로 큰 업로드를 컨트롤러 디스크에 쌓지 않게 합니다. 상한을 바꾸면 ConfigMap의 `JASCA_MAX_SCAN_UPLOAD_MB`와 함께 바꾸세요.
7. Trivy는 임시 파일을 `/tmp`(emptyDir 2Gi)에, 취약점 DB를 `/data/trivy`에 씁니다. Pod 메모리 한도는 2Gi입니다. 큰 이미지를 스캔하면 늘려야 할 수 있습니다.

```sh
kubectl -n jasca apply --dry-run=server -f jasca.yaml
kubectl -n jasca apply -f jasca.yaml
kubectl -n jasca rollout status deployment/jasca --timeout=300s
kubectl -n jasca get pods,pvc,svc,ingress
kubectl -n jasca logs deployment/jasca | grep database # database <Host>:<Port>/<Database> as <User>, schema <Schema>
```

DB에 닿지 못하면 앱은 1분 동안 다시 시도한 뒤 로그에 `database:` 오류를 남기고 끝납니다(Pod가 재시작됩니다). 원인은 아래 "문제 해결"을 보세요.

**사내 DB가 없을 때(전용 PostgreSQL)**: `postgres.yaml`의 `POSTGRES_PASSWORD`를 정해 먼저 적용하고(`kubectl -n jasca apply -f postgres.yaml`, `rollout status statefulset/jasca-postgres`), `jasca.yaml`에는 `JASCA_DB_HOST: "jasca-postgres"`, `JASCA_DB_PORT: "5432"`, `JASCA_DB_DATABASE: "jasca"`, `JASCA_DB_USER: "jasca"`, `JASCA_DB_SCHEMA: ""`, `JASCA_DB_SSLMODE: "require"`, `JASCA_DB_PASSWORD`에는 같은 암호를 적습니다. PostgreSQL Secret의 암호는 **DB 최초 초기화 때만** 적용되므로, 운영 중에는 DB 계정 암호와 두 Secret을 함께 바꾸세요.

설치 후 **Trivy DB를 올리기 전에는 서버 스캔이 동작하지 않습니다.** 아래 "Trivy DB 오프라인 갱신"을 먼저 하세요.

## Keycloak 설정 (SSO)

SSO는 선택입니다. 설정하지 않아도 로컬 관리자(`admin`)로 로그인할 수 있지만, 사용자별 로그인과 부서·그룹 기반 프로젝트 멤버 지정을 쓰려면 Keycloak이 필요합니다. 아래를 Keycloak에서 만든 뒤 JASCA 관리 화면에 입력합니다. 로그인 방식은 OIDC authorization code + PKCE입니다.

1. **로그인 client**: 이름 예 `jasca`, Client authentication **ON**(confidential), Standard flow만 사용.
   - Valid redirect URIs: `https://<접속 주소>/api/v1/auth/sso/callback`
   - 요청 scope는 `openid profile email`입니다. Credentials 탭의 Client Secret을 복사해 둡니다.
   - 신형 Keycloak의 Valid post logout redirect URIs는 쓰지 않습니다(JASCA는 Keycloak 로그아웃을 호출하지 않고 자체 세션만 끝냅니다).
2. **역할 매핑**(시스템 관리자와 보안 담당 지정): Keycloak에 역할 두 개를 만들고 사용자에게 줍니다(예: `jasca-admin`, `jasca-security`). 역할은 realm 역할이나 이 client의 역할 어느 쪽이든 됩니다. 토큰에 실리는 기본 `roles` scope를 지우지 마세요. 역할 이름은 JASCA의 **관리 → SSO (Keycloak)** 에 "관리자 역할", "보안 담당 역할"로 입력합니다. 두 역할을 모두 가지면 관리자가 되고, 둘 다 없으면 일반 사용자입니다. **로그인할 때마다 다시 계산**되므로 Keycloak에서 역할을 빼면 다음 로그인부터 내려갑니다. 단, **관리 → 사용자·역할**에서 역할을 직접 바꾼 사용자는 그 뒤로 Keycloak 역할을 따르지 않고 JASCA에서 정한 역할을 유지합니다. 같은 화면에서 역할을 **Keycloak 역할 따름**으로 되돌리면 다음 Keycloak 로그인부터 다시 Keycloak 역할로 정해집니다. 구형 Keycloak의 master realm(`/realms/master`)이면 `master-realm` client의 역할도 함께 읽습니다.
3. **groups 매퍼**(그룹 단위 프로젝트 멤버 지정에 사용): client → Client scopes → 전용 scope → Add mapper → *Group Membership*.
   - Token Claim Name `groups`, **Full group path = ON**, **Add to ID token = ON**.
   - Full path가 꺼져 있으면 `/`로 시작하지 않는 값은 무시하고(서버 로그에 안내가 남습니다) 저장된 그룹 소속을 그대로 둡니다. 매퍼가 없어도 로그인은 되며, 그룹은 동기화(아래 5번)가 채웁니다.
4. **부서를 사용자 속성으로 관리하는 경우**(사용자 Attributes 탭의 `department` = `AI실/보안팀`처럼 `/`로 상하위를 나눈 값): 같은 화면에서 Add mapper → *User Attribute*.
   - User Attribute `department`, Token Claim Name `department`, **Add to ID token = ON**, 한 사람이 여러 부서면 **Multivalued = ON**(아니면 OFF).
   - JASCA는 기본으로 `department` 속성을 읽습니다. 이름이 다르면 **관리 → Keycloak 동기화 → 부서 속성 이름**에 입력합니다. 부서를 쓰지 않으면 **부서 정보를 읽지 않음**을 켭니다(켜고 저장하면 저장된 모든 사용자의 부서가 바로 지워지고, 부서로 얻은 프로젝트 접근도 사라집니다).
   - 값은 그룹 경로처럼 쓰입니다(`AI실/보안팀` → `/AI실/보안팀`). 상위 부서(`/AI실`)를 프로젝트 멤버로 지정하면 하위 부서 사람도 포함됩니다. 한 사람당 부서 값은 10개, 값마다 10단계까지만 읽고, 한 값은 150바이트 이하여야 합니다.
   - 부서 값이 Keycloak 그룹 경로(삭제된 그룹 포함)와 같으면 그 그룹의 소속은 주지 않습니다(그룹 우선). 부서 이름이 그룹 이름과 겹치지 않게 두세요.
   - **`department`는 관리자만 고칠 수 있어야 합니다.** 사용자가 직접 바꿀 수 있으면 아무 부서나 적고 다시 로그인해 그 부서에 지정된 프로젝트를 볼 수 있습니다.
     - Keycloak 24 이상: **Realm settings → User profile**에 `department` 속성을 추가하고 *Who can edit*를 **Admin만** 체크합니다. 또는 **Realm settings → General → Unmanaged attributes = Only administrators can write**로 둡니다. **Enabled는 쓰지 마세요**(사용자가 계정 화면에서 고칠 수 있습니다).
     - 구형 Keycloak(User profile 없음, `/auth` 경로 버전): 서버 설정의 `read-only-attributes`로 `department`를 사용자 읽기 전용으로 둡니다(Quarkus 배포판 예: `--spi-user-profile-legacy-user-profile-read-only-attributes=department`, WildFly 배포판은 `standalone.xml`의 `userProfile` SPI → `legacy-user-profile` provider의 `read-only-attributes`. 이름은 버전마다 다를 수 있습니다).
     - 어느 버전이든 적용 후 **일반 사용자로 계정 화면(`…/realms/<realm>/account`)에 들어가 department를 고칠 수 없는지 직접 확인**하세요.
5. **동기화용 서비스 계정 client**: 이름 예 `jasca-sync`, Client authentication **ON**, Service accounts roles **ON**(Standard flow 끔).
   - Service account roles 탭 → Assign role → *Filter by clients* → `realm-management`의 **view-users**(그룹 조회가 부족하면 **query-groups**도). 구형 Keycloak에서는 master realm의 `master-realm` client 역할을 고릅니다. 관리 화면(**관리 → Keycloak 동기화**)의 안내 문구도 같은 두 역할을 적고 있습니다.
   - 이 계정으로 사용자·이메일·그룹·부서를 15분마다(기본, 1~1440분) 읽어 옵니다. Keycloak에서 비활성화되거나 삭제된 사용자는 다음 동기화 뒤 다음 요청부터 로그아웃(401)됩니다. 그룹 이름을 바꾸면 새 그룹으로 취급되므로 그 그룹으로 지정한 프로젝트 멤버를 다시 지정해야 합니다.
6. **구형 Keycloak(`/auth` 경로)**: Issuer URL에는 `https://sso.example.internal/auth/realms/<realm>`처럼 실제 `/auth`가 포함된 주소를 넣으세요. 신형은 `https://sso.example.internal/realms/<realm>`입니다. Keycloak이 알려 주는 `…/.well-known/openid-configuration`의 `issuer` 값과 글자 그대로 같아야 합니다. 동기화는 같은 주소에서 `/realms/`를 `/admin/realms/`로 바꿔 Admin API를 부르므로 `/auth`가 있는 서버에도 그대로 동작합니다.
7. **사내 CA 인증서**를 쓰는 Keycloak이면 JASCA가 그 CA를 신뢰해야 합니다. CA 파일을 ConfigMap으로 마운트하고 `SSL_CERT_FILE`을 지정합니다. 이 변수는 시스템 인증서 묶음을 **대체**하므로, 파일에는 사내 CA 외에 필요한 다른 CA도 함께 넣으세요.

```yaml
# jasca.yaml의 Deployment: containers[0].env, volumeMounts, volumes에 추가
          env:
            - { name: SSL_CERT_FILE, value: /etc/jasca-ca/ca.crt }
          volumeMounts:
            - { name: ca, mountPath: /etc/jasca-ca, readOnly: true }
      volumes:
        - name: ca
          configMap: { name: jasca-ca }   # kubectl -n jasca create configmap jasca-ca --from-file=ca.crt=사내CA.crt
```

   Harbor나 LLM 서버가 사내 CA를 쓰는 경우에도 같은 설정이 적용됩니다.

### 관리 화면에 입력

1. 로컬 `admin`으로 로그인합니다(`https://<접속 주소>/login?local=1`).
2. **관리 → SSO (Keycloak)**: Issuer URL, Client ID, Client Secret, 관리자 역할, 보안 담당 역할, **사이트 주소**(`https://<접속 주소>`; 비우면 브라우저가 접속한 주소)를 입력하고 "SSO 로그인 사용"을 켭니다. 사이트 주소는 로그인 콜백 주소, 알림 링크, **Harbor 웹훅 URL**의 기준이므로 꼭 넣으세요.
3. **관리 → Keycloak 동기화**: 서비스 계정 Client ID/Secret을 입력하고 **지금 동기화**로 확인합니다(결과에 그룹 수와 사용자 수가 보입니다).
4. 로그인 화면에서 Keycloak으로 한 번 로그인해 보고, **관리 → 사용자·역할**에서 계정, 역할, 부서를 확인합니다. 로그인 화면에는 Keycloak 버튼만 보이고, 비상용 로컬 로그인은 `/login?local=1`로만 열립니다.

로컬 `admin`과 같은 아이디(`admin`)를 쓰는 Keycloak 사용자는 로그인되지 않습니다(`conflict`). Keycloak에서 다른 아이디를 쓰세요.

### 첫 로그인에서 부서가 비어 있을 때

**관리 → Keycloak 동기화 → 최근 SSO 로그인의 부서** 표에서 최근 20건의 결과와 그때 읽은 부서를 봅니다(서버를 다시 시작하면 비워집니다). **관리 → 사용자·역할**의 부서 열에는 지금 저장된 부서가 보입니다.

SSO로 **처음 로그인하는 순간** 부서는 다음 중 하나가 맞을 때 채워집니다("부서 정보를 읽지 않음"이 꺼져 있어야 합니다).
1. Keycloak의 *User Attribute* 매퍼가 그 속성을 **ID 토큰**에 넣는다(위 4번, Add to ID token = ON).
2. 매퍼가 없으면 동기화의 서비스 계정으로 Admin API에서 그 사람 한 명만 읽는다(3초 제한, 실패해도 로그인은 됩니다). 실패하면 서버 로그의 `department from the Keycloak Admin API` 줄을 보세요.

둘 다 안 되면 첫 로그인의 부서는 비어 있고, 동기화가 속성을 읽어 온 뒤에야 채워집니다. 매퍼가 실제로 토큰에 값을 넣는지는 Keycloak 관리 콘솔 → **Clients → jasca → Client scopes → Evaluate**에서 사용자를 고르고 **Generated ID token**에 `"department": "AI실/보안팀"` 항목이 있는지 보세요.

## 관리자 첫 로그인

1. `https://<접속 주소>/login?local=1`에서 `admin` / 설치 때 정한 `JASCA_BOOTSTRAP_PASSWORD`로 로그인합니다. 처음부터 강한 값(12~72자)을 쓰고, 로그인 뒤 오른쪽 위 사용자 메뉴의 **비밀번호 바꾸기**로 바꿀 수 있습니다. Secret의 값은 빈 DB의 최초 `admin` 생성에만 쓰이고(이후에는 바꾼 비밀번호가 유지됩니다), 시작할 때마다 12~72자로 설정되어 있어야 앱이 시작합니다.
2. 로그인 5회 실패하면 15분간 잠기고, IP별 요청 제한도 있습니다.
3. **관리 → Trivy DB**에서 DB를 올립니다(다음 절). Keycloak을 쓰면 위 절차로 SSO를 설정합니다.
4. 처음 관리자는 SSO 역할 매핑으로 정하는 것을 권장합니다. 이미 로그인(또는 동기화)된 사용자는 **관리 → 사용자·역할**에서 역할을 지정할 수도 있습니다(여기서 바꾼 역할은 JASCA 안에서만 적용되고, **Keycloak 역할 따름**으로 되돌리기 전까지 Keycloak과 관계없이 유지됩니다).

## Trivy DB 오프라인 갱신

Trivy 취약점 DB는 인터넷 PC에서 받아 관리자 화면으로 올립니다. 서버는 DB를 받으러 밖으로 나가지 않습니다(Trivy를 항상 `--skip-db-update --skip-java-db-update --offline-scan --skip-version-check --disable-telemetry`로 실행하므로 버전 확인 요청도 보내지 않습니다).

인터넷이 되는 PC에서(oras 필요):

```sh
oras pull ghcr.io/aquasecurity/trivy-db:2          # db.tar.gz (trivy.db, metadata.json)
oras pull ghcr.io/aquasecurity/trivy-java-db:1     # javadb.tar.gz (자바 JAR 스캔용, 선택: 없으면 서버 스캔이 JAR/WAR/EAR을 건너뛰고 결과에 경고로 표시)
sha256sum db.tar.gz javadb.tar.gz > trivy-db.sha256
```

반입 매체로 옮긴 뒤 **관리 → Trivy DB**에서 `db.tar.gz`는 **취약점 DB** 칸에, `javadb.tar.gz`는 **Java DB** 칸에 **각각 따로** 올립니다. 칸을 잘못 골라도 파일 내용으로 구분해 맞는 DB에 적용하고, 어느 DB를 적용했는지 화면에 알려 줍니다.

- 올린 파일은 검사한 뒤 한 번에 교체합니다. 올바른 번들이 아니면 거부하고 기존 DB를 그대로 씁니다. 파일 크기는 `JASCA_MAX_SCAN_UPLOAD_MB`(Ingress `proxy-body-size` 포함), 풀었을 때 크기는 `JASCA_MAX_EXTRACT_MB`가 상한입니다.
- 취약점 DB 교체가 끝나면 **재평가가 자동으로 시작**됩니다(Java DB는 다음 서버 스캔부터 쓰이며 재평가를 시작하지 않습니다). 저장된 모든 대상(Harbor 보고서 대상 제외)의 최신 패키지 목록을 새 DB로 다시 평가하고, 새로 걸린 취약점은 "재평가"로 표시되며 알림이 갑니다. 진행 상황은 **관리 → 재평가**에서 봅니다. 스캔을 다시 돌릴 필요가 없습니다.
- 두 DB의 설치 여부와 생성 시각, 취약점 DB의 다음 갱신 예정 시각이 **관리 → Trivy DB**의 각 칸에 보입니다. 갱신 예정에서 7일 넘게 지나면 경고가 보이니(DB의 갱신 예정은 생성 하루 뒤라 폐쇄망에서는 늘 조금 지나 있습니다) 주기적으로(예: 매주) 같은 절차를 반복하세요. DB가 오래되면 새 취약점이 탐지되지 않습니다.
- 설치 직후 취약점 DB를 올리기 전에는 서버 스캔을 받지 않고(스캔 화면에 안내가 나오고 업로드는 409로 거부), 재평가도 걸러낼 DB가 없습니다.

## 업그레이드

이미지 태그만 바꾸면 됩니다. DB 스키마는 앱이 시작할 때 올립니다.

1. DB와 PVC를 백업합니다(아래 "백업과 복원").
2. 새 `jasca-vX.Y.Z.tar.gz`를 모든 워커에 반입합니다(위 "이미지 반입").
3. 새 `jasca.yaml`에 쓰던 값(Ingress host, `ingressClassName`, `JASCA_BOOTSTRAP_PASSWORD`, `JASCA_TZ`, DB 접속 정보, 이미지 경로)을 옮겨 적고 적용합니다. v1.1.1까지의 `jasca.yaml`(`JASCA_DATABASE_URL`과 `PGPASSWORD`)을 그대로 쓰면서 이미지 태그만 바꿔도 됩니다. 두 방식을 한 파일에 섞으면 앱이 시작하지 않습니다. `CHANGE_ME`인 채로 적용하면 Secret을 덮어씁니다. 새 `postgres.yaml`을 적용할 때도 `POSTGRES_PASSWORD`를 옮겨 적으세요.
```sh
kubectl apply -f jasca.yaml
kubectl -n jasca rollout status deployment/jasca
```
4. 로그인 화면 아래에 새 버전(`JASCA vX.Y.Z`)이 보이는지 보고, 로그인과 스캔 한 건으로 확인합니다. Recreate 전략이라 교체 중 잠시 접속이 끊깁니다.

## 전용 PostgreSQL에서 사내 DB로 옮기기

`postgres.yaml`로 띄운 DB의 데이터를 사내 DB의 스키마로 옮기는 절차입니다. 데이터를 옮기지 않고 새로 시작하려면 "신규 설치"대로 `jasca.yaml`만 적용하면 됩니다(Trivy DB는 PVC에 있어 그대로 남습니다).

덤프는 스키마 이름을 바꿔서 복원할 수 없으므로, 옮기기 전에 옛 DB의 `public` 스키마 이름을 받은 스키마 이름으로 바꿉니다(받은 스키마가 `public`이면 이름 변경을 건너뜁니다).

```sh
kubectl -n jasca scale deployment/jasca --replicas=0 # 앱을 멈춥니다
umask 077
kubectl -n jasca exec jasca-postgres-0 -- pg_dump -U jasca -d jasca -Fc > jasca-before-move.dump # 되돌릴 때 쓸 백업
kubectl -n jasca exec jasca-postgres-0 -- psql -U jasca -d jasca -c 'alter schema public rename to "<Schema>"'
kubectl -n jasca exec jasca-postgres-0 -- pg_dump -U jasca -d jasca -n '<Schema>' --no-owner --no-acl -f /tmp/jasca-move.sql
# 사내 DB에 넣습니다. 비밀번호를 물으면 받은 Password를 입력합니다.
kubectl -n jasca exec -it jasca-postgres-0 -- psql -h <Host> -p <Port> -U <User> -d <Database> -f /tmp/jasca-move.sql
kubectl -n jasca exec jasca-postgres-0 -- rm /tmp/jasca-move.sql
```

덤프 파일은 PostgreSQL Pod의 `/tmp`(노드의 임시 저장소)에 잠시 둡니다. 크기는 DB의 두 배쯤까지 될 수 있습니다.

넣는 중 아래 오류는 정상입니다. 스키마가 이미 만들어져 있고 계정이 그 소유자가 아니어서 나는 것과, 사내 DB가 17보다 낮은 버전일 때 나는 것입니다. 다른 오류가 있으면 멈추고 DB 담당자와 확인하세요.

- `permission denied for database …` 또는 `schema "…" already exists` (CREATE SCHEMA)
- `must be owner of schema …` (COMMENT ON SCHEMA)
- `unrecognized configuration parameter "transaction_timeout"`

그다음 새 `jasca.yaml`에 사내 DB 접속 정보와 **쓰던 값**(Ingress host, `JASCA_TZ` 등)을 적어 적용합니다. 로그인해 프로젝트와 결과 수가 그대로인지 확인한 뒤에 옛 DB를 정리하세요(`kubectl -n jasca delete -f postgres.yaml`은 PVC를 지우지 않습니다. 백업 파일과 PVC는 확인이 끝날 때까지 두세요). 되돌리려면 옛 DB에서 `alter schema "<Schema>" rename to public`을 실행하고 예전 `jasca.yaml`을 적용합니다.

## 백업과 복원

DB와 앱 PVC를 **같은 시점에** 함께 받으세요.

```sh
umask 077
kubectl -n jasca exec jasca-postgres-0 -- pg_dump -U jasca -d jasca -Fc > jasca.dump
```

사내 DB를 쓰면 DB 백업은 DB 담당자의 백업 정책을 따르거나, `pg_dump -h <Host> -p <Port> -U <User> -d <Database> -n '<Schema>' -Fc`로 JASCA 스키마만 받습니다.

앱 PVC(`jasca-data`)는 스토리지의 스냅샷 기능(CSI VolumeSnapshot 등)으로 받는 것이 가장 간단합니다. 스냅샷을 쓸 수 없으면, 앱 이미지에는 셸이 없으므로 이미 반입한 PostgreSQL 이미지로 임시 Pod를 띄워 받습니다(PVC가 ReadWriteOnce라 앱을 잠시 멈춥니다). 스캔 작업 폴더(`work`)는 제외합니다.

```sh
kubectl -n jasca scale deployment/jasca --replicas=0
kubectl -n jasca run jasca-data-backup --image=postgres:v17.11-jasca1 --restart=Never \
  --overrides='{"spec":{"securityContext":{"runAsUser":10001,"fsGroup":10001},"containers":[{"name":"jasca-data-backup","image":"postgres:v17.11-jasca1","command":["sleep","3600"],"volumeMounts":[{"name":"data","mountPath":"/data","readOnly":true}]}],"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"jasca-data"}}]}}'
kubectl -n jasca wait --for=condition=Ready pod/jasca-data-backup --timeout=120s
kubectl -n jasca exec jasca-data-backup -- tar -C /data --exclude=./work -cf - . > jasca-data.tar
kubectl -n jasca delete pod jasca-data-backup
kubectl -n jasca scale deployment/jasca --replicas=1
```

복원은 같은 방법으로 임시 Pod를 띄우되 `readOnly`를 빼고, `kubectl exec -i … -- tar -C /data -xf - < jasca-data.tar`로 풉니다. DB는 빈 DB에 `pg_restore -U jasca -d jasca --clean --if-exists`로 복원합니다. 백업 파일에는 사용자 정보와 보고서가 들어 있으므로 접근을 제한하세요.

## Harbor 웹훅 연동

Harbor가 이미지를 스캔하면 JASCA가 Harbor의 취약점 보고서를 가져와 저장합니다. JASCA는 Harbor에서 SBOM을 가져오지 않으므로 Harbor 대상은 재평가와 사내 Advisory 매칭에서 제외됩니다(대상 목록에 "재평가 제외"로 표시).

1. Harbor에서 이미지를 읽을 수 있는 **robot 계정**을 만듭니다(예: `robot$jasca`, 해당 프로젝트의 pull 권한).
2. JASCA **관리 → SSO**의 **사이트 주소**를 먼저 입력해 둡니다. 웹훅 URL이 이 주소로 만들어집니다.
3. **관리 → Harbor → Harbor 연결 추가**: 이름, Harbor 주소(`https://harbor.example.internal`), 로봇 계정, 로봇 계정 Secret을 입력합니다. 저장하면 **웹훅 URL**(`https://<접속 주소>/api/v1/hooks/harbor/<번호>`)과 **웹훅 Secret**이 한 번만 보입니다. Secret은 다시 볼 수 없습니다.
4. Harbor의 해당 프로젝트 → Webhooks → 새 웹훅: Endpoint URL에 위 웹훅 URL, **Auth Header에 웹훅 Secret**, 이벤트는 **Scanning finished**(`SCANNING_COMPLETED`)를 고릅니다. 다른 이벤트는 받아도 무시합니다(202).
5. **매핑**: JASCA는 Harbor 프로젝트와 저장소 패턴(`web/*`, `*` = 전체)을 JASCA 프로젝트에 연결합니다. 패턴이 더 구체적인 행이 먼저 적용됩니다. 매핑이 없는 이미지는 **매핑되지 않은 이미지** 목록에 쌓이고, 프로젝트를 고르면 그때 연결해 가져옵니다.
6. **연결 시험**으로 JASCA가 Harbor에 닿는지 확인합니다. JASCA는 등록한 Harbor 주소로만 호출합니다(이벤트 안의 주소는 쓰지 않음). Harbor가 사내 CA를 쓰면 위 Keycloak 7번의 `SSL_CERT_FILE` 설정이 필요합니다.
7. 웹훅 요청은 바로 202로 응답하고 보고서는 백그라운드에서 가져옵니다. 웹훅이 JASCA 앞의 Ingress를 통과하는지(본문 1MB 이하, `Authorization` 헤더 유지) 확인하세요.

## 자원과 규모

- 평상시 요청은 200m CPU / 256Mi, 한도는 2 CPU / 2Gi입니다(`jasca.yaml`). Trivy가 스캔 중 메모리를 많이 쓰므로, 큰 이미지나 큰 저장소를 스캔하다 `OOMKilled`가 나면 메모리 한도를 늘리세요. 서버 스캔은 동시에 1건만 처리하고 나머지는 큐에서 기다립니다.
- **replicas는 1이어야 합니다.** 스캔 큐, 재평가, 알림, 예외 만료, Keycloak 동기화가 프로세스 안에서 돌고 PVC도 ReadWriteOnce입니다. 늘리면 같은 작업이 중복됩니다.
- 디스크: PVC `jasca-data` 30Gi(Trivy DB 1~2GB + 작업 폴더, 압축 해제 상한 4GiB), `/tmp` emptyDir 2Gi. 스캔은 한 번에 하나씩 돌고, 올린 파일은 차례가 올 때까지 작업 폴더에서 기다렸다가 스캔이 끝나면 지워집니다. 큰 파일을 여러 개씩 올리는 환경이면 "기다리는 파일 크기의 합 + 4GiB"가 들어가도록 PVC를 늘리세요.
- PostgreSQL PVC에는 스캔마다 원본 보고서(gzip으로 저장, 내려받을 때는 JSON)와 패키지 목록이 쌓입니다. **관리 → 보존 기간**의 두 조건(대상당 최근 N개, N일)을 모두 넘긴 스캔은 원본, 패키지 목록, 결과 연결이 지워지고 스캔 기록과 결과(취약점 이력)는 남습니다. 대상의 현재 인벤토리(패키지가 있는 가장 최근 스캔)는 재평가와 사내 권고 매칭에 쓰이므로 항상 남습니다.
- 크기는 `대상 수 × max(최근 N개, 보존 일수 × 하루 업로드 수) × 스캔 1건`으로 잡으세요. 스캔 1건은 원본 0.1~1MB와 패키지 1,000개당 약 0.3MB입니다. 예: 대상 300개, CI가 하루 5번 올리고 보존 14일이면 300 × 70 × 약 0.8MB ≈ 17GB입니다. 기본값(90일)은 업로드가 잦은 곳에서 20Gi를 넘을 수 있으니 일수를 줄이거나 PVC를 늘리세요.
- 검사 대상 수백 개 규모를 기준으로 설계했고 2,000개까지는 무리 없이 동작하도록 만들었습니다.
- Ingress는 업로드 상한보다 조금 큰 `proxy-body-size`, 요청 버퍼링 끄기, 600초 읽기·쓰기 제한 시간이 필요합니다(`jasca.yaml`에 있음). NGINX가 아닌 Ingress는 같은 의미의 설정을 따로 하세요.
- AI 에이전트용 MCP 주소(`/mcp`)도 같은 Service와 Ingress로 나갑니다. 요청마다 JSON으로 한 번 응답하므로(SSE·WebSocket 없음) 따로 설정할 것이 없습니다. `Authorization` 헤더만 그대로 전달되면 됩니다. 개인 MCP 키로 작은 보고서를 올리는 요청은 본문이 8MB까지이므로 기본 `proxy-body-size`(2100m) 안에 들어갑니다.

## 문제 해결

| 증상 | 확인 |
|---|---|
| Pod가 시작하지 않고 로그에 `JASCA_BOOTSTRAP_PASSWORD must be set to 12-72 characters` | Secret의 `JASCA_BOOTSTRAP_PASSWORD`가 `CHANGE_ME`이거나 12자 미만입니다. 매번 시작할 때 검사합니다. |
| 로그에 `database:` 오류, `/readyz`가 503 | `password authentication failed`: `JASCA_DB_USER`, `JASCA_DB_PASSWORD`. `JASCA_DB_SCHEMA: schema … does not exist … or … no USAGE privilege`: 스키마 이름(대소문자 구분)과 권한. `no CREATE privilege on schema`: 계정에 그 스키마의 CREATE 권한이 필요합니다. `connection refused`나 시간 초과: `JASCA_DB_HOST`, `JASCA_DB_PORT`, 방화벽. 전용 PostgreSQL이면 Pod와 NetworkPolicy(`app=jasca`만 허용)도 봅니다. |
| 로그인 화면에서 "Keycloak에 연결하지 못했습니다"(`?error=sso`) | Issuer URL이 `.well-known/openid-configuration`의 `issuer`와 글자 그대로 같은지(구형은 `/auth` 포함), Pod에서 Keycloak으로 닿는지, 사내 CA(`SSL_CERT_FILE`)를 확인합니다. 서버 로그의 `sso callback` 줄에 단계(`discovery`, `exchange`, `verify`)가 나옵니다. |
| Keycloak 로그인 직후 `Invalid redirect_uri` | Keycloak client의 Valid redirect URIs가 `https://<접속 주소>/api/v1/auth/sso/callback`과 같은지, JASCA의 사이트 주소가 실제 접속 주소와 같은지 봅니다. |
| "로그인 요청을 확인하지 못했습니다"(`?error=state`) | 로그인 도중 10분이 지났거나 쿠키가 막혔습니다. 사이트 주소와 접속 주소가 다르면 쿠키가 전달되지 않습니다. |
| 역할이 반영되지 않음 | 관리 → SSO의 역할 이름이 Keycloak 역할 이름과 같은지, 토큰에 역할이 실리는지(Client scopes → Evaluate)를 봅니다. 역할은 다음 로그인 때 반영됩니다. |
| 부서가 비어 있음 | 위 "첫 로그인에서 부서가 비어 있을 때"를 보세요. |
| 동기화 실패(관리 → Keycloak 동기화의 마지막 오류) | 서비스 계정 Secret, `view-users` 역할, Issuer URL에 `/realms/`가 있는지 확인하고 **지금 동기화**를 눌러 오류 문구를 봅니다. |
| 서버 스캔이 "실패"로 끝남 | 스캔 상세의 원인 문구를 먼저 봅니다. "Trivy 실행에 실패했습니다"는 원인이 서버 로그(`server scan <번호>:` 줄)에 있습니다. 제한 시간(**관리 → Trivy DB → 스캔 옵션**에서 정하고, 비워 두면 `JASCA_SCAN_TIMEOUT_MIN`, 기본 15분), 메모리 한도(OOMKilled), 압축 파일 형식(zip, tar, tar.gz만)도 봅니다. |
| 스캔 파일 업로드가 507 "서버 저장 공간이 부족해 지금은 파일을 받을 수 없습니다" | 데이터 볼륨(`jasca-data`)의 남은 공간이 "올리는 파일 + 압축 해제 상한(`JASCA_MAX_EXTRACT_MB`)"보다 적습니다. 대기 중인 스캔이 끝나면 파일이 지워져 공간이 비니 잠시 뒤 다시 올리면 됩니다. 자주 나오면 PVC를 늘리세요. 남은 공간은 관리자 MCP 도구 `system_status`의 `data_volume`에 나옵니다. |
| 업로드가 413 | 보고서는 `JASCA_MAX_REPORT_MB`(기본 50), 스캔 파일은 `JASCA_MAX_SCAN_UPLOAD_MB`(기본 2048)가 상한입니다. Ingress `proxy-body-size`도 함께 봅니다. |
| CI 업로드가 401 | 토큰이 만료·폐기됐거나, 다른 프로젝트의 토큰이거나, 권한 범위에 `upload`가 없습니다. 토큰은 해당 프로젝트 키의 경로에서만 쓸 수 있습니다. |
| MCP 클라이언트가 `/mcp`에서 401·403 | 401은 MCP 키나 토큰이 틀렸거나 만료·폐기된 것, 또는 키 주인의 계정이 비활성화된 것입니다(클라이언트에 따라 OAuth 등록 오류로 보입니다). 403은 프로젝트 토큰의 권한 범위에 `read`가 없거나 프록시가 다른 사이트의 `Origin` 헤더를 붙이는 경우입니다. 도구 호출이 "Not allowed"로 답하면 키 주인의 역할이나 프로젝트 권한이 모자라거나 읽기 전용 키입니다. |
| MCP 키로 API를 부르면 403 "MCP 키는 MCP 주소(/mcp)와 스캔 업로드에만 쓸 수 있습니다" | 개인 MCP 키(`jsu_…`)는 `/mcp`와 업로드(`POST …/scans`, `POST …/scan-jobs`)에서만 받습니다. CI에는 프로젝트 API 토큰(`jsc_…`)을 쓰세요. |
| 모든 쓰기 요청이 403(`csrf`) | 프록시가 `Origin`/`Host`를 바꾸고 있습니다. 브라우저가 접속한 호스트가 그대로 전달되어야 합니다. |
| Harbor 웹훅이 401 | Harbor 웹훅의 Auth Header가 연결 생성 때 보인 Secret과 같은지 봅니다. Secret은 다시 볼 수 없으니, 잊었으면 연결을 새로 만드세요. |
| 알림이 오지 않음 | **관리 → 알림 채널**의 시험 발송, SMTP 설정, 프로젝트 **설정 → 알림**에서 채널과 이벤트를 골랐는지 확인합니다. 전송은 실패하면 1분, 5분, 30분 뒤에 다시 시도하고 4번째 실패에서 멈춥니다. |
| `/healthz`는 되는데 화면이 안 열림 | Ingress 경로와 TLS를 확인합니다. 앱은 `/` 전체를 서비스합니다. |

로그는 `kubectl -n jasca logs deploy/jasca`로 봅니다. 비밀값(키, 비밀번호, 토큰)은 로그에 남기지 않습니다.

## 서드파티 라이선스

이미지의 `/licenses/`에 Go 모듈과 npm 패키지의 라이선스, Pretendard(OFL)가 들어 있습니다. 포함된 Trivy 0.76.1(Aqua Security, Apache License 2.0)은 공식 이미지에 LICENSE 파일이 없어 `/licenses/Trivy-NOTICE.txt`에 고지문을 둡니다. 원문: https://github.com/aquasecurity/trivy/blob/main/LICENSE
