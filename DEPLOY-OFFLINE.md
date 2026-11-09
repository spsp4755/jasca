# JASCA v1.0.0 — 폐쇄망 배포 / 데이터 보존

> 첫 초안입니다. Keycloak 절은 자리표시자이며 최종 문서에서 완성합니다.

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
| jasca-v1.0.0.tar.gz | Linux/amd64 서비스 이미지 `jasca:v1.0.0`만 포함(Trivy 0.76.1 실행 파일 포함) |
| postgres-v17.11-jasca1.tar.gz | 별도 선택 이미지 `postgres:v17.11-jasca1` (공식 17.11-bookworm 기반, 쓰지 않는 gosu·snakeoil 키 제거, root로 실행 불가) |
| jasca.yaml | Secret·ConfigMap·PVC·Deployment·Service·Ingress |
| postgres.yaml | 전용 PostgreSQL·영구 PVC·내부 Service·NetworkPolicy |
| DEPLOY-OFFLINE.md | 이 문서 |
| RELEASE-NOTES.md | 이번 버전의 변경 사항 |
| SHA256SUMS | 반입 파일 무결성 검사 |

운영 데이터, 운영 암호, 테스트 계정, **Trivy 취약점 DB**는 이미지에 포함하지 않습니다. 사내 PostgreSQL을 쓰면 `postgres.yaml`과 PostgreSQL 이미지는 필요 없습니다.

## 이미지 반입

폐쇄망 Linux 서버에서 실행합니다.

```sh
sha256sum -c --ignore-missing SHA256SUMS # 이번에 반입한 파일 검증
podman load -i jasca-v1.0.0.tar.gz
podman load -i postgres-v17.11-jasca1.tar.gz
podman image inspect jasca:v1.0.0 --format '{{.Os}}/{{.Architecture}}'
```

**Podman load만으로 Kubernetes containerd에 이미지가 등록되지는 않습니다.** 실행 가능한 모든 워커의 실제 CRI에 반입하세요.

```sh
# 일반 containerd
sudo ctr -n k8s.io images import jasca-v1.0.0.tar.gz
sudo ctr -n k8s.io images import postgres-v17.11-jasca1.tar.gz
# k3s는 sudo k3s ctr images import, RKE2는 해당 런타임의 socket/ctr 사용.
```

사내 레지스트리를 쓰면 이미지를 push한 뒤 `jasca.yaml`의 `image:` 경로를 바꾸세요. `IfNotPresent`는 이미지가 없으면 pull을 시도하므로 사전 반입이 필수입니다.

## 신규 설치

Namespace `jasca`는 미리 생성되어 있다고 가정합니다(`kubectl create namespace jasca`). YAML은 namespace/IngressClass/StorageClass를 만들거나 고정하지 않습니다.

1. `jasca.yaml`의 `JASCA_BOOTSTRAP_PASSWORD`를 12~72자 ASCII로 변경(기본값 `CHANGE_ME`는 12자 미만이라 앱이 시작하지 않습니다).
2. `postgres.yaml`의 `POSTGRES_PASSWORD`를 강력한 암호로 변경. 앱도 같은 Secret을 `PGPASSWORD`로 참조하므로 URL 인코딩이 필요 없습니다.
3. Ingress host(`jasca.example.internal`)를 실제 사내 주소로 변경하고, 필요하면 `ingressClassName`을 지정.
4. 기본 StorageClass가 없으면 `postgres.yaml`과 `jasca.yaml`(PVC `jasca-data`, 기본 30Gi)의 `storageClassName`을 지정. 앱 PVC는 ReadWriteOnce 하나면 됩니다(replicas 1).
5. Ingress TLS 항목은 생략했습니다. 사내 앞단/LB/Ingress 공용 인증서로 **HTTPS**를 제공하세요.
6. 스캔 파일 업로드 상한은 기본 2GiB입니다. Ingress의 `proxy-body-size`(예: `2g`)와 읽기·쓰기 제한 시간(600초)이 이 값 이상이어야 합니다. 상한을 바꾸면 ConfigMap의 `JASCA_MAX_SCAN_UPLOAD_MB`와 함께 바꾸세요.
7. Trivy는 임시 파일을 `/tmp`(emptyDir 2Gi)에, 취약점 DB를 `/data/trivy`에 씁니다. Pod 메모리 한도는 2Gi입니다. 큰 이미지를 스캔하면 늘려야 할 수 있습니다.

```sh
kubectl -n jasca apply --dry-run=server -f postgres.yaml
kubectl -n jasca apply --dry-run=server -f jasca.yaml
kubectl -n jasca apply -f postgres.yaml
kubectl -n jasca rollout status statefulset/jasca-postgres --timeout=300s
kubectl -n jasca apply -f jasca.yaml
kubectl -n jasca rollout status deployment/jasca --timeout=300s
kubectl -n jasca get pods,pvc,svc,ingress
```

DB 스키마는 앱이 시작할 때 자동으로 만들고 올립니다. PostgreSQL Secret 암호는 **DB 최초 초기화 때만** 적용됩니다. 운영 중 Secret만 바꾸면 DB 암호는 바뀌지 않으므로 DB 계정 암호와 Secret을 함께 바꾸세요.

**기존 사내 DB**: `postgres.yaml`을 적용하지 않고 DB와 전용 계정(`jasca`)을 준비합니다. `jasca-config`의 `JASCA_DATABASE_URL`(호스트·DB·계정)을 바꾸고 `jasca-postgres-secrets` Secret에 `POSTGRES_PASSWORD`를 만듭니다. 외부 DB는 `sslmode=verify-full&sslrootcert=/마운트한/CA`를 사용하세요.

설치 후 **Trivy DB를 올리기 전에는 서버 스캔이 동작하지 않습니다.** 아래 "Trivy DB 오프라인 갱신"을 먼저 하세요.

## Keycloak 설정 (SSO)

> TODO: Task 19에서 최종 작성합니다(client 생성, redirect URI, 역할/그룹 매핑, 사내 CA 신뢰, 관리 화면 입력).

SSO는 선택입니다. 설정하지 않아도 로컬 관리자(`admin`)로 로그인할 수 있습니다.

## 관리자 첫 로그인

1. `https://<접속 주소>/`에서 `admin` / 설치 때 정한 `JASCA_BOOTSTRAP_PASSWORD`로 로그인하고, 비밀번호를 바꿉니다.
2. 관리자 화면에서 Trivy DB를 올립니다(다음 절).

## Trivy DB 오프라인 갱신

Trivy 취약점 DB는 인터넷 PC에서 받아 관리자 화면으로 올립니다. 서버는 DB를 받으러 밖으로 나가지 않습니다(`--skip-db-update`).

인터넷이 되는 PC에서(oras 필요):

```sh
oras pull ghcr.io/aquasecurity/trivy-db:2          # db.tar.gz (trivy.db, metadata.json)
oras pull ghcr.io/aquasecurity/trivy-java-db:1     # javadb.tar.gz (자바 JAR 스캔용, 선택)
sha256sum db.tar.gz javadb.tar.gz > trivy-db.sha256
```

반입 매체로 옮긴 뒤 **관리 → Trivy DB**에서 `db.tar.gz`(와 `javadb.tar.gz`)를 올립니다. 올린 DB의 생성 시각이 화면에 보입니다. 주기적으로(예: 매주) 같은 절차를 반복하세요. DB가 오래되면 새 취약점이 탐지되지 않습니다.

## 업그레이드

이미지 태그만 바꾸면 됩니다. DB 스키마는 앱이 시작할 때 올립니다.

1. DB와 PVC를 백업합니다(아래 "백업과 복원").
2. 새 `jasca-vX.Y.Z.tar.gz`를 모든 워커에 반입합니다(위 "이미지 반입").
3. 새 `jasca.yaml`에 쓰던 값(Ingress host, `ingressClassName`, `JASCA_BOOTSTRAP_PASSWORD`, `JASCA_TZ`, DB 주소, 이미지 경로)을 옮겨 적고 적용합니다. `CHANGE_ME`인 채로 적용하면 Secret을 덮어씁니다. 새 `postgres.yaml`을 적용할 때도 `POSTGRES_PASSWORD`를 옮겨 적으세요.
```sh
kubectl apply -f jasca.yaml
kubectl -n jasca rollout status deployment/jasca
```
4. 로그인과 스캔 한 건으로 확인합니다. Recreate 전략이라 교체 중 잠시 접속이 끊깁니다.

## 백업과 복원

DB와 앱 PVC를 **같은 시점에** 함께 받으세요.

```sh
umask 077
kubectl -n jasca exec jasca-postgres-0 -- pg_dump -U jasca -d jasca -Fc > jasca.dump
```

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

## 서드파티 라이선스

이미지의 `/licenses/`에 Go 모듈과 npm 패키지의 라이선스, Pretendard(OFL)가 들어 있습니다. 포함된 Trivy 0.76.1(Aqua Security, Apache License 2.0)은 공식 이미지에 LICENSE 파일이 없어 `/licenses/Trivy-NOTICE.txt`에 고지문을 둡니다. 원문: https://github.com/aquasecurity/trivy/blob/main/LICENSE
