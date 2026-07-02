# JASCA Kubernetes 배포 가이드

이 매니페스트는 기존 폐쇄망 Docker 배포와 동일한 `jasca-offline:latest` 단일 이미지를 Kubernetes에서 실행하기 위한 기본 구성입니다. JASCA 컨테이너 안에서 Web, API, PostgreSQL, Redis가 함께 실행되므로 운영 전환 리스크를 줄일 수 있습니다.

## 구성 방식

- `Deployment` replicas는 반드시 `1`입니다. 내부 PostgreSQL/Redis를 포함하므로 여러 Pod로 늘리면 데이터 손상 위험이 있습니다.
- `strategy: Recreate`를 사용합니다. 새 Pod가 뜨기 전에 기존 Pod를 내리는 방식이라 같은 PVC를 동시에 잡지 않습니다.
- `jasca-pgdata`, `jasca-redis`, `jasca-scan-results`, `jasca-trivy-db` PVC를 사용합니다.
- 웹은 Service `jasca:3000`으로 노출합니다.
- Ingress를 쓰는 경우 `ingress.example.yaml`을 복사해서 도메인/TLS Secret을 운영 환경에 맞게 수정합니다.

## 이미지 반입

폐쇄망 Kubernetes 노드가 외부 registry를 보지 못하면 각 노드의 container runtime에 이미지를 먼저 올려야 합니다.

Docker runtime 노드 예시:

```bash
gunzip -c jasca-offline.tar.gz | docker load
docker images | grep jasca-offline
```

containerd 노드 예시:

```bash
gunzip -c jasca-offline.tar.gz > jasca-offline.tar
sudo ctr -n k8s.io images import jasca-offline.tar
sudo ctr -n k8s.io images ls | grep jasca-offline
```

사내 registry를 사용할 수 있으면 다음 흐름이 가장 안정적입니다.

```bash
gunzip -c jasca-offline.tar.gz | docker load
docker tag jasca-offline:latest registry.internal/jasca/jasca-offline:latest
docker push registry.internal/jasca/jasca-offline:latest
```

그 후 `deployment.yaml`의 이미지를 `registry.internal/jasca/jasca-offline:latest`로 바꿉니다.

## 최초 배포

```bash
cd k8s/monolith
cp secret.example.yaml secret.yaml
vi secret.yaml
kubectl apply -f namespace.yaml
kubectl apply -f secret.yaml
kubectl apply -k .
```

Ingress를 사용할 경우:

```bash
cp ingress.example.yaml ingress.yaml
vi ingress.yaml
kubectl apply -f ingress.yaml
```

## Trivy DB 반입

JASCA 직접 스캔은 `/app/trivy-db`에 Trivy DB가 있어야 폐쇄망에서 정상 동작합니다.

PVC에 DB를 넣는 예시:

```bash
kubectl -n jasca run trivy-db-loader --rm -it --restart=Never \
  --image=busybox:1.36 \
  --overrides='{"spec":{"volumes":[{"name":"trivy-db","persistentVolumeClaim":{"claimName":"jasca-trivy-db"}}],"containers":[{"name":"trivy-db-loader","image":"busybox:1.36","command":["sh"],"stdin":true,"tty":true,"volumeMounts":[{"name":"trivy-db","mountPath":"/trivy-db"}]}]}}'
```

실무에서는 위 임시 Pod에 접속한 뒤 `/trivy-db/db/trivy.db`, `/trivy-db/db/metadata.json` 구조가 되도록 사내 Trivy DB를 복사합니다. Java DB를 사용하면 `/trivy-db/java-db/trivy-java.db`, `/trivy-db/java-db/metadata.json`도 넣습니다.

## 배포 확인

```bash
kubectl -n jasca get pods,pvc,svc
kubectl -n jasca logs deploy/jasca -f
kubectl -n jasca port-forward svc/jasca 3005:3000
```

브라우저에서 `http://localhost:3005`로 접속해 로그인, 스캔 업로드, 관리자 화면을 확인합니다.

## 기존 k8s 배포 업데이트

```bash
kubectl -n jasca set image deployment/jasca jasca=jasca-offline:latest
kubectl -n jasca rollout status deployment/jasca
```

같은 태그 `latest`를 다시 쓰는 환경이면 이미지 캐시 때문에 새 이미지가 안 잡힐 수 있습니다. 이 경우 digest 또는 버전 태그를 쓰거나 Pod를 재생성합니다.

```bash
kubectl -n jasca rollout restart deployment/jasca
kubectl -n jasca rollout status deployment/jasca
```

## 롤백

직전 ReplicaSet으로 롤백:

```bash
kubectl -n jasca rollout undo deployment/jasca
kubectl -n jasca rollout status deployment/jasca
```

이전 이미지 tar가 있는 경우:

```bash
gunzip -c jasca-offline-old.tar.gz | docker load
kubectl -n jasca set image deployment/jasca jasca=jasca-offline:old
kubectl -n jasca rollout status deployment/jasca
```

PVC는 삭제하지 마세요. `jasca-pgdata`에는 JASCA DB, `jasca-redis`에는 Redis 데이터, `jasca-scan-results`에는 원본 Trivy JSON 결과가 들어 있습니다.

## 운영 주의사항

- 이 매니페스트는 monolith 운영용입니다. replicas를 2 이상으로 늘리지 마세요.
- DB 비밀번호와 JWT Secret은 `secret.yaml`에 보관하고 Git에 올리지 마세요.
- Ingress에서 100MB 이상 업로드를 허용하려면 `proxy-body-size`를 크게 설정해야 합니다.
- 사내 AI 모델 URL을 DNS로 해석하지 못하면 k8s DNS 또는 CoreDNS/hostsAliases/ServiceEntry 등 클러스터 표준 방식으로 해결해야 합니다.
- Keycloak 비밀번호는 JASCA가 변경하지 않습니다. JASCA 관리자 비밀번호 변경은 로컬 DB 비밀번호만 변경합니다.
