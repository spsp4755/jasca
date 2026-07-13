# JASCA Kubernetes / Harbor 배포

이 오버레이는 다음 이미지를 사용합니다.

```text
harbor.kubagents-ofc.koreacb.com/jasca/jasca-offline:v0.3.12
```

접속 URL은 `https://jasca.kubagents-ofc.koreacb.com`입니다. JASCA monolith는 컨테이너 내부에서 PostgreSQL과 Redis를 함께 실행하므로 `replicas: 1`과 `Recreate` 전략을 유지해야 합니다.

## 1. Harbor에 이미지 반입

폐쇄망 반입 파일 `jasca-offline-v0.3.12-amd64.tar.gz`를 사용합니다. Podman이 압축 파일을 직접 읽지 못하는 환경이면 `gzip -dc`로 표준 입력을 사용합니다.

```bash
gzip -dc jasca-offline-v0.3.12-amd64.tar.gz | podman load
podman images | grep jasca-offline

podman login harbor.kubagents-ofc.koreacb.com
podman tag jasca-offline:v0.3.12-amd64 \
  harbor.kubagents-ofc.koreacb.com/jasca/jasca-offline:v0.3.12
podman push harbor.kubagents-ofc.koreacb.com/jasca/jasca-offline:v0.3.12
```

`podman load` 결과의 원본 태그가 다르면 `podman images` 출력의 이미지명:태그를 `podman tag` 첫 번째 인수에 사용합니다.

## 2. 사전 준비

클러스터에서 Harbor pull 자격 증명과 JASCA 비밀값을 생성합니다. `harbor-registry`와 `jasca-secret`은 Git에 넣지 않습니다.

```bash
kubectl create namespace jasca

kubectl -n jasca create secret docker-registry harbor-registry \
  --docker-server=harbor.kubagents-ofc.koreacb.com \
  --docker-username='<HARBOR_USER>' \
  --docker-password='<HARBOR_PASSWORD>'

cp secret.example.yaml secret.yaml
vi secret.yaml
kubectl apply -f secret.yaml
```

Ingress TLS Secret `jasca-kubagents-ofc-tls`은 조직의 인증서 발급 절차 또는 cert-manager로 사전에 생성합니다. 기존 JASCA DB를 옮기는 경우 `DB_PASSWORD`는 기존 PostgreSQL 데이터 디렉터리에서 사용하던 값과 반드시 같아야 합니다.

## 3. 배포

```bash
kubectl apply -k .
kubectl -n jasca rollout status deployment/jasca --timeout=10m
kubectl -n jasca get pods,pvc,svc,ingress
kubectl -n jasca logs deployment/jasca --tail=100
```

`jasca-trivy-db` PVC에는 오프라인 Trivy DB를 `/app/trivy-db/db/trivy.db` 구조로 반입합니다. ZAP을 사용하면 같은 namespace에 `zap-scanner` Service를 배포하거나, `configmap-patch.yaml`의 `ZAP_BASE_URL`을 사내 ZAP 서비스 주소로 바꿉니다.

## 4. 배포 확인과 롤백

```bash
kubectl -n jasca get ingress jasca
kubectl -n jasca describe pod -l app=jasca
kubectl -n jasca rollout history deployment/jasca
```

이전 Revision으로 되돌릴 때는 PVC를 삭제하지 않고 다음만 실행합니다.

```bash
kubectl -n jasca rollout undo deployment/jasca
kubectl -n jasca rollout status deployment/jasca --timeout=10m
```

새 이미지를 배포할 때는 `kustomization.yaml`의 `newTag`를 새 버전으로 변경한 뒤 `kubectl apply -k .`를 실행합니다.
