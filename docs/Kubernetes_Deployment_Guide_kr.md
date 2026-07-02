# JASCA Kubernetes 배포 가이드

Kubernetes 배포 파일은 `k8s/monolith`에 있습니다. 현재 JASCA 운영 이미지는 `jasca-offline:latest` 단일 컨테이너 안에서 Web, API, PostgreSQL, Redis를 함께 실행하는 구조입니다. 따라서 k8s에서도 우선 monolith 방식으로 올리는 것이 기존 Docker 운영과 가장 유사하고 안전합니다.

## 빠른 절차

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

상세한 이미지 반입, Trivy DB 반입, 롤백 방법은 `k8s/monolith/README_KO.md`를 참고하세요.
