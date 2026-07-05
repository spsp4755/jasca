# JASCA ZAP Scanner Kubernetes 배포

ZAP은 JASCA와 별도 Deployment로 실행합니다. JASCA는 내부 Service 주소인 `http://zap-scanner:8080`으로 ZAP API를 호출합니다.

## 적용

```bash
kubectl apply -k k8s/zap-scanner
```

## 확인

```bash
kubectl -n jasca get pod,svc -l app=zap-scanner
```

## 운영 주의

- ZAP Service는 외부에 노출하지 말고 JASCA에서만 접근하도록 네트워크 정책을 구성하는 것을 권장합니다.
- 폐쇄망에서는 `ghcr.io/zaproxy/zaproxy:stable` 이미지를 사전에 반입하거나 사내 레지스트리 주소로 변경해야 합니다.
- Active Scan은 대상 서비스에 부하를 줄 수 있으므로 관리자 설정에서 명시적으로 허용한 경우에만 사용하세요.
- JASCA 관리자 화면에서 ZAP 허용 대상 패턴을 설정하지 않으면 사용자가 URL 스캔을 실행할 수 없습니다.
