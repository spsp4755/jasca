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

- JASCA의 ZAP은 허용된 URL을 탐색하고 Passive Alert만 수집합니다. 공격성 Active Scan은 제공하지 않습니다.
- 운영계가 아닌 승인된 스테이징 URL만 관리자 허용 대상 목록에 등록합니다.
- ZAP Service와 API 포트 `8080`은 외부 Ingress로 노출하지 말고 JASCA에서만 접근하도록 네트워크 정책을 구성합니다.
- ZAP Pod의 egress는 승인된 검사 대상 네트워크로만 제한합니다.
- 로그인 검사는 최소 권한의 테스트 계정과 짧은 만료 세션만 사용합니다. 운영 관리자 계정이나 장기 API 토큰은 입력하지 마세요.
- 폐쇄망에서는 `ghcr.io/zaproxy/zaproxy:stable` 이미지를 사전에 반입하거나 사내 레지스트리 주소로 변경해야 합니다.
- JASCA 관리자 화면에서 ZAP 허용 대상 패턴을 설정하지 않으면 사용자가 URL 스캔을 실행할 수 없습니다.
- 관리자 화면에서 대상 프로필을 만들고 전역/프로필 허용 URL 패턴을 함께 설정하세요. 사용자는 프로필 밖의 URL을 스캔할 수 없으며, `ZAP 연결 테스트`는 ZAP 버전만 확인하고 Spider를 시작하지 않습니다.
