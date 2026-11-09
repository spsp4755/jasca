
## 버전 비교 생태계 추가

`internal/versions`는 패키지 인벤토리의 버전이 권고(advisory)의 영향 범위에 들어가는지 판단한다.
공개 함수는 `Compare`, `Matches`, `Known` 세 개이며, 생태계 이름(소문자)으로 비교기를 고른다.

### 기존 생태계에 이름만 추가

`internal/versions/versions.go`의 `init()`에서 해당 비교기의 `reg(...)` 호출 끝에 이름을 붙인다.

```go
reg("deb", debCompare, "debian", "ubuntu", "새이름")
```

### 새 비교 방식 추가

1. `internal/versions/<이름>.go`에 `func xxxCompare(a, b string) (int, error)`를 만든다. 반환은 -1/0/1이고, 빈 문자열이나 해석할 수 없는 버전은 에러로 돌려준다(패닉 금지). 숫자 비교는 `cmpDigits`를 쓰면 오버플로가 없다.
2. `versions.go`의 `init()`에 `reg("<이름>", xxxCompare, "eco1", "eco2")`를 추가한다.
3. `internal/versions/testdata/cases.json`의 `compare`에 `[생태계, a, b, 기대값]` 형식으로 15건 이상 넣는다. 테스트가 a/b를 뒤집은 결과도 함께 검사한다. `TestCases`의 이름 목록(`deb`, `rpm`, ...)에도 새 이름을 더한다.
4. 범위 표현은 모든 생태계가 같다. 쉼표나 공백은 AND, `||`는 OR, 연산자는 `< <= > >= = == !=`, `*`는 전체이다. 범위 안의 버전도 해당 비교기로 검증되므로 잘못된 범위는 에러가 된다.

### 알아 둘 점

- `Known(eco)`가 false이면 generic 비교(숫자/알파벳 구간 비교)가 쓰인 것이다. UI는 이 경우 경고를 보여 준다. generic은 `1.0-rc1`이 `1.0`보다 크게 나오는 한계가 있다.
- rpm 비교에서 한쪽에 release가 없으면 release는 비교하지 않는다(`<1.0` 같은 범위가 `1.0-1.el8`에 맞도록).
- 현재 매핑: debian/ubuntu = deb, redhat/centos/rocky/alma/amazon/oracle/suse/photon = rpm, alpine/wolfi/chainguard = apk, npm/gomod/cargo/nuget/composer/gem = semver, pip = pep440, maven = maven.
- 테스트 실행: `go test ./internal/versions/`
