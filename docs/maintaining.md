# JASCA 유지보수 안내


## 새 스캔 형식 추가

스캔 결과 파서는 `internal/formats` 에 있다. 새 형식 하나를 추가하는 순서는 다음과 같다.

1. **파서 파일**: `internal/formats/<이름>.go` 를 만든다. `Parser` 인터페이스(`Name`, `Detect(head []byte) bool`, `Parse(io.Reader) (*Report, error)`)를 구현한다.
   - `Detect` 는 본문 앞부분(몇 KB)만 보고 판정한다. 다른 형식과 겹치지 않는 키워드를 고른다.
   - `Parse` 는 `io.ReadAll` 로 본문 전체를 읽지 않는다. `eachKey`/`eachElem` 으로 최상위 객체를 스트리밍 디코딩하고, 닫는 토큰까지 읽어 잘린 파일이 오류가 되게 한다.
   - 심각도는 반드시 `NormalizeSeverity` 를 거치고, 결과는 `rep.add(Finding{...})` 로 넣어 지문을 계산한다. 시크릿 본문은 저장하지 않고 해시만 남긴다.
   - 이 보고서가 전부 다룬 결과 종류는 `Complete["vuln:<도구>"]` 같은 키로 표시한다(자동 해결 처리에 쓰인다). 확실하지 않으면 표시하지 않는다.
2. **등록**: 같은 파일에 `func init() { Register(<이름>Parser{}) }` 한 줄을 둔다. `Detect` 는 등록 순서대로 처음 맞는 파서를 고른다.
3. **픽스처**: `internal/formats/testdata/<이름>/` 에 실제 도구가 만든 출력을 넣는다(300KB 미만, 필요하면 `jq` 로 줄인다). 회사·내부 식별자가 들어가면 안 된다.
4. **테스트**: `formats_test.go` 의 `fixtures` 표에 파일을 추가하고(`TestDetect`, `TestParseTruncated` 가 자동으로 검사), 형식별 테스트(대상 종류, 패키지, 심각도, 지문)를 추가한 뒤 `go test ./internal/formats/...` 를 실행한다.


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
