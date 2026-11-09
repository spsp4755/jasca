
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
