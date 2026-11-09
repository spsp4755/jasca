package formats

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

var fixtures = map[string]string{
	"testdata/trivy/image-alpine.json": "trivy",
	"testdata/trivy/fs-mixed.json":     "trivy",
	"testdata/sarif/semgrep.sarif":     "sarif",
	"testdata/sarif/checkov.sarif":     "sarif",
	"testdata/harbor/report.json":      "harbor",
	"testdata/cyclonedx/image.json":    "cyclonedx",
}

func load(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parse(t *testing.T, name, path string) *Report {
	t.Helper()
	p, ok := Get(name)
	if !ok {
		t.Fatalf("no parser %s", name)
	}
	r, err := p.Parse(bytes.NewReader(load(t, path)))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestDetect(t *testing.T) {
	for path, want := range fixtures {
		b := load(t, path)
		if len(b) > 8192 {
			b = b[:8192]
		}
		p, ok := Detect(b)
		if !ok || p.Name() != want {
			t.Errorf("%s: got %v %v, want %s", path, p, ok, want)
		}
	}
	for _, in := range []string{"\x89PNG\r\n\x1a\n\x00\x00", "{}", "[]", ""} {
		if p, ok := Detect([]byte(in)); ok {
			t.Errorf("%q matched %s", in, p.Name())
		}
	}
}

func findKind(r *Report, kind string) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Kind == kind {
			out = append(out, f)
		}
	}
	return out
}

func TestTrivyImage(t *testing.T) {
	r := parse(t, "trivy", "testdata/trivy/image-alpine.json")
	if r.TargetKind != "image" || r.TargetName != "alpine" || r.Ref != "3.12" {
		t.Fatalf("target %q %q %q", r.TargetKind, r.TargetName, r.Ref)
	}
	if len(r.Packages) <= 10 {
		t.Fatalf("packages %d", len(r.Packages))
	}
	for _, p := range r.Packages {
		if p.Ecosystem != "alpine" {
			t.Fatalf("ecosystem %q", p.Ecosystem)
		}
	}
	var got bool
	for _, f := range r.Findings {
		if f.RuleID == "CVE-2022-37434" {
			got = f.Severity == "CRITICAL" && f.PkgName == "zlib" && f.FixedVersion == "1.2.12-r2" &&
				f.Vuln != nil && len(f.Vuln.CWEs) > 0 && f.Tool == "trivy" && len(f.Fingerprint) == 32
		}
	}
	if !got {
		t.Fatal("CVE-2022-37434 missing or wrong")
	}
	if !r.Complete["vuln:trivy"] {
		t.Fatal("not complete")
	}
}

func TestTrivyFSMixed(t *testing.T) {
	r := parse(t, "trivy", "testdata/trivy/fs-mixed.json")
	if len(findKind(r, "misconfig")) != 2 || len(findKind(r, "secret")) == 0 {
		t.Fatalf("findings %+v", r.Findings)
	}
	var lodash bool
	for _, f := range findKind(r, "vuln") {
		if f.PkgName == "lodash" && f.PkgPath == "package-lock.json" {
			lodash = true
		}
	}
	if !lodash {
		t.Fatal("no lodash vuln")
	}
	if r.Packages[0].Ecosystem != "npm" {
		t.Fatalf("eco %q", r.Packages[0].Ecosystem)
	}
	if i := parse(t, "trivy", "testdata/trivy/image-alpine.json"); i.OS == nil || i.OS.Family != "alpine" || i.OS.Name != "3.12.12" {
		t.Fatalf("trivy os %+v", i.OS)
	}
	for _, k := range []string{"vuln:trivy", "misconfig:trivy", "secret:trivy"} {
		if !r.Complete[k] {
			t.Errorf("%s not complete", k)
		}
	}
	for _, f := range findKind(r, "secret") {
		b, _ := json.Marshal(f)
		if strings.Contains(string(b), "AWS_ACCESS_KEY_ID") || strings.Contains(string(b), "export ") {
			t.Fatalf("secret match leaked: %s", b)
		}
		if f.Details["redacted_match_sha256"] == "" || len(f.Fingerprint) != 32 {
			t.Fatal("no hash/fingerprint")
		}
	}
	if m := findKind(r, "misconfig")[0]; m.Location != "Dockerfile" || m.RuleID == "" || m.Severity != "HIGH" && m.Severity != "MEDIUM" && m.Severity != "LOW" && m.Severity != "CRITICAL" {
		t.Fatalf("misconfig %+v", m)
	}
}

func TestSARIF(t *testing.T) {
	r := parse(t, "sarif", "testdata/sarif/semgrep.sarif")
	if !r.Complete["sast:semgrep oss"] || len(r.Findings) != 2 {
		t.Fatalf("%+v %v", r.Findings, r.Complete)
	}
	if f := r.Findings[0]; f.Tool != "semgrep oss" || f.Kind != "sast" || f.Severity != "HIGH" || f.Location != "app/run.py" {
		t.Fatalf("%+v", f)
	}
	if r.Findings[1].Severity != "LOW" { // note, no security-severity
		t.Fatalf("%+v", r.Findings[1])
	}
	c := parse(t, "sarif", "testdata/sarif/checkov.sarif")
	if !c.Complete["sast:checkov"] || c.Findings[0].Severity != "HIGH" {
		t.Fatalf("%+v", c.Findings)
	}
	for in, want := range map[float64]string{9.5: "CRITICAL", 7: "HIGH", 4: "MEDIUM", 0.1: "LOW", 0: "UNKNOWN"} {
		if got := sarifScoreSeverity(in); got != want {
			t.Errorf("%v: %s want %s", in, got, want)
		}
	}
}

func TestSARIFFingerprintIgnoresLine(t *testing.T) {
	src := string(load(t, "testdata/sarif/semgrep.sarif"))
	moved := strings.ReplaceAll(strings.ReplaceAll(src, `"startLine": 12, "endLine": 12`, `"startLine": 17, "endLine": 17`), `"startLine": 40`, `"startLine": 45`)
	if moved == src {
		t.Fatal("replace failed")
	}
	p, _ := Get("sarif")
	a, _ := p.Parse(strings.NewReader(src))
	b, err := p.Parse(strings.NewReader(moved))
	if err != nil {
		t.Fatal(err)
	}
	for i := range a.Findings {
		if !bytes.Equal(a.Findings[i].Fingerprint, b.Findings[i].Fingerprint) {
			t.Errorf("finding %d fingerprint changed", i)
		}
	}
	if bytes.Equal(a.Findings[0].Fingerprint, a.Findings[1].Fingerprint) {
		t.Fatal("different findings share a fingerprint")
	}
}

func TestHarbor(t *testing.T) {
	r := parse(t, "harbor", "testdata/harbor/report.json")
	if r.TargetKind != "image" || r.TargetName != "library/web" || r.Ref != "1.4.2" || len(r.Findings) != 3 || !r.Complete["vuln:trivy"] {
		t.Fatalf("%+v", r)
	}
	f := r.Findings[0]
	if f.Severity != "CRITICAL" || f.FixedVersion != "1.2.12-r2" || f.Vuln == nil || f.Vuln.CVSSScore == nil || *f.Vuln.CVSSScore != 9.8 {
		t.Fatalf("%+v", f)
	}
	if r.Findings[2].Severity != "LOW" {
		t.Fatalf("negligible -> %s", r.Findings[2].Severity)
	}
}

func TestCycloneDX(t *testing.T) {
	r := parse(t, "cyclonedx", "testdata/cyclonedx/image.json")
	if r.TargetKind != "sbom" || r.TargetName != "alpine" || r.Ref != "3.12" || len(r.Packages) <= 10 || len(r.Findings) != 0 || len(r.Complete) != 0 {
		t.Fatalf("%q %q %q %d %d %v", r.TargetKind, r.TargetName, r.Ref, len(r.Packages), len(r.Findings), r.Complete)
	}
	for _, p := range r.Packages {
		if p.Ecosystem == "" || p.Name == "" && p.PURL == "" {
			t.Fatalf("bad package %+v", p)
		}
	}
	if r.OS == nil || r.OS.Family != "alpine" || r.OS.Name != "3.12.12" {
		t.Fatalf("os %+v", r.OS)
	}
	p := r.Packages[len(r.Packages)-1]
	if p.PURL == "" || p.Ecosystem != "alpine" || p.Version == "" {
		t.Fatalf("%+v", p)
	}
}

func TestParseTruncated(t *testing.T) {
	for path, name := range fixtures {
		b := load(t, path)
		p, _ := Get(name)
		if _, err := p.Parse(bytes.NewReader(b[:len(b)/2])); err == nil {
			t.Errorf("%s: truncated parsed without error", path)
		}
	}
}

func TestFingerprintRules(t *testing.T) {
	a := Fingerprint(Finding{Kind: "vuln", RuleID: "CVE-1", PkgName: "x", PkgPath: "p", Severity: "LOW"})
	b := Fingerprint(Finding{Kind: "vuln", RuleID: "CVE-1", PkgName: "x", PkgPath: "p", Severity: "HIGH", PkgVersion: "2"})
	if !bytes.Equal(a, b) {
		t.Fatal("vuln fingerprint must ignore severity and version")
	}
	if NormalizeSeverity("moderate") != "MEDIUM" || NormalizeSeverity("zzz") != "UNKNOWN" {
		t.Fatal("severity")
	}
}

func TestSARIFDedupAndZeroScore(t *testing.T) {
	const doc = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"T"}},"results":[
	{"ruleId":"R","level":"note","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1,"snippet":{"text":"x := 1"}}}}]},
	{"ruleId":"R","level":"error","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":9,"snippet":{"text":"x := 1"}}}}]},
	{"ruleId":"Z","level":"error","properties":{"security-severity":"0"},"message":{"text":"z"}}]}]}`
	p, _ := Get("sarif")
	r, err := p.Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 2 || r.Findings[0].Severity != "HIGH" || r.Findings[1].Severity != "HIGH" {
		t.Fatalf("%+v", r.Findings)
	}
}

// Debian packages: Trivy lists version and release apart; the package keeps the full version (as findings print
// it) and the source package, which the recheck needs.
func TestTrivyDebianSourcePackage(t *testing.T) {
	r := parse(t, "trivy", "testdata/trivy/image-debian.json")
	got := map[string]Package{}
	for _, p := range r.Packages {
		if _, dup := got[p.Name]; dup {
			t.Fatalf("package %s listed twice: %+v", p.Name, r.Packages)
		}
		got[p.Name] = p
	}
	if p := got["libssl1.1"]; p.Version != "1.1.1w-0+deb11u8" || p.SrcName != "openssl" || p.SrcVersion != "1.1.1w-0+deb11u8" || p.Ecosystem != "debian" {
		t.Fatalf("libssl1.1: %+v", p)
	}
	if p := got["zlib1g"]; p.Version != "1:1.2.11.dfsg-2+deb11u2" || p.SrcName != "zlib" || p.SrcVersion != "1:1.2.11.dfsg-2+deb11u2" {
		t.Fatalf("zlib1g: %+v", p)
	}
	cdx := `{"bomFormat":"CycloneDX","components":[{"type":"library","name":"libssl1.1","version":"1.1.1w-0+deb11u8",
		"purl":"pkg:deb/debian/libssl1.1@1.1.1w-0%2Bdeb11u8?distro=debian-11.11","properties":[
		{"name":"aquasecurity:trivy:SrcName","value":"openssl"},{"name":"aquasecurity:trivy:SrcVersion","value":"1.1.1w"},
		{"name":"aquasecurity:trivy:SrcRelease","value":"0+deb11u8"},{"name":"aquasecurity:trivy:SrcEpoch","value":"1"}]}]}`
	c, err := cdxParser{}.Parse(strings.NewReader(cdx))
	if err != nil {
		t.Fatal(err)
	}
	if p := c.Packages[0]; p.SrcName != "openssl" || p.SrcVersion != "1:1.1.1w-0+deb11u8" {
		t.Fatalf("cyclonedx: %+v", p)
	}
}

// The same JAR version at two paths is two inventory entries, so a recheck fingerprints both copies.
func TestTrivySamePackageTwoPaths(t *testing.T) {
	doc := `{"SchemaVersion":2,"ArtifactName":"app","ArtifactType":"container_image","Results":[{"Target":"Java","Class":"lang-pkgs","Type":"jar",
		"Packages":[{"Name":"org.x:lib","Version":"1.0","FilePath":"a/lib.jar"},{"Name":"org.x:lib","Version":"1.0","FilePath":"b/lib.jar"},
		{"Name":"org.x:lib","Version":"1.0","FilePath":"a/lib.jar"}]}]}`
	p, _ := Get("trivy")
	rep, err := p.Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Packages) != 2 || rep.Packages[0].Path != "a/lib.jar" || rep.Packages[1].Path != "b/lib.jar" {
		t.Fatalf("packages %+v", rep.Packages)
	}
}
