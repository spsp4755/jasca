package trivy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestArgsNoShell(t *testing.T) {
	o := Options{CacheDir: "/c", Scanners: []string{"vuln", "secret"}}
	a := Args("fs", "/in", o)
	i := slices.Index(a, "--scanners")
	if i < 0 || a[i+1] != "vuln,secret" {
		t.Fatalf("scanners: %v", a)
	}
	for _, e := range a {
		if strings.Contains(e, " ") {
			t.Fatalf("space in %q", e)
		}
	}
	if a[0] != "fs" || a[len(a)-1] != "/in" {
		t.Fatalf("fs: %v", a)
	}
	im := Args("image", "/x.tar", o)
	if im[0] != "image" || im[len(im)-2] != "--input" || im[len(im)-1] != "/x.tar" {
		t.Fatalf("image: %v", im)
	}
	sb := Args("sbom", "/s.json", o)
	if sb[0] != "sbom" || sb[len(sb)-1] != "/s.json" || sb[slices.Index(sb, "--scanners")+1] != "vuln" {
		t.Fatalf("sbom: %v", sb)
	}
	for _, f := range []string{"--format", "--list-all-pkgs", "--skip-db-update", "--skip-java-db-update", "--skip-check-update", "--offline-scan", "--cache-dir", "--quiet"} {
		if !slices.Contains(a, f) {
			t.Fatalf("missing %s", f)
		}
	}
	// trivy 0.76.1 sbom has no misconfig checks and rejects --skip-check-update ("unknown flag")
	if slices.Contains(sb, "--skip-check-update") || !slices.Contains(sb, "--offline-scan") {
		t.Fatalf("sbom flags: %v", sb)
	}
}

func TestCycloneDXWithOS(t *testing.T) {
	out, err := CycloneDXWithOS(&OSInfo{Family: "alpine", Name: "3.12.12"}, []Package{
		{PURL: "pkg:apk/alpine/zlib@1.2.12-r0?arch=x86_64&distro=3.12.12", Name: "zlib", Version: "1.2.12-r0", Ecosystem: "alpine"}})
	if err != nil {
		t.Fatal(err)
	}
	var bom struct {
		Components []struct{ Type, Name, Version, Purl string }
	}
	json.Unmarshal(out, &bom)
	if len(bom.Components) != 2 || bom.Components[0].Type != "operating-system" || bom.Components[0].Name != "alpine" ||
		bom.Components[0].Version != "3.12.12" || bom.Components[1].Name != "zlib" {
		t.Fatalf("%+v", bom.Components)
	}
	plain, _ := CycloneDX([]Package{{PURL: "pkg:npm/a@1", Name: "a", Version: "1"}})
	if bytes.Contains(plain, []byte("operating-system")) {
		t.Fatal("OS component without OS")
	}
}

type ent struct {
	name string
	data []byte
	typ  byte
	link string
}

func mkTar(t *testing.T, ents []ent, truncate bool) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for _, e := range ents {
		h := &tar.Header{Name: e.name, Size: int64(len(e.data)), Mode: 0o644, Typeflag: tar.TypeReg}
		if e.typ != 0 {
			h.Typeflag, h.Linkname, h.Size = e.typ, e.link, 0
		}
		tw.WriteHeader(h)
		tw.Write(e.data)
	}
	tw.Close()
	gz.Close()
	out := b.Bytes()
	if truncate {
		out = out[:len(out)/2]
	}
	return out
}

func metaJSON() []byte {
	return []byte(`{"Version":2,"NextUpdate":"2026-11-10T00:00:00Z","UpdatedAt":"2026-11-09T00:00:00Z","DownloadedAt":"2026-11-09T01:00:00Z"}`)
}

func bigDB(n int) []byte { return bytes.Repeat([]byte{7}, n) }

func seedOld(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	os.MkdirAll(filepath.Join(d, "db"), 0o755)
	os.WriteFile(filepath.Join(d, "db", "old.txt"), []byte("old-content"), 0o644)
	return d
}

func oldIntact(t *testing.T, d string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(d, "db", "old.txt"))
	if err != nil || string(b) != "old-content" {
		t.Fatalf("old db damaged: %v %q", err, b)
	}
	es, _ := os.ReadDir(d)
	for _, e := range es {
		if strings.HasPrefix(e.Name(), ".incoming-") {
			t.Fatalf("leftover %s", e.Name())
		}
	}
}

func TestBundleInstallOK(t *testing.T) {
	d := seedOld(t)
	k, st, err := InstallBundle(d, bytes.NewReader(mkTar(t, []ent{{name: "trivy.db", data: bigDB(2 << 20)}, {name: "metadata.json", data: metaJSON()}}, false)), 64<<20)
	if err != nil || k != "db" || st.Version != 2 {
		t.Fatalf("%v %q %+v", err, k, st)
	}
	s, err := Status(d)
	if err != nil || s.Version != 2 || s.UpdatedAt.IsZero() || s.NextUpdate.IsZero() || s.JavaDB {
		t.Fatalf("%v %+v", err, s)
	}
	if _, err := os.Stat(filepath.Join(d, "db", "old.txt")); err == nil {
		t.Fatal("old not replaced")
	}
	// java db
	k, _, err = InstallBundle(d, bytes.NewReader(mkTar(t, []ent{{name: "trivy-java.db", data: bigDB(2 << 20)}, {name: "metadata.json", data: metaJSON()}}, false)), 64<<20)
	if err != nil || k != "java-db" {
		t.Fatalf("%v %q", err, k)
	}
	if s, _ := Status(d); !s.JavaDB || s.JavaUpdatedAt.IsZero() {
		t.Fatalf("%+v", s)
	}
}

func TestBundleRejects(t *testing.T) {
	good := ent{name: "trivy.db", data: bigDB(2 << 20)}
	cases := map[string][]byte{
		"missing metadata": mkTar(t, []ent{good}, false),
		"truncated":        mkTar(t, []ent{good, {name: "metadata.json", data: metaJSON()}}, true),
		"traversal":        mkTar(t, []ent{{name: "../evil", data: []byte("x")}, good, {name: "metadata.json", data: metaJSON()}}, false),
		"absolute":         mkTar(t, []ent{{name: "/tmp/evil", data: []byte("x")}, good, {name: "metadata.json", data: metaJSON()}}, false),
		"symlink":          mkTar(t, []ent{{name: "l", typ: tar.TypeSymlink, link: "/etc"}, good, {name: "metadata.json", data: metaJSON()}}, false),
		"small db":         mkTar(t, []ent{{name: "trivy.db", data: bigDB(100)}, {name: "metadata.json", data: metaJSON()}}, false),
		"bad metadata":     mkTar(t, []ent{good, {name: "metadata.json", data: []byte(`{"Version":0}`)}}, false),
		"too big":          mkTar(t, []ent{good, {name: "metadata.json", data: metaJSON()}}, false),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			d := seedOld(t)
			max := int64(64 << 20)
			if name == "too big" {
				max = 1 << 20
			}
			_, _, err := InstallBundle(d, bytes.NewReader(b), max)
			if err == nil {
				t.Fatal("expected error")
			}
			if (name == "too big") != errors.Is(err, ErrTooLarge) {
				t.Fatalf("ErrTooLarge: %v", err)
			}
			oldIntact(t, d)
		})
	}
}

func TestCycloneDXRoundTrip(t *testing.T) {
	out, err := CycloneDX([]Package{
		{PURL: "pkg:npm/lodash@4.17.15", Name: "lodash", Version: "4.17.15", Ecosystem: "npm"},
		{Name: "requests", Version: "2.0.0", Ecosystem: "pypi"},
		{Name: "mystery", Version: "1", Ecosystem: "weird"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var bom struct {
		BomFormat, SpecVersion string
		Components             []struct{ Type, Name, Version, Purl string }
	}
	if err := json.Unmarshal(out, &bom); err != nil {
		t.Fatal(err)
	}
	if bom.BomFormat != "CycloneDX" || bom.SpecVersion != "1.5" || len(bom.Components) != 2 {
		t.Fatalf("%+v", bom)
	}
	c := bom.Components[1]
	if c.Name != "requests" || c.Version != "2.0.0" || c.Purl != "pkg:pypi/requests@2.0.0" || c.Type != "library" {
		t.Fatalf("%+v", c)
	}
	if bom.Components[0].Purl != "pkg:npm/lodash@4.17.15" {
		t.Fatalf("%+v", bom.Components[0])
	}
}

func TestPURLTable(t *testing.T) {
	for _, c := range []struct {
		p    Package
		want string
	}{
		{Package{Name: "requests", Version: "2.0.0", Ecosystem: "pypi"}, "pkg:pypi/requests@2.0.0"},
		{Package{Name: "github.com/a/b", Version: "v1.2.3", Ecosystem: "golang"}, "pkg:golang/github.com/a/b@v1.2.3"},
		{Package{Name: "org.apache:commons-lang3", Version: "3.0", Ecosystem: "maven"}, "pkg:maven/org.apache/commons-lang3@3.0"},
		{Package{Name: "@scope/name", Version: "1.0.0", Ecosystem: "npm"}, "pkg:npm/%40scope/name@1.0.0"},
	} {
		if got := buildPURL(c.p); got != c.want {
			t.Errorf("%+v: got %s want %s", c.p, got, c.want)
		}
	}
}

func TestRunCapsAndStderr(t *testing.T) {
	sh := filepath.Join(t.TempDir(), "fake.sh")
	os.WriteFile(sh, []byte("#!/bin/sh\necho out\necho boom >&2\nexit 3\n"), 0o755)
	var b bytes.Buffer
	err := Run(context.Background(), Options{Bin: sh, CacheDir: "/c", Scanners: []string{"vuln"}, Timeout: 5 * time.Second}, "fs", "/in", &b)
	if err == nil || !strings.Contains(err.Error(), "boom") || b.String() != "out\n" {
		t.Fatalf("%v %q", err, b.String())
	}
}

func TestRunRealTrivy(t *testing.T) {
	if os.Getenv("JASCA_TEST_TRIVY") != "1" {
		t.Skip("set JASCA_TEST_TRIVY=1 (and JASCA_TRIVY_BIN, JASCA_TRIVY_CACHE)")
	}
	cache := os.Getenv("JASCA_TRIVY_CACHE")
	var b bytes.Buffer
	err := Run(context.Background(), Options{Bin: os.Getenv("JASCA_TRIVY_BIN"), CacheDir: cache, Scanners: []string{"vuln"}, Timeout: 2 * time.Minute}, "fs", "testdata/fs", &b)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "lodash") {
		t.Fatalf("no lodash in output: %.300s", b.String())
	}
}
