// Package formats parses scan reports (Trivy, SARIF, Harbor, CycloneDX) into a common Report.
package formats

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

type Report struct {
	Format     string // "trivy" | "sarif" | "harbor" | "cyclonedx"
	TargetKind string // "image" | "repo" | "fs" | "sbom" ("" = unknown; caller decides)
	TargetName string
	Ref        string
	Packages   []Package
	Findings   []Finding
	Complete   map[string]bool // result kinds this report fully covers, e.g. "vuln:trivy"
	OS         *OSInfo         // operating system of an image/SBOM when the report says so

	fpIndex map[string]int
}

type OSInfo struct{ Family, Name string }

var sevRank = map[string]int{"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

// add appends f; a finding with an already-seen fingerprint is merged into the first (highest severity kept).
func (r *Report) add(f Finding) {
	f.Fingerprint = Fingerprint(f)
	if r.fpIndex == nil {
		r.fpIndex = map[string]int{}
	}
	if i, ok := r.fpIndex[string(f.Fingerprint)]; ok {
		if sevRank[f.Severity] > sevRank[r.Findings[i].Severity] {
			r.Findings[i].Severity = f.Severity
		}
		return
	}
	r.fpIndex[string(f.Fingerprint)] = len(r.Findings)
	r.Findings = append(r.Findings, f)
}

// Package is one installed package. SrcName/SrcVersion are the OS source package (Debian/Ubuntu advisories are
// keyed by it); empty when the report does not say.
type Package struct{ PURL, Name, Version, Ecosystem, Path, SrcName, SrcVersion string }

// fullVersion renders epoch:version-release the way Trivy prints InstalledVersion.
func fullVersion(epoch int, ver, rel string) string {
	if ver == "" {
		return ""
	}
	if rel != "" {
		ver += "-" + rel
	}
	if epoch > 0 {
		ver = fmt.Sprintf("%d:%s", epoch, ver)
	}
	return ver
}

type Finding struct {
	Kind, Tool, RuleID, Title, Severity                  string // Kind: vuln|misconfig|secret|sast
	PkgName, PkgVersion, FixedVersion, PkgPath, Location string
	Fingerprint                                          []byte
	Vuln                                                 *VulnInfo
	Details                                              map[string]any
}

type VulnInfo struct {
	Title, Description, CVSSVector string
	CVSSScore                      *float64
	Refs, CWEs                     []string
	Published, Modified            *time.Time
}

type Parser interface {
	Name() string
	Detect(head []byte) bool
	Parse(r io.Reader) (*Report, error)
}

var parsers []Parser

func Register(p Parser) { parsers = append(parsers, p) }

func Get(name string) (Parser, bool) {
	for _, p := range parsers {
		if p.Name() == name {
			return p, true
		}
	}
	return nil, false
}

// Detect returns the first registered parser whose Detect accepts head (the first few KB of the body).
func Detect(head []byte) (Parser, bool) {
	head = bytes.TrimSpace(bytes.TrimPrefix(head, []byte("\xef\xbb\xbf")))
	if len(head) == 0 || head[0] != '{' {
		return nil, false
	}
	for _, p := range parsers {
		if p.Detect(head) {
			return p, true
		}
	}
	return nil, false
}

// NormalizeSeverity maps any tool's severity word to CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN.
func NormalizeSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM", "MODERATE":
		return "MEDIUM"
	case "LOW", "NEGLIGIBLE":
		return "LOW"
	}
	return "UNKNOWN"
}

func sha(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

// Fingerprint identifies a finding across scans. Line numbers and severities never take part.
func Fingerprint(f Finding) []byte {
	switch f.Kind {
	case "vuln":
		return sha(fmt.Sprintf("vuln|%s|%s|%s", f.RuleID, f.PkgName, f.PkgPath))
	case "misconfig":
		return sha(fmt.Sprintf("misconfig|%s|%s|%s", f.RuleID, f.Location, str(f.Details, "resource")))
	case "secret":
		return sha(fmt.Sprintf("secret|%s|%s|%s", f.RuleID, f.Location, str(f.Details, "redacted_match_sha256")))
	case "sast":
		if p := str(f.Details, "partial_fingerprints"); p != "" {
			return sha(fmt.Sprintf("sast|%s|%s|%s", f.Tool, f.RuleID, p))
		}
		return sha(fmt.Sprintf("sast|%s|%s|%s|%x", f.Tool, f.RuleID, f.Location, sha(str(f.Details, "snippet"))))
	}
	return sha(fmt.Sprintf("%s|%s|%s|%s|%s", f.Kind, f.Tool, f.RuleID, f.PkgName, f.Location))
}

// ecoFromPURL returns the jasca ecosystem for language-package purl types.
func ecoFromPURL(purl string) string {
	t, _, ok := strings.Cut(strings.TrimPrefix(purl, "pkg:"), "/")
	if !ok || !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	switch t {
	case "npm", "maven", "cargo", "nuget", "gem", "composer":
		return t
	case "pypi":
		return "pip"
	case "golang":
		return "gomod"
	}
	return "" // apk/deb/rpm: the distro name from the scanner is more specific
}

// splitImageRef splits "repo:tag" / "repo@sha256:..." into name and ref. Registry ports are kept in name.
func splitImageRef(s string) (name, ref string) {
	if i := strings.Index(s, "@"); i >= 0 {
		return s[:i], s[i+1:]
	}
	if i := strings.LastIndex(s, ":"); i > strings.LastIndex(s, "/") {
		return s[:i], s[i+1:]
	}
	return s, ""
}

// --- streaming JSON helpers: walk one container without buffering the body ---

func delim(dec *json.Decoder, want json.Delim) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := t.(json.Delim); !ok || d != want {
		return fmt.Errorf("json: expected %q, got %v", want, t)
	}
	return nil
}

// eachKey calls fn for every key of the next object; fn must consume the value.
func eachKey(dec *json.Decoder, fn func(key string) error) error {
	if err := delim(dec, '{'); err != nil {
		return err
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		if err := fn(t.(string)); err != nil {
			return err
		}
	}
	return delim(dec, '}')
}

// eachElem calls fn for every element of the next array; fn must consume the element.
func eachElem(dec *json.Decoder, fn func() error) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if t == nil { // null
		return nil
	}
	if d, ok := t.(json.Delim); !ok || d != '[' {
		return fmt.Errorf("json: expected array, got %v", t)
	}
	for dec.More() {
		if err := fn(); err != nil {
			return err
		}
	}
	return delim(dec, ']')
}

func skip(dec *json.Decoder) error { var v json.RawMessage; return dec.Decode(&v) }

func parseTime(s string) *time.Time {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		t = t.UTC()
		return &t
	}
	return nil
}
