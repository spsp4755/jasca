package formats

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type harborParser struct{}

func init() { Register(harborParser{}) }

func (harborParser) Name() string { return "harbor" }

func (harborParser) Detect(head []byte) bool {
	return bytes.Contains(head, []byte("vnd.security.vulnerability.report")) ||
		(bytes.Contains(head, []byte(`"generated_at"`)) && bytes.Contains(head, []byte(`"scanner"`)))
}

type harborVuln struct {
	ID, Package, Version, Severity, Description string
	FixVersion                                  string `json:"fix_version"`
	Links                                       []string
	CweIDs                                      []string `json:"cwe_ids"`
	PreferredCVSS                               struct {
		ScoreV3  *float64 `json:"score_v3"`
		VectorV3 string   `json:"vector_v3"`
	} `json:"preferred_cvss"`
}

func (harborParser) Parse(r io.Reader) (*Report, error) {
	dec := json.NewDecoder(r)
	rep := &Report{Format: "harbor", TargetKind: "image", Complete: map[string]bool{}}
	tool := "harbor"
	var vulns []harborVuln
	var hasVulns bool
	err := eachKey(dec, func(k string) error {
		switch k {
		case "artifact":
			var a struct {
				Repository, Digest string
				Tags               []string
			}
			if err := dec.Decode(&a); err != nil {
				return err
			}
			rep.TargetName, rep.Ref = a.Repository, a.Digest
			if len(a.Tags) > 0 {
				rep.Ref = a.Tags[0]
			}
		case "scanner":
			var s struct{ Name string }
			if err := dec.Decode(&s); err != nil {
				return err
			}
			if s.Name != "" {
				tool = strings.ToLower(s.Name)
			}
		case "vulnerabilities":
			hasVulns = true
			return eachElem(dec, func() error {
				var v harborVuln
				if err := dec.Decode(&v); err != nil {
					return err
				}
				vulns = append(vulns, v)
				return nil
			})
		default:
			return skip(dec)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("harbor: %w", err)
	}
	if !hasVulns {
		return nil, fmt.Errorf("harbor: no vulnerabilities key")
	}
	rep.Complete["vuln:"+tool] = true
	for _, v := range vulns {
		rep.Packages = append(rep.Packages, Package{Name: v.Package, Version: v.Version})
		rep.add(Finding{Kind: "vuln", Tool: tool, RuleID: v.ID, Severity: NormalizeSeverity(v.Severity),
			PkgName: v.Package, PkgVersion: v.Version, FixedVersion: v.FixVersion,
			Vuln: &VulnInfo{Description: v.Description, Refs: v.Links, CWEs: v.CweIDs,
				CVSSVector: v.PreferredCVSS.VectorV3, CVSSScore: v.PreferredCVSS.ScoreV3}})
	}
	return rep, nil
}
