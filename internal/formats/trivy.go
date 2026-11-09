package formats

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

type trivyParser struct{}

func init() { Register(trivyParser{}) }

func (trivyParser) Name() string { return "trivy" }

func (trivyParser) Detect(head []byte) bool {
	return bytes.Contains(head, []byte(`"SchemaVersion"`)) && bytes.Contains(head, []byte(`"ArtifactName"`))
}

type trivyPkg struct {
	Name, Version, Release, FilePath, SrcName, SrcVersion, SrcRelease string
	Epoch, SrcEpoch                                                   int
	Identifier                                                        struct{ PURL string }
}

type trivyVuln struct {
	VulnerabilityID, PkgName, InstalledVersion, FixedVersion, PkgPath string
	PkgIdentifier                                                     struct{ PURL string }
	Title, Description, Severity                                      string
	CweIDs, References                                                []string
	PublishedDate, LastModifiedDate                                   string
	CVSS                                                              map[string]struct {
		V3Vector string
		V3Score  float64
	}
}

type trivyMisconf struct {
	ID, Title, Description, Message, Resolution, Severity, Status, Namespace string
	CauseMetadata                                                            struct {
		Resource           string
		StartLine, EndLine int
	}
}

type trivySecret struct {
	RuleID, Category, Title, Severity, Match string
	StartLine, EndLine                       int
}

type trivyResult struct {
	Target, Class, Type string
	Packages            []trivyPkg
	Vulnerabilities     []trivyVuln
	Misconfigurations   []trivyMisconf
	Secrets             []trivySecret
}

// trivyEco maps Trivy's Class/Type to a jasca ecosystem.
func trivyEco(class, typ string) string {
	if class == "os-pkgs" {
		return typ
	}
	switch typ {
	case "jar", "pom", "gradle", "sbt":
		return "maven"
	case "pip", "pipenv", "poetry", "uv", "python-pkg":
		return "pip"
	case "npm", "yarn", "pnpm", "bun", "node-pkg":
		return "npm"
	case "gomod", "gobinary":
		return "gomod"
	case "cargo", "rust-binary":
		return "cargo"
	case "nuget", "dotnet-core":
		return "nuget"
	case "bundler", "gemspec":
		return "gem"
	}
	return typ
}

func (trivyParser) Parse(r io.Reader) (*Report, error) {
	dec := json.NewDecoder(r)
	rep := &Report{Format: "trivy", Complete: map[string]bool{}}
	var artType string
	seenResults := false
	err := eachKey(dec, func(k string) error {
		switch k {
		case "ArtifactName":
			var s string
			if err := dec.Decode(&s); err != nil {
				return err
			}
			rep.TargetName = s
		case "ArtifactType":
			return dec.Decode(&artType)
		case "Metadata":
			var m struct{ OS *OSInfo }
			if err := dec.Decode(&m); err != nil {
				return err
			}
			if m.OS != nil {
				rep.OS = m.OS
				rep.Complete["vuln:trivy"] = true
			}
		case "Results":
			seenResults = true
			return eachElem(dec, func() error {
				var res trivyResult
				if err := dec.Decode(&res); err != nil {
					return err
				}
				addTrivyResult(rep, &res)
				return nil
			})
		default:
			return skip(dec)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("trivy: %w", err)
	}
	if rep.TargetName == "" && !seenResults {
		return nil, fmt.Errorf("trivy: not a trivy report")
	}
	switch artType {
	case "container_image":
		rep.TargetKind = "image"
		rep.TargetName, rep.Ref = splitImageRef(rep.TargetName)
	case "filesystem":
		rep.TargetKind = "fs"
	case "repository":
		rep.TargetKind = "repo"
	case "cyclonedx", "spdx":
		rep.TargetKind = "sbom"
	}
	return rep, nil
}

func addTrivyResult(rep *Report, res *trivyResult) {
	path := ""
	if res.Class == "lang-pkgs" {
		path = res.Target
	}
	switch res.Class {
	case "os-pkgs", "lang-pkgs":
		rep.Complete["vuln:trivy"] = true
	case "config":
		rep.Complete["misconfig:trivy"] = true
	case "secret":
		rep.Complete["secret:trivy"] = true
	}
	eco := trivyEco(res.Class, res.Type)
	seen := map[[3]string]bool{}
	addPkg := func(name, ver, purl, fp, srcName, srcVer string) {
		key := [3]string{name, ver, fp} // one entry per file: the same JAR at two paths is two findings
		if seen[key] {
			return
		}
		seen[key] = true
		e := ecoFromPURL(purl)
		if e == "" {
			e = eco
		}
		p := path
		if fp != "" {
			p = fp
		}
		rep.Packages = append(rep.Packages, Package{PURL: purl, Name: name, Version: ver, Ecosystem: e, Path: p, SrcName: srcName, SrcVersion: srcVer})
	}
	for _, p := range res.Packages { // OS packages split epoch/version/release; findings carry the full version
		addPkg(p.Name, fullVersion(p.Epoch, p.Version, p.Release), p.Identifier.PURL, p.FilePath,
			p.SrcName, fullVersion(p.SrcEpoch, p.SrcVersion, p.SrcRelease))
	}
	for _, v := range res.Vulnerabilities {
		addPkg(v.PkgName, v.InstalledVersion, v.PkgIdentifier.PURL, v.PkgPath, "", "")
		fp := path
		if v.PkgPath != "" {
			fp = v.PkgPath
		}
		vi := &VulnInfo{Title: v.Title, Description: v.Description, CWEs: v.CweIDs, Refs: v.References,
			Published: parseTime(v.PublishedDate), Modified: parseTime(v.LastModifiedDate)}
		for _, src := range []string{"nvd", "redhat", "ghsa"} { // prefer NVD, then any source with a v3 vector
			if c, ok := v.CVSS[src]; ok && c.V3Vector != "" {
				vi.CVSSVector, vi.CVSSScore = c.V3Vector, ptr(c.V3Score)
				break
			}
		}
		if vi.CVSSVector == "" {
			for _, c := range v.CVSS {
				if c.V3Vector != "" {
					vi.CVSSVector, vi.CVSSScore = c.V3Vector, ptr(c.V3Score)
					break
				}
			}
		}
		rep.add(Finding{Kind: "vuln", Tool: "trivy", RuleID: v.VulnerabilityID, Title: v.Title,
			Severity: NormalizeSeverity(v.Severity), PkgName: v.PkgName, PkgVersion: v.InstalledVersion,
			FixedVersion: v.FixedVersion, PkgPath: fp, Vuln: vi})
	}
	for _, m := range res.Misconfigurations {
		if m.Status != "" && m.Status != "FAIL" {
			continue
		}
		rep.add(Finding{Kind: "misconfig", Tool: "trivy", RuleID: m.ID, Title: m.Title,
			Severity: NormalizeSeverity(m.Severity), Location: res.Target, Details: map[string]any{
				"message": m.Message, "description": m.Description, "resolution": m.Resolution,
				"resource": m.CauseMetadata.Resource, "namespace": m.Namespace,
				"start_line": m.CauseMetadata.StartLine, "end_line": m.CauseMetadata.EndLine}})
	}
	for _, s := range res.Secrets {
		// Only the hash of the match is kept; Code lines and Match text are dropped.
		rep.add(Finding{Kind: "secret", Tool: "trivy", RuleID: s.RuleID, Title: s.Title,
			Severity: NormalizeSeverity(s.Severity), Location: res.Target, Details: map[string]any{
				"category": s.Category, "start_line": s.StartLine, "end_line": s.EndLine,
				"redacted_match_sha256": fmt.Sprintf("%x", sha(s.Match))}})
	}
}

func ptr[T any](v T) *T { return &v }
