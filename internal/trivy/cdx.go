package trivy

import (
	"encoding/json"
	"net/url"
	"strings"
)

type Package struct{ PURL, Name, Version, Ecosystem string }

var purlType = map[string]string{
	"npm": "npm", "pypi": "pypi", "pip": "pypi", "maven": "maven", "go": "golang", "golang": "golang", "gomod": "golang",
	"cargo": "cargo", "rust": "cargo", "gem": "gem", "rubygems": "gem", "nuget": "nuget", "composer": "composer",
}

func buildPURL(p Package) string {
	t, ok := purlType[strings.ToLower(p.Ecosystem)]
	if !ok || p.Name == "" || p.Version == "" {
		return ""
	}
	n := p.Name
	if t == "maven" {
		n = strings.Replace(n, ":", "/", 1)
	}
	segs := strings.Split(n, "/")
	for i, sg := range segs { // purl spec: escape each segment, keep "/" as the namespace separator
		segs[i] = strings.ReplaceAll(url.PathEscape(sg), "@", "%40")
	}
	n = strings.Join(segs, "/")
	return "pkg:" + t + "/" + n + "@" + url.PathEscape(p.Version)
}

// CycloneDX renders a minimal CycloneDX 1.5 BOM. Packages with no purl and no derivable one are skipped.
func CycloneDX(pkgs []Package) ([]byte, error) {
	type comp struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Version string `json:"version"`
		PURL    string `json:"purl"`
	}
	comps := []comp{}
	for _, p := range pkgs {
		purl := p.PURL
		if purl == "" {
			purl = buildPURL(p)
		}
		if purl == "" {
			continue
		}
		comps = append(comps, comp{"library", p.Name, p.Version, purl})
	}
	return json.Marshal(map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": comps})
}
