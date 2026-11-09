package formats

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type cdxParser struct{}

func init() { Register(cdxParser{}) }

func (cdxParser) Name() string { return "cyclonedx" }

func (cdxParser) Detect(head []byte) bool {
	return bytes.Contains(head, []byte(`"bomFormat"`)) && bytes.Contains(head, []byte("CycloneDX"))
}

func (cdxParser) Parse(r io.Reader) (*Report, error) {
	dec := json.NewDecoder(r)
	rep := &Report{Format: "cyclonedx", TargetKind: "sbom", Complete: map[string]bool{}}
	sawFormat := false
	err := eachKey(dec, func(k string) error {
		switch k {
		case "bomFormat":
			var s string
			if err := dec.Decode(&s); err != nil {
				return err
			}
			sawFormat = s == "CycloneDX"
		case "metadata":
			var m struct {
				Component struct{ Name, Version, Type string }
			}
			if err := dec.Decode(&m); err != nil {
				return err
			}
			rep.TargetName, rep.Ref = m.Component.Name, m.Component.Version
			if m.Component.Type == "container" {
				rep.TargetName, rep.Ref = splitImageRef(m.Component.Name)
			}
		case "components":
			return eachElem(dec, func() error {
				var c struct {
					Name, Version, PURL string
					Properties          []struct{ Name, Value string }
				}
				if err := dec.Decode(&c); err != nil {
					return err
				}
				eco := ecoFromPURL(c.PURL)
				for _, p := range c.Properties {
					if eco == "" && p.Name == "aquasecurity:trivy:PkgType" {
						eco = p.Value
					}
				}
				if eco == "" && strings.HasPrefix(c.PURL, "pkg:") {
					eco, _, _ = strings.Cut(strings.TrimPrefix(c.PURL, "pkg:"), "/")
				}
				rep.Packages = append(rep.Packages, Package{PURL: c.PURL, Name: c.Name, Version: c.Version, Ecosystem: eco})
				return nil
			})
		default:
			return skip(dec)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("cyclonedx: %w", err)
	}
	if !sawFormat {
		return nil, fmt.Errorf("cyclonedx: bomFormat missing")
	}
	return rep, nil
}
