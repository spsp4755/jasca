package formats

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

type sarifParser struct{}

func init() { Register(sarifParser{}) }

func (sarifParser) Name() string { return "sarif" }

func (sarifParser) Detect(head []byte) bool {
	return bytes.Contains(head, []byte(`"runs"`)) && bytes.Contains(head, []byte("sarif")) ||
		bytes.Contains(head, []byte(`"runs"`)) && bytes.Contains(head, []byte(`"2.1.0"`))
}

type sarifRule struct {
	ID                   string
	Name                 string
	ShortDescription     struct{ Text string }
	DefaultConfiguration struct{ Level string }
	Properties           map[string]any
}

type sarifRun struct {
	Tool struct {
		Driver struct {
			Name  string
			Rules []sarifRule
		}
	}
	Results []struct {
		RuleID    string
		RuleIndex *int
		Level     string
		Message   struct{ Text string }
		Locations []struct {
			PhysicalLocation struct {
				ArtifactLocation struct{ URI string }
				Region           struct {
					StartLine, EndLine int
					Snippet            struct{ Text string }
				}
			}
		}
		PartialFingerprints map[string]string
		Properties          map[string]any
	}
}

// sarifScoreSeverity maps a GitHub-style security-severity score to the severity enum.
func sarifScoreSeverity(s float64) string {
	switch {
	case s >= 9:
		return "CRITICAL"
	case s >= 7:
		return "HIGH"
	case s >= 4:
		return "MEDIUM"
	case s > 0:
		return "LOW"
	}
	return "UNKNOWN"
}

func secSeverity(p map[string]any) (float64, bool) {
	switch v := p["security-severity"].(type) {
	case float64:
		return v, true
	case string:
		f, err := strconv.ParseFloat(v, 64)
		return f, err == nil
	}
	return 0, false
}

func (sarifParser) Parse(r io.Reader) (*Report, error) {
	dec := json.NewDecoder(r)
	rep := &Report{Format: "sarif", Complete: map[string]bool{}}
	sawRuns := false
	err := eachKey(dec, func(k string) error {
		if k != "runs" {
			return skip(dec)
		}
		sawRuns = true
		return eachElem(dec, func() error {
			var run sarifRun
			if err := dec.Decode(&run); err != nil {
				return err
			}
			addSarifRun(rep, &run)
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("sarif: %w", err)
	}
	if !sawRuns {
		return nil, fmt.Errorf("sarif: no runs")
	}
	return rep, nil
}

func addSarifRun(rep *Report, run *sarifRun) {
	tool := strings.ToLower(strings.TrimSpace(run.Tool.Driver.Name))
	if tool == "" {
		tool = "sarif"
	}
	rep.Complete["sast:"+tool] = true
	rules := run.Tool.Driver.Rules
	for _, res := range run.Results {
		var rule sarifRule
		if res.RuleIndex != nil && *res.RuleIndex >= 0 && *res.RuleIndex < len(rules) {
			rule = rules[*res.RuleIndex]
		} else {
			for _, ru := range rules {
				if ru.ID == res.RuleID {
					rule = ru
				}
			}
		}
		sev := ""
		if s, ok := secSeverity(res.Properties); ok {
			sev = sarifScoreSeverity(s)
		} else if s, ok := secSeverity(rule.Properties); ok {
			sev = sarifScoreSeverity(s)
		} else {
			level := res.Level
			if level == "" {
				level = rule.DefaultConfiguration.Level
			}
			switch level {
			case "error":
				sev = "HIGH"
			case "note":
				sev = "LOW"
			default: // "warning" is also SARIF's default level
				sev = "MEDIUM"
			}
		}
		f := Finding{Kind: "sast", Tool: tool, RuleID: res.RuleID, Severity: sev, Title: rule.ShortDescription.Text,
			Details: map[string]any{"message": res.Message.Text}}
		if f.Title == "" {
			f.Title = rule.Name
		}
		snippet := res.Message.Text
		if len(res.Locations) > 0 {
			pl := res.Locations[0].PhysicalLocation
			f.Location = pl.ArtifactLocation.URI
			f.Details["start_line"], f.Details["end_line"] = pl.Region.StartLine, pl.Region.EndLine
			if pl.Region.Snippet.Text != "" {
				snippet = pl.Region.Snippet.Text
			}
		}
		f.Details["snippet"] = strings.Join(strings.Fields(snippet), " ")
		if len(res.PartialFingerprints) > 0 {
			keys := make([]string, 0, len(res.PartialFingerprints))
			for k := range res.PartialFingerprints {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var parts []string
			for _, k := range keys {
				parts = append(parts, k+"="+res.PartialFingerprints[k])
			}
			f.Details["partial_fingerprints"] = strings.Join(parts, ";")
		}
		rep.add(f)
	}
}
