package versions

import (
	"fmt"
	"strings"
)

type constraint struct{ op, ver string } // op "*" matches everything

var rangeOps = []string{"<=", ">=", "!=", "==", "<", ">", "="}

func splitOp(t string) (op, rest string) {
	for _, o := range rangeOps {
		if strings.HasPrefix(t, o) {
			return o, t[len(o):]
		}
	}
	return "", t
}

func parseRange(eco, rng string) ([][]constraint, error) {
	if strings.TrimSpace(rng) == "" {
		return nil, fmt.Errorf("empty range")
	}
	var groups [][]constraint
	for _, g := range strings.Split(rng, "||") {
		var group []constraint
		for _, part := range strings.Split(g, ",") {
			f := strings.Fields(part)
			if len(f) == 0 {
				return nil, fmt.Errorf("malformed range %q: empty clause", rng)
			}
			for i := 0; i < len(f); i++ {
				if f[i] == "*" {
					group = append(group, constraint{op: "*"})
					continue
				}
				op, ver := splitOp(f[i])
				if op == "" {
					op = "="
				}
				if ver == "" { // operator separated from its version by a space
					if i++; i == len(f) {
						return nil, fmt.Errorf("malformed range %q: operator %q has no version", rng, op)
					}
					ver = f[i]
				}
				if strings.ContainsAny(ver[:1], "<>=!") {
					return nil, fmt.Errorf("malformed range %q: bad operator near %q", rng, ver)
				}
				if _, err := Compare(eco, ver, ver); err != nil {
					return nil, fmt.Errorf("malformed range %q: %w", rng, err)
				}
				group = append(group, constraint{op, ver})
			}
		}
		groups = append(groups, group)
	}
	return groups, nil
}

// Matches reports whether version satisfies rng. Comma or space = AND,
// "||" = OR, "*" = any version.
func Matches(ecosystem, version, rng string) (bool, error) {
	groups, err := parseRange(ecosystem, rng)
	if err != nil {
		return false, err
	}
	if _, err := Compare(ecosystem, version, version); err != nil {
		return false, err
	}
	for _, g := range groups {
		ok := true
		for _, c := range g {
			if c.op == "*" {
				continue
			}
			n, _ := Compare(ecosystem, version, c.ver)
			if !(c.op == "<" && n < 0 || c.op == "<=" && n <= 0 || c.op == ">" && n > 0 ||
				c.op == ">=" && n >= 0 || (c.op == "=" || c.op == "==") && n == 0 || c.op == "!=" && n != 0) {
				ok = false
				break
			}
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}
