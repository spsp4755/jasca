package versions

import (
	"fmt"
	"strings"
)

// genericSegs splits into digit runs and letter runs, dropping separators.
func genericSegs(v string) []string {
	v = strings.ToLower(v)
	if len(v) > 1 && v[0] == 'v' && isDigit(v[1]) {
		v = v[1:]
	}
	var segs []string
	for i := 0; i < len(v); {
		switch {
		case isDigit(v[i]):
			j := i
			for j < len(v) && isDigit(v[j]) {
				j++
			}
			segs, i = append(segs, v[i:j]), j
		case isAlpha(v[i]):
			j := i
			for j < len(v) && isAlpha(v[j]) {
				j++
			}
			segs, i = append(segs, v[i:j]), j
		default:
			i++
		}
	}
	return segs
}

// shortcut: a missing segment sorts lower, so "1.0-rc1" > "1.0"; add an ecosystem comparator if that matters.
func genericCompare(a, b string) (int, error) {
	x, y := genericSegs(a), genericSegs(b)
	if len(x) == 0 || len(y) == 0 {
		return 0, fmt.Errorf("unparseable version %q / %q", a, b)
	}
	for i := 0; i < len(x) && i < len(y); i++ {
		p, q := x[i], y[i]
		pn, qn := isDigit(p[0]), isDigit(q[0])
		var c int
		switch {
		case pn && qn:
			c = cmpDigits(p, q)
		case pn:
			c = 1
		case qn:
			c = -1
		default:
			c = strings.Compare(p, q)
		}
		if c != 0 {
			return c, nil
		}
	}
	return sign(len(x) - len(y)), nil
}
