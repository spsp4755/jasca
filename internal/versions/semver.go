package versions

import (
	"fmt"
	"strings"
)

type semver struct {
	core []string
	pre  []string // nil = release
}

func semverParse(v string) (semver, error) {
	if v == "" {
		return semver{}, errEmpty
	}
	orig := v
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') {
		v = v[1:]
	}
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	var s semver
	core, pre, hasPre := strings.Cut(v, "-")
	s.core = strings.Split(core, ".")
	if len(s.core) > 4 {
		return s, fmt.Errorf("bad semver %q", orig)
	}
	for _, p := range s.core {
		if !allDigits(p) {
			return s, fmt.Errorf("bad semver %q", orig)
		}
	}
	if hasPre {
		s.pre = strings.Split(pre, ".")
		for _, p := range s.pre {
			if p == "" {
				return s, fmt.Errorf("bad semver %q", orig)
			}
			for i := 0; i < len(p); i++ {
				if !isAlnum(p[i]) && p[i] != '-' {
					return s, fmt.Errorf("bad semver %q", orig)
				}
			}
		}
	}
	return s, nil
}

func semverCompare(a, b string) (int, error) {
	x, err := semverParse(a)
	if err != nil {
		return 0, err
	}
	y, err := semverParse(b)
	if err != nil {
		return 0, err
	}
	for i := 0; i < len(x.core) || i < len(y.core); i++ {
		p, q := "0", "0"
		if i < len(x.core) {
			p = x.core[i]
		}
		if i < len(y.core) {
			q = y.core[i]
		}
		if c := cmpDigits(p, q); c != 0 {
			return c, nil
		}
	}
	switch {
	case x.pre == nil && y.pre == nil:
		return 0, nil
	case x.pre == nil:
		return 1, nil
	case y.pre == nil:
		return -1, nil
	}
	for i := 0; i < len(x.pre) && i < len(y.pre); i++ {
		p, q := x.pre[i], y.pre[i]
		pn, qn := allDigits(p), allDigits(q)
		var c int
		switch {
		case pn && qn:
			c = cmpDigits(p, q)
		case pn:
			c = -1
		case qn:
			c = 1
		default:
			c = strings.Compare(p, q)
		}
		if c != 0 {
			return c, nil
		}
	}
	return sign(len(x.pre) - len(y.pre)), nil
}
