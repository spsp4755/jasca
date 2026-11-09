package versions

import "fmt"

func debParse(v string) (epoch, up, rev string, err error) {
	if v == "" {
		return "", "", "", errEmpty
	}
	epoch = "0"
	for i := 0; i < len(v); i++ {
		if v[i] == ':' {
			epoch, v = v[:i], v[i+1:]
			if !allDigits(epoch) {
				return "", "", "", fmt.Errorf("bad deb epoch in %q", v)
			}
			break
		}
	}
	for i := len(v) - 1; i >= 0; i-- {
		if v[i] == '-' {
			v, rev = v[:i], v[i+1:]
			break
		}
	}
	if v == "" {
		return "", "", "", fmt.Errorf("empty deb upstream version")
	}
	return epoch, v, rev, nil
}

func debCompare(a, b string) (int, error) {
	ea, ua, ra, err := debParse(a)
	if err != nil {
		return 0, err
	}
	eb, ub, rb, err := debParse(b)
	if err != nil {
		return 0, err
	}
	if c := cmpDigits(ea, eb); c != 0 {
		return c, nil
	}
	if c := debVerrev(ua, ub); c != 0 {
		return c, nil
	}
	return debVerrev(ra, rb), nil
}

// debOrder is dpkg's order(): '~' < end < letters < everything else.
func debOrder(s string, i int) int {
	if i >= len(s) {
		return 0
	}
	switch c := s[i]; {
	case isDigit(c):
		return 0
	case isAlpha(c):
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

// debVerrev is dpkg's verrevcmp.
func debVerrev(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			if ac, bc := debOrder(a, i), debOrder(b, j); ac != bc {
				return sign(ac - bc)
			}
			if i < len(a) {
				i++
			}
			if j < len(b) {
				j++
			}
		}
		si, sj := i, j
		for i < len(a) && isDigit(a[i]) {
			i++
		}
		for j < len(b) && isDigit(b[j]) {
			j++
		}
		if c := cmpDigits(a[si:i], b[sj:j]); c != 0 {
			return c
		}
	}
	return 0
}
