package versions

import (
	"fmt"
	"strings"
)

func rpmCompare(a, b string) (int, error) {
	ea, va, ra, err := rpmSplit(a)
	if err != nil {
		return 0, err
	}
	eb, vb, rb, err := rpmSplit(b)
	if err != nil {
		return 0, err
	}
	if c := cmpDigits(ea, eb); c != 0 {
		return c, nil
	}
	if c := rpmvercmp(va, vb); c != 0 {
		return c, nil
	}
	// A missing release acts as a wildcard so "<1.0" style ranges work on "1.0-1.el8".
	if ra == "" || rb == "" {
		return 0, nil
	}
	return rpmvercmp(ra, rb), nil
}

func rpmSplit(v string) (epoch, ver, rel string, err error) {
	if v == "" {
		return "", "", "", errEmpty
	}
	if i := strings.IndexByte(v, ':'); i >= 0 {
		epoch, v = v[:i], v[i+1:]
		if !allDigits(epoch) {
			return "", "", "", fmt.Errorf("bad rpm epoch")
		}
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		v, rel = v[:i], v[i+1:]
	}
	if v == "" {
		return "", "", "", fmt.Errorf("empty rpm version")
	}
	return epoch, v, rel, nil
}

func at(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}

func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }

// rpmvercmp is a port of rpm's rpmvercmp, including ~ and ^.
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}
		if at(a, i) == '~' || at(b, j) == '~' {
			if at(a, i) != '~' {
				return 1
			}
			if at(b, j) != '~' {
				return -1
			}
			i++
			j++
			continue
		}
		if at(a, i) == '^' || at(b, j) == '^' {
			if i >= len(a) {
				return -1
			}
			if j >= len(b) {
				return 1
			}
			if a[i] != '^' {
				return 1
			}
			if b[j] != '^' {
				return -1
			}
			i++
			j++
			continue
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		si, sj := i, j
		num := isDigit(a[i])
		if num {
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isAlpha(a[i]) {
				i++
			}
			for j < len(b) && isAlpha(b[j]) {
				j++
			}
		}
		if sj == j { // segments of different type: numeric is newer
			if num {
				return 1
			}
			return -1
		}
		if num {
			if c := cmpDigits(a[si:i], b[sj:j]); c != 0 {
				return c
			}
		} else if c := strings.Compare(a[si:i], b[sj:j]); c != 0 {
			return c
		}
	}
	if i >= len(a) && j >= len(b) {
		return 0
	}
	if i < len(a) {
		return 1
	}
	return -1
}
