// Package versions compares package versions and evaluates affected-version
// ranges per ecosystem.
package versions

import (
	"errors"
	"strings"
)

type cmpFunc func(a, b string) (int, error)

type comparator struct {
	name string
	fn   cmpFunc
}

var byEco = map[string]comparator{}

func init() {
	reg("deb", debCompare, "debian", "ubuntu")
	reg("rpm", rpmCompare, "redhat", "centos", "rocky", "alma", "amazon", "oracle", "suse", "photon")
	reg("apk", apkCompare, "alpine", "wolfi", "chainguard")
	reg("semver", semverCompare, "npm", "gomod", "cargo", "nuget", "composer", "gem")
	reg("pep440", pepCompare, "pip")
	reg("maven", mavenCompare, "maven")
}

func reg(name string, fn cmpFunc, ecos ...string) {
	for _, e := range ecos {
		byEco[e] = comparator{name, fn}
	}
}

func lookup(eco string) comparator {
	if c, ok := byEco[strings.ToLower(strings.TrimSpace(eco))]; ok {
		return c
	}
	return comparator{"generic", genericCompare}
}

func comparatorName(eco string) string { return lookup(eco).name }

// Known reports whether the ecosystem has a dedicated comparator.
// False means the generic comparison is used.
func Known(ecosystem string) bool { return lookup(ecosystem).name != "generic" }

var errEmpty = errors.New("empty version")

// Compare returns -1, 0 or 1.
func Compare(ecosystem, a, b string) (int, error) {
	return lookup(ecosystem).fn(strings.TrimSpace(a), strings.TrimSpace(b))
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return c|0x20 >= 'a' && c|0x20 <= 'z' }

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return s != ""
}

// cmpDigits compares two digit strings numerically without overflow.
// Empty counts as 0.
func cmpDigits(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return sign(len(a) - len(b))
	}
	return strings.Compare(a, b)
}
