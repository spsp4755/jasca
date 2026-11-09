package versions

import (
	"encoding/json"
	"os"
	"testing"
)

type caseFile struct {
	Compare   [][]any `json:"compare"`
	Match     [][]any `json:"match"`
	Malformed [][]any `json:"malformed"`
}

func load(t *testing.T) caseFile {
	t.Helper()
	b, err := os.ReadFile("testdata/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var c caseFile
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCases(t *testing.T) {
	c := load(t)
	per := map[string]int{}
	for _, r := range c.Compare {
		eco, a, b, want := r[0].(string), r[1].(string), r[2].(string), int(r[3].(float64))
		per[comparatorName(eco)]++
		got, err := Compare(eco, a, b)
		if err != nil || got != want {
			t.Errorf("Compare(%s,%q,%q)=%d,%v want %d", eco, a, b, got, err, want)
		}
		rev, err := Compare(eco, b, a)
		if err != nil || rev != -want {
			t.Errorf("Compare(%s,%q,%q)=%d,%v want %d (reversed)", eco, b, a, rev, err, -want)
		}
	}
	for _, name := range []string{"deb", "rpm", "apk", "semver", "pep440", "maven", "generic"} {
		if per[name] < 15 {
			t.Errorf("only %d compare cases for %s", per[name], name)
		}
	}
	for _, r := range c.Match {
		eco, v, rng, want := r[0].(string), r[1].(string), r[2].(string), r[3].(bool)
		got, err := Matches(eco, v, rng)
		if err != nil || got != want {
			t.Errorf("Matches(%s,%q,%q)=%v,%v want %v", eco, v, rng, got, err, want)
		}
	}
}

func TestKnown(t *testing.T) {
	for _, e := range []string{"debian", "Ubuntu", "rocky", "alpine", "npm", "pip", "maven", "gomod"} {
		if !Known(e) {
			t.Errorf("Known(%q) = false", e)
		}
	}
	for _, e := range []string{"", "foo", "conan"} {
		if Known(e) {
			t.Errorf("Known(%q) = true", e)
		}
	}
}

func TestMalformedRange(t *testing.T) {
	for _, r := range load(t).Malformed {
		eco, rng := r[0].(string), r[1].(string)
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("Matches(%s,%q) panicked: %v", eco, rng, p)
				}
			}()
			if _, err := Matches(eco, "1.0", rng); err == nil {
				t.Errorf("Matches(%s,%q) expected error", eco, rng)
			}
		}()
	}
}

func TestMalformedVersion(t *testing.T) {
	for _, eco := range []string{"debian", "rocky", "alpine", "npm", "pip", "maven", "foo"} {
		if _, err := Compare(eco, "", "1.0"); err == nil {
			t.Errorf("%s: empty version should error", eco)
		}
	}
	for _, v := range []string{"not.a.version", "1.x", "1..2"} {
		if _, err := Matches("npm", v, ">=1.0"); err == nil {
			t.Errorf("npm %q should error", v)
		}
	}
}
