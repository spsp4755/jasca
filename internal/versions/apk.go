package versions

import (
	"fmt"
	"regexp"
)

var (
	apkRe    = regexp.MustCompile(`^(\d+(?:\.\d+)*)([a-z])?((?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)\d*)*)(?:-r(\d+))?$`)
	apkSufRe = regexp.MustCompile(`_([a-z]+)(\d*)`)
	apkRank  = map[string]int{"alpha": -4, "beta": -3, "pre": -2, "rc": -1, "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5}
)

type apkSuf struct {
	rank int
	n    string
}

type apkVer struct {
	nums   []string
	letter string
	sufs   []apkSuf
	rev    string
}

func apkParse(v string) (apkVer, error) {
	if v == "" {
		return apkVer{}, errEmpty
	}
	m := apkRe.FindStringSubmatch(v)
	if m == nil {
		return apkVer{}, fmt.Errorf("bad apk version %q", v)
	}
	r := apkVer{nums: splitDots(m[1]), letter: m[2], rev: m[4]}
	for _, s := range apkSufRe.FindAllStringSubmatch(m[3], -1) {
		r.sufs = append(r.sufs, apkSuf{apkRank[s[1]], s[2]})
	}
	return r, nil
}

func splitDots(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return out
}

func apkCompare(a, b string) (int, error) {
	x, err := apkParse(a)
	if err != nil {
		return 0, err
	}
	y, err := apkParse(b)
	if err != nil {
		return 0, err
	}
	for i := 0; i < len(x.nums) || i < len(y.nums); i++ {
		if i >= len(x.nums) {
			return -1, nil
		}
		if i >= len(y.nums) {
			return 1, nil
		}
		if c := cmpDigits(x.nums[i], y.nums[i]); c != 0 {
			return c, nil
		}
	}
	if x.letter != y.letter {
		return sign(int(at(x.letter, 0)) - int(at(y.letter, 0))), nil
	}
	for i := 0; i < len(x.sufs) || i < len(y.sufs); i++ {
		var p, q apkSuf // missing suffix: rank 0
		if i < len(x.sufs) {
			p = x.sufs[i]
		}
		if i < len(y.sufs) {
			q = y.sufs[i]
		}
		if p.rank != q.rank {
			return sign(p.rank - q.rank), nil
		}
		if c := cmpDigits(p.n, q.n); c != 0 {
			return c, nil
		}
	}
	return cmpDigits(x.rev, y.rev), nil
}
