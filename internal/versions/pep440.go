package versions

import (
	"fmt"
	"regexp"
	"strings"
)

var pepRe = regexp.MustCompile(`^v?(?:(?:(?P<epoch>\d+)!)?(?P<rel>\d+(?:\.\d+)*)` +
	`(?P<pre>[-_.]?(?P<pretag>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<prenum>\d+)?)?` +
	`(?P<post>(?:-(?P<postn1>\d+))|(?:[-_.]?(?P<posttag>post|rev|r)[-_.]?(?P<postn2>\d+)?))?` +
	`(?P<dev>[-_.]?dev[-_.]?(?P<devn>\d+)?)?)` +
	`(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?$`)

type pep struct {
	epoch, rel []string  // rel segments
	pre        [3]string // kind(-1 dev-only,0 real,1 none), rank, n
	hasPost    bool
	post       string
	hasDev     bool
	dev        string
	local      []string
	hasLocal   bool
}

func pepParse(v string) (p pep, err error) {
	if v == "" {
		return p, errEmpty
	}
	m := pepRe.FindStringSubmatch(strings.ToLower(v))
	if m == nil {
		return p, fmt.Errorf("bad PEP 440 version %q", v)
	}
	g := func(n string) string { return m[pepRe.SubexpIndex(n)] }
	p.epoch = []string{g("epoch")}
	p.rel = splitDots(g("rel"))
	p.hasPost = g("post") != ""
	p.post = g("postn1") + g("postn2")
	p.hasDev = g("dev") != ""
	p.dev = g("devn")
	switch {
	case g("pre") != "":
		rank := map[string]string{"a": "0", "alpha": "0", "b": "1", "beta": "1"}[g("pretag")]
		if rank == "" {
			rank = "2" // c, rc, pre, preview
		}
		p.pre = [3]string{"0", rank, g("prenum")}
	case !p.hasPost && p.hasDev:
		p.pre = [3]string{"-1"}
	default:
		p.pre = [3]string{"1"}
	}
	if l := g("local"); l != "" {
		p.hasLocal = true
		p.local = strings.FieldsFunc(l, func(r rune) bool { return r == '-' || r == '_' || r == '.' })
	}
	return p, nil
}

func pepCompare(a, b string) (int, error) {
	x, err := pepParse(a)
	if err != nil {
		return 0, err
	}
	y, err := pepParse(b)
	if err != nil {
		return 0, err
	}
	if c := cmpDigits(x.epoch[0], y.epoch[0]); c != 0 {
		return c, nil
	}
	for i := 0; i < len(x.rel) || i < len(y.rel); i++ {
		p, q := "0", "0"
		if i < len(x.rel) {
			p = x.rel[i]
		}
		if i < len(y.rel) {
			q = y.rel[i]
		}
		if c := cmpDigits(p, q); c != 0 {
			return c, nil
		}
	}
	if x.pre[0] != y.pre[0] {
		return sign(map[string]int{"-1": -1, "0": 0, "1": 1}[x.pre[0]] - map[string]int{"-1": -1, "0": 0, "1": 1}[y.pre[0]]), nil
	}
	if c := strings.Compare(x.pre[1], y.pre[1]); c != 0 {
		return c, nil
	}
	if c := cmpDigits(x.pre[2], y.pre[2]); c != 0 {
		return c, nil
	}
	if x.hasPost != y.hasPost {
		return map[bool]int{true: 1, false: -1}[x.hasPost], nil
	}
	if c := cmpDigits(x.post, y.post); c != 0 {
		return c, nil
	}
	if x.hasDev != y.hasDev {
		return map[bool]int{true: -1, false: 1}[x.hasDev], nil
	}
	if c := cmpDigits(x.dev, y.dev); c != 0 {
		return c, nil
	}
	if x.hasLocal != y.hasLocal {
		return map[bool]int{true: 1, false: -1}[x.hasLocal], nil
	}
	for i := 0; i < len(x.local) && i < len(y.local); i++ {
		p, q := x.local[i], y.local[i]
		pn, qn := allDigits(p), allDigits(q)
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
	return sign(len(x.local) - len(y.local)), nil
}
