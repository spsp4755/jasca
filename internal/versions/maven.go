package versions

import "strings"

// Port of Maven's ComparableVersion (3.3.x item model).
// Qualifier order: alpha < beta < milestone < rc < snapshot < "" < sp < unknown.

type mItem interface {
	isNull() bool
	cmp(o mItem) int // o may be nil, meaning "absent"
}

type mInt string // digits without leading zeros ("0" for zero)
type mStr string // normalized qualifier
type mList struct{ items []mItem }

var mQualifiers = []string{"alpha", "beta", "milestone", "rc", "snapshot", "", "sp"}

const mReleaseIdx = "5"

func newMInt(s string) mInt {
	if s = strings.TrimLeft(s, "0"); s == "" {
		s = "0"
	}
	return mInt(s)
}

func newMStr(s string, followedByDigit bool) mStr {
	if followedByDigit && len(s) == 1 {
		switch s {
		case "a":
			s = "alpha"
		case "b":
			s = "beta"
		case "m":
			s = "milestone"
		}
	}
	switch s {
	case "ga", "final", "release":
		s = ""
	case "cr":
		s = "rc"
	}
	return mStr(s)
}

func (s mStr) comparable() string {
	for i, q := range mQualifiers {
		if string(s) == q {
			return string(rune('0' + i))
		}
	}
	return "7-" + string(s) // unknown qualifiers sort after all known ones
}

func (i mInt) isNull() bool   { return i == "0" }
func (s mStr) isNull() bool   { return s.comparable() == mReleaseIdx }
func (l *mList) isNull() bool { return len(l.items) == 0 }

func (i mInt) cmp(o mItem) int {
	switch v := o.(type) {
	case nil:
		if i == "0" {
			return 0
		}
		return 1
	case mInt:
		return cmpDigits(string(i), string(v))
	}
	return 1
}

func (s mStr) cmp(o mItem) int {
	switch v := o.(type) {
	case nil:
		return strings.Compare(s.comparable(), mReleaseIdx)
	case mStr:
		return strings.Compare(s.comparable(), v.comparable())
	}
	return -1
}

func (l *mList) cmp(o mItem) int {
	switch v := o.(type) {
	case nil:
		if len(l.items) == 0 {
			return 0
		}
		return l.items[0].cmp(nil)
	case mInt:
		return -1
	case mStr:
		return 1
	case *mList:
		for i := 0; i < len(l.items) || i < len(v.items); i++ {
			var a, b mItem
			if i < len(l.items) {
				a = l.items[i]
			}
			if i < len(v.items) {
				b = v.items[i]
			}
			var r int
			if a == nil {
				r = -b.cmp(nil)
			} else {
				r = a.cmp(b)
			}
			if r != 0 {
				return r
			}
		}
	}
	return 0
}

func (l *mList) normalize() {
	for i := len(l.items) - 1; i >= 0; i-- {
		if last := l.items[i]; last.isNull() {
			l.items = append(l.items[:i], l.items[i+1:]...)
		} else if _, ok := last.(*mList); !ok {
			break
		}
	}
}

func mItemOf(digit bool, s string) mItem {
	if digit {
		return newMInt(s)
	}
	return newMStr(s, false)
}

func mavenParse(v string) *mList {
	v = strings.ToLower(v)
	root := &mList{}
	list, stack := root, []*mList{root}
	dig, start := false, 0
	push := func() {
		nl := &mList{}
		list.items = append(list.items, nl)
		list = nl
		stack = append(stack, nl)
	}
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c == '.' || c == '-':
			if i == start {
				list.items = append(list.items, mInt("0"))
			} else {
				list.items = append(list.items, mItemOf(dig, v[start:i]))
			}
			start = i + 1
			if c == '-' {
				push()
			}
		case isDigit(c):
			if !dig && i > start {
				list.items = append(list.items, newMStr(v[start:i], true))
				start = i
			}
			dig = true
		default:
			if dig && i > start {
				list.items = append(list.items, mItemOf(true, v[start:i]))
				start = i
			}
			dig = false
		}
	}
	if len(v) > start {
		list.items = append(list.items, mItemOf(dig, v[start:]))
	}
	for i := len(stack) - 1; i >= 0; i-- {
		stack[i].normalize()
	}
	return root
}

func mavenCompare(a, b string) (int, error) {
	if a == "" || b == "" {
		return 0, errEmpty
	}
	return sign(mavenParse(a).cmp(mavenParse(b))), nil
}
