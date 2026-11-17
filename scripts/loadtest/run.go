package main

import (
	"archive/tar"
	"bytes"
	"cmp"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

const inventorySQL = `(select sc.id from scans sc where sc.target_id = t.id and sc.status = 'done'
	and exists (select 1 from packages p where p.scan_id = sc.id) order by sc.id desc limit 1)` // recheck.go latestInventorySQL

func pct(d []time.Duration, p int) time.Duration {
	if len(d) == 0 {
		return 0
	}
	slices.Sort(d)
	return d[min(len(d)*p/100, len(d)-1)]
}

func ms(d time.Duration) string { return fmt.Sprintf("%.0f", float64(d.Microseconds())/1000) }

// --- upload: CI reports through the real API, into targets that have a history ---

type report struct {
	url, token                         string
	body                               []byte
	pkgs, vulns, wantNew, wantFixed    int
	took                               time.Duration
	scanID                             int64
	gotNew, gotFixed, status, respOpen int
}

// upload pushes, for n seeded targets of every size, the report a CI would send next: the target's inventory and
// open vulnerabilities, two of its vulnerable packages now clean and two new CVEs. The server must take it as that
// (2 new, the others' findings fixed): if it sees a target full of new findings, the seed is not what the server writes.
func upload(db *pgx.Conn, n int) {
	rows, _ := db.Query(ctx, `select t.id, t.kind, t.name, p.key, 'jsc_lt_' || pn.n, inv.id, coalesce(sc.summary->'os'->>'family', '')
		from targets t join projects p on p.id = t.project_id join (select id, row_number() over (order by id) n from projects) pn on pn.id = p.id
			cross join lateral `+inventorySQL+` inv(id) join scans sc on sc.id = inv.id
		where t.id % greatest((select count(*) from targets) / $1, 1) = 0 and t.name like '%svc-%' order by t.id limit $1`, n)
	type tgt struct {
		ID                   int64
		Kind, Name, Key, Tok string
		Scan                 int64
		OS                   string
	}
	tgts, err := pgx.CollectRows(rows, pgx.RowToStructByPos[tgt])
	must(err)
	var reps []*report
	for i, t := range tgts {
		rows, _ := db.Query(ctx, `select ecosystem, name, version, purl, path, src_name, src_version from packages where scan_id = $1`, t.Scan)
		pkgs, err := pgx.CollectRows(rows, pgx.RowToStructByPos[pkg])
		must(err)
		purl := map[string]string{}
		for _, p := range pkgs {
			purl[p.Name] = p.PURL
		}
		rows, _ = db.Query(ctx, `select f.rule_id, f.pkg_name, f.pkg_version, f.fixed_version, f.pkg_path, f.severity, f.title, v.description, '',
				f.status = 'open' from findings f join vulns v on v.id = f.rule_id
			where f.target_id = $1 and f.kind = 'vuln' and f.status <> 'fixed' order by f.pkg_name, f.rule_id`, t.ID)
		var vulns []vuln
		var v vuln
		var open bool
		r := &report{pkgs: len(pkgs), wantNew: 2}
		dropped := map[string]bool{}
		_, err = pgx.ForEachRow(rows, []any{&v.ID, &v.Pkg, &v.Ver, &v.Fixed, &v.Path, &v.Sev, &v.Title, &v.Desc, &v.PURL, &open}, func() error {
			if v.PURL = purl[v.Pkg]; v.PURL == "" { // the package left the inventory: the finding is about to be resolved anyway
				return nil
			}
			if len(dropped) < 2 || dropped[v.Pkg] { // the first two vulnerable packages are clean in this build
				if dropped[v.Pkg] = true; open {
					r.wantFixed++
				}
				return nil
			}
			vulns = append(vulns, v)
			return nil
		})
		must(err)
		if len(vulns) == 0 {
			continue
		}
		for k := range 2 {
			w := vulns[0]
			w.ID, w.Title = fmt.Sprintf("CVE-2026-%d", 900000+int(t.ID)*10+k+int(time.Now().Unix()%100000)*10), "Newly published vulnerability"
			vulns = append(vulns, w)
		}
		r.vulns = len(vulns)
		r.body = trivyReport(t.Name+":loadtest", t.Kind, t.OS, pkgs, vulns)
		r.url = *base + "/api/v1/projects/" + t.Key + "/scans?" + url.Values{"target": {t.Name}, "kind": {t.Kind}, "ref": {fmt.Sprint("loadtest-", time.Now().Unix())}}.Encode()
		r.token = t.Tok
		reps = append(reps, r)
		fmt.Printf("\rprepared %d/%d", i+1, len(tgts))
	}
	fmt.Print("\r")
	post := func(r *report) {
		req, _ := http.NewRequest("POST", r.url, bytes.NewReader(r.body))
		req.Header.Set("Authorization", "Bearer "+r.token)
		t := time.Now()
		resp, err := http.DefaultClient.Do(req)
		must(err)
		var out struct {
			ScanID  int64          `json:"scan_id"`
			Summary map[string]int `json:"summary"`
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		r.took, r.status = time.Since(t), resp.StatusCode
		if resp.StatusCode != 201 {
			log.Fatalf("upload: %d %s", resp.StatusCode, b)
		}
		must(json.Unmarshal(b, &out))
		r.scanID, r.respOpen = out.ScanID, out.Summary["open"]
	}
	var one, many []*report // alternating, so that every size is in both
	for i, r := range reps {
		if i%2 == 0 {
			one = append(one, r)
		} else {
			many = append(many, r)
		}
	}
	for _, r := range one {
		post(r)
	}
	t := time.Now()
	var wg sync.WaitGroup
	ch := make(chan *report)
	for range 5 {
		wg.Go(func() {
			for r := range ch {
				post(r)
			}
		})
	}
	for _, r := range many {
		ch <- r
	}
	close(ch)
	wg.Wait()
	wall := time.Since(t)
	for _, r := range reps {
		must(db.QueryRow(ctx, `select count(*) filter (where change = 'new'), count(*) filter (where change = 'fixed') from scan_changes where scan_id = $1`,
			r.scanID).Scan(&r.gotNew, &r.gotFixed))
		if r.gotNew != r.wantNew || r.gotFixed != r.wantFixed {
			log.Fatalf("scan %d: the server recorded %d new and %d fixed findings, the report meant %d and %d: the seeded target is not what the server writes",
				r.scanID, r.gotNew, r.gotFixed, r.wantNew, r.wantFixed)
		}
	}
	fmt.Printf("%d reports taken as meant (2 new each, the dropped packages' findings fixed)\n\n| 패키지 수 | 보고서 | 크기(중앙값) | 한 건씩: 중앙값 | 최대 | 5건 동시: 중앙값 | 최대 |\n|---|---|---|---|---|---|---|\n", len(reps))
	for _, b := range []struct {
		lo, hi int
		label  string
	}{{0, 200, "200 미만"}, {200, 600, "600 미만"}, {600, 1500, "1,500 미만"}, {1500, 1 << 30, ""}} {
		var d1, d5 []time.Duration
		var kb []int
		for i, r := range reps {
			if r.pkgs < b.lo || r.pkgs >= b.hi {
				continue
			}
			kb = append(kb, len(r.body)/1024)
			if i%2 == 0 {
				d1 = append(d1, r.took)
			} else {
				d5 = append(d5, r.took)
			}
		}
		if len(kb) == 0 {
			continue
		}
		sort.Ints(kb)
		fmt.Printf("| %d 이상 %s | %d | %d KB | %s ms | %s ms | %s ms | %s ms |\n", b.lo, b.label, len(kb), kb[len(kb)/2], ms(pct(d1, 50)), ms(pct(d1, 100)), ms(pct(d5, 50)), ms(pct(d5, 100)))
	}
	fmt.Printf("\n5건 동시: %d건에 %.1f초 (초당 %.1f건)\n", len(many), wall.Seconds(), float64(len(many))/wall.Seconds())
}

// --- scans: ten server scans of one archive, queued at once ---

// serverScans uploads the same mid-size source archive ten times (two lock files with known-vulnerable packages
// among ~60 MB of files) and reports how long each waited in the queue and ran. It needs the Trivy DB installed.
func serverScans(db *pgx.Conn) {
	var arc bytes.Buffer
	zw := gzip.NewWriter(&arc)
	tw := tar.NewWriter(zw)
	add := func(name string, b []byte) {
		must(tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(b)), ModTime: time.Now()}))
		tw.Write(b)
	}
	lock := map[string]any{"": map[string]any{"name": "loadtest-app", "version": "1.0.0"}}
	for _, p := range strings.Fields("lodash@4.17.15 minimist@1.2.0 axios@0.21.0 express@4.16.0 moment@2.24.0 jquery@3.4.1 handlebars@4.5.3 node-fetch@2.6.0 ws@7.4.5 underscore@1.12.0 qs@6.5.2 tar@4.4.13 y18n@4.0.0 ini@1.3.5 json5@2.1.3 glob-parent@5.1.1 path-parse@1.0.6 ansi-regex@5.0.0 semver@5.7.1 follow-redirects@1.13.0 jsonwebtoken@8.5.1 serialize-javascript@3.0.0 async@2.6.3 debug@2.6.8") {
		name, ver, _ := strings.Cut(p, "@")
		lock["node_modules/"+name] = map[string]string{"version": ver, "resolved": "https://registry.npmjs.org/" + name + "/-/" + name + "-" + ver + ".tgz"}
	}
	for i := range 800 {
		name := fmt.Sprint("lt-module-", i)
		lock["node_modules/"+name] = map[string]string{"version": fmt.Sprintf("%d.%d.%d", 1+i%9, i%30, i%40), "resolved": "https://registry.example.internal/" + name + ".tgz"}
	}
	b, _ := json.MarshalIndent(map[string]any{"name": "loadtest-app", "version": "1.0.0", "lockfileVersion": 3, "packages": lock}, "", "  ")
	add("app/package-lock.json", b)
	add("app/requirements.txt", []byte("django==2.2.0\nrequests==2.19.0\nurllib3==1.24.1\npyyaml==5.1\nflask==0.12.2\njinja2==2.10\npillow==6.2.0\ncryptography==2.8\n"))
	rnd := rand.New(rand.NewPCG(1, 2)) // the same archive every run
	words := strings.Fields("const let function return import export from async await class extends value result error request response handler config index module service util")
	for i := range 4000 { // source-like text, about 15 KB a file
		var f strings.Builder
		for f.Len() < 15000 {
			fmt.Fprintf(&f, "%s %s_%d = %s(%d);\n", words[rnd.IntN(len(words))], words[rnd.IntN(len(words))], rnd.IntN(1e6), words[rnd.IntN(len(words))], rnd.IntN(1e9))
		}
		add(fmt.Sprintf("app/src/dir%d/file%d.js", i/100, i), []byte(f.String()))
	}
	must(tw.Close())
	must(zw.Close())
	fmt.Printf("archive: %.1f MB compressed, 4,002 files\n", float64(arc.Len())/1e6)

	var admin int64
	var key string
	must(db.QueryRow(ctx, `select (select id from users where username = 'lt.user00001'), (select key from projects order by id offset 5 limit 1)`).Scan(&admin, &key))
	cookie := session(db, admin)
	var ids []int64
	start := time.Now()
	for i := range 10 {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		mw.WriteField("kind", "fs")
		mw.WriteField("target", fmt.Sprintf("loadtest-scan-%d-%d", start.Unix(), i))
		fw, _ := mw.CreateFormFile("file", "app.tar.gz")
		fw.Write(arc.Bytes())
		mw.Close()
		req, _ := http.NewRequest("POST", *base+"/api/v1/projects/"+key+"/scan-jobs", &body)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("Origin", *base)
		req.AddCookie(cookie)
		resp, err := http.DefaultClient.Do(req)
		must(err)
		rb, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var out struct {
			ScanID int64 `json:"scan_id"`
			ID     int64 `json:"id"`
		}
		if json.Unmarshal(rb, &out); resp.StatusCode >= 300 || out.ScanID+out.ID == 0 {
			log.Fatalf("scan job: %d %s", resp.StatusCode, rb)
		}
		ids = append(ids, out.ScanID+out.ID)
	}
	fmt.Printf("10 uploads accepted in %.1fs; waiting for the queue\n", time.Since(start).Seconds())
	for {
		var left int
		must(db.QueryRow(ctx, `select count(*) from scans where id = any($1) and status in ('queued', 'running')`, ids).Scan(&left))
		if left == 0 {
			break
		}
		if time.Since(start) > 40*time.Minute {
			log.Fatalf("%d scans still not finished after 40 minutes", left)
		}
		time.Sleep(time.Second)
	}
	rows, _ := db.Query(ctx, `select s.id, s.status, extract(epoch from j.started_at - s.created_at)::float8, extract(epoch from j.finished_at - j.started_at)::float8,
			coalesce((s.summary->>'packages')::int, 0), coalesce((s.summary->>'open')::int, 0), s.error
		from scans s join jobs j on j.scan_id = s.id where s.id = any($1) order by s.id`, ids)
	var id int64
	var status, errText string
	var wait, run float64
	var pkgs, open int
	fmt.Println("\n| 스캔 | 상태 | 대기(초) | 실행(초) | 패키지 | 열린 결과 |\n|---|---|---|---|---|---|")
	_, err := pgx.ForEachRow(rows, []any{&id, &status, &wait, &run, &pkgs, &open, &errText}, func() error {
		fmt.Printf("| %d | %s %s | %.1f | %.1f | %d | %d |\n", id, status, errText, wait, run, pkgs, open)
		return nil
	})
	must(err)
	fmt.Printf("\n올린 뒤 10건이 모두 끝나기까지 %.0f초\n", time.Since(start).Seconds())
}

// --- measure: every page's requests, one user at a time and many at once ---

type page struct {
	name, path string
	admin      bool   // only an administrator has this page
	body       string // a POST with this body (MCP)
}

// The requests the pages make. {proj} is the user's largest project; the other {…} are things inside it.
var pages = []page{
	{name: "로그인 뒤 첫 요청 (me)", path: "/api/v1/me"},
	{name: "홈", path: "/api/v1/dashboard"},
	{name: "프로젝트 목록", path: "/api/v1/projects"},
	{name: "프로젝트 요약", path: "/api/v1/projects/{proj}"},
	{name: "프로젝트 · 결과 (열린 것)", path: "/api/v1/findings?project={proj}&status=open&limit=50"},
	{name: "프로젝트 · 결과 2쪽", path: "/api/v1/findings?project={proj}&status=open&limit=50&cursor={cursor}"},
	{name: "프로젝트 · 결과 CRITICAL·HIGH", path: "/api/v1/findings?project={proj}&status=open&severity=CRITICAL,HIGH&limit=50"},
	{name: "프로젝트 · 결과 검색", path: "/api/v1/findings?project={proj}&status=open&q=lt-module-1&limit=50"},
	{name: "프로젝트 · 결과 기한순", path: "/api/v1/findings?project={proj}&status=open&sort=due&limit=50"},
	{name: "프로젝트 · 기한 지난 결과", path: "/api/v1/findings?project={proj}&due=overdue&sort=due&limit=50"},
	{name: "프로젝트 · 대상 하나의 결과", path: "/api/v1/findings?project={proj}&target_id={target}&status=open&limit=50"},
	{name: "프로젝트 · 대상", path: "/api/v1/projects/{proj}/targets"},
	{name: "프로젝트 · 스캔", path: "/api/v1/projects/{proj}/scans?limit=50"},
	{name: "프로젝트 · 조치 계획", path: "/api/v1/projects/{proj}/fixes"},
	{name: "프로젝트 · 보고서", path: "/api/v1/projects/{proj}/report"},
	{name: "프로젝트 · 담당자 고르기", path: "/api/v1/projects/{proj}/assignees?q="},
	{name: "프로젝트 · findings.csv", path: "/api/v1/findings.csv?project={proj}&status=open"},
	{name: "스캔 상세", path: "/api/v1/scans/{scan}"},
	{name: "스캔 상세 · 결과", path: "/api/v1/scans/{scan}/findings?limit=200"},
	{name: "결과 상세", path: "/api/v1/findings/{finding}"},
	{name: "취약점 상세", path: "/api/v1/vulns/{vuln}"},
	{name: "전체 결과 (열린 것)", path: "/api/v1/findings?status=open&limit=50"},
	{name: "전체 결과 검색 (CVE)", path: "/api/v1/findings?status=open&q={vuln}&limit=50"},
	{name: "전체 결과 · 내 담당", path: "/api/v1/findings?status=open&assignee=me&limit=50"},
	{name: "전체 결과 · 기한 지남", path: "/api/v1/findings?due=overdue&sort=due&limit=50"},
	{name: "패키지 찾기 (lodash)", path: "/api/v1/packages?q=lodash"},
	{name: "패키지 찾기 (log4j <2.17.1)", path: "/api/v1/packages?q=log4j&version=%3C2.17.1"},
	{name: "패키지 찾기 (흔한 이름)", path: "/api/v1/packages?q=lt-module-10"},
	{name: "예외 목록", path: "/api/v1/exceptions"},
	{name: "예외 목록 (대기)", path: "/api/v1/exceptions?status=pending"},
	{name: "사내 Advisory", path: "/api/v1/advisories"},
	{name: "MCP tools/list", path: "/mcp", body: `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`},
	{name: "MCP list_findings", path: "/mcp", body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_findings","arguments":{"project":"{proj}"}}}`},
	{name: "감사 로그", path: "/api/v1/audit?limit=50", admin: true},
	{name: "감사 로그 (스캔 업로드만)", path: "/api/v1/audit?action=scan.upload&limit=50", admin: true},
	{name: "감사 로그 (프로젝트)", path: "/api/v1/audit?project={proj}&limit=50", admin: true},
	{name: "관리 · 사용자", path: "/api/v1/admin/users", admin: true},
	{name: "관리 · MCP 키", path: "/api/v1/admin/mcp-keys", admin: true},
	{name: "관리 · 재평가", path: "/api/v1/admin/recheck", admin: true},
}

type vuser struct {
	id     int64
	admin  bool
	cookie *http.Cookie
	mcpKey string
	vars   *strings.Replacer
}

type stat struct {
	d     []time.Duration
	bytes int
	errs  int
	first string // the first error
}

type sample struct {
	page  int
	took  time.Duration
	bytes int
	err   string
}

func (u *vuser) get(i int) sample {
	p := pages[i]
	method, body := "GET", io.Reader(nil)
	if p.body != "" {
		method, body = "POST", strings.NewReader(u.vars.Replace(p.body))
	}
	req, _ := http.NewRequest(method, *base+u.vars.Replace(p.path), body)
	if p.body != "" {
		req.Header.Set("Authorization", "Bearer "+u.mcpKey)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req.AddCookie(u.cookie)
	}
	t := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return sample{page: i, err: err.Error()}
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	s := sample{page: i, took: time.Since(t), bytes: len(b)}
	if resp.StatusCode != 200 || p.body != "" && bytes.Contains(b, []byte(`"isError":true`)) {
		s.err = fmt.Sprintf("%d %.200s", resp.StatusCode, b)
	}
	return s
}

// run has every user request each of their pages n times (in random order when there are several users).
func run(users []*vuser, n int) []stat {
	out := make([]stat, len(pages))
	ch := make(chan sample, 1024)
	var wg sync.WaitGroup
	for _, u := range users {
		wg.Go(func() {
			var order []int
			for i, p := range pages {
				if (!p.admin || u.admin) && (p.body == "" || u.mcpKey != "") {
					order = append(order, slices.Repeat([]int{i}, n)...)
				}
			}
			if len(users) > 1 {
				rand.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
			}
			for _, i := range order {
				ch <- u.get(i)
			}
		})
	}
	go func() { wg.Wait(); close(ch) }()
	for s := range ch {
		st := &out[s.page]
		if s.err != "" {
			if st.errs++; st.first == "" {
				st.first = s.err
			}
			continue
		}
		st.d, st.bytes = append(st.d, s.took), max(st.bytes, s.bytes)
	}
	return out
}

func measure(db *pgx.Conn, n, nUsers int, outFile string) {
	http.DefaultTransport.(*http.Transport).MaxIdleConnsPerHost = nUsers * 2
	// two administrators, two security users and members who each see only their own projects
	rows, _ := db.Query(ctx, `with u as (select id, system_role, row_number() over (order by id) n from users where username like 'lt.user%')
		select id, system_role, case when n % 3 = 0 then 'jsu_lt_' || n else '' end,
			case when system_role <> '' then (select p.key from projects p order by (select count(*) from targets t where t.project_id = p.id) desc, p.id limit 1)
			else (select p.key from project_members pm join projects p on p.id = pm.project_id where pm.principal_kind = 'user' and pm.principal = u.id::text
				order by (select count(*) from targets t where t.project_id = p.id) desc, p.id limit 1) end
		from u where n in (1, 2, 3, 6) or system_role = '' and n % 3 = 0 order by n limit $1`, nUsers)
	type urow struct {
		ID        int64
		Role, Key string
		Proj      *string
	}
	urows, err := pgx.CollectRows(rows, pgx.RowToStructByPos[urow])
	must(err)
	var users []*vuser
	var member *vuser
	for _, r := range urows {
		if r.Proj == nil {
			continue
		}
		var target, scan, finding int64
		var vulnID string
		err := db.QueryRow(ctx, `select t.id, `+inventorySQL+`, f.id, f.rule_id from projects p join targets t on t.project_id = p.id
			join findings f on f.target_id = t.id and f.status = 'open' and f.kind = 'vuln' where p.key = $1 order by t.id, f.id limit 1`, *r.Proj).
			Scan(&target, &scan, &finding, &vulnID)
		if errors.Is(err, pgx.ErrNoRows) { // a project without an open vulnerability has no pages to ask for
			continue
		}
		must(err)
		u := &vuser{id: r.ID, admin: r.Role == "admin", cookie: session(db, r.ID), mcpKey: r.Key}
		if r.Role == "" && member == nil {
			member = u
		}
		u.vars = strings.NewReplacer("{proj}", *r.Proj, "{target}", fmt.Sprint(target), "{scan}", fmt.Sprint(scan), "{finding}", fmt.Sprint(finding), "{vuln}", vulnID)
		// the second page starts where the first ends
		req, _ := http.NewRequest("GET", *base+u.vars.Replace("/api/v1/findings?project={proj}&status=open&limit=50"), nil)
		req.AddCookie(u.cookie)
		resp, err := http.DefaultClient.Do(req)
		must(err)
		var first struct {
			Next string `json:"next_cursor"`
		}
		json.NewDecoder(resp.Body).Decode(&first)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			log.Fatalf("user %d cannot list findings of %s: %d (is the server on this database?)", r.ID, *r.Proj, resp.StatusCode)
		}
		u.vars = strings.NewReplacer("{proj}", *r.Proj, "{target}", fmt.Sprint(target), "{scan}", fmt.Sprint(scan), "{finding}", fmt.Sprint(finding), "{vuln}", vulnID, "{cursor}", first.Next)
		users = append(users, u)
	}
	if member == nil || !users[0].admin {
		log.Fatal("measure needs a seeded administrator and a member with an open finding: is this a seeded database?")
	}
	fmt.Printf("%d users (the administrator's largest project is %s, the member's %s)\n", len(users), users[0].vars.Replace("{proj}"), member.vars.Replace("{proj}"))
	if pw := os.Getenv("JASCA_BOOTSTRAP_PASSWORD"); pw != "" { // the local admin's sign-in: the password hash is the cost
		var d []time.Duration
		for range 5 {
			req, _ := http.NewRequest("POST", *base+"/api/v1/auth/local", strings.NewReader(fmt.Sprintf(`{"username":"admin","password":%q}`, pw)))
			req.Header.Set("Origin", *base)
			t := time.Now()
			resp, err := http.DefaultClient.Do(req)
			must(err)
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 {
				log.Fatalf("local sign-in: %d", resp.StatusCode)
			}
			d = append(d, time.Since(t))
		}
		fmt.Printf("로그인 (로컬 admin, 5회): 중앙값 %s ms, 최대 %s ms\n", ms(pct(d, 50)), ms(pct(d, 100)))
	}
	admin1 := run(users[:1], n)
	member1 := run([]*vuser{member}, n)
	t := time.Now()
	all := run(users, max(n/3, 2))
	wall := time.Since(t)
	total := 0
	type row struct {
		Page                                     string
		AdminMed, AdminP95, MemberMed, MemberP95 float64 `json:",omitempty"`
		ManyMed, ManyP95                         float64
		KB                                       int
		Errors                                   int    `json:",omitempty"`
		Error                                    string `json:",omitempty"`
	}
	var table []row
	f := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
	fmt.Printf("\n| 화면 (요청) | 관리자 1명: 중앙값 | p95 | 멤버 1명: 중앙값 | p95 | %d명 동시: 중앙값 | p95 | 응답 크기 |\n|---|---|---|---|---|---|---|---|\n", len(users))
	for i, p := range pages {
		a, m, c := admin1[i], member1[i], all[i]
		total += len(c.d)
		r := row{Page: p.name, AdminMed: f(pct(a.d, 50)), AdminP95: f(pct(a.d, 95)), MemberMed: f(pct(m.d, 50)), MemberP95: f(pct(m.d, 95)),
			ManyMed: f(pct(c.d, 50)), ManyP95: f(pct(c.d, 95)), KB: max(a.bytes, m.bytes, c.bytes) / 1024, Errors: a.errs + m.errs + c.errs, Error: cmp.Or(a.first, m.first, c.first)}
		table = append(table, r)
		cell := func(v float64) string {
			if v == 0 {
				return "-"
			}
			return fmt.Sprintf("%.0f ms", v)
		}
		fmt.Printf("| %s | %s | %s | %s | %s | %s | %s | %d KB |\n", p.name, cell(r.AdminMed), cell(r.AdminP95), cell(r.MemberMed), cell(r.MemberP95), cell(r.ManyMed), cell(r.ManyP95), r.KB)
		if r.Errors > 0 {
			fmt.Printf("  !! %d errors, first: %s\n", r.Errors, r.Error)
		}
	}
	fmt.Printf("\n동시 구간: %d명이 쉬지 않고 %d건, %.1f초 (초당 %.0f건)\n", len(users), total, wall.Seconds(), float64(total)/wall.Seconds())
	if outFile != "" {
		b, _ := json.MarshalIndent(table, "", " ")
		must(os.WriteFile(outFile, b, 0o644))
	}
}
