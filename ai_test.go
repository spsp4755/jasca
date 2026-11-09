package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func init() {
	matrixRoutes = append(matrixRoutes,
		matrixCase{Method: "GET", Path: "/api/v1/ai/runs/{ai_run}"},
		matrixCase{Method: "POST", Path: "/api/v1/projects/{key}/ai-report"},
		matrixCase{Method: "GET", Path: "/api/v1/projects/{key}/ai-reports", List: "[]"})
	matrixExempt["POST /api/v1/vulns/{id}/ai-guide"] = "shared catalog entry; the impact part only sees the requester's visible findings"
}

type fakeLLM struct {
	*httptest.Server
	mu    sync.Mutex
	paths []string
	users []string
	reqs  []map[string]any
	auths []string
	resp  func(system, user string, req map[string]any) (int, string)
}

func newFakeLLM(t *testing.T, resp func(system, user string, req map[string]any) (int, string)) *fakeLLM {
	f := &fakeLLM{resp: resp}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		msgs, _ := req["messages"].([]any)
		var sys, usr string
		if len(msgs) == 2 {
			sys, _ = msgs[0].(map[string]any)["content"].(string)
			usr, _ = msgs[1].(map[string]any)["content"].(string)
		}
		f.mu.Lock()
		f.paths = append(f.paths, r.URL.Path)
		f.reqs = append(f.reqs, req)
		f.users = append(f.users, usr)
		f.auths = append(f.auths, r.Header.Get("Authorization"))
		f.mu.Unlock()
		code, text := f.resp(sys, usr, req)
		if code != 200 {
			http.Error(w, "nope secret-body", code)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": text}}}})
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeLLM) countUser(prefix string) (n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.users {
		if strings.HasPrefix(u, prefix) {
			n++
		}
	}
	return
}

func (f *fakeLLM) count(sub string) (n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.reqs {
		b, _ := json.Marshal(r)
		if strings.Contains(string(b), sub) {
			n++
		}
	}
	return
}

func echoLLM(t *testing.T) *fakeLLM {
	return newFakeLLM(t, func(sys, usr string, _ map[string]any) (int, string) {
		if strings.HasPrefix(usr, "[파트 1") {
			return 200, "<think>생각</think>GENERAL-PART"
		}
		return 200, "IMPACT\n" + usr
	})
}

func enableAI(t *testing.T, s *server, f *fakeLLM, base string, maxTokens int) {
	t.Helper()
	if err := s.putSetting(context.Background(), "ai", aiSettings{BaseURL: f.URL + base, Model: "m", APIKey: "sk-secret-key", TimeoutSec: 5, MaxInputTokens: maxTokens, Enabled: true}); err != nil {
		t.Fatal(err)
	}
}

type aiTestRunView struct {
	ID        int64   `json:"id"`
	Kind      string  `json:"kind"`
	ProjectID *int64  `json:"project_id"`
	VulnID    *string `json:"vuln_id"`
	State     string  `json:"state"`
	Output    string  `json:"output"`
	Error     string  `json:"error"`
}

func waitRun(t *testing.T, s *server, ck *http.Cookie, id int64) aiTestRunView {
	t.Helper()
	for i := 0; i < 100; i++ {
		for { // the worker is started by main, not testServer: run the queued jobs here, in order
			if ran, err := s.runNextJob(context.Background()); err != nil {
				t.Fatal(err)
			} else if !ran {
				break
			}
		}
		rec := do(t, s, "GET", fmt.Sprintf("/api/v1/ai/runs/%d", id), nil, ck)
		var r aiTestRunView
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &r) != nil {
			t.Fatalf("get run: %d %s", rec.Code, rec.Body.String())
		}
		if r.State == "done" || r.State == "failed" {
			return r
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("run did not finish")
	return aiTestRunView{}
}

func addFinding(t *testing.T, s *server, pid, tid int64, rule, sev, pkg, title string, n int) {
	t.Helper()
	sqlExec(t, s, `insert into findings(project_id, target_id, fingerprint, kind, tool, rule_id, severity, pkg_name, pkg_version, fixed_version, title)
		values($1, $2, $3, 'vuln', 'trivy', $4, $5, $6, '1.0.0', '1.0.1', $7)`, pid, tid, fmt.Sprintf("fp-%s-%d", rule, n), rule, sev, pkg, title)
}

func mkTarget(t *testing.T, s *server, pid int64, name string) int64 {
	t.Helper()
	var id int64
	if err := s.db.QueryRow(context.Background(), `insert into targets(project_id, kind, name) values($1, 'image', $2) returning id`, pid, name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func postRun(t *testing.T, s *server, path string, ck *http.Cookie) int64 {
	t.Helper()
	rec := do(t, s, "POST", path, nil, ck)
	var r struct {
		RunID int64 `json:"run_id"`
	}
	if rec.Code/100 != 2 || json.Unmarshal(rec.Body.Bytes(), &r) != nil || r.RunID == 0 {
		t.Fatalf("POST %s: %d %s", path, rec.Code, rec.Body.String())
	}
	return r.RunID
}

func TestAIGuideCachesGeneralOnly(t *testing.T) {
	s := testServer(t)
	f := echoLLM(t)
	enableAI(t, s, f, "/v1", 12000)
	u1, u2 := mkUser(t, s, "u1", ""), mkUser(t, s, "u2", "")
	p1, p2 := mkProject(t, s, "alpha-proj"), mkProject(t, s, "beta-proj")
	addMember(t, s, p1, "user", itoa(u1.ID), "viewer")
	addMember(t, s, p2, "user", itoa(u2.ID), "viewer")
	sqlExec(t, s, `insert into vulns(id, title, description) values('CVE-2024-1111', 'bad bug', 'does bad things')`)
	addFinding(t, s, p1, mkTarget(t, s, p1, "img-a"), "CVE-2024-1111", "HIGH", "libfoo", "t", 1)
	addFinding(t, s, p2, mkTarget(t, s, p2, "img-b"), "CVE-2024-1111", "LOW", "libfoo", "t", 1)
	c1, c2 := loginAs(t, s, u1), loginAs(t, s, u2)

	r1 := waitRun(t, s, c1, postRun(t, s, "/api/v1/vulns/CVE-2024-1111/ai-guide", c1))
	if r1.State != "done" || !strings.Contains(r1.Output, "GENERAL-PART") || !strings.Contains(r1.Output, "alpha-proj") || r1.ProjectID != nil || strings.Contains(r1.Output, "생각") {
		t.Fatalf("run 1: %+v", r1)
	}
	r2 := waitRun(t, s, c2, postRun(t, s, "/api/v1/vulns/CVE-2024-1111/ai-guide", c2))
	if r2.State != "done" || !strings.Contains(r2.Output, "GENERAL-PART") || !strings.Contains(r2.Output, "beta-proj") {
		t.Fatalf("run 2: %+v", r2)
	}
	if strings.Contains(r2.Output, "alpha-proj") || strings.Contains(r2.Output, "img-a") {
		t.Fatalf("user 2's guide leaks user 1's project: %s", r2.Output)
	}
	if n := f.countUser("[파트 1"); n != 1 {
		t.Fatalf("general part generated %d times, want 1 (cached)", n)
	}
	var cached string
	s.db.QueryRow(context.Background(), `select ai_guide from vulns where id='CVE-2024-1111'`).Scan(&cached)
	if cached != "GENERAL-PART" {
		t.Fatalf("cache holds %q, want the general part only", cached)
	}
	// the general-part request carries no project data at all
	if f.count("alpha-proj") != 1 || f.count("beta-proj") != 1 {
		t.Fatalf("project keys sent to the LLM more than once each")
	}
	// u2 cannot read u1's run; an admin can
	if rec := do(t, s, "GET", fmt.Sprintf("/api/v1/ai/runs/%d", r1.ID), nil, c2); rec.Code != 404 {
		t.Fatalf("other user reads a guide run: %d", rec.Code)
	}
	if rec := do(t, s, "GET", fmt.Sprintf("/api/v1/ai/runs/%d", r1.ID), nil, loginAs(t, s, mkUser(t, s, "adm", "admin"))); rec.Code != 200 {
		t.Fatalf("admin cannot read guide run: %d", rec.Code)
	}
	if rec := do(t, s, "POST", "/api/v1/vulns/CVE-9999-0000/ai-guide", nil, c1); rec.Code != 404 {
		t.Fatalf("unknown vuln: %d", rec.Code)
	}
}

func TestAIStripsThink(t *testing.T) {
	for in, want := range map[string]string{
		"<think>a</think>\n답":                         "답",
		"x</thinking> y </think>  z":                  "z",
		"<reasoning>q</reasoning>\n# R\n</think>\n본문": "본문",
		"  그냥 답  ":                                    "그냥 답",
	} {
		if got := cleanAnswer(in); got != want {
			t.Errorf("cleanAnswer(%q) = %q, want %q", in, got, want)
		}
	}
	s := testServer(t)
	f := newFakeLLM(t, func(string, string, map[string]any) (int, string) {
		return 200, "<think>비밀 추론</think>\n# 보고서"
	})
	enableAI(t, s, f, "/v1", 12000)
	u := mkUser(t, s, "own", "")
	p := mkProject(t, s, "rep-proj")
	addMember(t, s, p, "user", itoa(u.ID), "member")
	ck := loginAs(t, s, u)
	r := waitRun(t, s, ck, postRun(t, s, "/api/v1/projects/rep-proj/ai-report", ck))
	if r.State != "done" || r.Output != "# 보고서" || r.Kind != "project_report" || r.ProjectID == nil {
		t.Fatalf("%+v", r)
	}
}

func TestAIRespectsTokenLimit(t *testing.T) {
	s := testServer(t)
	f := newFakeLLM(t, func(string, string, map[string]any) (int, string) { return 200, "ok" })
	enableAI(t, s, f, "/v1", 1500)
	u := mkUser(t, s, "own", "")
	p := mkProject(t, s, "big-proj")
	addMember(t, s, p, "user", itoa(u.ID), "owner")
	tg := mkTarget(t, s, p, "img")
	addFinding(t, s, p, tg, "CVE-2024-9001", "CRITICAL", "crit-pkg", strings.Repeat("긴제목", 20), 0)
	for i := 0; i < 50; i++ {
		addFinding(t, s, p, tg, fmt.Sprintf("CVE-2024-%04d", i), "LOW", "low-pkg", strings.Repeat("긴제목", 20), i)
	}
	ck := loginAs(t, s, u)
	r := waitRun(t, s, ck, postRun(t, s, "/api/v1/projects/big-proj/ai-report", ck))
	if r.State != "done" || f.count("CVE-2024-9001") != 1 {
		t.Fatalf("%+v", r)
	}
	f.mu.Lock()
	b, _ := json.Marshal(f.reqs[0]["messages"])
	f.mu.Unlock()
	var msgs []struct{ Content string }
	json.Unmarshal(b, &msgs)
	if n := len([]rune(msgs[0].Content+msgs[1].Content)) / 2; n > 1500 {
		t.Fatalf("sent ~%d tokens, limit 1500", n)
	}
	if f.count("CVE-2024-0049") != 0 {
		t.Fatal("trimmed run still lists every LOW finding")
	}
	// a limit nothing fits in fails with a Korean message and calls nothing
	enableAI(t, s, f, "/v1", 100)
	before := len(f.reqs)
	r = waitRun(t, s, ck, postRun(t, s, "/api/v1/projects/big-proj/ai-report", ck))
	if r.State != "failed" || !strings.Contains(r.Error, "입력") || len(f.reqs) != before {
		t.Fatalf("%+v calls=%d", r, len(f.reqs))
	}
}

func TestAIRetriesWithoutTemperature(t *testing.T) {
	s := testServer(t)
	f := newFakeLLM(t, func(_, _ string, req map[string]any) (int, string) {
		if _, ok := req["temperature"]; ok {
			return 400, ""
		}
		return 200, "된다"
	})
	enableAI(t, s, f, "/v1", 12000)
	u := mkUser(t, s, "own", "")
	p := mkProject(t, s, "rt-proj")
	addMember(t, s, p, "user", itoa(u.ID), "member")
	ck := loginAs(t, s, u)
	r := waitRun(t, s, ck, postRun(t, s, "/api/v1/projects/rt-proj/ai-report", ck))
	if r.State != "done" || r.Output != "된다" || len(f.reqs) != 2 || f.reqs[0]["temperature"] != 0.2 {
		t.Fatalf("%+v reqs=%v", r, f.reqs)
	}
	// a hard failure shows no upstream body
	f.resp = func(string, string, map[string]any) (int, string) { return 500, "" }
	r = waitRun(t, s, ck, postRun(t, s, "/api/v1/projects/rt-proj/ai-report", ck))
	if r.State != "failed" || strings.Contains(r.Error, "secret-body") {
		t.Fatalf("%+v", r)
	}
}

func TestAIOnlyCallsConfiguredHost(t *testing.T) {
	s := testServer(t)
	other := newFakeLLM(t, func(string, string, map[string]any) (int, string) { return 200, "other" })
	f := newFakeLLM(t, func(string, string, map[string]any) (int, string) { return 200, "mine" })
	// a redirect to another host is not followed
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/v1/chat/completions", 307)
	}))
	defer redir.Close()
	enableAI(t, s, f, "/v1/", 12000)
	u := mkUser(t, s, "own", "")
	p := mkProject(t, s, "host-proj")
	addMember(t, s, p, "user", itoa(u.ID), "member")
	ck := loginAs(t, s, u)
	r := waitRun(t, s, ck, postRun(t, s, "/api/v1/projects/host-proj/ai-report", ck))
	if r.Output != "mine" || len(f.paths) != 1 || f.paths[0] != "/v1/chat/completions" {
		t.Fatalf("%+v paths=%v", r, f.paths)
	}
	s.putSetting(context.Background(), "ai", aiSettings{BaseURL: redir.URL, Model: "m", TimeoutSec: 5, MaxInputTokens: 12000, Enabled: true})
	r = waitRun(t, s, ck, postRun(t, s, "/api/v1/projects/host-proj/ai-report", ck))
	if r.State != "failed" || len(other.reqs) != 0 {
		t.Fatalf("redirect followed: %+v other=%d", r, len(other.reqs))
	}
	// disabled → nothing queued
	s.putSetting(context.Background(), "ai", aiSettings{BaseURL: f.URL, Enabled: false})
	if rec := do(t, s, "POST", "/api/v1/projects/host-proj/ai-report", nil, ck); rec.Code != 409 {
		t.Fatalf("disabled: %d %s", rec.Code, rec.Body.String())
	}
}

func TestAISettingsNoKeyLeak(t *testing.T) {
	s := testServer(t)
	f := newFakeLLM(t, func(string, string, map[string]any) (int, string) { return 200, "pong" })
	admin := loginAs(t, s, mkUser(t, s, "adm", "admin"))
	sec := loginAs(t, s, mkUser(t, s, "sec", "security"))
	body := map[string]any{"base_url": f.URL + "/v1", "model": "m1", "api_key": "sk-very-secret", "timeout_sec": 30, "max_input_tokens": 9000, "enabled": true}
	if rec := do(t, s, "PUT", "/api/v1/admin/ai", body, sec); rec.Code != 403 {
		t.Fatalf("security edits ai: %d", rec.Code)
	}
	if rec := do(t, s, "PUT", "/api/v1/admin/ai/prompts", map[string]string{"vuln_guide": "x"}, sec); rec.Code != 403 {
		t.Fatalf("security edits prompts: %d", rec.Code)
	}
	if rec := do(t, s, "PUT", "/api/v1/admin/ai", body, admin); rec.Code != 200 {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	// an omitted/empty key keeps the stored one
	body["api_key"] = ""
	body["model"] = "m2"
	do(t, s, "PUT", "/api/v1/admin/ai", body, admin)
	rec := do(t, s, "GET", "/api/v1/admin/ai", nil, admin)
	var got map[string]any
	json.Unmarshal(rec.Body.Bytes(), &got)
	if strings.Contains(rec.Body.String(), "very-secret") || got["api_key_set"] != true || got["model"] != "m2" || got["timeout_sec"] != 30.0 || got["enabled"] != true {
		t.Fatalf("%s", rec.Body.String())
	}
	if _, has := got["api_key"]; has {
		t.Fatal("api_key returned")
	}
	rec = do(t, s, "POST", "/api/v1/admin/ai/test", map[string]any{"base_url": f.URL + "/v1", "model": "m2"}, admin)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "very-secret") || !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("test: %d %s", rec.Code, rec.Body.String())
	}
	f.mu.Lock()
	last := f.reqs[len(f.reqs)-1]
	f.mu.Unlock()
	if last["model"] != "m2" || f.auths[len(f.auths)-1] != "Bearer sk-very-secret" {
		t.Fatalf("%v", last)
	}
	// a test against another host never carries the stored key there (the form must send its own key)
	other := echoLLM(t)
	rec = do(t, s, "POST", "/api/v1/admin/ai/test", map[string]any{"base_url": other.URL + "/v1", "model": "m2"}, admin)
	if !strings.Contains(rec.Body.String(), `"ok":true`) || len(other.auths) != 1 || other.auths[0] != "" {
		t.Fatalf("stored key sent to a new base_url: %v %s", other.auths, rec.Body.String())
	}
	do(t, s, "POST", "/api/v1/admin/ai/test", map[string]any{"base_url": other.URL + "/v1", "model": "m2", "api_key": "sk-typed"}, admin)
	if other.auths[1] != "Bearer sk-typed" {
		t.Fatalf("typed key not used: %v", other.auths)
	}
	if rec := do(t, s, "PUT", "/api/v1/admin/ai", map[string]any{"base_url": "file:///etc/passwd"}, admin); rec.Code != 400 {
		t.Fatalf("bad url: %d", rec.Code)
	}
	// prompts: empty = default; saved text is used
	do(t, s, "PUT", "/api/v1/admin/ai/prompts", map[string]string{"vuln_guide": "", "project_report": "나의 보고서 프롬프트"}, admin)
	rec = do(t, s, "GET", "/api/v1/admin/ai/prompts", nil, admin)
	var pr map[string]string
	json.Unmarshal(rec.Body.Bytes(), &pr)
	if pr["project_report"] != "나의 보고서 프롬프트" || pr["vuln_guide"] != "" {
		t.Fatalf("%s", rec.Body.String())
	}
	var n int
	s.db.QueryRow(context.Background(), `select count(*) from audit_log where action='settings.update' and details::text like '%sk-very%'`).Scan(&n)
	var m int
	s.db.QueryRow(context.Background(), `select count(*) from audit_log where action='settings.update' and target in ('ai','ai_prompts')`).Scan(&m)
	if n != 0 || m != 3 {
		t.Fatalf("audit: leaked=%d rows=%d", n, m)
	}
	// a new guide prompt drops the cached general parts written with the old one
	sqlExec(t, s, `insert into vulns(id, ai_guide, ai_guide_at) values('CVE-2024-7777', 'old part', now())`)
	do(t, s, "PUT", "/api/v1/admin/ai/prompts", map[string]string{"vuln_guide": "새 프롬프트", "project_report": "나의 보고서 프롬프트"}, admin)
	if n := qInt(t, s, `select count(*) from vulns where ai_guide <> '' or ai_guide_at is not null`); n != 0 {
		t.Fatalf("guide cache kept after prompt change: %d", n)
	}
}

func TestAIRunsAccess(t *testing.T) {
	s := testServer(t)
	f := newFakeLLM(t, func(string, string, map[string]any) (int, string) { return 200, "ok" })
	enableAI(t, s, f, "/v1", 12000)
	own, viewer, out := mkUser(t, s, "own", ""), mkUser(t, s, "vw", ""), mkUser(t, s, "out", "")
	p := mkProject(t, s, "acc-proj")
	addMember(t, s, p, "user", itoa(own.ID), "member")
	addMember(t, s, p, "user", itoa(viewer.ID), "viewer")
	co, cv, cx := loginAs(t, s, own), loginAs(t, s, viewer), loginAs(t, s, out)
	if rec := do(t, s, "POST", "/api/v1/projects/acc-proj/ai-report", nil, cv); rec.Code != 403 {
		t.Fatalf("viewer starts a report: %d", rec.Code)
	}
	if rec := do(t, s, "POST", "/api/v1/projects/acc-proj/ai-report", nil, cx); rec.Code != 404 {
		t.Fatalf("outsider starts a report: %d", rec.Code)
	}
	id := postRun(t, s, "/api/v1/projects/acc-proj/ai-report", co)
	waitRun(t, s, co, id)
	if r := waitRun(t, s, cv, id); r.Output != "ok" { // project runs follow project access
		t.Fatalf("%+v", r)
	}
	if rec := do(t, s, "GET", fmt.Sprintf("/api/v1/ai/runs/%d", id), nil, cx); rec.Code != 404 {
		t.Fatalf("outsider reads run: %d", rec.Code)
	}
	rec := do(t, s, "GET", "/api/v1/projects/acc-proj/ai-reports", nil, cv)
	var list []map[string]any
	if json.Unmarshal(rec.Body.Bytes(), &list) != nil || len(list) != 1 || list[0]["state"] != "done" || list[0]["kind"] != "project_report" {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	var n int
	s.db.QueryRow(context.Background(), `select count(*) from audit_log where action='ai.report' and project_id=$1`, p).Scan(&n)
	if n != 1 {
		t.Fatalf("audit rows %d", n)
	}
}

// A second request while the same run is still queued returns that run instead of queueing another LLM call.
func TestAIRunNotQueuedTwice(t *testing.T) {
	s := testServer(t)
	enableAI(t, s, echoLLM(t), "", 0)
	sqlExec(t, s, `insert into vulns(id, title) values('CVE-2024-1111', 'bug')`)
	ck := loginAs(t, s, mkUser(t, s, "kim", ""))
	a := postRun(t, s, "/api/v1/vulns/CVE-2024-1111/ai-guide", ck)
	b := postRun(t, s, "/api/v1/vulns/CVE-2024-1111/ai-guide", ck)
	if a != b || qInt(t, s, `select count(*) from jobs where kind='ai'`) != 1 {
		t.Fatalf("runs %d %d", a, b)
	}
}
