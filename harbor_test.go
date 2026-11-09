package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type fakeHarbor struct {
	*httptest.Server
	mu    sync.Mutex
	paths []string
	auth  string
}

func newFakeHarbor(t *testing.T) *fakeHarbor {
	f := &fakeHarbor{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.paths = append(f.paths, r.URL.EscapedPath())
		u, p, _ := r.BasicAuth()
		f.auth = u + ":" + p + "|" + r.Header.Get("X-Accept-Vulnerabilities")
		f.mu.Unlock()
		if r.URL.Path == "/api/v2.0/systeminfo" {
			w.Write([]byte(`{}`))
			return
		}
		w.Write(readFixture(t, "harbor/report.json"))
	}))
	t.Cleanup(f.Close)
	return f
}

func harborSetup(t *testing.T, s *server, baseURL string) (ck *http.Cookie, linkID int64, hdr http.Header, created map[string]any) {
	t.Helper()
	ck = loginAs(t, s, mkUser(t, s, "adm", "admin"))
	rec := do(t, s, "POST", "/api/v1/admin/harbor", map[string]string{"name": "h", "base_url": baseURL + "/", "robot_user": "robot$ci", "robot_secret": "r0bot-s3cret"}, ck)
	wantCode(t, rec, 201, "create link")
	json.Unmarshal(rec.Body.Bytes(), &created)
	linkID = int64(created["id"].(float64))
	hdr = http.Header{"Authorization": {created["webhook_secret"].(string)}}
	return
}

const harborEvent = `{"type":"SCANNING_COMPLETED","event_data":{"resources":[{"digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","tag":"1.4.2","resource_url":"https://evil.example.invalid/library/web:1.4.2"}],"repository":{"namespace":"library","repo_full_name":"library/web"}}}`

func TestHarborWebhookBadSecret401(t *testing.T) {
	s := testServer(t)
	fh := newFakeHarbor(t)
	_, id, _, _ := harborSetup(t, s, fh.URL)
	hook := "/api/v1/hooks/harbor/" + itoa(id)
	wantCode(t, do(t, s, "POST", hook, harborEvent, http.Header{"Authorization": {"nope"}}), 401, "bad secret")
	wantCode(t, do(t, s, "POST", hook, harborEvent, http.Header{}), 401, "no secret")
	wantCode(t, do(t, s, "POST", "/api/v1/hooks/harbor/999", harborEvent, http.Header{"Authorization": {"x"}}), 401, "unknown link")
	var n int
	s.db.QueryRow(context.Background(), `select (select count(*) from jobs)+(select count(*) from harbor_unmapped)`).Scan(&n)
	if n != 0 {
		t.Fatalf("rejected webhook left %d rows", n)
	}
}

func TestHarborWebhookMappedFetches(t *testing.T) {
	s := testServer(t)
	fh := newFakeHarbor(t)
	ck, id, hdr, _ := harborSetup(t, s, fh.URL)
	pid := mkProject(t, s, "web")
	wantCode(t, do(t, s, "PUT", "/api/v1/admin/harbor/"+itoa(id)+"/mappings",
		[]map[string]any{{"harbor_project": "library", "repo_pattern": "*", "project_id": pid}}, ck), 204, "mappings")
	wantCode(t, do(t, s, "POST", "/api/v1/hooks/harbor/"+itoa(id), harborEvent, hdr), 202, "webhook")
	if !runHarborJob(t, s) {
		t.Fatal("no job queued")
	}
	var scans int
	var excluded bool
	var name, src string
	err := s.db.QueryRow(context.Background(), `select count(*), bool_and(t.recheck_excluded), min(t.name), min(sc.source)
		from scans sc join targets t on t.id = sc.target_id where sc.project_id = $1 and sc.status = 'done'`, pid).Scan(&scans, &excluded, &name, &src)
	if err != nil || scans != 1 || !excluded || src != "harbor" || !strings.HasSuffix(name, "/library/web") {
		t.Fatalf("scans=%d excluded=%v name=%q src=%q err=%v", scans, excluded, name, src, err)
	}
	if !strings.HasPrefix(fh.auth, "robot$ci:r0bot-s3cret|application/vnd.security.vulnerability.report; version=1.1") {
		t.Fatalf("auth/headers: %q", fh.auth)
	}
	if len(fh.paths) != 1 || !strings.Contains(fh.paths[0], "/projects/library/repositories/web/artifacts/sha256:0123") ||
		!strings.HasSuffix(fh.paths[0], "/additions/vulnerabilities") {
		t.Fatalf("paths: %v", fh.paths)
	}
}

func TestHarborIgnoresEventURLs(t *testing.T) {
	s := testServer(t)
	evil := newFakeHarbor(t)
	fh := newFakeHarbor(t)
	ck, id, hdr, _ := harborSetup(t, s, fh.URL)
	pid := mkProject(t, s, "web")
	do(t, s, "PUT", "/api/v1/admin/harbor/"+itoa(id)+"/mappings", []map[string]any{{"harbor_project": "library", "repo_pattern": "w*", "project_id": pid}}, ck)
	ev := strings.ReplaceAll(harborEvent, "https://evil.example.invalid", evil.URL)
	wantCode(t, do(t, s, "POST", "/api/v1/hooks/harbor/"+itoa(id), ev, hdr), 202, "webhook")
	runHarborJob(t, s)
	if len(evil.paths) != 0 || len(fh.paths) != 1 {
		t.Fatalf("evil=%v real=%v", evil.paths, fh.paths)
	}
}

func TestHarborUnmappedThenAssign(t *testing.T) {
	s := testServer(t)
	fh := newFakeHarbor(t)
	ck, id, hdr, _ := harborSetup(t, s, fh.URL)
	pid := mkProject(t, s, "web")
	for range 2 { // a repeat updates the one row
		wantCode(t, do(t, s, "POST", "/api/v1/hooks/harbor/"+itoa(id), harborEvent, hdr), 202, "webhook")
	}
	if runHarborJob(t, s) {
		t.Fatal("unmapped event must not enqueue")
	}
	rec := do(t, s, "GET", "/api/v1/admin/harbor/unmapped", nil, ck)
	var list []map[string]any
	json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 1 || list[0]["repository"] != "library/web" || list[0]["harbor_project"] != "library" || list[0]["tag"] != "1.4.2" {
		t.Fatalf("unmapped: %s", rec.Body.String())
	}
	uid := itoa(int64(list[0]["id"].(float64)))
	wantCode(t, do(t, s, "POST", "/api/v1/admin/harbor/unmapped/"+uid+"/assign", map[string]int64{"project_id": 99999}, ck), 400, "bad project")
	wantCode(t, do(t, s, "POST", "/api/v1/admin/harbor/unmapped/"+uid+"/assign", map[string]int64{"project_id": pid}, ck), 204, "assign")
	if !runHarborJob(t, s) {
		t.Fatal("assign did not enqueue a fetch")
	}
	var scans, maps, left int
	s.db.QueryRow(context.Background(), `select (select count(*) from scans where project_id=$1 and status='done'),
		(select count(*) from harbor_mappings where project_id=$1 and repo_pattern='library/web'), (select count(*) from harbor_unmapped)`, pid).Scan(&scans, &maps, &left)
	if scans != 1 || maps != 1 || left != 0 {
		t.Fatalf("scans=%d maps=%d left=%d", scans, maps, left)
	}
	// the mapping now routes the next event straight to a fetch
	do(t, s, "POST", "/api/v1/hooks/harbor/"+itoa(id), harborEvent, hdr)
	if !runHarborJob(t, s) {
		t.Fatal("mapped event did not enqueue")
	}
	wantCode(t, do(t, s, "POST", "/api/v1/admin/harbor/"+itoa(id)+"/test", nil, ck), 200, "test")
}

func TestHarborNeverReturnsSecrets(t *testing.T) {
	s := testServer(t)
	fh := newFakeHarbor(t)
	ck, id, _, created := harborSetup(t, s, fh.URL)
	if !strings.HasPrefix(created["webhook_url"].(string), "http") || !strings.HasSuffix(created["webhook_url"].(string), "/api/v1/hooks/harbor/"+itoa(id)) {
		t.Fatalf("webhook_url: %v", created["webhook_url"])
	}
	if len(created["webhook_secret"].(string)) < 43 {
		t.Fatal("secret too short")
	}
	rec := do(t, s, "GET", "/api/v1/admin/harbor", nil, ck)
	body := rec.Body.String()
	if strings.Contains(body, "r0bot-s3cret") || strings.Contains(body, created["webhook_secret"].(string)) || !strings.Contains(body, `"robot_secret_set":true`) {
		t.Fatalf("list leaks or lacks flag: %s", body)
	}
	// an update with an empty robot secret keeps the stored one
	wantCode(t, do(t, s, "PUT", "/api/v1/admin/harbor/"+itoa(id), map[string]string{"name": "h2", "base_url": fh.URL, "robot_user": "robot$ci", "robot_secret": ""}, ck), 204, "put")
	var sec string
	s.db.QueryRow(context.Background(), `select robot_secret from harbor_links where id=$1`, id).Scan(&sec)
	if sec != "r0bot-s3cret" {
		t.Fatalf("robot secret changed: %q", sec)
	}
	var a int
	s.db.QueryRow(context.Background(), `select count(*) from audit_log where action like 'harbor.%' and details::text like '%s3cret%'`).Scan(&a)
	if a != 0 {
		t.Fatal("audit leaks a secret")
	}
	var n int
	s.db.QueryRow(context.Background(), `select count(*) from audit_log where action = 'harbor.link_create'`).Scan(&n)
	if n != 1 {
		t.Fatalf("audit rows: %d", n)
	}
}

// runHarborJob runs the oldest queued harbor_fetch job inline (the real runner is Task 9's) and reports whether there was one.
func runHarborJob(t *testing.T, s *server) bool {
	t.Helper()
	ctx := context.Background()
	j := &job{}
	err := s.db.QueryRow(ctx, `select id, kind, scan_id, payload, created_by from jobs where kind = 'harbor_fetch' and state = 'queued'
		order by id limit 1`).Scan(&j.ID, &j.Kind, &j.ScanID, &j.Payload, &j.CreatedBy)
	if err != nil {
		return false
	}
	if err := s.harborFetch(ctx, j); err != nil {
		t.Fatalf("harborFetch: %v", err)
	}
	sqlExec(t, s, `update jobs set state = 'done' where id = $1`, j.ID)
	return true
}
