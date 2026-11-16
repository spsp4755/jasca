package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// trivyDBBuilt makes s look like it has a vulnerability DB built at the given time (next update a day later).
func trivyDBBuilt(t *testing.T, s *server, at time.Time) {
	t.Helper()
	dir := filepath.Join(s.trivyCacheDir(), "db")
	os.MkdirAll(dir, 0o755)
	meta := fmt.Sprintf(`{"Version":2,"UpdatedAt":%q,"NextUpdate":%q}`, at.UTC().Format(time.RFC3339), at.Add(24*time.Hour).UTC().Format(time.RFC3339))
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), []byte(meta), 0o644); err != nil {
		t.Fatal(err)
	}
}

func checkOf(t *testing.T, list []sysCheck, key string) sysCheck {
	t.Helper()
	for _, c := range list {
		if c.Key == key {
			return c
		}
	}
	t.Fatalf("no check %q in %+v", key, list)
	return sysCheck{}
}

type systemResp struct {
	Version  string     `json:"version"`
	Checks   []sysCheck `json:"checks"`
	LogLines []string   `json:"log_lines"`
	Totals   struct {
		Projects int `json:"projects"`
	} `json:"totals"`
}

// The status route is for administrators; a fresh install says what is missing, the worst rows first.
func TestSystemStatusRoute(t *testing.T) {
	s := testServer(t)
	admin := loginAs(t, s, mkUser(t, s, "root", "admin"))
	for name, auth := range map[string][]any{"anonymous": nil, "member": {loginAs(t, s, mkUser(t, s, "dev", ""))},
		"security": {loginAs(t, s, mkUser(t, s, "sec", "security"))}} {
		for _, path := range []string{"/api/v1/admin/system", "/api/v1/admin/ops-alerts"} {
			if rec := do(t, s, "GET", path, nil, auth...); rec.Code != 401 && rec.Code != 403 {
				t.Errorf("%s GET %s: %d", name, path, rec.Code)
			}
		}
	}
	rec := do(t, s, "GET", "/api/v1/admin/system", nil, admin)
	if rec.Code != 200 {
		t.Fatalf("status: %d %s", rec.Code, rec.Body.String())
	}
	st := decode[systemResp](t, rec)
	if st.Version != version || st.LogLines == nil || len(st.Checks) < 8 {
		t.Fatalf("status: %+v", st)
	}
	if c := st.Checks[0]; c.Key != "trivy_db" || c.State != "bad" || c.Value != "설치 안 됨" || c.Action == "" || c.Link != "/admin/trivy" {
		t.Errorf("the missing vulnerability DB is not the first row: %+v", st.Checks)
	}
	if c := checkOf(t, st.Checks, "java_db"); c.State != "warn" {
		t.Errorf("java db: %+v", c)
	}
	for _, key := range []string{"app", "database", "scans", "recheck", "notifications"} {
		if c := checkOf(t, st.Checks, key); c.State != "ok" || c.Value == "" || c.Action != "" {
			t.Errorf("%s on a fresh install: %+v", key, c)
		}
	}
	seen := "bad"
	for _, c := range st.Checks { // bad, then warn, then ok
		if c.State == "bad" && seen != "bad" || c.State == "warn" && seen == "ok" {
			t.Errorf("rows are not sorted by state: %+v", st.Checks)
		}
		seen = c.State
	}
	if strings.Contains(rec.Body.String(), "keycloak_sync") {
		t.Error("the Keycloak sync row shows without a configured sync")
	}
}

// Each state of each row, from collected values.
func TestSystemChecks(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 17, 3, 0, 0, 0, time.UTC)
	base := func() *sysInfo {
		in, err := s.systemInfo(ctx)
		if err != nil {
			t.Fatal(err)
		}
		in.Volume = &struct{ TotalMB, FreeMB int64 }{30 << 10, 20 << 10}
		in.VulnDB, in.Trivy.UpdatedAt, in.Trivy.NextUpdate = true, now.Add(-48*time.Hour), now.Add(-24*time.Hour)
		in.Trivy.JavaDB, in.Trivy.JavaUpdatedAt = true, now.Add(-72*time.Hour)
		in.LogCount, in.LogLines = 0, nil
		return in
	}
	fresh := time.Now().Add(-24 * time.Hour) // the 악용 정보 row (intel.go) reads its dates against the real clock
	if err := s.putSetting(ctx, "intel", intelStatus{KEV: intelSource{Date: &fresh, Count: 1, LoadedAt: &fresh}, EPSS: intelSource{Date: &fresh, Count: 1, LoadedAt: &fresh}}); err != nil {
		t.Fatal(err)
	}
	for _, c := range s.systemChecks(ctx, base(), now) {
		if c.State != "ok" || c.alert || c.Action != "" {
			t.Errorf("healthy: %+v", c)
		}
	}
	oldest := 90
	failedAt := now.Add(-time.Hour)
	for _, c := range []struct {
		name, key, state string
		alert            bool
		set              func(in *sysInfo)
	}{
		{"max upload would be refused", "data_volume", "warn", true, func(in *sysInfo) { in.Volume.FreeMB = s.cfg.MaxExtractMB + s.cfg.MaxScanUploadMB - 1 }},
		{"enough for the largest upload", "data_volume", "ok", false, func(in *sysInfo) { in.Volume.FreeMB = s.cfg.MaxExtractMB + s.cfg.MaxScanUploadMB }},
		{"every upload refused", "data_volume", "bad", true, func(in *sysInfo) { in.Volume.FreeMB = s.cfg.MaxExtractMB - 1 }},
		{"no vulnerability DB", "trivy_db", "bad", false, func(in *sysInfo) { in.VulnDB = false }},
		{"6 days past next update", "trivy_db", "ok", false, func(in *sysInfo) { in.Trivy.NextUpdate = now.Add(-6 * 24 * time.Hour) }},
		{"7 days past next update", "trivy_db", "bad", true, func(in *sysInfo) { in.Trivy.NextUpdate = now.Add(-7 * 24 * time.Hour) }},
		{"no Java DB", "java_db", "warn", false, func(in *sysInfo) { in.Trivy.JavaDB = false }},
		{"pool exhausted", "database", "warn", false, func(in *sysInfo) { in.DB.InUse = in.DB.Max }},
		{"scan waits 90 minutes", "scans", "warn", false, func(in *sysInfo) { in.Scans.Queued, in.Scans.OldestQueuedMin = 1, &oldest }},
		{"scan on its second attempt", "scans", "warn", false, func(in *sysInfo) { in.Scans.Running, in.Scans.Attempts = 1, 2 }},
		{"scan failed today", "scans", "warn", false, func(in *sysInfo) { in.Scans.Failed24 = 1 }},
		{"recheck running", "recheck", "ok", false, func(in *sysInfo) { in.Recheck = &recheckRun{State: "running", Total: 10, Done: 3} }},
		{"recheck failed", "recheck", "bad", true, func(in *sysInfo) { in.Recheck = &recheckRun{State: "failed", Error: "3 of 10 targets failed"} }},
		{"delivery gave up this week", "notifications", "warn", false, func(in *sysInfo) {
			in.Notify.Failed7, in.Notify.LastError = 2, "서버에 연결하지 못했습니다."
		}},
		{"delivery gave up today", "notifications", "warn", true, func(in *sysInfo) { in.Notify.Failed7, in.Notify.Failed24 = 2, 1 }},
		{"sync works", "keycloak_sync", "ok", false, func(in *sysInfo) { in.Sync.ClientID, in.Sync.LastRun = "jasca-sync", &failedAt }},
		{"sync fails", "keycloak_sync", "bad", true, func(in *sysInfo) {
			in.Sync.ClientID, in.Sync.LastRun, in.Sync.LastError = "jasca-sync", &failedAt, "token: 401 Unauthorized"
		}},
		{"server logged something", "server_log", "warn", false, func(in *sysInfo) { in.LogCount, in.LogLines = 3, []string{"x"} }},
	} {
		in := base()
		c.set(in)
		got := checkOf(t, s.systemChecks(ctx, in, now), c.key)
		if got.State != c.state || got.alert != c.alert || got.Value == "" || (got.State == "ok") != (got.Action == "") {
			t.Errorf("%s: %+v", c.name, got)
		}
	}
	// what a failed run or delivery said reaches the row, on one line
	in := base()
	in.Recheck = &recheckRun{State: "failed", Error: "line one\nline two"}
	if c := checkOf(t, s.systemChecks(ctx, in, now), "recheck"); !strings.Contains(c.Action, "line one line two") {
		t.Errorf("recheck error: %+v", c)
	}
	// a row another feature registers shows up, sorted with the rest
	sysChecks = append(sysChecks, func(context.Context, *server) sysCheck {
		return sysCheck{Key: "extra", Label: "추가 항목", State: "bad", Value: "값", Action: "조치"}
	})
	defer func() { sysChecks = sysChecks[:len(sysChecks)-1] }()
	if list := s.systemChecks(ctx, base(), now); list[0].Key != "extra" {
		t.Errorf("registered row: %+v", list)
	}
}

// The collection reads what is in the database and on disk.
func TestSystemInfoCollects(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	pid, _ := memberSession(t, s)
	tid := qint64(t, s, `insert into targets(project_id, kind, name) values($1, 'fs', 'A') returning id`, pid)
	s.db.Exec(ctx, `insert into scans(project_id, target_id, source, format, status, created_at) values
		($1, $2, 'server', 'trivy', 'queued', now() - interval '2 hours'), ($1, $2, 'server', 'trivy', 'failed', now())`, pid, tid)
	ch := qint64(t, s, `insert into notify_channels(kind, name, config) values('mattermost', '운영', '{"webhook_url":"http://127.0.0.1:1/hooks/x"}') returning id`)
	s.db.Exec(ctx, `insert into deliveries(channel_id, event, payload, state, last_error) values
		($1, 'scan_failed', '{}', 'failed', '서버에 연결하지 못했습니다.'), ($1, 'ops_alert', '{}', 'failed', 'x'), ($1, 'test', '{}', 'queued', '')`, ch)
	s.db.Exec(ctx, `insert into recheck_runs(reason, state, error) values('manual', 'failed', '1 of 2 targets failed')`)
	s.putSetting(ctx, "sync", syncSettings{ClientID: "jasca-sync", ClientSecret: "s3cret", LastError: "token: 401"})
	trivyDBBuilt(t, s, time.Now().Add(-30*24*time.Hour))
	in, err := s.systemInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if in.Scans.Queued != 1 || in.Scans.Failed24 != 1 || in.Scans.OldestQueuedMin == nil || *in.Scans.OldestQueuedMin < 119 ||
		in.Notify.Queued != 1 || in.Notify.Failed7 != 2 || in.Notify.Failed24 != 1 || in.Notify.LastError != "x" ||
		in.Recheck == nil || in.Recheck.State != "failed" || !in.VulnDB || in.Trivy.JavaDB || in.Volume == nil || in.Volume.TotalMB == 0 ||
		in.Sync.ClientSecret != "" || in.Sync.LastError == "" || in.Totals.Projects != 1 || in.DB.Name == "" {
		t.Fatalf("collected: %+v", in)
	}
	list := s.systemChecks(ctx, in, time.Now())
	for key, state := range map[string]string{"trivy_db": "bad", "recheck": "bad", "keycloak_sync": "bad", "scans": "warn", "notifications": "warn", "java_db": "warn"} {
		if c := checkOf(t, list, key); c.State != state {
			t.Errorf("%s: %+v", key, c)
		}
	}
}

func opsDeliveries(t *testing.T, s *server) int {
	t.Helper()
	return qInt(t, s, `select count(*) from deliveries where event = 'ops_alert'`)
}

// One message per channel when a condition starts, none while it lasts (the stale DB again after a week), a new
// one when it comes back; a failed operator alert raises no alert.
func TestOpsAlertEpisodes(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	admin := loginAs(t, s, mkUser(t, s, "root", "admin"))
	now := time.Now()
	check := func(at time.Time) {
		t.Helper()
		if err := s.opsCheck(ctx, at); err != nil {
			t.Fatal(err)
		}
	}
	trivyDBBuilt(t, s, now.Add(-30*24*time.Hour)) // stale
	check(now)
	if n := opsDeliveries(t, s); n != 0 {
		t.Fatalf("alerts without a chosen channel: %d", n)
	}
	a := qint64(t, s, `insert into notify_channels(kind, name, config) values('mattermost', '운영', '{"webhook_url":"http://127.0.0.1:1/hooks/x"}') returning id`)
	b := qint64(t, s, `insert into notify_channels(kind, name, config, enabled) values('email', '꺼진 채널', '{"to":["ops@example.internal"]}', false) returning id`)
	if rec := do(t, s, "PUT", "/api/v1/admin/ops-alerts", map[string]any{"channel_ids": []int64{a, 9999}}, admin); rec.Code != 400 {
		t.Errorf("unknown channel: %d", rec.Code)
	}
	if rec := do(t, s, "PUT", "/api/v1/admin/ops-alerts", map[string]any{"channel_ids": []int64{b, a, a}}, admin); rec.Code != 204 {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	if got := decode[struct {
		IDs []int64 `json:"channel_ids"`
	}](t, do(t, s, "GET", "/api/v1/admin/ops-alerts", nil, admin)); len(got.IDs) != 2 {
		t.Errorf("get: %+v", got)
	}
	if n := qInt(t, s, `select count(*) from audit_log where action = 'ops_alerts.update'`); n != 1 {
		t.Errorf("audit rows: %d", n)
	}

	check(now) // what was already wrong is reported once a channel is chosen; the switched-off channel gets nothing
	if n := opsDeliveries(t, s); n != 1 {
		t.Fatalf("first alert: %d deliveries", n)
	}
	m := s.renderMsg(ctx, "ops_alert", []byte(qStr(t, s, `select payload::text from deliveries where event = 'ops_alert'`)))
	if !strings.HasPrefix(m.Title, "[JASCA 운영] 취약점 DB") || len(m.Lines) != 2 || !strings.Contains(m.Lines[1], "db.tar.gz") || m.subject() != m.Title {
		t.Errorf("message: %+v", m)
	}
	check(now.Add(time.Hour))
	check(now.Add(6 * 24 * time.Hour))
	if n := opsDeliveries(t, s); n != 1 {
		t.Fatalf("repeated within a week: %d", n)
	}
	check(now.Add(7*24*time.Hour + time.Minute)) // the weekly reminder
	if n := opsDeliveries(t, s); n != 2 {
		t.Fatalf("weekly reminder: %d", n)
	}
	// saving the channels again does not repeat it
	do(t, s, "PUT", "/api/v1/admin/ops-alerts", map[string]any{"channel_ids": []int64{a}}, admin)
	check(now.Add(8 * 24 * time.Hour))
	if n := opsDeliveries(t, s); n != 2 {
		t.Fatalf("after saving the setting: %d", n)
	}

	// a fresh DB ends the episode; a stale one later is a new alert
	at := now.Add(9 * 24 * time.Hour)
	trivyDBBuilt(t, s, at)
	check(at)
	trivyDBBuilt(t, s, at.Add(-30*24*time.Hour))
	check(at.Add(time.Hour))
	if n := opsDeliveries(t, s); n != 3 {
		t.Fatalf("new episode: %d", n)
	}

	// a delivery that gave up is reported once; an operator alert that gave up is not
	trivyDBBuilt(t, s, at.Add(2*time.Hour))
	s.db.Exec(ctx, `update deliveries set state = 'failed', last_error = '서버에 연결하지 못했습니다.' where event = 'ops_alert'`)
	check(at.Add(2 * time.Hour))
	if n := opsDeliveries(t, s); n != 3 {
		t.Fatalf("a failed operator alert raised another: %d", n)
	}
	s.db.Exec(ctx, `insert into deliveries(channel_id, event, payload, state, last_error) values($1, 'scan_failed', '{}', 'failed', '서버에 연결하지 못했습니다.')`, a)
	check(at.Add(2 * time.Hour))
	check(at.Add(3 * time.Hour))
	if n := opsDeliveries(t, s); n != 4 {
		t.Fatalf("delivery gave up: %d", n)
	}
	if n := qInt(t, s, `select count(*) from deliveries where event = 'ops_alert' and payload->'data'->>'label' = '알림 전송'`); n != 1 {
		t.Errorf("the alert is not about deliveries")
	}

	// every chosen channel switched off: nothing is marked sent, so the alert goes out once a channel is on again
	s.db.Exec(ctx, `update notify_channels set enabled = false`)
	trivyDBBuilt(t, s, at.Add(-30*24*time.Hour))
	check(at.Add(4 * time.Hour))
	s.db.Exec(ctx, `update notify_channels set enabled = true where id = $1`, a)
	check(at.Add(5 * time.Hour))
	if n := qInt(t, s, `select count(*) from deliveries where event = 'ops_alert' and state = 'queued' and payload->'data'->>'label' = '취약점 DB'`); n != 1 {
		t.Fatalf("after the channel was switched on again: %d", n)
	}
}

// /me tells every signed-in user how old the vulnerability DB is.
func TestMeCarriesVulnDB(t *testing.T) {
	s := testServer(t)
	ck := loginAs(t, s, mkUser(t, s, "dev", ""))
	type me struct {
		VulnDB *vulnDBInfo `json:"vuln_db"`
	}
	if got := decode[me](t, do(t, s, "GET", "/api/v1/me", nil, ck)); got.VulnDB != nil {
		t.Errorf("without a DB: %+v", got.VulnDB)
	}
	trivyDBBuilt(t, s, time.Now().Add(-3*24*time.Hour))
	if got := decode[me](t, do(t, s, "GET", "/api/v1/me", nil, ck)); got.VulnDB == nil || got.VulnDB.Stale || got.VulnDB.UpdatedAt.IsZero() {
		t.Errorf("3 days old: %+v", got.VulnDB)
	}
	trivyDBBuilt(t, s, time.Now().Add(-9*24*time.Hour))
	if got := decode[me](t, do(t, s, "GET", "/api/v1/me", nil, ck)); got.VulnDB == nil || !got.VulnDB.Stale {
		t.Errorf("9 days old: %+v", got.VulnDB)
	}
}

// A result checked on this server records which vulnerability DB it was checked against; a report scanned
// elsewhere records none and leaves the target unchecked here.
func TestScanRecordsVulnDB(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	pid, ck := memberSession(t, s)
	built := time.Date(2026, 11, 13, 6, 0, 0, 0, time.UTC)
	trivyDBBuilt(t, s, built)
	doc := trivyDoc("A", []tv{{ID: "CVE-2024-1000"}}, nil)
	res, err := s.ingest(ctx, ingestInput{ProjectID: pid, TargetKind: "fs", TargetName: "A", Source: "server", Report: parseReport(t, "trivy", doc), Raw: doc})
	if err != nil {
		t.Fatal(err)
	}
	dbOf := func(q string, args ...any) string { return qStr(t, s, q, args...) }
	if got := dbOf(`select coalesce(summary->>'db_updated_at', '') from scans where id = $1`, res.ScanID); got != "2026-11-13T06:00:00Z" {
		t.Errorf("server scan summary: %q", got)
	}
	if got := dbOf(`select coalesce(db_checked_at::text, '') from targets where id = $1`, res.TargetID); !strings.HasPrefix(got, "2026-11-13 06:00:00") {
		t.Errorf("target after a server scan: %q", got)
	}
	type target struct {
		Name        string     `json:"name"`
		DBCheckedAt *time.Time `json:"db_checked_at"`
	}
	if list := decode[[]target](t, do(t, s, "GET", "/api/v1/projects/web/targets", nil, ck)); len(list) != 1 || list[0].DBCheckedAt == nil || !list[0].DBCheckedAt.Equal(built) {
		t.Errorf("target list: %+v", list)
	}
	// the same report again within ten minutes is a duplicate: its summary still reads as counts
	if dup, err := s.ingest(ctx, ingestInput{ProjectID: pid, TargetKind: "fs", TargetName: "A", Source: "server", Report: parseReport(t, "trivy", doc), Raw: doc}); err != nil || !dup.Duplicate || dup.Summary["open"] != 1 {
		t.Errorf("duplicate: %+v %v", dup, err)
	}
	// a CI upload of the same target: no date on the scan, and the target is unchecked here until a re-evaluation
	up := mustUpload(t, s, "web", "target=A&kind=fs", trivyDoc("A", []tv{{ID: "CVE-2024-1000"}, {ID: "CVE-2024-2000"}}, nil), ck)
	if got := dbOf(`select coalesce(summary->>'db_updated_at', '') from scans where id = $1`, up.ScanID); got != "" {
		t.Errorf("CI upload summary: %q", got)
	}
	if got := dbOf(`select coalesce(db_checked_at::text, '') from targets where id = $1`, up.TargetID); got != "" || up.TargetID != res.TargetID {
		t.Errorf("target after a CI upload: %q (target %d, want %d)", got, up.TargetID, res.TargetID)
	}
}

func qStr(t *testing.T, s *server, q string, args ...any) string {
	t.Helper()
	var v string
	if err := s.db.QueryRow(context.Background(), q, args...).Scan(&v); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return v
}
