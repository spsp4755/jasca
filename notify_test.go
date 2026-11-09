package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"strings"
	"testing"
	"time"
)

func mkChannel(t *testing.T, s *server, kind, name, cfg string, enabled bool) int64 {
	t.Helper()
	var id int64
	if err := s.db.QueryRow(context.Background(), `insert into notify_channels(kind, name, config, enabled) values($1, $2, $3, $4) returning id`,
		kind, name, cfg, enabled).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func countDeliveries(t *testing.T, s *server, where string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(context.Background(), `select count(*) from deliveries where `+where).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestEmitQueuesForSubscribers(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	p := mkProject(t, s, "web")
	other := mkProject(t, s, "other")
	on := mkChannel(t, s, "mattermost", "on", `{"webhook_url":"http://x.example.internal/h"}`, true)
	wrongEvent := mkChannel(t, s, "mattermost", "ev", `{"webhook_url":"http://x.example.internal/h"}`, true)
	off := mkChannel(t, s, "mattermost", "off", `{"webhook_url":"http://x.example.internal/h"}`, false)
	foreign := mkChannel(t, s, "mattermost", "foreign", `{"webhook_url":"http://x.example.internal/h"}`, true)
	sqlExec(t, s, `insert into notify_subs values($1,$2,'{new_critical}'),($1,$3,'{policy_failed}'),($1,$4,'{new_critical}'),($5,$6,'{new_critical}')`, p, on, wrongEvent, off, other, foreign)
	s.emit(ctx, p, "new_critical", map[string]any{"title": "t"})
	if n := countDeliveries(t, s, fmt.Sprintf("channel_id=%d and state='queued' and event='new_critical'", on)); n != 1 {
		t.Errorf("subscribed channel got %d deliveries, want 1", n)
	}
	if n := countDeliveries(t, s, "true"); n != 1 {
		t.Errorf("%d deliveries in all, want 1", n)
	}
}

func TestNotifyIngestHooks(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	p := mkProject(t, s, "web")
	ch := mkChannel(t, s, "mattermost", "mm", `{"webhook_url":"http://x.example.internal/h"}`, true)
	sqlExec(t, s, `insert into notify_subs values($1,$2,'{new_critical,policy_failed}')`, p, ch)
	var tid, f1, f2 int64
	s.db.QueryRow(ctx, `insert into targets(project_id, kind, name) values($1,'image','img') returning id`, p).Scan(&tid)
	ins := `insert into findings(project_id, target_id, fingerprint, kind, tool, rule_id, title, severity) values($1,$2,$3,'vuln','trivy','CVE-1','x',$4) returning id`
	s.db.QueryRow(ctx, ins, p, tid, []byte("a"), "CRITICAL").Scan(&f1)
	s.db.QueryRow(ctx, ins, p, tid, []byte("b"), "LOW").Scan(&f2)
	for _, h := range afterIngest {
		h(ctx, s, &ingestResult{ProjectID: p, TargetID: tid, New: []int64{f2}, Policy: policyResult{Passed: true}})
	}
	if n := countDeliveries(t, s, "true"); n != 0 {
		t.Fatalf("low finding and passed policy queued %d", n)
	}
	for _, h := range afterIngest {
		h(ctx, s, &ingestResult{ProjectID: p, TargetID: tid, New: []int64{f1, f2}, Policy: policyResult{Reasons: []string{"too many"}}})
	}
	if countDeliveries(t, s, "event='new_critical'") != 1 || countDeliveries(t, s, "event='policy_failed'") != 1 {
		t.Errorf("want one new_critical and one policy_failed")
	}
}

func TestDeliveryRetryAndTimeout(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	old := sendTimeout
	sendTimeout = 200 * time.Millisecond
	defer func() { sendTimeout = old }()
	slow := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body) // lets the server notice the client hanging up
		if slow {
			select { // the real fake sleeps 15s; the request context ends when the client gives up
			case <-time.After(15 * time.Second):
			case <-r.Context().Done():
			}
		}
		io.WriteString(w, "ok")
	}))
	defer srv.Close()
	p := mkProject(t, s, "web")
	ch := mkChannel(t, s, "mattermost", "mm", fmt.Sprintf(`{"webhook_url":%q}`, srv.URL), true)
	sqlExec(t, s, `insert into notify_subs values($1,$2,'{scan_failed}')`, p, ch)
	s.emit(ctx, p, "scan_failed", map[string]any{"target": "img"})
	for i, wantMin := range []int{1, 5, 30} {
		s.deliverDue(ctx)
		var attempts int
		var state, lastErr string
		var secs float64
		s.db.QueryRow(ctx, `select attempts, state, last_error, extract(epoch from next_at - now()) from deliveries`).Scan(&attempts, &state, &lastErr, &secs)
		if attempts != i+1 || state != "queued" || !strings.Contains(lastErr, "시간") {
			t.Fatalf("round %d: attempts=%d state=%s err=%q", i, attempts, state, lastErr)
		}
		if secs < float64(wantMin*60)-30 || secs > float64(wantMin*60)+1 {
			t.Fatalf("round %d: next attempt in %.0fs, want about %dm", i, secs, wantMin)
		}
		sqlExec(t, s, `update deliveries set next_at = now()`)
	}
	s.deliverDue(ctx)
	if countDeliveries(t, s, "state='failed' and attempts=4") != 1 {
		t.Fatal("fourth failure should end as failed")
	}
	// a fresh one succeeds once the server answers
	slow = false
	s.emit(ctx, p, "scan_failed", map[string]any{"target": "img"})
	s.deliverDue(ctx)
	if countDeliveries(t, s, "state='sent'") != 1 {
		t.Error("delivery not sent")
	}
	// not due yet: untouched
	sqlExec(t, s, `insert into deliveries(channel_id, event, payload, next_at) values($1,'scan_failed','{}', now() + interval '1 hour')`, ch)
	s.deliverDue(ctx)
	if countDeliveries(t, s, "state='queued' and attempts=0") != 1 {
		t.Error("future delivery was sent early")
	}
}

// fakeSMTP accepts one message without auth or TLS and returns what the client sent as DATA.
func fakeSMTP(t *testing.T) (port int, got chan string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	got = make(chan string, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		say := func(s string) { fmt.Fprintf(c, "%s\r\n", s) }
		say("220 fake")
		var data strings.Builder
		in := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if in {
				if line == ".\r\n" {
					in = false
					got <- data.String()
					say("250 ok")
					continue
				}
				data.WriteString(line)
				continue
			}
			switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
			case strings.HasPrefix(cmd, "EHLO"):
				say("250 fake")
			case strings.HasPrefix(cmd, "DATA"):
				in = true
				say("354 go")
			case strings.HasPrefix(cmd, "QUIT"):
				say("221 bye")
				return
			default:
				say("250 ok")
			}
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, got
}

func TestEmailEscapes(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	port, got := fakeSMTP(t)
	if err := s.putSetting(ctx, "smtp", smtpSettings{Host: "127.0.0.1", Port: port, From: "JASCA <jasca@example.internal>", TLS: "none"}); err != nil {
		t.Fatal(err)
	}
	p := mkProject(t, s, "web")
	ch := mkChannel(t, s, "email", "mail", `{"to":["sec@example.internal"]}`, true)
	sqlExec(t, s, `insert into notify_subs values($1,$2,'{new_critical}')`, p, ch)
	s.emit(ctx, p, "new_critical", map[string]any{"title": "<script>alert(1)</script>", "top": []any{"<img src=x onerror=1>"}})
	s.deliverDue(ctx)
	if countDeliveries(t, s, "state='sent'") != 1 {
		var e string
		s.db.QueryRow(ctx, `select last_error from deliveries`).Scan(&e)
		t.Fatalf("not sent: %s", e)
	}
	msg, err := mail.ReadMessage(strings.NewReader(<-got))
	if err != nil {
		t.Fatal(err)
	}
	mt, params, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if mt != "multipart/alternative" {
		t.Fatalf("content type %s", mt)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	parts := map[string]string{}
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		b, _ := io.ReadAll(part)
		pt, _, _ := mime.ParseMediaType(part.Header.Get("Content-Type"))
		parts[pt] = string(b)
	}
	html, text := parts["text/html"], parts["text/plain"]
	if html == "" || text == "" {
		t.Fatalf("need both parts, got %v", parts)
	}
	if strings.Contains(html, "<script>") || strings.Contains(html, "<img") || !strings.Contains(html, "&lt;script&gt;") {
		t.Errorf("html not escaped: %s", html)
	}
	if !strings.Contains(text, "<script>alert(1)</script>") {
		t.Errorf("plain text lost the title: %s", text)
	}
}

func TestChannelsNoSecretLeak(t *testing.T) {
	s := testServer(t)
	admin := loginAs(t, s, mkUser(t, s, "adm", "admin"))
	var remote string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remote = "x"
		w.WriteHeader(500)
		io.WriteString(w, "REMOTE-BODY-SECRET")
	}))
	defer srv.Close()
	hook := srv.URL + "/hooks/tok3n-abc"
	rec := do(t, s, "POST", "/api/v1/admin/channels", map[string]any{"kind": "mattermost", "name": "mm", "enabled": true, "config": map[string]any{"webhook_url": hook}}, admin)
	wantCode(t, rec, 201, "create mm")
	mm := decode[map[string]any](t, rec)["id"].(float64)
	wantCode(t, do(t, s, "POST", "/api/v1/admin/channels", map[string]any{"kind": "email", "name": "mail", "enabled": true, "config": map[string]any{"to": []string{"a@example.internal"}}}, admin), 201, "create email")
	wantCode(t, do(t, s, "POST", "/api/v1/admin/channels", map[string]any{"kind": "mattermost", "name": "bad", "enabled": true, "config": map[string]any{}}, admin), 400, "no webhook")
	wantCode(t, do(t, s, "POST", "/api/v1/admin/channels", map[string]any{"kind": "email", "name": "bad", "enabled": true, "config": map[string]any{"to": []string{"nope"}}}, admin), 400, "bad address")
	wantCode(t, do(t, s, "PUT", "/api/v1/admin/smtp", map[string]any{"host": "smtp.example.internal", "port": 587, "username": "u", "password": "SMTP-PW-1", "from": "JASCA <j@example.internal>", "tls": "starttls"}, admin), 204, "put smtp")
	wantCode(t, do(t, s, "PUT", "/api/v1/admin/smtp", map[string]any{"host": "smtp.example.internal", "port": 587, "username": "u", "from": "JASCA <j@example.internal>", "tls": "starttls"}, admin), 204, "put smtp keep pw")
	wantCode(t, do(t, s, "PUT", "/api/v1/admin/smtp", map[string]any{"host": "h", "port": 0, "from": "j@example.internal", "tls": "starttls"}, admin), 400, "bad port")
	var st smtpSettings
	s.getSetting(context.Background(), "smtp", &st)
	if st.Password != "SMTP-PW-1" {
		t.Error("empty password overwrote the stored one")
	}
	list := do(t, s, "GET", "/api/v1/admin/channels", nil, admin)
	smtp := do(t, s, "GET", "/api/v1/admin/smtp", nil, admin)
	for _, b := range []string{list.Body.String(), smtp.Body.String()} {
		if strings.Contains(b, "tok3n") || strings.Contains(b, "SMTP-PW-1") || strings.Contains(b, `"password"`) {
			t.Errorf("secret leaked: %s", b)
		}
	}
	if !strings.Contains(list.Body.String(), `"webhook_url_set":true`) || !strings.Contains(smtp.Body.String(), `"password_set":true`) {
		t.Errorf("missing *_set flags: %s %s", list.Body.String(), smtp.Body.String())
	}
	// PUT without config keeps the stored webhook
	wantCode(t, do(t, s, "PUT", fmt.Sprintf("/api/v1/admin/channels/%d", int64(mm)), map[string]any{"kind": "mattermost", "name": "mm2", "enabled": true}, admin), 204, "put no config")
	var cfg string
	s.db.QueryRow(context.Background(), `select config->>'webhook_url' from notify_channels where id=$1`, int64(mm)).Scan(&cfg)
	if cfg != hook {
		t.Errorf("webhook changed to %q", cfg)
	}
	// the test endpoint reports a short Korean error, never the remote body
	rec = do(t, s, "POST", fmt.Sprintf("/api/v1/admin/channels/%d/test", int64(mm)), nil, admin)
	wantCode(t, rec, 200, "test")
	out := decode[struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}](t, rec)
	if remote == "" || out.OK || out.Error == "" || strings.Contains(rec.Body.String(), "REMOTE-BODY") || strings.Contains(rec.Body.String(), "tok3n") || len(out.Error) > 200 {
		t.Errorf("test endpoint: %s", rec.Body.String())
	}
	if auditCount(t, s, "channel.create") != 2 || auditCount(t, s, "channel.update") != 1 || auditCount(t, s, "smtp.update") != 2 || auditCount(t, s, "channel.test") != 1 {
		t.Error("writes not audited")
	}
	// non-admin gets 403 on admin routes
	user := loginAs(t, s, mkUser(t, s, "bob", ""))
	wantCode(t, do(t, s, "GET", "/api/v1/admin/channels", nil, user), 403, "user admin list")
	wantCode(t, do(t, s, "GET", "/api/v1/admin/smtp", nil, user), 403, "user smtp")
	wantCode(t, do(t, s, "DELETE", fmt.Sprintf("/api/v1/admin/channels/%d", int64(mm)), nil, admin), 204, "delete")
	wantCode(t, do(t, s, "DELETE", fmt.Sprintf("/api/v1/admin/channels/%d", int64(mm)), nil, admin), 404, "delete again")
}

func TestUserChannelsListMinimal(t *testing.T) {
	s := testServer(t)
	mkChannel(t, s, "mattermost", "mm", `{"webhook_url":"http://x.example.internal/tok3n"}`, true)
	mkChannel(t, s, "email", "mail", `{"to":["a@example.internal"]}`, true)
	user := loginAs(t, s, mkUser(t, s, "bob", ""))
	rec := do(t, s, "GET", "/api/v1/channels", nil, user)
	wantCode(t, rec, 200, "list")
	var rows []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil || len(rows) != 2 {
		t.Fatalf("%v %s", err, rec.Body.String())
	}
	for _, r := range rows {
		if len(r) != 3 || r["id"] == nil || r["name"] == nil || r["kind"] == nil {
			t.Errorf("row has more than id, name, kind: %v", r)
		}
	}
	if strings.Contains(rec.Body.String(), "tok3n") {
		t.Error("config leaked")
	}
	wantCode(t, do(t, s, "GET", "/api/v1/channels", nil), 401, "anonymous")
}
