package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Notifications (spec 3.12): channels (Mattermost webhook, email through one global SMTP server), per-project
// subscriptions (projects.go), and a durable delivery queue with retries.

var (
	sendTimeout  = 10 * time.Second                                                // one send, dial included
	retryBackoff = []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute} // after failure 1, 2, 3; the 4th is final
)

func init() {
	notifyEmit = (*server).queueEvent
	afterIngest = append(afterIngest, notifyAfterIngest)
	routeRegistrars = append(routeRegistrars, (*server).notifyRoutes)
}

var eventLabels = map[string]string{
	"new_critical": "새 Critical/High 취약점", "policy_failed": "정책 실패", "scan_failed": "스캔 실패",
	"exception_requested": "예외 요청", "exception_approved": "예외 승인", "exception_rejected": "예외 반려",
	"exception_expiring": "예외 만료 임박", "exception_expired": "예외 만료", "new_known": "새로 알려진 취약점", "test": "시험 메시지",
}

// --- queueing ---

// queueEvent writes one delivery per enabled channel the project subscribed to for event. It never fails the caller.
func (s *server) queueEvent(ctx context.Context, projectID int64, event string, payload map[string]any) {
	ctx = context.WithoutCancel(ctx) // the request that raised the event may already be gone
	var key, name string
	if err := s.db.QueryRow(ctx, `select key, name from projects where id=$1`, projectID).Scan(&key, &name); err != nil {
		log.Printf("notify %s: project %d: %v", event, projectID, err)
		return
	}
	b, _ := json.Marshal(map[string]any{"project_key": key, "project_name": name, "data": payload})
	if _, err := s.db.Exec(ctx, `insert into deliveries(channel_id, event, payload)
		select c.id, $2, $3 from notify_subs ns join notify_channels c on c.id = ns.channel_id
		where ns.project_id=$1 and c.enabled and $2 = any(ns.events)`, projectID, event, json.RawMessage(b)); err != nil {
		log.Printf("notify %s: queue: %v", event, err)
	}
}

// notifyAfterIngest emits new_critical (new CRITICAL/HIGH findings) and policy_failed for a stored scan.
func notifyAfterIngest(ctx context.Context, s *server, r *ingestResult) {
	var tname string
	s.db.QueryRow(ctx, `select name from targets where id=$1`, r.TargetID).Scan(&tname)
	if len(r.New) > 0 {
		rows, err := s.db.Query(ctx, `select severity, rule_id, title from findings
			where id = any($1) and severity in ('CRITICAL','HIGH') order by severity, id`, r.New)
		if err != nil {
			log.Printf("notify new_critical: %v", err)
		} else {
			var top []string
			var crit, high int
			for rows.Next() {
				var sev, rule, title string
				if rows.Scan(&sev, &rule, &title) != nil {
					break
				}
				if sev == "CRITICAL" {
					crit++
				} else {
					high++
				}
				if len(top) < 5 {
					top = append(top, sev+" "+rule+" "+title)
				}
			}
			rows.Close()
			if crit+high > 0 {
				s.emit(ctx, r.ProjectID, "new_critical", map[string]any{"scan_id": r.ScanID, "target": tname, "critical": crit, "high": high, "top": top})
			}
		}
	}
	if !r.Policy.Passed {
		s.emit(ctx, r.ProjectID, "policy_failed", map[string]any{"scan_id": r.ScanID, "target": tname, "reasons": r.Policy.Reasons})
	}
}

// --- rendering ---

type notifyMsg struct{ Subject, Text, HTML string }

// scalar renders a payload value as text; lists become comma-joined lines.
func scalar(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = scalar(e)
		}
		return strings.Join(parts, "\n")
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// renderMsg builds the message for a stored delivery. Every value is escaped for HTML with html.EscapeString.
func (s *server) renderMsg(ctx context.Context, event string, raw []byte) notifyMsg {
	var p struct {
		Key  string         `json:"project_key"`
		Name string         `json:"project_name"`
		Data map[string]any `json:"data"`
	}
	json.Unmarshal(raw, &p)
	label := eventLabels[event]
	if label == "" {
		label = event
	}
	base := ""
	if sso, err := s.ssoConf(ctx); err == nil {
		base = strings.TrimRight(sso.PublicURL, "/")
	}
	link := ""
	if base != "" && p.Key != "" {
		link = base + "/projects/" + url.PathEscape(p.Key)
		if id, ok := p.Data["scan_id"].(float64); ok {
			link = base + "/scans/" + strconv.FormatInt(int64(id), 10)
		}
	}
	keys := make([]string, 0, len(p.Data))
	for k := range p.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	head := "[" + p.Name + "] " + label
	var text, h strings.Builder
	text.WriteString(head + "\n")
	h.WriteString("<h3>" + html.EscapeString(head) + "</h3><table>")
	for _, k := range keys {
		v := scalar(p.Data[k])
		text.WriteString("\n" + k + ": " + v)
		h.WriteString("<tr><th align=\"left\">" + html.EscapeString(k) + "</th><td>" +
			strings.ReplaceAll(html.EscapeString(v), "\n", "<br>") + "</td></tr>")
	}
	h.WriteString("</table>")
	if link != "" {
		text.WriteString("\n\n" + link)
		h.WriteString("<p><a href=\"" + html.EscapeString(link) + "\">" + html.EscapeString(link) + "</a></p>")
	}
	return notifyMsg{Subject: "[JASCA] " + head, Text: text.String(), HTML: h.String()}
}

// mattermostText is the Markdown body; @ is broken so a payload value cannot ping @channel.
func (m notifyMsg) mattermostText() string {
	var b strings.Builder
	lines := strings.Split(m.Text, "\n")
	b.WriteString("**" + strings.ReplaceAll(lines[0], "*", "\\*") + "**\n")
	for _, l := range lines[1:] {
		b.WriteString(strings.NewReplacer("@", "@​", "`", "'").Replace(l) + "\n")
	}
	return b.String()
}

// --- sending ---

type smtpSettings struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	From     string `json:"from"`
	TLS      string `json:"tls"` // starttls tls none
}

func (s *server) smtpConf(ctx context.Context) (smtpSettings, error) {
	st := smtpSettings{Port: 587, TLS: "starttls"}
	_, err := s.getSetting(ctx, "smtp", &st)
	return st, err
}

// sendErr maps a failure to a short Korean text. The remote body and the URL (it holds the webhook token) never go in.
func sendErr(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("응답 시간이 초과되었습니다.")
	}
	if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
		return errors.New("응답 시간이 초과되었습니다.")
	}
	return err
}

var errSendConn = errors.New("서버에 연결하지 못했습니다.")

// sendChannel delivers m through a channel of kind with its stored config. The error text is safe to show.
func (s *server) sendChannel(ctx context.Context, kind string, cfg []byte, m notifyMsg) error {
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	switch kind {
	case "mattermost":
		var c struct {
			WebhookURL string `json:"webhook_url"`
		}
		if json.Unmarshal(cfg, &c) != nil || c.WebhookURL == "" {
			return errors.New("Webhook URL이 설정되지 않았습니다.")
		}
		body, _ := json.Marshal(map[string]string{"text": m.mattermostText()})
		req, err := http.NewRequestWithContext(ctx, "POST", c.WebhookURL, bytes.NewReader(body))
		if err != nil {
			return errors.New("Webhook URL 형식이 올바르지 않습니다.")
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := (&http.Client{Timeout: sendTimeout, CheckRedirect: noRedirect}).Do(req)
		if err != nil {
			if e := sendErr(err); e != err {
				return e
			}
			return errSendConn
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		if resp.StatusCode/100 != 2 {
			return fmt.Errorf("Mattermost가 오류를 돌려주었습니다(HTTP %d).", resp.StatusCode)
		}
		return nil
	case "email":
		var c struct {
			To []string `json:"to"`
		}
		if json.Unmarshal(cfg, &c) != nil || len(c.To) == 0 {
			return errors.New("받는 사람이 설정되지 않았습니다.")
		}
		st, err := s.smtpConf(ctx)
		if err != nil || st.Host == "" {
			return errors.New("메일 서버(SMTP)가 설정되지 않았습니다.")
		}
		return sendMail(ctx, st, c.To, m)
	}
	return errors.New("알 수 없는 채널 종류입니다.")
}

// plainAuth is PLAIN without net/smtp's refusal to run on a connection without TLS (internal relays).
type plainAuth struct{ user, pass string }

func (a plainAuth) Start(*smtp.ServerInfo) (string, []byte, error) {
	return "PLAIN", []byte("\x00" + a.user + "\x00" + a.pass), nil
}
func (a plainAuth) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		return nil, errors.New("unexpected server challenge")
	}
	return nil, nil
}

func sendMail(ctx context.Context, st smtpSettings, to []string, m notifyMsg) error {
	from, err := mail.ParseAddress(st.From)
	if err != nil {
		return errors.New("보내는 사람 주소가 올바르지 않습니다.")
	}
	addr := net.JoinHostPort(st.Host, strconv.Itoa(st.Port))
	tlsConf := &tls.Config{ServerName: st.Host, MinVersion: tls.VersionTLS12}
	var conn net.Conn
	d := &net.Dialer{Timeout: sendTimeout}
	if st.TLS == "tls" {
		conn, err = (&tls.Dialer{NetDialer: d, Config: tlsConf}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		if e := sendErr(err); e != err {
			return e
		}
		return errSendConn
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(sendTimeout)) // the whole conversation, not just the dial
	fail := func(err error) error {
		if e := sendErr(err); e != err {
			return e
		}
		return errors.New("메일 서버가 요청을 거부했거나 응답이 올바르지 않습니다.")
	}
	c, err := smtp.NewClient(conn, st.Host)
	if err != nil {
		return fail(err)
	}
	defer c.Close()
	if st.TLS == "starttls" {
		if err := c.StartTLS(tlsConf); err != nil {
			return fail(err)
		}
	}
	if st.Username != "" {
		if err := c.Auth(plainAuth{st.Username, st.Password}); err != nil {
			return fail(err)
		}
	}
	if err := c.Mail(from.Address); err != nil {
		return fail(err)
	}
	for _, t := range to {
		if err := c.Rcpt(t); err != nil {
			return fail(err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fail(err)
	}
	if _, err := w.Write(buildMail(from, to, m)); err != nil {
		return fail(err)
	}
	if err := w.Close(); err != nil {
		return fail(err)
	}
	c.Quit()
	return nil
}

// buildMail makes multipart/alternative (plain text, then HTML). Header values are validated addresses or encoded.
func buildMail(from *mail.Address, to []string, m notifyMsg) []byte {
	var buf bytes.Buffer
	var idb [8]byte
	rand.Read(idb[:])
	mw := multipart.NewWriter(&buf)
	hdr := "From: " + from.String() + "\r\nTo: " + strings.Join(to, ", ") + "\r\nSubject: " + mime.QEncoding.Encode("utf-8", strings.NewReplacer("\r", " ", "\n", " ").Replace(m.Subject)) +
		"\r\nDate: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\nMessage-ID: <" + hex.EncodeToString(idb[:]) + "@jasca>\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/alternative; boundary=" + mw.Boundary() + "\r\n\r\n"
	for _, p := range []struct{ typ, body string }{{"text/plain", m.Text}, {"text/html", m.HTML}} {
		pw, _ := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {p.typ + "; charset=utf-8"}, "Content-Transfer-Encoding": {"quoted-printable"}})
		qw := quotedprintable.NewWriter(pw)
		qw.Write([]byte(p.body))
		qw.Close()
	}
	mw.Close()
	return append([]byte(hdr), buf.Bytes()...)
}

// --- worker ---

// notifyLoop sends due deliveries every 10 seconds until ctx ends. Start it with the server's base context.
func (s *server) notifyLoop(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		s.deliverDue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// deliverDue sends the queued deliveries whose time has come. A failure is retried after 1m, 5m and 30m, then
// the delivery is failed for good. Old finished deliveries are deleted after 30 days.
func (s *server) deliverDue(ctx context.Context) {
	type due struct {
		ID       int64
		Event    string
		Payload  []byte
		Attempts int
		Kind     string
		Cfg      []byte
		Enabled  bool
	}
	rows, err := s.db.Query(ctx, `select d.id, d.event, d.payload, d.attempts, c.kind, c.config, c.enabled
		from deliveries d join notify_channels c on c.id = d.channel_id
		where d.state='queued' and d.next_at <= now() order by d.id limit 50`)
	if err != nil {
		log.Printf("notify: due: %v", err)
		return
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[due])
	if err != nil {
		log.Printf("notify: due: %v", err)
		return
	}
	for _, d := range list {
		if ctx.Err() != nil {
			return
		}
		var serr error
		if !d.Enabled {
			serr = errors.New("채널이 중지되어 있습니다.")
		} else {
			serr = s.sendChannel(ctx, d.Kind, d.Cfg, s.renderMsg(ctx, d.Event, d.Payload))
		}
		var q string
		switch {
		case serr == nil:
			q = `update deliveries set state='sent', attempts=attempts+1, last_error='' where id=$1`
		case d.Attempts >= len(retryBackoff) || !d.Enabled:
			q = `update deliveries set state='failed', attempts=attempts+1, last_error=$2 where id=$1`
		default:
			q = fmt.Sprintf(`update deliveries set attempts=attempts+1, last_error=$2, next_at=now() + interval '%d seconds' where id=$1`,
				int(retryBackoff[d.Attempts].Seconds()))
		}
		args := []any{d.ID}
		if serr != nil {
			args = append(args, serr.Error())
		}
		if _, err := s.db.Exec(ctx, q, args...); err != nil {
			log.Printf("notify: delivery %d: %v", d.ID, err)
		}
	}
	s.db.Exec(ctx, `delete from deliveries where state <> 'queued' and created_at < now() - interval '30 days'`)
}

// --- routes ---

func (s *server) notifyRoutes() {
	s.handle("GET /api/v1/admin/channels", permAdmin, s.handleChannelList)
	s.handle("POST /api/v1/admin/channels", permAdmin, s.handleChannelCreate)
	s.handle("PUT /api/v1/admin/channels/{id}", permAdmin, s.handleChannelPut)
	s.handle("DELETE /api/v1/admin/channels/{id}", permAdmin, s.handleChannelDelete)
	s.handle("POST /api/v1/admin/channels/{id}/test", permAdmin, s.handleChannelTest)
	s.handle("GET /api/v1/admin/smtp", permAdmin, s.handleSMTPGet)
	s.handle("PUT /api/v1/admin/smtp", permAdmin, s.handleSMTPPut)
	s.handle("GET /api/v1/channels", permUser, s.handleChannelsMinimal)
}

// channelIn is the body of POST and PUT. Config is optional on PUT (keeps the stored one).
type channelIn struct {
	Kind    string          `json:"kind"`
	Name    string          `json:"name"`
	Enabled bool            `json:"enabled"`
	Config  json.RawMessage `json:"config"`
}

// normConfig validates a config for kind and returns its stored form. old is the stored config ("" on create):
// a Mattermost config without webhook_url keeps the old one.
func normConfig(kind string, raw json.RawMessage, old []byte) ([]byte, string) {
	switch kind {
	case "mattermost":
		var c struct {
			WebhookURL string `json:"webhook_url"`
		}
		if len(raw) > 0 && json.Unmarshal(raw, &c) != nil {
			return nil, "설정 형식이 올바르지 않습니다."
		}
		if c.WebhookURL == "" && old != nil {
			return old, ""
		}
		if u, err := url.Parse(c.WebhookURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, "Webhook URL은 http 또는 https 주소여야 합니다."
		}
		b, _ := json.Marshal(map[string]string{"webhook_url": c.WebhookURL})
		return b, ""
	case "email":
		var c struct {
			To []string `json:"to"`
		}
		if json.Unmarshal(raw, &c) != nil || len(c.To) == 0 || len(c.To) > 50 {
			return nil, "받는 사람을 1~50명 지정하세요."
		}
		for i, t := range c.To {
			a, err := mail.ParseAddress(strings.TrimSpace(t))
			if err != nil || a.Name != "" || strings.ContainsAny(t, "<>\r\n") {
				return nil, "메일 주소가 올바르지 않습니다: " + html.EscapeString(t)
			}
			c.To[i] = a.Address
		}
		b, _ := json.Marshal(map[string]any{"to": slices.Compact(c.To)})
		return b, ""
	}
	return nil, "채널 종류는 mattermost 또는 email입니다."
}

func readChannelBody(w http.ResponseWriter, r *http.Request) (in channelIn, ok bool) {
	if err := readJSON(r, 64<<10, &in); err != nil {
		writeBodyErr(w, err)
		return in, false
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 100 {
		badRequest(w, "이름은 1~100자로 입력하세요.")
		return in, false
	}
	return in, true
}

func (s *server) handleChannelList(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	rows, err := s.db.Query(r.Context(), `select id, kind, name, config, enabled, created_at from notify_channels order by id`)
	if err != nil {
		writeInternal(w, "channel list", err)
		return
	}
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var kind, name string
		var cfg []byte
		var enabled bool
		var at time.Time
		if err := rows.Scan(&id, &kind, &name, &cfg, &enabled, &at); err != nil {
			rows.Close()
			writeInternal(w, "channel list", err)
			return
		}
		pub := map[string]any{}
		var m map[string]any
		json.Unmarshal(cfg, &m)
		if kind == "mattermost" {
			u, _ := m["webhook_url"].(string)
			pub["webhook_url_set"] = u != ""
		} else if to, ok := m["to"]; ok {
			pub["to"] = to
		}
		out = append(out, map[string]any{"id": id, "kind": kind, "name": name, "config": pub, "enabled": enabled, "created_at": at.UTC()})
	}
	rows.Close()
	writeJSON(w, 200, out)
}

func (s *server) handleChannelCreate(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	in, ok := readChannelBody(w, r)
	if !ok {
		return
	}
	cfg, msg := normConfig(in.Kind, in.Config, nil)
	if msg != "" {
		badRequest(w, msg)
		return
	}
	var id int64
	err := s.db.QueryRow(r.Context(), `insert into notify_channels(kind, name, config, enabled) values($1,$2,$3,$4) returning id`,
		in.Kind, in.Name, json.RawMessage(cfg), in.Enabled).Scan(&id)
	if err != nil {
		writeInternal(w, "channel create", err)
		return
	}
	s.audit(r.Context(), c, "channel.create", nil, itoa(id), map[string]any{"kind": in.Kind, "name": in.Name})
	writeJSON(w, 201, map[string]any{"id": id})
}

func (s *server) handleChannelPut(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	in, ok := readChannelBody(w, r)
	if !ok {
		return
	}
	id := pathID(r)
	var kind string
	var old []byte
	err := s.db.QueryRow(r.Context(), `select kind, config from notify_channels where id=$1`, id).Scan(&kind, &old)
	if errors.Is(err, pgx.ErrNoRows) {
		writeErr(w, 404, "not_found", "채널을 찾을 수 없습니다.")
		return
	}
	if err != nil {
		writeInternal(w, "channel put", err)
		return
	}
	if in.Kind != kind {
		badRequest(w, "채널 종류는 바꿀 수 없습니다.")
		return
	}
	cfg := old
	if len(in.Config) > 0 && string(in.Config) != "null" {
		var msg string
		if cfg, msg = normConfig(kind, in.Config, old); msg != "" {
			badRequest(w, msg)
			return
		}
	}
	if _, err := s.db.Exec(r.Context(), `update notify_channels set name=$2, config=$3, enabled=$4 where id=$1`,
		id, in.Name, json.RawMessage(cfg), in.Enabled); err != nil {
		writeInternal(w, "channel put", err)
		return
	}
	s.audit(r.Context(), c, "channel.update", nil, itoa(id), map[string]any{"name": in.Name, "enabled": in.Enabled})
	w.WriteHeader(204)
}

func (s *server) handleChannelDelete(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	id := pathID(r)
	tag, err := s.db.Exec(r.Context(), `delete from notify_channels where id=$1`, id)
	if err != nil {
		writeInternal(w, "channel delete", err)
		return
	}
	if tag.RowsAffected() == 0 {
		writeErr(w, 404, "not_found", "채널을 찾을 수 없습니다.")
		return
	}
	s.audit(r.Context(), c, "channel.delete", nil, itoa(id), nil)
	w.WriteHeader(204)
}

func (s *server) handleChannelTest(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	id := pathID(r)
	var kind, name string
	var cfg []byte
	err := s.db.QueryRow(r.Context(), `select kind, name, config from notify_channels where id=$1`, id).Scan(&kind, &name, &cfg)
	if errors.Is(err, pgx.ErrNoRows) {
		writeErr(w, 404, "not_found", "채널을 찾을 수 없습니다.")
		return
	}
	if err != nil {
		writeInternal(w, "channel test", err)
		return
	}
	raw, _ := json.Marshal(map[string]any{"project_name": "JASCA", "data": map[string]any{"channel": name, "message": "JASCA 알림 채널 시험 메시지입니다."}})
	serr := s.sendChannel(r.Context(), kind, cfg, s.renderMsg(r.Context(), "test", raw))
	s.audit(r.Context(), c, "channel.test", nil, itoa(id), map[string]any{"ok": serr == nil})
	if serr != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": serr.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *server) handleChannelsMinimal(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	rows, _ := s.db.Query(r.Context(), `select id, name, kind from notify_channels order by id`)
	type ch struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
		Kind string `json:"kind"`
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[ch])
	if err != nil {
		writeInternal(w, "channels", err)
		return
	}
	if list == nil {
		list = []ch{}
	}
	writeJSON(w, 200, list)
}

func (s *server) handleSMTPGet(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	st, err := s.smtpConf(r.Context())
	if err != nil {
		writeInternal(w, "smtp get", err)
		return
	}
	writeJSON(w, 200, map[string]any{"host": st.Host, "port": st.Port, "username": st.Username, "password_set": st.Password != "",
		"from": st.From, "tls": st.TLS})
}

func (s *server) handleSMTPPut(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	var in smtpSettings
	if err := readJSON(r, 16<<10, &in); err != nil {
		writeBodyErr(w, err)
		return
	}
	in.Host, in.Username, in.From = strings.TrimSpace(in.Host), strings.TrimSpace(in.Username), strings.TrimSpace(in.From)
	if in.Port < 1 || in.Port > 65535 || !slices.Contains([]string{"starttls", "tls", "none"}, in.TLS) {
		badRequest(w, "포트 또는 암호화 방식이 올바르지 않습니다.")
		return
	}
	if in.Host != "" {
		if strings.ContainsAny(in.Host, " /\\@\r\n") {
			badRequest(w, "호스트 이름이 올바르지 않습니다.")
			return
		}
		if a, err := mail.ParseAddress(in.From); err != nil || strings.ContainsAny(in.From, "\r\n") || a.Address == "" {
			badRequest(w, "보내는 사람 주소가 올바르지 않습니다.")
			return
		}
	}
	old, err := s.smtpConf(r.Context())
	if err != nil {
		writeInternal(w, "smtp put", err)
		return
	}
	if in.Password == "" {
		in.Password = old.Password
	}
	if err := s.putSetting(r.Context(), "smtp", in); err != nil {
		writeInternal(w, "smtp put", err)
		return
	}
	s.audit(r.Context(), c, "smtp.update", nil, "", map[string]any{"host": in.Host, "port": in.Port, "tls": in.TLS, "password_changed": in.Password != old.Password})
	w.WriteHeader(204)
}
