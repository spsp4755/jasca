package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/spsp4755/jasca/internal/trivy"
)

// System status: 관리 → 시스템 상태 (GET /api/v1/admin/system), the MCP tool system_status and the operator alerts
// (운영 알림) all read one collection, systemInfo, and one set of rows, systemChecks, so they cannot disagree.

func init() {
	routeRegistrars = append(routeRegistrars, (*server).systemRoutes)
	workerStarters = append(workerStarters, func(ctx context.Context, s *server) { s.runOpsAlerts(ctx) })
}

// sysCheck is one row of the status screen.
type sysCheck struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	State  string `json:"state"`            // ok, warn, bad (정상, 주의, 문제)
	Value  string `json:"value"`            // one line: what is the case now
	Action string `json:"action,omitempty"` // what to do, when State is not ok
	Link   string `json:"link,omitempty"`   // the screen where that is done
	alert  bool   // the operators are told once while this holds (opsCheck)
}

// sysChecks are the rows other features add from an init(): append a func returning one sysCheck.
var sysChecks []func(ctx context.Context, s *server) sysCheck

// vulnDBStale is the rule of 관리 → Trivy DB: seven days past the DB's own next-update time. trivy-db sets that
// about a day after the build, so a copy carried into a closed network is always a little past it.
func vulnDBStale(next, now time.Time) bool { return now.Sub(next) >= 7*24*time.Hour }

// vulnDBInfo is what every signed-in user learns about the vulnerability DB (GET /me).
type vulnDBInfo struct {
	UpdatedAt time.Time `json:"updated_at"`
	Stale     bool      `json:"stale"`
}

// vulnDBDate is when the installed vulnerability DB was built, nil without one: the DB a result is checked against.
func (s *server) vulnDBDate() *time.Time {
	st, err := trivy.Status(s.trivyCacheDir())
	if err != nil {
		return nil
	}
	at := st.UpdatedAt.UTC()
	return &at
}

// sysInfo is the state of the service as numbers and dates, collected in one go.
type sysInfo struct {
	DB struct {
		Version, Name, Schema string
		SizeMB, LatencyMS     int64
		InUse, Max            int32
	}
	Volume       *struct{ TotalMB, FreeMB int64 } // nil when the data directory cannot be measured
	TrivyVersion string
	Trivy        trivy.DBStatus
	VulnDB       bool // a vulnerability DB is installed
	Scans        struct {
		Queued, Running, Failed24, Done24, Jobs, Attempts int
		OldestQueuedMin                                   *int
	}
	Recheck    *recheckRun // the latest run
	SSOEnabled bool
	Sync       syncSettings
	Notify     struct {
		Queued, Failed7, Failed24 int // Failed24 leaves out operator alerts: a failed alert never raises another
		LastError                 string
	}
	Totals struct {
		PendingEx, Users, Projects, Targets, Keys, Overdue int
		Open                                               sevCounts
	}
	LogCount int      // entries of the last 24 hours that are not the start-up lines
	LogLines []string // the newest five of them
}

func (s *server) systemInfo(ctx context.Context) (*sysInfo, error) {
	in := &sysInfo{}
	t0 := time.Now()
	if err := s.db.QueryRow(ctx, `select current_setting('server_version'), current_database(), coalesce(current_schema(), ''),
		pg_database_size(current_database()) >> 20`).Scan(&in.DB.Version, &in.DB.Name, &in.DB.Schema, &in.DB.SizeMB); err != nil {
		return nil, err
	}
	in.DB.LatencyMS = time.Since(t0).Milliseconds()
	in.DB.Version, _, _ = strings.Cut(in.DB.Version, " ") // "17.11 (Debian 17.11-1.pgdg12+2)"
	st := s.db.Stat()
	in.DB.InUse, in.DB.Max = st.AcquiredConns(), st.MaxConns()

	var fs syscall.Statfs_t
	if err := syscall.Statfs(s.cfg.DataDir, &fs); err == nil && fs.Blocks > 0 {
		in.Volume = &struct{ TotalMB, FreeMB int64 }{int64(fs.Blocks) * int64(fs.Bsize) >> 20, int64(fs.Bavail) * int64(fs.Bsize) >> 20}
	}

	in.TrivyVersion = s.trivyVersion(ctx)
	var err error
	in.Trivy, err = trivy.Status(s.trivyCacheDir())
	in.VulnDB = err == nil

	if err := s.db.QueryRow(ctx, `select count(*) filter (where status = 'queued'), count(*) filter (where status = 'running'),
			count(*) filter (where status = 'failed' and created_at > now() - interval '24 hours'),
			count(*) filter (where status = 'done' and created_at > now() - interval '24 hours'),
			(select count(*) from jobs where state in ('queued', 'running')),
			(select coalesce(max(attempts), 0) from jobs where state in ('queued', 'running') and kind = 'server_scan'),
			(extract(epoch from now() - min(created_at) filter (where status = 'queued')) / 60)::int
		from scans where status in ('queued', 'running') or created_at > now() - interval '24 hours'`).
		Scan(&in.Scans.Queued, &in.Scans.Running, &in.Scans.Failed24, &in.Scans.Done24, &in.Scans.Jobs, &in.Scans.Attempts,
			&in.Scans.OldestQueuedMin); err != nil {
		return nil, err
	}

	rows, _ := s.db.Query(ctx, `select `+recheckRunCols+` from recheck_runs order by id desc limit 1`)
	runs, err := pgx.CollectRows(rows, pgx.RowToStructByName[recheckRun])
	if err != nil {
		return nil, err
	}
	if len(runs) == 1 {
		in.Recheck = &runs[0]
	}

	sso, err := s.ssoConf(ctx)
	if err != nil {
		return nil, err
	}
	in.SSOEnabled = sso.Enabled
	if in.Sync, err = s.syncConf(ctx); err != nil {
		return nil, err
	}
	in.Sync.ClientSecret = ""

	t := &in.Totals
	if err := s.db.QueryRow(ctx, `select (select count(*) from deliveries where state = 'queued'),
			(select count(*) from deliveries where state = 'failed' and created_at > now() - interval '7 days'),
			(select count(*) from deliveries where state = 'failed' and event <> 'ops_alert' and created_at > now() - interval '24 hours'),
			coalesce((select last_error from deliveries where state = 'failed' order by id desc limit 1), ''),
			(select count(*) from exceptions where status = 'pending' and expires_at > now()),
			(select count(*) from users where active), (select count(*) from projects),
			(select count(*) from targets), (select count(*) from mcp_keys where revoked_at is null and expires_at > now()),
			(select count(*) from findings where status = 'open' and due_at < now()), fc.*
		from `+openCountsSQL("true")+` fc`).Scan(&in.Notify.Queued, &in.Notify.Failed7, &in.Notify.Failed24, &in.Notify.LastError,
		&t.PendingEx, &t.Users, &t.Projects, &t.Targets, &t.Keys, &t.Overdue,
		&t.Open.Critical, &t.Open.High, &t.Open.Medium, &t.Open.Low, &t.Open.Unknown, &t.Open.Open); err != nil {
		return nil, err
	}

	// shortcut: log entries have no level; nearly everything the server logs is a failure, so all but the
	// start-up lines count. Give entries a level if routine lines are ever logged.
	for _, e := range serverLog.snapshot() {
		// "context canceled": a browser left before its answer, not a fault of the server
		if time.Since(e.at) > 24*time.Hour || strings.Contains(e.text, " listening on ") || strings.Contains(e.text, "shutting down") ||
			strings.Contains(e.text, "context canceled") ||
			(strings.Contains(e.text, " database ") && strings.Contains(e.text, ", schema ")) {
			continue
		}
		in.LogCount++
		in.LogLines = append(in.LogLines, e.text)
	}
	in.LogLines = in.LogLines[max(0, len(in.LogLines)-5):]
	return in, nil
}

// ago says how long before now t was, in Korean.
func ago(t, now time.Time) string {
	switch d := now.Sub(t); {
	case d < time.Minute:
		return "방금"
	case d < time.Hour:
		return fmt.Sprintf("%d분 전", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d시간 전", int(d.Hours()))
	default:
		return fmt.Sprintf("%d일 전", int(d.Hours()/24))
	}
}

// mb writes megabytes as "512MB" or "21.3GB".
func mb(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%dMB", n)
	}
	return fmt.Sprintf("%.1fGB", float64(n)/1024)
}

// systemChecks turns the collected state into the rows of the status screen, the ones needing attention first.
// The rules:
//   - data volume: 문제 below JASCA_MAX_EXTRACT_MB free (every scan upload is refused with 507), 주의 below
//     JASCA_MAX_EXTRACT_MB + JASCA_MAX_SCAN_UPLOAD_MB (the largest allowed upload would be refused)
//   - vulnerability DB: 문제 when missing or stale (vulnDBStale); Java DB: 주의 when missing
//   - scans: 주의 when one has waited over an hour, is on a repeated attempt, or one failed in the last 24 hours
//   - re-evaluation, Keycloak sync: 문제 when the last run failed
//   - notifications: 주의 when a delivery gave up in the last 7 days
func (s *server) systemChecks(ctx context.Context, in *sysInfo, now time.Time) []sysCheck {
	at := func(t time.Time) string { return t.In(s.cfg.Loc).Format("2006-01-02 15:04") }
	day := func(t time.Time) string { return t.In(s.cfg.Loc).Format("2006-01-02") }
	out := []sysCheck{{Key: "app", Label: "JASCA", State: "ok",
		Value: fmt.Sprintf("버전 %s · %s 시작(%s)", version, at(startedAt), ago(startedAt, now))}}

	db := sysCheck{Key: "database", Label: "데이터베이스", State: "ok", Value: fmt.Sprintf("PostgreSQL %s · 응답 %dms · 크기 %s · 연결 %d/%d 사용",
		in.DB.Version, in.DB.LatencyMS, mb(in.DB.SizeMB), in.DB.InUse, in.DB.Max)}
	if in.DB.Max > 0 && in.DB.InUse >= in.DB.Max {
		db.State, db.Action = "warn", "DB 연결이 모두 사용 중이라 요청이 기다립니다. DB가 허용하면 JASCA_DB_MAX_CONNS를 늘리세요."
	}
	out = append(out, db)

	if v := in.Volume; v != nil {
		c := sysCheck{Key: "data_volume", Label: "데이터 볼륨", State: "ok", Value: fmt.Sprintf("남은 공간 %s / 전체 %s", mb(v.FreeMB), mb(v.TotalMB))}
		switch {
		case v.FreeMB < s.cfg.MaxExtractMB:
			c.State, c.Action = "bad", fmt.Sprintf("남은 공간이 압축 해제 상한(%s)보다 적어 스캔 파일을 받지 못합니다(507). 데이터 볼륨(PVC jasca-data)을 늘리세요.", mb(s.cfg.MaxExtractMB))
		case v.FreeMB < s.cfg.MaxExtractMB+s.cfg.MaxScanUploadMB:
			c.State, c.Action = "warn", fmt.Sprintf("가장 큰 파일(%s)을 올리면 공간 부족으로 거절됩니다. 대기 중인 스캔이 끝난 뒤에도 그대로면 데이터 볼륨(PVC jasca-data)을 늘리세요.", mb(s.cfg.MaxScanUploadMB))
		}
		c.alert = c.State != "ok"
		out = append(out, c)
	}

	vdb := sysCheck{Key: "trivy_db", Label: "취약점 DB", State: "ok", Link: "/admin/trivy"}
	switch {
	case !in.VulnDB:
		vdb.State, vdb.Value = "bad", "설치 안 됨"
		vdb.Action = "서버 스캔과 재평가가 동작하지 않습니다. 관리 → Trivy DB에서 db.tar.gz를 올리세요."
	case vulnDBStale(in.Trivy.NextUpdate, now):
		vdb.State, vdb.alert = "bad", true
		vdb.Value = fmt.Sprintf("%s 생성(%s) · 갱신 예정일에서 %d일 지남", day(in.Trivy.UpdatedAt), ago(in.Trivy.UpdatedAt, now), int(now.Sub(in.Trivy.NextUpdate).Hours()/24))
		vdb.Action = "그 뒤에 알려진 취약점은 탐지되지 않습니다. 인터넷 PC에서 새 db.tar.gz를 받아 관리 → Trivy DB에 올리세요."
	default:
		vdb.Value = fmt.Sprintf("%s 생성(%s)", day(in.Trivy.UpdatedAt), ago(in.Trivy.UpdatedAt, now))
	}
	jdb := sysCheck{Key: "java_db", Label: "Java DB", State: "ok", Link: "/admin/trivy"}
	if in.Trivy.JavaDB {
		jdb.Value = fmt.Sprintf("%s 생성(%s)", day(in.Trivy.JavaUpdatedAt), ago(in.Trivy.JavaUpdatedAt, now))
	} else {
		jdb.State, jdb.Value = "warn", "설치 안 됨"
		jdb.Action = "서버 스캔이 JAR/WAR/EAR 파일을 건너뜁니다. 관리 → Trivy DB에서 javadb.tar.gz를 올리세요."
	}
	out = append(out, vdb, jdb)

	sc := sysCheck{Key: "scans", Label: "스캔 대기열", State: "ok",
		Value: fmt.Sprintf("대기 %d건 · 실행 %d건 · 최근 24시간 완료 %d건, 실패 %d건", in.Scans.Queued, in.Scans.Running, in.Scans.Done24, in.Scans.Failed24)}
	switch w := in.Scans.OldestQueuedMin; {
	case w != nil && *w > 60:
		sc.State, sc.Value = "warn", sc.Value+fmt.Sprintf(" · 가장 오래 기다린 스캔 %d분", *w)
		sc.Action = "서버 스캔은 한 번에 하나씩 실행합니다. 실행 중인 스캔이 멈춘 것 같으면 그 스캔을 취소하세요."
	case in.Scans.Attempts > 1:
		sc.State, sc.Value = "warn", sc.Value+fmt.Sprintf(" · %d번째 시도 중", in.Scans.Attempts)
		sc.Action = "스캔 도중 서버가 다시 시작되어 재시도하고 있습니다. 메모리 부족(OOMKilled)인지 확인하세요. 세 번 중단되면 그 스캔은 실패로 끝납니다."
	case in.Scans.Failed24 > 0:
		sc.State, sc.Action = "warn", "실패한 스캔의 상세 화면에서 원인을 확인하세요. 원인이 Trivy 실행 실패면 아래 서버 로그에 이유가 있습니다."
	}
	out = append(out, sc)

	rc := sysCheck{Key: "recheck", Label: "재평가", State: "ok", Value: "실행 기록 없음", Link: "/admin/recheck"}
	if r := in.Recheck; r != nil {
		switch r.State {
		case "running":
			rc.Value = fmt.Sprintf("진행 중 · 대상 %d/%d · %s 시작", r.Done, r.Total, at(r.StartedAt))
		case "failed":
			rc.State, rc.alert, rc.Value = "bad", true, fmt.Sprintf("마지막 실행 실패 · %s 시작", at(r.StartedAt))
			rc.Action = "오류: " + clip(clean(r.Error), 200) + " — 관리 → 재평가에서 다시 실행하세요."
		default:
			rc.Value = fmt.Sprintf("마지막 실행 %s · 대상 %d개 · 새 결과 %d건", at(r.StartedAt), r.Total, r.NewFindings)
			if r.State == "canceled" {
				rc.Value += " · 취소됨"
			}
		}
	}
	out = append(out, rc)

	nt := sysCheck{Key: "notifications", Label: "알림 전송", State: "ok", Link: "/admin/channels",
		Value: fmt.Sprintf("대기 %d건 · 최근 7일 전송 실패 %d건", in.Notify.Queued, in.Notify.Failed7)}
	if in.Notify.Failed7 > 0 {
		nt.State = "warn"
		nt.Action = "마지막 오류: " + clip(clean(in.Notify.LastError), 200) + " — 관리 → 알림 채널에서 시험 발송으로 확인하세요."
	}
	nt.alert = in.Notify.Failed24 > 0
	out = append(out, nt)

	if in.Sync.ClientID != "" { // only when the sync is set up
		kc := sysCheck{Key: "keycloak_sync", Label: "Keycloak 동기화", State: "ok", Value: "아직 실행하지 않음", Link: "/admin/sync"}
		if in.Sync.LastRun != nil {
			kc.Value = fmt.Sprintf("마지막 동기화 %s · 사용자 %d명 · 그룹 %d개", at(*in.Sync.LastRun), in.Sync.Users, in.Sync.Groups)
		}
		if in.Sync.LastError != "" {
			kc.State, kc.alert, kc.Value = "bad", true, "동기화 실패"
			if in.Sync.LastRun != nil {
				kc.Value += " · 마지막 시도 " + at(*in.Sync.LastRun)
			}
			kc.Action = "오류: " + clip(clean(in.Sync.LastError), 200) + " — 관리 → Keycloak 동기화에서 설정을 확인하고 지금 동기화를 눌러 보세요."
		}
		out = append(out, kc)
	}

	for _, f := range sysChecks {
		out = append(out, f(ctx, s))
	}

	lg := sysCheck{Key: "server_log", Label: "서버 로그", State: "ok", Value: "최근 24시간 경고·오류 없음"}
	if in.LogCount > 0 {
		lg.State, lg.Value = "warn", fmt.Sprintf("최근 24시간 경고·오류 %d건", in.LogCount)
		lg.Action = "아래 최근 로그를 확인하세요. 전체 로그는 kubectl -n jasca logs deploy/jasca 로 봅니다."
	}
	out = append(out, lg)

	rank := map[string]int{"bad": 0, "warn": 1}
	slices.SortStableFunc(out, func(a, b sysCheck) int {
		ra, oka := rank[a.State]
		rb, okb := rank[b.State]
		if !oka {
			ra = 2
		}
		if !okb {
			rb = 2
		}
		return ra - rb
	})
	return out
}

func (s *server) systemRoutes() {
	s.handle("GET /api/v1/admin/system", permAdmin, s.handleSystem)
	s.handle("GET /api/v1/admin/ops-alerts", permAdmin, s.handleOpsAlertsGet)
	s.handle("PUT /api/v1/admin/ops-alerts", permAdmin, s.handleOpsAlertsPut)
}

func (s *server) handleSystem(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	in, err := s.systemInfo(r.Context())
	if err != nil {
		writeInternal(w, "system status", err)
		return
	}
	now := time.Now()
	lines := in.LogLines
	if lines == nil {
		lines = []string{}
	}
	writeJSON(w, 200, map[string]any{"version": version, "started_at": startedAt.UTC().Truncate(time.Second), "now": now.UTC().Truncate(time.Second),
		"checks": s.systemChecks(r.Context(), in, now), "log_lines": lines,
		"totals": map[string]any{"active_users": in.Totals.Users, "projects": in.Totals.Projects, "targets": in.Totals.Targets,
			"open_findings": in.Totals.Open.Open, "overdue_findings": in.Totals.Overdue, "pending_exceptions": in.Totals.PendingEx}})
}

// --- operator alerts (운영 알림) ---

// opsAlerts is settings['ops_alerts']: the channels an administrator picked, and when each alert that still holds
// was last sent (an entry is dropped when its condition clears, so the next occurrence is a new alert).
type opsAlerts struct {
	Channels []int64              `json:"channel_ids"`
	Sent     map[string]time.Time `json:"sent"`
}

// opsReminder: only the stale vulnerability DB is repeated while it lasts, once a week (nothing else gets worse by waiting).
const opsReminder = 7 * 24 * time.Hour

func (s *server) handleOpsAlertsGet(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	var st opsAlerts
	if _, err := s.getSetting(r.Context(), "ops_alerts", &st); err != nil {
		writeInternal(w, "ops alerts get", err)
		return
	}
	if st.Channels == nil {
		st.Channels = []int64{}
	}
	writeJSON(w, 200, map[string]any{"channel_ids": st.Channels})
}

func (s *server) handleOpsAlertsPut(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	var in struct {
		Channels []int64 `json:"channel_ids"`
	}
	if err := readJSON(r, 16<<10, &in); err != nil {
		writeBodyErr(w, err)
		return
	}
	slices.Sort(in.Channels)
	in.Channels = slices.Compact(in.Channels)
	var known int
	if err := s.db.QueryRow(ctx, `select count(*) from notify_channels where id = any($1)`, in.Channels).Scan(&known); err != nil {
		writeInternal(w, "ops alerts put", err)
		return
	}
	if known != len(in.Channels) {
		badRequest(w, "없는 알림 채널이 들어 있습니다. 화면을 새로 고친 뒤 다시 고르세요.")
		return
	}
	if in.Channels == nil {
		in.Channels = []int64{}
	}
	// only the channels: what was already sent stays, so saving does not repeat an alert
	if err := s.mergeSetting(ctx, "ops_alerts", map[string]any{"channel_ids": in.Channels}); err != nil {
		writeInternal(w, "ops alerts put", err)
		return
	}
	s.audit(ctx, c, "ops_alerts.update", nil, "", map[string]any{"channel_ids": in.Channels})
	w.WriteHeader(204)
}

// runOpsAlerts checks every hour (first a minute after the start, when the loops have run once) until ctx ends.
func (s *server) runOpsAlerts(ctx context.Context) {
	wait := time.Minute
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = time.Hour
		if err := s.opsCheck(ctx, time.Now()); err != nil && ctx.Err() == nil {
			log.Printf("ops alerts: %v", err)
		}
	}
}

// opsCheck queues one message per chosen channel for every alert condition that newly holds, and forgets the ones
// that cleared. Without a chosen channel nothing is marked sent, so picking one later still reports what is wrong.
func (s *server) opsCheck(ctx context.Context, now time.Time) error {
	var st opsAlerts
	if _, err := s.getSetting(ctx, "ops_alerts", &st); err != nil {
		return err
	}
	if len(st.Channels) == 0 {
		return nil
	}
	in, err := s.systemInfo(ctx)
	if err != nil {
		return err
	}
	sent := map[string]time.Time{}
	changed := false
	for _, c := range s.systemChecks(ctx, in, now) {
		if !c.alert {
			continue
		}
		last, ok := st.Sent[c.Key]
		if ok && !(c.Key == "trivy_db" && now.Sub(last) >= opsReminder) {
			sent[c.Key] = last
			continue
		}
		b, _ := json.Marshal(map[string]any{"data": map[string]any{"label": c.Label, "value": c.Value, "action": c.Action}})
		tag, err := s.db.Exec(ctx, `insert into deliveries(channel_id, event, payload)
			select id, 'ops_alert', $2 from notify_channels where id = any($1) and enabled`, st.Channels, json.RawMessage(b))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 { // every chosen channel is switched off: say it again once one is on
			if ok {
				sent[c.Key] = last
			}
			continue
		}
		sent[c.Key], changed = now.UTC().Truncate(time.Second), true
	}
	if !changed && len(sent) == len(st.Sent) {
		return nil
	}
	return s.mergeSetting(ctx, "ops_alerts", map[string]any{"sent": sent})
}
