package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
)

// The administrator's MCP tools: what someone running the service asks about (is it healthy, what failed, who has
// which role, what is queued) and the few actions that go with it. They are listed only for a personal key whose
// user is administrator at the moment of the call. Settings with secrets (SSO, SMTP, channels, AI, Harbor
// connections) stay on the administration screens: an agent reads them here without the secrets and changes none.

var startedAt = time.Now()

// logRing keeps the last entries the process logged, for get_server_logs. main() tees the standard logger into it.
type logRing struct {
	mu      sync.Mutex
	entries []logEntry
	next    int
}

type logEntry struct {
	at   time.Time
	text string
}

const logRingSize = 2000

var serverLog logRing

// Write takes one log entry (the standard logger writes each entry in one call).
func (l *logRing) Write(p []byte) (int, error) {
	e := logEntry{time.Now(), strings.TrimRight(clip(string(p), 4000), "\n")}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) < logRingSize {
		l.entries = append(l.entries, e)
	} else {
		l.entries[l.next] = e
		l.next = (l.next + 1) % logRingSize
	}
	return len(p), nil
}

// snapshot returns the kept entries, oldest first.
func (l *logRing) snapshot() []logEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append(slices.Clone(l.entries[l.next:]), l.entries[:l.next]...)
}

func mcpAdminTools() []mcpTool {
	none := `{"type": "object", "additionalProperties": false, "properties": {}}`
	return []mcpTool{
		readTool(mcpAdmin, "system_status", "시스템 상태: 버전, DB, Trivy DB, 스캔 대기열, 동기화, 알림, 디스크와 문제점",
			"Health of the service in one call: version and uptime, database, disk space of the data volume, the Trivy "+
				"vulnerability DB and its age, scans queued, running and failed, the latest re-evaluation run, Keycloak sync, "+
				"notification deliveries, pending exception requests, and totals. problems lists in plain words what needs "+
				"attention; it is empty when all is well. Call this first when asked how the service is doing.",
			none, mcpSystemStatus),
		readTool(mcpAdmin, "get_server_logs", "서버 로그: 최근 로그에서 찾기",
			"The server's recent log lines, oldest first (times are UTC): errors of scans, Keycloak sign-in and sync, "+
				"notifications, Harbor, and internal errors. Kept in memory since the last start, the newest 2000 entries. "+
				"Secrets are never logged.",
			`{"type": "object", "additionalProperties": false, "properties": {
				"query": {"type": "string", "maxLength": 200, "description": "Only lines containing this text, case-insensitive: for example sso, keycloak sync, server scan, notify, panic."},
				"minutes": {"type": "integer", "minimum": 1, "maximum": 100000, "description": "Only lines of the last N minutes."},
				"limit": `+limitSchema(100, 500)+`}}`, mcpServerLogs),
		readTool(mcpAdmin, "list_all_scans", "전체 프로젝트의 스캔 현황 (대기·진행·실패)",
			"Scans across all projects, newest first: project, target, source, status, error, who started it. By default "+
				"the queued, running and failed ones of the last 72 hours, which is the operator's worklist.",
			`{"type": "object", "additionalProperties": false, "properties": {
				"status": {"type": "array", "items": {"type": "string", "enum": ["queued", "running", "done", "failed", "canceled"]}, "description": "Default: queued, running, failed."},
				"project": {"type": "string", "description": "Only this project: a project key."},
				"hours": {"type": "integer", "minimum": 1, "maximum": 8760, "default": 72, "description": "Only scans created in the last N hours."},
				"limit": `+limitSchema(50, 200)+`}}`, mcpListAllScans),
		readTool(mcpAdmin, "list_notifications", "알림 전송 현황 (실패·대기)",
			"Notification deliveries (Mattermost, e-mail), newest first: channel, event, state, attempts and the last "+
				"error. By default the failed and still queued ones. A delivery is retried after 1, 5 and 30 minutes and "+
				"then fails for good; finished ones are kept 30 days.",
			`{"type": "object", "additionalProperties": false, "properties": {
				"state": {"type": "array", "items": {"type": "string", "enum": ["queued", "sent", "failed"]}, "description": "Default: failed, queued."},
				"limit": `+limitSchema(50, 200)+`}}`, mcpListNotifications),
		readTool(mcpAdmin, "list_users", "사용자 목록: 역할, 활성 여부, 마지막 로그인",
			"List user accounts: username, name, e-mail, source (local or sso), system role, whether the role follows "+
				"Keycloak, active or not, last sign-in, groups and departments.",
			`{"type": "object", "additionalProperties": false, "properties": {
				"query": {"type": "string", "maxLength": 100, "description": "Case-insensitive part of the username, name or e-mail."},
				"role": {"type": "string", "enum": ["user", "security", "administrator"], "description": "Only accounts with this system role."},
				"active": {"type": "boolean", "description": "true: only active accounts. false: only deactivated ones."},
				"limit": `+limitSchema(100, 500)+`}}`, mcpListUsers),
		readTool(mcpAdmin, "list_mcp_keys", "전체 사용자의 MCP 키 현황",
			"Every user's personal MCP keys (never the key itself): owner, name, read-only or not, when it was last used, "+
				"when it expires, whether it is revoked. Keys of deactivated accounts do not work.",
			`{"type": "object", "additionalProperties": false, "properties": {
				"user": {"type": "string", "description": "Only this user's keys: a username."},
				"limit": `+limitSchema(100, 500)+`}}`, mcpListKeys),
		readTool(mcpAdmin, "get_settings", "운영 설정 조회 (비밀값 제외)",
			"The service's settings without any secret: remediation deadlines by severity, retention of raw reports, the "+
				"default policy of new projects, SSO (Keycloak), Keycloak sync, Trivy scan options, AI, SMTP, notification "+
				"channels and Harbor connections. Read-only: settings are changed on the administration screens.",
			none, mcpGetSettings),
		readTool(mcpAdmin, "list_harbor_unmapped", "매핑되지 않은 Harbor 이미지",
			"Images Harbor reported a scan for that no mapping assigns to a project yet, newest first. Assign one with "+
				"assign_harbor_image to fetch its report.",
			`{"type": "object", "additionalProperties": false, "properties": {"limit": `+limitSchema(50, 500)+`}}`, mcpListHarborUnmapped),

		writeTool(mcpAdmin, false, "update_user", "사용자 역할 변경·비활성화",
			"Change a user's system role or deactivate/reactivate the account. role keycloak hands the role back to "+
				"Keycloak from the user's next sign-in. Deactivating ends the user's sessions and stops their MCP keys. "+
				"You cannot lower or deactivate yourself, nor the local emergency account admin.",
			`{"type": "object", "additionalProperties": false, "required": ["username"], "properties": {
				"username": {"type": "string", "description": "The account's exact username, from list_users."},
				"role": {"type": "string", "enum": ["user", "security", "administrator", "keycloak"], "description": "user: no system role. keycloak: follow the Keycloak role mapping again."},
				"active": {"type": "boolean", "description": "false deactivates the account, true reactivates it."}}}`, mcpUpdateUser),
		writeTool(mcpAdmin, false, "revoke_mcp_key", "다른 사용자의 MCP 키 폐기",
			"Revoke any user's personal MCP key at once, for example when a key leaked.",
			fmt.Sprintf(idSchema, "Key id from list_mcp_keys."), mcpRevokeKey),
		writeTool(mcpAdmin, false, "run_keycloak_sync", "Keycloak 동기화 지금 실행",
			"Read users, groups and departments from Keycloak now instead of waiting for the next scheduled run. "+
				"Returns the numbers read and the error, if any.",
			none, mcpRunSync),
		writeTool(mcpAdmin, false, "start_recheck", "전체 대상 재평가 시작",
			"Start a re-evaluation: every target's latest package inventory is matched against the installed "+
				"vulnerability DB again, without new scans. It runs in the background behind new scans; system_status "+
				"shows its progress. Refused while one is running.",
			none, mcpStartRecheck),
		writeTool(mcpAdmin, false, "assign_harbor_image", "매핑되지 않은 Harbor 이미지를 프로젝트에 연결",
			"Assign an unmapped Harbor image to a project and fetch its vulnerability report.",
			`{"type": "object", "additionalProperties": false, "required": ["id", "project"], "properties": {
				"id": {"type": "integer", "minimum": 1, "description": "Id from list_harbor_unmapped."},`+projectProp+`}}`, mcpAssignHarbor),
	}
}

func noArgs(raw json.RawMessage) error { return toolArgs(raw, &struct{}{}) }

// --- system_status ---

func mcpSystemStatus(m *mcpCall, raw json.RawMessage) (any, error) {
	if err := noArgs(raw); err != nil {
		return nil, err
	}
	ctx, s := m.r.Context(), m.s
	problems := []string{}
	problem := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	out := map[string]any{"version": version, "started_at": startedAt.UTC().Truncate(time.Second),
		"uptime_hours": int(time.Since(startedAt).Hours()), "time_zone": s.cfg.Loc.String(), "now": time.Now().UTC().Truncate(time.Second)}

	// database
	var db struct {
		Version, Name, Schema string
		SizeMB                int64
	}
	if err := s.db.QueryRow(ctx, `select current_setting('server_version'), current_database(), coalesce(current_schema(), ''),
		pg_database_size(current_database()) >> 20`).Scan(&db.Version, &db.Name, &db.Schema, &db.SizeMB); err != nil {
		return nil, err
	}
	st := s.db.Stat()
	out["database"] = map[string]any{"server_version": db.Version, "database": db.Name, "schema": db.Schema, "size_mb": db.SizeMB,
		"connections_in_use": st.AcquiredConns(), "connections_max": st.MaxConns()}
	if st.MaxConns() > 0 && st.AcquiredConns() >= st.MaxConns() {
		problem("All %d database connections are in use: requests are waiting. Raise JASCA_DB_MAX_CONNS if the database allows it.", st.MaxConns())
	}

	// the data volume: the Trivy DB and scan uploads live there
	var fs syscall.Statfs_t
	if err := syscall.Statfs(s.cfg.DataDir, &fs); err == nil && fs.Blocks > 0 {
		total, free := fs.Blocks*uint64(fs.Bsize)>>20, fs.Bavail*uint64(fs.Bsize)>>20
		out["data_volume"] = map[string]any{"path": s.cfg.DataDir, "total_mb": total, "free_mb": free}
		if free < 5<<10 {
			problem("The data volume has only %d MB free: server scans extract up to %d MB. Grow the volume (PVC jasca-data).", free, s.cfg.MaxExtractMB)
		}
	}

	// Trivy
	tv := s.trivyStatus(ctx)
	trivyOut := map[string]any{"trivy_version": tv["trivy_version"], "vulnerability_db_installed": tv["updated_at"] != nil,
		"vulnerability_db_built_at": tv["updated_at"], "java_db_installed": tv["java_db"] != nil}
	if at, ok := tv["updated_at"].(time.Time); ok {
		age := int(time.Since(at).Hours() / 24)
		trivyOut["vulnerability_db_age_days"] = age
		if age > 8 {
			problem("The Trivy vulnerability DB is %d days old: newer vulnerabilities are not detected. Upload a fresh db.tar.gz at 관리 → Trivy DB.", age)
		}
	} else {
		problem("The Trivy vulnerability DB is not installed: server scans and re-evaluation do not work. Upload db.tar.gz at 관리 → Trivy DB.")
	}
	if tv["java_db"] == nil {
		problem("The Trivy Java DB is not installed: server scans skip JAR/WAR/EAR files. Upload javadb.tar.gz at 관리 → Trivy DB.")
	}
	out["trivy"] = trivyOut

	// scans, jobs
	var sc struct {
		Queued, Running, Failed24, Done24, Jobs int
		OldestQueuedMin                         *int
	}
	if err := s.db.QueryRow(ctx, `select count(*) filter (where status = 'queued'), count(*) filter (where status = 'running'),
			count(*) filter (where status = 'failed' and created_at > now() - interval '24 hours'),
			count(*) filter (where status = 'done' and created_at > now() - interval '24 hours'),
			(select count(*) from jobs where state in ('queued', 'running')),
			(extract(epoch from now() - min(created_at) filter (where status = 'queued')) / 60)::int
		from scans where status in ('queued', 'running') or created_at > now() - interval '24 hours'`).
		Scan(&sc.Queued, &sc.Running, &sc.Failed24, &sc.Done24, &sc.Jobs, &sc.OldestQueuedMin); err != nil {
		return nil, err
	}
	scans := map[string]any{"queued": sc.Queued, "running": sc.Running, "failed_last_24h": sc.Failed24, "done_last_24h": sc.Done24,
		"background_jobs_waiting_or_running": sc.Jobs}
	if sc.OldestQueuedMin != nil {
		scans["oldest_queued_minutes"] = *sc.OldestQueuedMin
		if *sc.OldestQueuedMin > 60 {
			problem("A scan has been queued for %d minutes: the server scans one at a time. list_all_scans shows the queue.", *sc.OldestQueuedMin)
		}
	}
	if sc.Failed24 > 0 {
		problem("%d scans failed in the last 24 hours. list_all_scans shows them with their errors.", sc.Failed24)
	}
	out["scans"] = scans

	// the latest re-evaluation
	rows, _ := s.db.Query(ctx, `select `+recheckRunCols+` from recheck_runs order by id desc limit 1`)
	if runs, err := pgx.CollectRows(rows, pgx.RowToStructByName[recheckRun]); err != nil {
		return nil, err
	} else if len(runs) == 1 {
		r := runs[0]
		out["last_recheck"] = map[string]any{"reason": r.Reason, "state": r.State, "targets_done": r.Done, "targets_total": r.Total,
			"new_findings": r.NewFindings, "started_at": r.StartedAt.Truncate(time.Second), "finished_at": sec(r.FinishedAt), "error": r.Error}
		if r.State == "failed" {
			problem("The last re-evaluation failed: %s", clip(r.Error, 200))
		}
	}

	// Keycloak
	sso, err := s.ssoConf(ctx)
	if err != nil {
		return nil, err
	}
	sy, err := s.syncConf(ctx)
	if err != nil {
		return nil, err
	}
	kc := map[string]any{"sso_enabled": sso.Enabled, "sync_configured": sy.ClientID != "", "sync_interval_min": sy.IntervalMin,
		"last_sync_at": sy.LastRun, "last_sync_error": sy.LastError, "users_read": sy.Users, "groups_read": sy.Groups}
	if sy.LastError != "" {
		problem("Keycloak sync is failing: %s", clip(sy.LastError, 200))
	}
	out["keycloak"] = kc

	// notifications, exceptions, Harbor, totals
	var n struct {
		Queued, Failed7, PendingEx, Unmapped, Users, Projects, Targets, Keys, Overdue int
		Open                                                                          sevCounts
	}
	if err := s.db.QueryRow(ctx, `select (select count(*) from deliveries where state = 'queued'),
			(select count(*) from deliveries where state = 'failed' and created_at > now() - interval '7 days'),
			(select count(*) from exceptions where status = 'pending' and expires_at > now()),
			(select count(*) from harbor_unmapped), (select count(*) from users where active), (select count(*) from projects),
			(select count(*) from targets), (select count(*) from mcp_keys where revoked_at is null and expires_at > now()),
			(select count(*) from findings where status = 'open' and due_at < now()), fc.*
		from `+openCountsSQL("true")+` fc`).Scan(&n.Queued, &n.Failed7, &n.PendingEx, &n.Unmapped, &n.Users, &n.Projects, &n.Targets,
		&n.Keys, &n.Overdue, &n.Open.Critical, &n.Open.High, &n.Open.Medium, &n.Open.Low, &n.Open.Unknown, &n.Open.Open); err != nil {
		return nil, err
	}
	out["notifications"] = map[string]any{"queued": n.Queued, "failed_last_7d": n.Failed7}
	if n.Failed7 > 0 {
		problem("%d notifications failed in the last 7 days. list_notifications shows the errors.", n.Failed7)
	}
	out["waiting_for_people"] = map[string]any{"pending_exception_requests": n.PendingEx, "unmapped_harbor_images": n.Unmapped}
	out["totals"] = map[string]any{"active_users": n.Users, "projects": n.Projects, "targets": n.Targets, "live_mcp_keys": n.Keys,
		"open_findings": n.Open, "overdue_findings": n.Overdue}
	out["problems"] = problems
	return out, nil
}

// --- logs, scans, notifications ---

func mcpServerLogs(m *mcpCall, raw json.RawMessage) (any, error) {
	var a struct {
		Query   string `json:"query"`
		Minutes *int   `json:"minutes"`
		Limit   *int   `json:"limit"`
	}
	if err := toolArgs(raw, &a); err != nil {
		return nil, err
	}
	limit, err := limitArg(a.Limit, 100, 500)
	if err != nil {
		return nil, err
	}
	all := serverLog.snapshot()
	q := strings.ToLower(strings.TrimSpace(a.Query))
	lines := []string{}
	for _, e := range all {
		if a.Minutes != nil && time.Since(e.at) > time.Duration(*a.Minutes)*time.Minute {
			continue
		}
		if q == "" || strings.Contains(strings.ToLower(e.text), q) {
			lines = append(lines, e.text)
		}
	}
	matched := len(lines)
	lines = lines[max(0, matched-limit):] // the newest ones
	return struct {
		Kept      int       `json:"kept"` // entries in memory
		KeptSince time.Time `json:"kept_since"`
		Matched   int       `json:"matched"`
		Lines     []string  `json:"lines"`
	}{len(all), logSince(all), matched, lines}, nil
}

func logSince(all []logEntry) time.Time {
	if len(all) == 0 {
		return startedAt.UTC().Truncate(time.Second)
	}
	return all[0].at.UTC().Truncate(time.Second)
}

func mcpListAllScans(m *mcpCall, raw json.RawMessage) (any, error) {
	var a struct {
		Status  []string `json:"status"`
		Project string   `json:"project"`
		Hours   *int     `json:"hours"`
		Limit   *int     `json:"limit"`
	}
	if err := toolArgs(raw, &a); err != nil {
		return nil, err
	}
	limit, err := limitArg(a.Limit, 50, 200)
	if err = errors.Join(err, enumArg("status", []string{"queued", "running", "done", "failed", "canceled"}, a.Status...)); err != nil {
		return nil, err
	}
	hours := 72
	if a.Hours != nil {
		if hours = *a.Hours; hours < 1 || hours > 8760 {
			return nil, toolErrorf("Invalid arguments: hours must be between 1 and 8760.")
		}
	}
	if len(a.Status) == 0 {
		a.Status = []string{"queued", "running", "failed"}
	}
	type row struct {
		ID         int64      `json:"id"`
		Project    string     `json:"project"`
		Target     string     `json:"target"`
		Source     string     `json:"source"`
		Status     string     `json:"status"`
		Error      string     `json:"error,omitempty"`
		Ref        string     `json:"ref,omitempty"`
		StartedBy  string     `json:"started_by,omitempty"`
		CreatedAt  time.Time  `json:"created_at"`
		FinishedAt *time.Time `json:"finished_at,omitempty"`
	}
	list, err := collect[row](m.r.Context(), m.s, `select s.id, p.key, t.name, s.source, s.status, left(s.error, 500), s.ref,
			coalesce((select u.username from users u where u.id = s.created_by_user),
				(select 'API token ' || k.name from api_tokens k where k.id = s.created_by_token), ''),
			date_trunc('second', s.created_at), date_trunc('second', s.finished_at)
		from scans s join projects p on p.id = s.project_id join targets t on t.id = s.target_id
		where s.status = any($1) and s.created_at > now() - make_interval(hours => $2) and ($3 = '' or p.key = $3)
		order by s.id desc limit $4`, a.Status, hours, a.Project, limit+1)
	if err != nil {
		return nil, err
	}
	more := len(list) > limit
	return struct {
		Scans     []row `json:"scans"`
		Truncated bool  `json:"truncated,omitempty"`
	}{list[:min(limit, len(list))], more}, nil
}

func mcpListNotifications(m *mcpCall, raw json.RawMessage) (any, error) {
	var a struct {
		State []string `json:"state"`
		Limit *int     `json:"limit"`
	}
	if err := toolArgs(raw, &a); err != nil {
		return nil, err
	}
	limit, err := limitArg(a.Limit, 50, 200)
	if err = errors.Join(err, enumArg("state", []string{"queued", "sent", "failed"}, a.State...)); err != nil {
		return nil, err
	}
	if len(a.State) == 0 {
		a.State = []string{"failed", "queued"}
	}
	type row struct {
		ID          int64     `json:"id"`
		Channel     string    `json:"channel"`
		ChannelKind string    `json:"channel_kind"`
		Event       string    `json:"event"`
		Project     string    `json:"project,omitempty"`
		State       string    `json:"state"`
		Attempts    int       `json:"attempts"`
		LastError   string    `json:"last_error,omitempty"`
		CreatedAt   time.Time `json:"created_at"`
		NextTryAt   time.Time `json:"next_try_at"` // meaningful while queued
	}
	list, err := collect[row](m.r.Context(), m.s, `select d.id, c.name, c.kind, d.event, coalesce(d.payload->>'project_key', ''), d.state, d.attempts,
			left(d.last_error, 500), date_trunc('second', d.created_at), date_trunc('second', d.next_at)
		from deliveries d join notify_channels c on c.id = d.channel_id where d.state = any($1) order by d.id desc limit $2`, a.State, limit)
	return struct {
		Deliveries []row `json:"deliveries"`
	}{list}, err
}

// --- users, keys ---

func mcpListUsers(m *mcpCall, raw json.RawMessage) (any, error) {
	var a struct {
		Query  string `json:"query"`
		Role   string `json:"role"`
		Active *bool  `json:"active"`
		Limit  *int   `json:"limit"`
	}
	if err := toolArgs(raw, &a); err != nil {
		return nil, err
	}
	limit, err := limitArg(a.Limit, 100, 500)
	if err != nil {
		return nil, err
	}
	roles := map[string]string{"user": "", "security": "security", "administrator": "admin"}
	want, ok := roles[a.Role]
	if a.Role != "" && !ok {
		return nil, toolErrorf("Invalid arguments: role must be one of user, security, administrator.")
	}
	var list []adminUser
	if err := m.api("GET /api/v1/admin/users", nil, nil, nil, &list); err != nil {
		return nil, err
	}
	q := strings.ToLower(strings.TrimSpace(a.Query))
	list = slices.DeleteFunc(list, func(u adminUser) bool {
		return a.Role != "" && u.SystemRole != want || a.Active != nil && u.Active != *a.Active ||
			q != "" && !strings.Contains(strings.ToLower(u.Username+"\n"+u.Name+"\n"+u.Email), q)
	})
	out := struct {
		Total int          `json:"total"`
		Users []mcpAccount `json:"users"`
	}{len(list), []mcpAccount{}}
	for _, u := range list[:min(limit, len(list))] {
		out.Users = append(out.Users, mcpAccountRow(u))
	}
	return out, nil
}

type mcpAccount struct {
	Username     string     `json:"username"`
	Name         string     `json:"name,omitempty"`
	Email        string     `json:"email,omitempty"`
	Source       string     `json:"source"`
	Role         string     `json:"role"`
	RoleFollowsK bool       `json:"role_follows_keycloak,omitempty"`
	Active       bool       `json:"active"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
	Groups       []string   `json:"groups,omitempty"`
	Departments  []string   `json:"departments,omitempty"`
}

func mcpAccountRow(u adminUser) mcpAccount {
	role := map[string]string{"": "user", "security": "security", "admin": "administrator"}[u.SystemRole]
	return mcpAccount{u.Username, u.Name, u.Email, u.Source, role, u.RoleFromSSO, u.Active, sec(u.LastLoginAt), u.Groups, u.Depts}
}

func mcpUpdateUser(m *mcpCall, raw json.RawMessage) (any, error) {
	var a struct {
		Username string `json:"username"`
		Role     string `json:"role"`
		Active   *bool  `json:"active"`
	}
	if err := toolArgs(raw, &a); err != nil {
		return nil, err
	}
	in := map[string]any{}
	switch a.Role {
	case "":
	case "keycloak":
		in["role_from_sso"] = true
	case "user", "security", "administrator":
		in["system_role"] = map[string]string{"user": "", "security": "security", "administrator": "admin"}[a.Role]
	default:
		return nil, toolErrorf("Invalid arguments: role must be one of user, security, administrator, keycloak.")
	}
	if a.Active != nil {
		in["active"] = *a.Active
	}
	if len(in) == 0 {
		return nil, toolErrorf("Invalid arguments: pass role, active or both.")
	}
	if a.Username == "me" {
		return nil, toolErrorf("Invalid arguments: username must be an exact username.")
	}
	id, err := m.userID(a.Username)
	if err != nil {
		return nil, err
	}
	var u adminUser
	if err := m.api("PATCH /api/v1/admin/users/{id}", map[string]string{"id": itoa(id)}, nil, in, &u); err != nil {
		return nil, err
	}
	return mcpAccountRow(u), nil
}

func mcpListKeys(m *mcpCall, raw json.RawMessage) (any, error) {
	var a struct {
		User  string `json:"user"`
		Limit *int   `json:"limit"`
	}
	if err := toolArgs(raw, &a); err != nil {
		return nil, err
	}
	limit, err := limitArg(a.Limit, 100, 500)
	if err != nil {
		return nil, err
	}
	var list []struct {
		mcpKey
		Username string `json:"username"`
		Active   bool   `json:"user_active"`
	}
	if err := m.api("GET /api/v1/admin/mcp-keys", nil, nil, nil, &list); err != nil {
		return nil, err
	}
	type row struct {
		ID         int64      `json:"id"`
		User       string     `json:"user"`
		Name       string     `json:"name"`
		ReadOnly   bool       `json:"read_only,omitempty"`
		State      string     `json:"state"` // live, revoked, expired, user deactivated
		LastUsedAt *time.Time `json:"last_used_at,omitempty"`
		ExpiresAt  time.Time  `json:"expires_at"`
		CreatedAt  time.Time  `json:"created_at"`
	}
	out := struct {
		Total int   `json:"total"`
		Keys  []row `json:"keys"`
	}{Keys: []row{}}
	for _, k := range list {
		if a.User != "" && !strings.EqualFold(a.User, k.Username) {
			continue
		}
		state := "live"
		switch {
		case k.RevokedAt != nil:
			state = "revoked"
		case k.ExpiresAt.Before(time.Now()):
			state = "expired"
		case !k.Active:
			state = "user deactivated"
		}
		if out.Total++; len(out.Keys) < limit {
			out.Keys = append(out.Keys, row{k.ID, k.Username, k.Name, k.ReadOnly, state, sec(k.LastUsedAt),
				k.ExpiresAt.Truncate(time.Second), k.CreatedAt.Truncate(time.Second)})
		}
	}
	return out, nil
}

func mcpRevokeKey(m *mcpCall, raw json.RawMessage) (any, error) {
	var a struct {
		ID *int64 `json:"id"`
	}
	if err := toolArgs(raw, &a); err != nil {
		return nil, err
	}
	if a.ID == nil || *a.ID < 1 {
		return nil, toolErrorf("Invalid arguments: id is required: a key id from list_mcp_keys.")
	}
	err := m.api("DELETE /api/v1/admin/mcp-keys/{id}", map[string]string{"id": itoa(*a.ID)}, nil, nil, nil)
	if errors.Is(err, errRESTNotFound) {
		return nil, toolErrorf("MCP key %d not found.", *a.ID)
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"revoked": true, "key_id": *a.ID}, nil
}

// --- settings, sync, recheck, Harbor ---

func mcpGetSettings(m *mcpCall, raw json.RawMessage) (any, error) {
	if err := noArgs(raw); err != nil {
		return nil, err
	}
	out := map[string]json.RawMessage{}
	for name, route := range map[string]string{
		"remediation_deadlines": "GET /api/v1/admin/sla", "raw_report_retention": "GET /api/v1/admin/retention",
		"default_policy": "GET /api/v1/admin/default-policy", "sso": "GET /api/v1/admin/sso", "keycloak_sync": "GET /api/v1/admin/sync",
		"trivy": "GET /api/v1/admin/trivy", "ai": "GET /api/v1/admin/ai", "smtp": "GET /api/v1/admin/smtp",
		"notification_channels": "GET /api/v1/admin/channels", "harbor_connections": "GET /api/v1/admin/harbor",
	} {
		var v json.RawMessage
		if err := m.api(route, nil, nil, nil, &v); err != nil {
			return nil, err
		}
		out[name] = v
	}
	return out, nil
}

func mcpRunSync(m *mcpCall, raw json.RawMessage) (any, error) {
	if err := noArgs(raw); err != nil {
		return nil, err
	}
	var res struct {
		Groups int    `json:"groups"`
		Users  int    `json:"users"`
		Error  string `json:"error,omitempty"`
	}
	// the sync outlives an agent that stops waiting: half a sync would leave users without their groups
	ctx, cancel := context.WithTimeout(context.WithoutCancel(m.r.Context()), 5*time.Minute)
	defer cancel()
	mm := *m
	mm.r = m.r.WithContext(ctx)
	err := mm.api("POST /api/v1/admin/sync/run", nil, nil, nil, &res)
	return res, err
}

func mcpStartRecheck(m *mcpCall, raw json.RawMessage) (any, error) {
	if err := noArgs(raw); err != nil {
		return nil, err
	}
	var run recheckRun
	if err := m.api("POST /api/v1/admin/recheck", nil, nil, nil, &run); err != nil {
		return nil, err
	}
	return map[string]any{"started": true, "run_id": run.ID, "targets_total": run.Total}, nil
}

func mcpListHarborUnmapped(m *mcpCall, raw json.RawMessage) (any, error) {
	var a struct {
		Limit *int `json:"limit"`
	}
	if err := toolArgs(raw, &a); err != nil {
		return nil, err
	}
	limit, err := limitArg(a.Limit, 50, 500)
	if err != nil {
		return nil, err
	}
	type row struct {
		ID            int64     `json:"id"`
		Connection    string    `json:"connection"`
		HarborProject string    `json:"harbor_project"`
		Repository    string    `json:"repository"`
		Tag           string    `json:"tag,omitempty"`
		Digest        string    `json:"digest"`
		ReceivedAt    time.Time `json:"received_at"`
	}
	list, err := collect[row](m.r.Context(), m.s, `select h.id, l.name, h.harbor_project, h.repository, h.tag, h.digest,
			date_trunc('second', h.received_at)
		from harbor_unmapped h join harbor_links l on l.id = h.link_id order by h.received_at desc, h.id desc limit $1`, limit)
	return struct {
		Images []row `json:"images"`
	}{list}, err
}

func mcpAssignHarbor(m *mcpCall, raw json.RawMessage) (any, error) {
	var a struct {
		ID      *int64 `json:"id"`
		Project string `json:"project"`
	}
	if err := toolArgs(raw, &a); err != nil {
		return nil, err
	}
	if a.ID == nil || *a.ID < 1 {
		return nil, toolErrorf("Invalid arguments: id is required: an id from list_harbor_unmapped.")
	}
	if err := m.needProject(a.Project); err != nil {
		return nil, err
	}
	err := m.api("POST /api/v1/admin/harbor/unmapped/{id}/assign", map[string]string{"id": itoa(*a.ID)}, nil,
		map[string]int64{"project_id": m.c.Project.ID}, nil)
	if errors.Is(err, errRESTNotFound) {
		return nil, toolErrorf("Unmapped image %d not found: it may have been assigned already.", *a.ID)
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"assigned": true, "project": m.c.Project.Key, "next": "The report is fetched in the background; list_scans of the project shows it."}, nil
}
