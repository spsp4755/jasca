package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

func init() { routeRegistrars = append(routeRegistrars, (*server).aiRoutes) }

func (s *server) aiRoutes() {
	s.handle("GET /api/v1/admin/ai", permAdmin, s.handleGetAI)
	s.handle("PUT /api/v1/admin/ai", permAdmin, s.handlePutAI)
	s.handle("POST /api/v1/admin/ai/test", permAdmin, s.handleTestAI)
	s.handle("GET /api/v1/admin/ai/prompts", permAdmin, s.handleGetAIPrompts)
	s.handle("PUT /api/v1/admin/ai/prompts", permAdmin, s.handlePutAIPrompts)
	s.handle("POST /api/v1/vulns/{id}/ai-guide", permUser, s.handleAIGuide)
	// not an obj perm: a vuln_guide run has no project, so the handler decides (requester or admin)
	s.handle("GET /api/v1/ai/runs/{id}", permUser, s.handleAIRun)
	s.handle("POST /api/v1/projects/{key}/ai-report", permProj("member"), s.handleAIReport)
	s.handle("GET /api/v1/projects/{key}/ai-reports", permProj("viewer"), s.handleAIReports)
	s.registerObj("ai_run", func(ctx context.Context, id string) (int64, error) {
		n, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			return 0, pgx.ErrNoRows
		}
		var pid int64
		err = s.db.QueryRow(ctx, `select project_id from ai_runs where id=$1 and project_id is not null`, n).Scan(&pid)
		return pid, err
	})
	s.registerJob("ai", s.runAIJob)
}

type aiSettings struct {
	BaseURL        string `json:"base_url"`
	Model          string `json:"model"`
	APIKey         string `json:"api_key"`
	TimeoutSec     int    `json:"timeout_sec"`
	MaxInputTokens int    `json:"max_input_tokens"`
	Enabled        bool   `json:"enabled"`
}

func (s *server) aiConf(ctx context.Context) (aiSettings, error) {
	c := aiSettings{}
	_, err := s.getSetting(ctx, "ai", &c)
	if c.TimeoutSec <= 0 {
		c.TimeoutSec = 120
	}
	if c.MaxInputTokens <= 0 {
		c.MaxInputTokens = 12000
	}
	return c, err
}

type aiPrompts struct {
	VulnGuide     string `json:"vuln_guide"`
	ProjectReport string `json:"project_report"`
}

func (s *server) aiPromptConf(ctx context.Context) (aiPrompts, error) {
	var p aiPrompts
	_, err := s.getSetting(ctx, "ai_prompts", &p)
	return p, err
}

func (s *server) handleGetAI(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	st, err := s.aiConf(r.Context())
	if err != nil {
		writeInternal(w, "get ai", err)
		return
	}
	writeJSON(w, 200, map[string]any{"base_url": st.BaseURL, "model": st.Model, "api_key_set": st.APIKey != "",
		"timeout_sec": st.TimeoutSec, "max_input_tokens": st.MaxInputTokens, "enabled": st.Enabled})
}

// aiPatch is the PUT/test body; nil fields keep the stored value and an empty api_key keeps the stored key.
type aiPatch struct {
	BaseURL        *string `json:"base_url,omitempty"`
	Model          *string `json:"model,omitempty"`
	APIKey         *string `json:"api_key,omitempty"`
	TimeoutSec     *int    `json:"timeout_sec,omitempty"`
	MaxInputTokens *int    `json:"max_input_tokens,omitempty"`
	Enabled        *bool   `json:"enabled,omitempty"`
}

func (p *aiPatch) validate() string {
	if p.BaseURL != nil {
		*p.BaseURL = strings.TrimRight(strings.TrimSpace(*p.BaseURL), "/")
		if u, err := url.Parse(*p.BaseURL); *p.BaseURL != "" && (err != nil || u.Host == "" || u.Scheme != "http" && u.Scheme != "https") {
			return "Base URL은 http:// 또는 https:// 로 시작해야 합니다."
		}
	}
	if p.Model != nil {
		*p.Model = strings.TrimSpace(*p.Model)
	}
	if p.APIKey != nil {
		*p.APIKey = strings.TrimSpace(*p.APIKey)
		if *p.APIKey == "" {
			p.APIKey = nil
		}
	}
	if p.TimeoutSec != nil && (*p.TimeoutSec < 1 || *p.TimeoutSec > 600) {
		return "응답 대기 시간은 1~600초여야 합니다."
	}
	if p.MaxInputTokens != nil && (*p.MaxInputTokens < 100 || *p.MaxInputTokens > 1000000) {
		return "최대 입력 토큰은 100 이상이어야 합니다."
	}
	return ""
}

func (p *aiPatch) apply(st *aiSettings) {
	if p.BaseURL != nil {
		st.BaseURL = *p.BaseURL
	}
	if p.Model != nil {
		st.Model = *p.Model
	}
	if p.APIKey != nil {
		st.APIKey = *p.APIKey
	}
	if p.TimeoutSec != nil {
		st.TimeoutSec = *p.TimeoutSec
	}
	if p.MaxInputTokens != nil {
		st.MaxInputTokens = *p.MaxInputTokens
	}
	if p.Enabled != nil {
		st.Enabled = *p.Enabled
	}
}

func (s *server) handlePutAI(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	var req aiPatch
	if err := readJSON(r, 8<<10, &req); err != nil {
		writeBodyErr(w, err)
		return
	}
	if msg := req.validate(); msg != "" {
		writeErr(w, 400, "bad_request", msg)
		return
	}
	if err := s.mergeSetting(r.Context(), "ai", req); err != nil {
		writeInternal(w, "put ai", err)
		return
	}
	s.audit(r.Context(), c, "settings.update", nil, "ai", map[string]any{"credential_changed": req.APIKey != nil})
	s.handleGetAI(w, r, c)
}

// handleTestAI sends one tiny request with the form's values over the stored ones. The answer carries no upstream text.
func (s *server) handleTestAI(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	var req aiPatch
	if err := readJSON(r, 8<<10, &req); err != nil {
		writeBodyErr(w, err)
		return
	}
	if msg := req.validate(); msg != "" {
		writeErr(w, 400, "bad_request", msg)
		return
	}
	st, err := s.aiConf(r.Context())
	if err != nil {
		writeInternal(w, "test ai", err)
		return
	}
	req.apply(&st)
	if _, err := aiChat(r.Context(), st, "Reply with OK.", "ping"); err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *server) handleGetAIPrompts(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	p, err := s.aiPromptConf(r.Context())
	if err != nil {
		writeInternal(w, "get ai prompts", err)
		return
	}
	writeJSON(w, 200, p)
}

func (s *server) handlePutAIPrompts(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	var p aiPrompts
	if err := readJSON(r, 64<<10, &p); err != nil {
		writeBodyErr(w, err)
		return
	}
	if len(p.VulnGuide) > 16<<10 || len(p.ProjectReport) > 16<<10 {
		writeErr(w, 400, "bad_request", "프롬프트는 16KB를 넘을 수 없습니다.")
		return
	}
	if err := s.putSetting(r.Context(), "ai_prompts", p); err != nil {
		writeInternal(w, "put ai prompts", err)
		return
	}
	s.audit(r.Context(), c, "settings.update", nil, "ai_prompts", map[string]any{
		"vuln_guide_custom": p.VulnGuide != "", "project_report_custom": p.ProjectReport != ""})
	writeJSON(w, 200, p)
}

// ---- LLM call ----

// cleanAnswer drops reasoning: everything up to and including the last closing reasoning tag.
func cleanAnswer(s string) string {
	for _, tag := range []string{"</think>", "</thinking>", "</reasoning>"} {
		if i := strings.LastIndex(s, tag); i >= 0 {
			s = s[i+len(tag):]
		}
	}
	return strings.TrimSpace(s)
}

func aiTokens(parts ...string) (n int) {
	for _, p := range parts {
		n += len([]rune(p)) / 2
	}
	return
}

// aiChat calls <base_url>/chat/completions, the only URL this feature ever talks to. Errors are Korean and
// carry nothing from the upstream body.
func aiChat(ctx context.Context, st aiSettings, system, user string) (string, error) {
	if st.BaseURL == "" || st.Model == "" {
		return "", errors.New("AI 연결 설정(Base URL, 모델)이 비어 있습니다.")
	}
	cl := &http.Client{Timeout: time.Duration(st.TimeoutSec) * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	body := map[string]any{"model": st.Model, "temperature": 0.2,
		"messages": []map[string]string{{"role": "system", "content": system}, {"role": "user", "content": user}}}
	for attempt := 0; ; attempt++ {
		b, _ := json.Marshal(body)
		req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(st.BaseURL, "/")+"/chat/completions", bytes.NewReader(b))
		if err != nil {
			return "", errors.New("AI 연결 설정의 Base URL이 올바르지 않습니다.")
		}
		req.Header.Set("Content-Type", "application/json")
		if st.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+st.APIKey)
		}
		resp, err := cl.Do(req)
		if err != nil {
			log.Printf("ai: request: %v", err)
			return "", errors.New("AI 서버에 연결하지 못했습니다. 주소와 응답 대기 시간을 확인하세요.")
		}
		raw, rerr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if resp.StatusCode/100 == 4 && attempt == 0 {
			delete(body, "temperature") // some servers reject it
			continue
		}
		if resp.StatusCode/100 != 2 || rerr != nil {
			return "", fmt.Errorf("AI 서버가 오류를 반환했습니다 (HTTP %d).", resp.StatusCode)
		}
		var out struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		if json.Unmarshal(raw, &out) != nil || len(out.Choices) == 0 {
			return "", errors.New("AI 서버의 응답 형식이 올바르지 않습니다.")
		}
		ans := cleanAnswer(out.Choices[0].Message.Content)
		if ans == "" {
			return "", errors.New("AI 서버가 빈 응답을 보냈습니다.")
		}
		return ans, nil
	}
}

// ---- routes ----

const sevRank = `case severity when 'CRITICAL' then 0 when 'HIGH' then 1 when 'MEDIUM' then 2 when 'LOW' then 3 else 4 end`

func (s *server) aiEnabled(w http.ResponseWriter, ctx context.Context) bool {
	st, err := s.aiConf(ctx)
	if err != nil {
		writeInternal(w, "ai conf", err)
		return false
	}
	if !st.Enabled || st.BaseURL == "" {
		writeErr(w, 409, "ai_disabled", "AI 기능이 꺼져 있습니다. 관리자에게 문의하세요.")
		return false
	}
	return true
}

// startRun records a queued run and its job in one transaction.
func (s *server) startRun(ctx context.Context, kind string, projectID *int64, vulnID *string, userID int64) (int64, error) {
	var id int64
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `insert into ai_runs(kind, project_id, vuln_id, requested_by) values($1, $2, $3, $4) returning id`,
			kind, projectID, vulnID, userID).Scan(&id); err != nil {
			return err
		}
		_, err := s.enqueue(ctx, tx, "ai", nil, map[string]int64{"run_id": id}, 0)
		return err
	})
	return id, err
}

func (s *server) handleAIGuide(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx, vid := r.Context(), r.PathValue("id")
	if c.User == nil {
		writeErr(w, 403, "forbidden", "권한이 없습니다.")
		return
	}
	var one int
	if err := s.db.QueryRow(ctx, `select 1 from vulns where id=$1`, vid).Scan(&one); errors.Is(err, pgx.ErrNoRows) {
		writeErr(w, 404, "not_found", "취약점 정보를 찾을 수 없습니다.")
		return
	} else if err != nil {
		writeInternal(w, "ai guide", err)
		return
	}
	if !s.aiEnabled(w, ctx) {
		return
	}
	id, err := s.startRun(ctx, "vuln_guide", nil, &vid, c.User.ID)
	if err != nil {
		writeInternal(w, "ai guide run", err)
		return
	}
	s.audit(ctx, c, "ai.guide", nil, vid, map[string]any{"run_id": id})
	writeJSON(w, 202, map[string]any{"run_id": id})
}

func (s *server) handleAIReport(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	if c.User == nil || !s.aiEnabled(w, ctx) {
		if c.User == nil {
			writeErr(w, 403, "forbidden", "권한이 없습니다.")
		}
		return
	}
	id, err := s.startRun(ctx, "project_report", &c.Project.ID, nil, c.User.ID)
	if err != nil {
		writeInternal(w, "ai report run", err)
		return
	}
	s.audit(ctx, c, "ai.report", &c.Project.ID, c.Project.Key, map[string]any{"run_id": id})
	writeJSON(w, 202, map[string]any{"run_id": id})
}

type aiRunView struct {
	ID          int64      `json:"id"`
	Kind        string     `json:"kind"`
	ProjectID   *int64     `json:"project_id"`
	VulnID      *string    `json:"vuln_id"`
	RequestedBy *int64     `json:"requested_by"`
	State       string     `json:"state"`
	Output      string     `json:"output"`
	Error       string     `json:"error"`
	CreatedAt   time.Time  `json:"created_at"`
	FinishedAt  *time.Time `json:"finished_at"`
}

const aiRunCols = `select id, kind, project_id, vuln_id, requested_by, state, %s, error, created_at, finished_at from ai_runs `

func (s *server) handleAIRun(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	notFound := func() { writeErr(w, 404, "not_found", "찾을 수 없습니다.") }
	n, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || c.User == nil {
		notFound()
		return
	}
	var v aiRunView
	err = s.db.QueryRow(ctx, fmt.Sprintf(aiRunCols, "output")+`where id=$1`, n).Scan(&v.ID, &v.Kind, &v.ProjectID, &v.VulnID,
		&v.RequestedBy, &v.State, &v.Output, &v.Error, &v.CreatedAt, &v.FinishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		notFound()
		return
	}
	if err != nil {
		writeInternal(w, "ai run", err)
		return
	}
	ok := false
	if v.ProjectID == nil {
		ok = c.User.SystemRole == "admin" || v.RequestedBy != nil && *v.RequestedBy == c.User.ID
	} else {
		role, err := projectRole(s, ctx, c.User, *v.ProjectID)
		if err != nil {
			writeInternal(w, "ai run access", err)
			return
		}
		ok = role != ""
	}
	if !ok {
		notFound()
		return
	}
	writeJSON(w, 200, v)
}

// handleAIReports lists a project's report runs, newest first, without the (large) output.
func (s *server) handleAIReports(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	rows, _ := s.db.Query(r.Context(), fmt.Sprintf(aiRunCols, "''")+`where project_id=$1 and kind='project_report' order by id desc limit 50`, c.Project.ID)
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[aiRunView])
	if err != nil {
		writeInternal(w, "ai reports", err)
		return
	}
	if list == nil {
		list = []aiRunView{}
	}
	writeJSON(w, 200, list)
}

// ---- job ----

func (s *server) runAIJob(ctx context.Context, j *job) error {
	var p struct {
		RunID int64 `json:"run_id"`
	}
	if err := json.Unmarshal(j.Payload, &p); err != nil {
		return err
	}
	var kind string
	var projectID *int64
	var vulnID *string
	var by *int64
	if err := s.db.QueryRow(ctx, `update ai_runs set state='running' where id=$1 returning kind, project_id, vuln_id, requested_by`, p.RunID).
		Scan(&kind, &projectID, &vulnID, &by); err != nil {
		return err
	}
	var out string
	var err error
	switch {
	case kind == "vuln_guide" && vulnID != nil:
		out, err = s.genGuide(ctx, *vulnID, by)
	case kind == "project_report" && projectID != nil:
		out, err = s.genReport(ctx, *projectID)
	default:
		err = errors.New("잘못된 실행 정보입니다.")
	}
	if err != nil {
		_, uerr := s.db.Exec(context.WithoutCancel(ctx), `update ai_runs set state='failed', error=$2, finished_at=now() where id=$1`, p.RunID, err.Error())
		return errors.Join(err, uerr)
	}
	_, err = s.db.Exec(ctx, `update ai_runs set state='done', output=$2, finished_at=now() where id=$1`, p.RunID, out)
	return err
}

var errAITooBig = errors.New("AI에 보낼 입력이 최대 입력 토큰을 넘어 보고서를 만들 수 없습니다. 관리자에게 최대 입력 토큰을 늘려 달라고 요청하세요.")

// fitLines builds the user message with as many of the n lines (already ordered most important first) as fit
// the token limit, dropping from the end. It fails when even none fit.
func fitLines(max int, system string, n int, build func(k int) string) (string, error) {
	for k := n; k >= 0; k-- {
		msg := build(k)
		if k < n {
			msg += fmt.Sprintf("\n\n(입력 길이 제한으로 심각도가 낮은 항목 %d건을 생략했습니다.)", n-k)
		}
		if aiTokens(system, msg) <= max {
			return msg, nil
		}
	}
	return "", errAITooBig
}

func truncRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func (s *server) genGuide(ctx context.Context, vid string, by *int64) (string, error) {
	st, err := s.aiConf(ctx)
	if err != nil {
		return "", err
	}
	pr, err := s.aiPromptConf(ctx)
	if err != nil {
		return "", err
	}
	system := cmpOr(pr.VulnGuide, defaultVulnGuidePrompt)
	var title, desc, vector, general string
	var score *float64
	var cwes, refs []string
	err = s.db.QueryRow(ctx, `select title, description, cvss_score::float8, cvss_vector, cwe_ids, refs, ai_guide from vulns where id=$1`, vid).
		Scan(&title, &desc, &score, &vector, &cwes, &refs, &general)
	if err != nil {
		return "", errors.New("취약점 정보를 찾을 수 없습니다.")
	}
	if general == "" { // part 1 depends on the catalog only, so it is shared by everyone
		if len(refs) > 10 {
			refs = refs[:10]
		}
		msg := fmt.Sprintf("[파트 1: 일반 설명]\nID: %s\n제목: %s\nCVSS: %s %s\nCWE: %s\n설명: %s\n참고: %s",
			vid, title, fmtScore(score), vector, strings.Join(cwes, ", "), truncRunes(desc, 4000), strings.Join(refs, ", "))
		if aiTokens(system, msg) > st.MaxInputTokens {
			return "", errAITooBig
		}
		if general, err = aiChat(ctx, st, system, msg); err != nil {
			return "", err
		}
		s.db.Exec(ctx, `update vulns set ai_guide=$2, ai_guide_at=now() where id=$1`, vid, general)
	}
	impact := "## 내 영향\n내가 볼 수 있는 프로젝트에는 이 취약점이 열린 상태로 발견된 항목이 없습니다."
	var u *user
	if by != nil {
		if u, err = s.loadUser(ctx, *by); err != nil {
			u = nil
		}
	}
	cond, args := s.visibleProjectsSQL(u, "f", 2)
	rows, _ := s.db.Query(ctx, `select p.key, t.name, f.pkg_name, f.pkg_version, f.fixed_version, f.severity
		from findings f join targets t on t.id = f.target_id join projects p on p.id = f.project_id
		where f.rule_id=$1 and f.status='open' and `+cond+` order by `+strings.ReplaceAll(sevRank, "severity", "f.severity")+`, p.key, t.name, f.id limit 200`, append([]any{vid}, args...)...)
	type row struct{ Proj, Target, Pkg, Ver, Fixed, Sev string }
	items, err := pgx.CollectRows(rows, pgx.RowToStructByPos[row])
	if err != nil {
		return "", err
	}
	if len(items) > 0 {
		msg, err := fitLines(st.MaxInputTokens, system, len(items), func(k int) string {
			var b strings.Builder
			fmt.Fprintf(&b, "[파트 2: 내 영향]\nCVE: %s (%s)\n내가 볼 수 있는 프로젝트의 열린 항목:\n", vid, title)
			for _, it := range items[:k] {
				fmt.Fprintf(&b, "- 프로젝트 %s / 대상 %s / %s %s / 조치 버전 %s / %s\n", it.Proj, it.Target, it.Pkg, it.Ver, cmpOr(it.Fixed, "없음"), it.Sev)
			}
			return b.String()
		})
		if err != nil {
			return "", err
		}
		if impact, err = aiChat(ctx, st, system, msg); err != nil {
			return "", err
		}
	}
	return general + "\n\n" + impact, nil
}

func fmtScore(f *float64) string {
	if f == nil {
		return "-"
	}
	return strconv.FormatFloat(*f, 'f', 1, 64)
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (s *server) genReport(ctx context.Context, pid int64) (string, error) {
	st, err := s.aiConf(ctx)
	if err != nil {
		return "", err
	}
	pr, err := s.aiPromptConf(ctx)
	if err != nil {
		return "", err
	}
	system := cmpOr(pr.ProjectReport, defaultProjectReportPrompt)
	var key, name string
	if err := s.db.QueryRow(ctx, `select key, name from projects where id=$1`, pid).Scan(&key, &name); err != nil {
		return "", errors.New("프로젝트를 찾을 수 없습니다.")
	}
	var head strings.Builder
	fmt.Fprintf(&head, "프로젝트: %s (%s)\n", name, key)
	// severity summary of open findings
	rows, _ := s.db.Query(ctx, `select severity, count(*) from findings where project_id=$1 and status='open' group by severity order by `+sevRank, pid)
	type cnt struct {
		Sev string
		N   int
	}
	counts, err := pgx.CollectRows(rows, pgx.RowToStructByPos[cnt])
	if err != nil {
		return "", err
	}
	head.WriteString("열린 결과 수:")
	for _, c := range counts {
		fmt.Fprintf(&head, " %s %d", c.Sev, c.N)
	}
	if len(counts) == 0 {
		head.WriteString(" 없음")
	}
	// exceptions in force or waiting
	rows, _ = s.db.Query(ctx, `select scope, coalesce(vuln_id, ''), resolution, status, to_char(expires_at at time zone 'UTC', 'YYYY-MM-DD')
		from exceptions where project_id=$1 and status in ('pending','approved') order by expires_at limit 20`, pid)
	type ex struct{ Scope, Vuln, Res, Status, Exp string }
	exc, err := pgx.CollectRows(rows, pgx.RowToStructByPos[ex])
	if err != nil {
		return "", err
	}
	head.WriteString("\n\n예외(승인·대기):\n")
	for _, e := range exc {
		fmt.Fprintf(&head, "- %s %s %s %s (만료 %s)\n", e.Scope, e.Vuln, e.Res, e.Status, e.Exp)
	}
	if len(exc) == 0 {
		head.WriteString("- 없음\n")
	}
	// 30-day trend: first seen (new) and fixed per day, only days with something
	rows, _ = s.db.Query(ctx, `select d::date::text, (select count(*) from findings where project_id=$1 and first_seen_at::date = d::date),
			(select count(*) from findings where project_id=$1 and fixed_at::date = d::date)
		from generate_series(current_date - 29, current_date, '1 day') d order by d`, pid)
	type tr struct {
		Day      string
		New, Fix int
	}
	trend, err := pgx.CollectRows(rows, pgx.RowToStructByPos[tr])
	if err != nil {
		return "", err
	}
	head.WriteString("\n최근 30일 추세(날짜: 새로 발견 / 해결):\n")
	for _, t := range trend {
		if t.New != 0 || t.Fix != 0 {
			fmt.Fprintf(&head, "- %s: +%d / -%d\n", t.Day, t.New, t.Fix)
		}
	}
	// top 50 open findings, most severe and oldest first
	rows, _ = s.db.Query(ctx, `select f.severity, f.rule_id, t.name, f.pkg_name, f.pkg_version, f.fixed_version, f.title,
			greatest(0, (current_date - f.first_seen_at::date))
		from findings f join targets t on t.id = f.target_id where f.project_id=$1 and f.status='open'
		order by `+strings.ReplaceAll(sevRank, "severity", "f.severity")+`, f.first_seen_at, f.id limit 50`, pid)
	type fr struct {
		Sev, Rule, Target, Pkg, Ver, Fixed, Title string
		Days                                      int
	}
	items, err := pgx.CollectRows(rows, pgx.RowToStructByPos[fr])
	if err != nil {
		return "", err
	}
	msg, err := fitLines(st.MaxInputTokens, system, len(items), func(k int) string {
		var b strings.Builder
		b.WriteString(head.String() + "\n열린 결과 (심각도 높은 순, 오래된 순):\n")
		for _, it := range items[:k] {
			fmt.Fprintf(&b, "- %s %s / 대상 %s / %s %s → %s / %s / %d일째 열림\n", it.Sev, it.Rule, it.Target, it.Pkg, it.Ver, cmpOr(it.Fixed, "조치 버전 없음"), truncRunes(it.Title, 80), it.Days)
		}
		return b.String()
	})
	if err != nil {
		return "", err
	}
	return aiChat(ctx, st, system, msg)
}
