package main

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/spsp4755/jasca/internal/formats"
)

func (s *server) scanRoutes() {
	s.registerObj("scan", s.objByID(`select project_id from scans where id = $1`))
	s.handle("POST /api/v1/projects/{key}/scans", permUpload, s.handleScanUpload)
	s.handle("GET /api/v1/projects/{key}/scans", permProj("viewer"), s.handleScanList)
	s.handle("GET /api/v1/scans/{id}", permObj("scan", "viewer"), s.handleScanGet)
	s.handle("GET /api/v1/scans/{id}/findings", permObj("scan", "viewer"), s.handleScanFindings)
	s.handle("GET /api/v1/scans/{id}/raw", permObj("scan", "viewer"), s.handleScanRaw)
}

var targetKinds = []string{"image", "repo", "fs", "sbom"}

// handleScanUpload takes a raw report (optionally Content-Encoding: gzip). Query: target, kind, ref override what the
// report says; format skips detection; scanners=vuln,misconfig,secret marks those kinds complete for the report's
// tool, since Trivy JSON does not say which scanners ran.
func (s *server) handleScanUpload(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	q := r.URL.Query()
	max := s.cfg.MaxReportMB << 20
	tooLarge := func() {
		writeErr(w, 413, "too_large", fmt.Sprintf("보고서는 %dMB 이하만 올릴 수 있습니다.", s.cfg.MaxReportMB))
	}
	unreadable := func() {
		badRequest(w, "보고서를 읽지 못했습니다. 압축이 잘렸거나 손상되었습니다.")
	}
	// both limits: the decoded size is what counts, the compressed one stops endless empty gzip members
	var body io.Reader = http.MaxBytesReader(w, r.Body, max)
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(body)
		if err != nil {
			unreadable()
			return
		}
		body = zr
	}
	raw, err := io.ReadAll(io.LimitReader(body, max+1))
	if _, ok := errors.AsType[*http.MaxBytesError](err); ok || int64(len(raw)) > max {
		tooLarge()
		return
	}
	if err != nil {
		unreadable()
		return
	}
	var p formats.Parser
	var ok bool
	if f := q.Get("format"); f != "" {
		p, ok = formats.Get(f)
	} else {
		p, ok = formats.Detect(raw[:min(len(raw), 8192)])
	}
	if !ok {
		writeErr(w, 400, "unsupported_format", "지원하지 않는 보고서 형식입니다. Trivy JSON, SARIF, Harbor, CycloneDX 보고서를 올리세요.")
		return
	}
	rep, err := p.Parse(bytes.NewReader(raw))
	if err != nil {
		badRequest(w, "보고서를 해석하지 못했습니다. 파일이 잘렸거나 형식이 맞지 않습니다.")
		return
	}
	kind := cmp.Or(q.Get("kind"), rep.TargetKind)
	name := strings.TrimSpace(cmp.Or(q.Get("target"), rep.TargetName))
	ref := cmp.Or(q.Get("ref"), rep.Ref)
	if !slices.Contains(targetKinds, kind) {
		badRequest(w, "대상 종류(kind)는 image, repo, fs, sbom 중 하나로 지정하세요.")
		return
	}
	if name == "" || utf8.RuneCountInString(name) > 512 || len(ref) > 512 {
		badRequest(w, "대상 이름(target)은 1~512자, ref는 512자 이하로 지정하세요.")
		return
	}
	if v := q.Get("scanners"); v != "" {
		if rep.Complete == nil {
			rep.Complete = map[string]bool{}
		}
		tools := []string{}
		if rep.Format == "trivy" {
			tools = append(tools, "trivy")
		}
		for k := range rep.Complete {
			_, tool, _ := strings.Cut(k, ":")
			tools = append(tools, tool)
		}
		for _, sc := range strings.Split(v, ",") {
			if !slices.Contains([]string{"vuln", "misconfig", "secret"}, sc) {
				badRequest(w, "scanners는 vuln, misconfig, secret을 쉼표로 이어 지정하세요.")
				return
			}
			for _, tool := range tools {
				rep.Complete[sc+":"+tool] = true
			}
		}
	}
	in := ingestInput{ProjectID: c.Project.ID, TargetKind: kind, TargetName: name, Ref: ref, Source: "upload", Report: rep, Raw: raw}
	if c.User != nil {
		in.UserID = &c.User.ID
	}
	if c.Token != nil {
		in.TokenID = &c.Token.ID
	}
	res, err := s.ingest(ctx, in)
	if err != nil {
		writeInternal(w, "ingest", err)
		return
	}
	s.audit(ctx, c, "scan.upload", &c.Project.ID, kind+":"+name, map[string]any{"scan_id": res.ScanID, "format": rep.Format,
		"ref": ref, "duplicate": res.Duplicate, "findings": len(rep.Findings), "policy_passed": res.Policy.Passed})
	status := 201
	if res.Duplicate {
		status = 200
	}
	writeJSON(w, status, map[string]any{"scan_id": res.ScanID, "target_id": res.TargetID, "summary": res.Summary,
		"policy": res.Policy, "duplicate": res.Duplicate})
}

type scanView struct {
	ID             int64           `json:"id"`
	ProjectID      int64           `json:"project_id"`
	TargetID       int64           `json:"target_id"`
	TargetKind     string          `json:"target_kind"`
	TargetName     string          `json:"target_name"`
	Source         string          `json:"source"`
	Format         string          `json:"format"`
	Ref            string          `json:"ref"`
	Status         string          `json:"status"`
	Error          string          `json:"error"`
	CreatedByUser  *int64          `json:"created_by_user"`
	CreatedByToken *int64          `json:"created_by_token"`
	CreatedBy      string          `json:"created_by"` // who to show: the user's name or the token's name
	Summary        json.RawMessage `json:"summary"`
	Policy         json.RawMessage `json:"policy"` // null until evaluated
	HasRaw         bool            `json:"has_raw"`
	CreatedAt      time.Time       `json:"created_at"`
	FinishedAt     *time.Time      `json:"finished_at"`
}

const scanCols = `select s.id, s.project_id, s.target_id, t.kind, t.name, s.source, s.format, s.ref, s.status, s.error,
		s.created_by_user, s.created_by_token,
		coalesce((select coalesce(nullif(u.name, ''), u.username) from users u where u.id = s.created_by_user),
			(select 'API 토큰 ' || k.name from api_tokens k where k.id = s.created_by_token), ''),
		s.summary, s.policy, s.raw is not null, s.created_at, s.finished_at
	from scans s join targets t on t.id = s.target_id `

func (s *server) handleScanList(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	q := r.URL.Query()
	f := &where{}
	f.add("s.project_id = ?", c.Project.ID)
	for _, p := range []struct{ name, cond string }{{"target_id", "s.target_id = ?"}, {"before", "s.id < ?"}} {
		if v := q.Get(p.name); v != "" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				badRequest(w, p.name+"는 숫자여야 합니다.")
				return
			}
			f.add(p.cond, n)
		}
	}
	limit, msg := pageLimit(q.Get("limit"))
	if msg != "" {
		badRequest(w, msg)
		return
	}
	rows, _ := s.db.Query(r.Context(), scanCols+`where `+f.sql()+` order by s.id desc limit `+strconv.Itoa(limit), f.args...)
	items, err := pgx.CollectRows(rows, pgx.RowToStructByPos[scanView])
	if err != nil {
		writeInternal(w, "scan list", err)
		return
	}
	var next *int64
	if len(items) == limit {
		next = &items[len(items)-1].ID
	}
	writeJSON(w, 200, map[string]any{"items": items, "next_before": next})
}

// scanDiff compares a scan with the previous finished scan of the same target and format:
// new = only in this scan, fixed = only in the previous one, unchanged = in both.
type scanDiff struct {
	New            int    `json:"new"`
	Fixed          int    `json:"fixed"`
	Unchanged      int    `json:"unchanged"`
	PreviousScanID *int64 `json:"previous_scan_id"`
}

func (s *server) handleScanGet(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	id := pathID(r)
	rows, _ := s.db.Query(ctx, scanCols+`where s.id = $1`, id)
	v, err := pgx.CollectOneRow(rows, pgx.RowToStructByPos[scanView])
	if err != nil {
		writeInternal(w, "scan get", err)
		return
	}
	var d scanDiff
	err = s.db.QueryRow(ctx, `with prev as (select p.id from scans p join scans c on c.id = $1 and p.target_id = c.target_id
				and p.format = c.format and p.status = 'done' and p.finished_at < c.finished_at
			order by p.finished_at desc limit 1),
		cur as (select finding_id from scan_findings where scan_id = $1),
		old as (select finding_id from scan_findings where scan_id = (select id from prev))
		select (select count(*) from cur where finding_id not in (select finding_id from old)),
			(select count(*) from old where finding_id not in (select finding_id from cur)),
			(select count(*) from cur where finding_id in (select finding_id from old)),
			(select id from prev)`, id).Scan(&d.New, &d.Fixed, &d.Unchanged, &d.PreviousScanID)
	if err != nil {
		writeInternal(w, "scan diff", err)
		return
	}
	writeJSON(w, 200, struct {
		scanView
		Diff scanDiff `json:"diff"`
	}{v, d})
}

func (s *server) handleScanFindings(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	f := &where{}
	f.add("f.id in (select finding_id from scan_findings where scan_id = ?)", pathID(r))
	s.writeFindings(w, r, f)
}

func (s *server) handleScanRaw(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	id := pathID(r)
	var raw []byte
	if err := s.db.QueryRow(r.Context(), `select raw from scans where id = $1`, id).Scan(&raw); err != nil {
		writeInternal(w, "scan raw", err)
		return
	}
	if raw == nil {
		writeErr(w, 404, "not_found", "원본 보고서가 없습니다. 보존 기간이 지나 삭제되었습니다.")
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="scan-`+strconv.FormatInt(id, 10)+`.json.gz"`)
	w.Write(raw)
}
