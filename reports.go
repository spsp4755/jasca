package main

import (
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

func init() { routeRegistrars = append(routeRegistrars, (*server).reportRoutes) }

func (s *server) reportRoutes() {
	s.handle("GET /api/v1/projects/{key}/report", permProj("viewer"), s.handleProjectReport)
}

type reportFinding struct {
	ID           int64     `json:"id"`
	Target       string    `json:"target"`
	Kind         string    `json:"kind"`
	RuleID       string    `json:"rule_id"`
	Title        string    `json:"title"`
	Severity     string    `json:"severity"`
	PkgName      string    `json:"pkg_name"`
	PkgVersion   string    `json:"pkg_version"`
	FixedVersion string    `json:"fixed_version"`
	FirstSeenAt  time.Time `json:"first_seen_at"`
}

// handleProjectReport returns everything the printable report page shows; the page does the layout.
func (s *server) handleProjectReport(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx, pid := r.Context(), c.Project.ID
	fail := func(err error) { writeInternal(w, "report", err) }
	rep := struct {
		Project     *project        `json:"project"`
		GeneratedAt time.Time       `json:"generated_at"`
		Summary     any             `json:"summary"`
		Targets     []targetView    `json:"targets"`
		Findings    []reportFinding `json:"findings"`
		Exceptions  []exception     `json:"exceptions"` // as GET /exceptions lists them, so the page names them the same way
		Policy      policy          `json:"policy"`
		AIReport    any             `json:"ai_report"`
	}{Project: c.Project, GeneratedAt: time.Now().UTC()}
	var sev sevCounts
	var byKind struct{ Vuln, Misconfig, Secret, SAST int }
	if err := s.db.QueryRow(ctx, `select count(*) filter (where severity = 'CRITICAL'), count(*) filter (where severity = 'HIGH'),
			count(*) filter (where severity = 'MEDIUM'), count(*) filter (where severity = 'LOW'),
			count(*) filter (where severity = 'UNKNOWN'), count(*), count(*) filter (where kind = 'vuln'),
			count(*) filter (where kind = 'misconfig'), count(*) filter (where kind = 'secret'), count(*) filter (where kind = 'sast')
		from findings where status = 'open' and project_id = $1`, pid).
		Scan(&sev.Critical, &sev.High, &sev.Medium, &sev.Low, &sev.Unknown, &sev.Open, &byKind.Vuln, &byKind.Misconfig, &byKind.Secret, &byKind.SAST); err != nil {
		fail(err)
		return
	}
	rep.Summary = map[string]any{"by_severity": sev,
		"by_kind": map[string]int{"vuln": byKind.Vuln, "misconfig": byKind.Misconfig, "secret": byKind.Secret, "sast": byKind.SAST}}
	trows, err := s.db.Query(ctx, `select t.id, t.kind, t.name, t.last_scan_at, t.recheck_excluded, fc.*
		from targets t cross join lateral `+openCountsSQL("f.target_id = t.id")+` fc where t.project_id = $1 order by t.name, t.kind`, pid)
	if err != nil {
		fail(err)
		return
	}
	rep.Targets = []targetView{}
	for trows.Next() {
		var v targetView
		k := &v.Counts
		if err := trows.Scan(&v.ID, &v.Kind, &v.Name, &v.LastScanAt, &v.RecheckExcluded, &k.Critical, &k.High, &k.Medium, &k.Low, &k.Unknown, &k.Open); err != nil {
			trows.Close()
			fail(err)
			return
		}
		rep.Targets = append(rep.Targets, v)
	}
	if err := trows.Err(); err != nil {
		fail(err)
		return
	}
	if rep.Findings, err = collect[reportFinding](ctx, s, `select f.id, t.name, f.kind, f.rule_id, f.title, f.severity, f.pkg_name,
			f.pkg_version, f.fixed_version, f.first_seen_at from findings f join targets t on t.id = f.target_id
		where f.project_id = $1 and f.status = 'open'
		order by array_position(array['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'], f.severity), f.first_seen_at, f.id limit 100`, pid); err != nil {
		fail(err)
		return
	}
	if rep.Exceptions, err = collect[exception](ctx, s, exceptionCols+`where e.project_id = $1 and e.status = 'approved' and e.expires_at > now()
		order by e.expires_at, e.id`, pid); err != nil {
		fail(err)
		return
	}
	if rep.Policy, err = s.projectPolicy(ctx, pid); err != nil {
		fail(err)
		return
	}
	var ai struct {
		ID        int64     `json:"id"`
		Output    string    `json:"output"`
		CreatedAt time.Time `json:"created_at"`
	}
	switch err := s.db.QueryRow(ctx, `select id, output, coalesce(finished_at, created_at) from ai_runs
		where kind = 'project_report' and project_id = $1 and state = 'done' order by id desc limit 1`, pid).Scan(&ai.ID, &ai.Output, &ai.CreatedAt); {
	case err == nil:
		rep.AIReport = ai
	case !errors.Is(err, pgx.ErrNoRows):
		fail(err)
		return
	}
	writeJSON(w, 200, rep)
}
