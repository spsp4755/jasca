package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

func init() { routeRegistrars = append(routeRegistrars, (*server).dashboardRoutes) }

func (s *server) dashboardRoutes() {
	s.handle("GET /api/v1/dashboard", permUser, s.handleDashboard)
}

type trendPoint struct {
	Date     string `json:"date"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
}

// dashFinding and the structs below list their fields in the order of the SELECTs (RowToStructByPos).
type dashFinding struct {
	ID           int64      `json:"id"`
	ProjectKey   string     `json:"project_key"`
	Target       string     `json:"target"`
	RuleID       string     `json:"rule_id"`
	Title        string     `json:"title"`
	Severity     string     `json:"severity"`
	PkgName      string     `json:"pkg_name"`
	PkgVersion   string     `json:"pkg_version"`
	FixedVersion string     `json:"fixed_version"`
	Location     string     `json:"location"` // where a secret or misconfiguration sits; those have no package
	Origin       string     `json:"origin"`
	FirstSeenAt  time.Time  `json:"first_seen_at"`
	DueAt        *time.Time `json:"due_at"`
}

type dashScan struct {
	ID         int64           `json:"id"`
	ProjectKey string          `json:"project_key"`
	Target     string          `json:"target"`
	Source     string          `json:"source"`
	Status     string          `json:"status"`
	Summary    json.RawMessage `json:"summary"`
	Policy     json.RawMessage `json:"policy"`
	CreatedAt  time.Time       `json:"created_at"`
}

const dashFindingSQL = `select f.id, p.key, t.name, f.rule_id, f.title, f.severity, f.pkg_name, f.pkg_version, f.fixed_version,
	f.location, f.origin, f.first_seen_at, f.due_at from findings f join projects p on p.id = f.project_id join targets t on t.id = f.target_id where `

func collect[T any](ctx context.Context, s *server, q string, args ...any) ([]T, error) {
	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[T])
	if out == nil {
		out = []T{}
	}
	return out, err
}

func (s *server) handleDashboard(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	fail := func(err error) { writeInternal(w, "dashboard", err) }
	// project_id of an exception, scan and finding alike is read as alias.project_id; a global exception
	// (NULL project) is visible to admin and security only, which visibleProjectsSQL's "true" gives.
	vis := func(alias string, n int) (string, []any) { return s.visibleProjectsSQL(c.User, alias, n) }
	d := struct {
		Totals      sevCounts     `json:"totals"`
		Trend       []trendPoint  `json:"trend"`
		Oldest      []dashFinding `json:"oldest_critical"`
		Expiring    []exception   `json:"expiring_exceptions"`
		RecentScans []dashScan    `json:"recent_scans"`
		NewlyKnown  []dashFinding `json:"newly_known"`
		Overdue     sevCounts     `json:"overdue"` // open findings past their deadline; open = all of them
		Mine        struct {
			Open    int `json:"open"`
			Overdue int `json:"overdue"`
		} `json:"mine"` // open findings assigned to the caller
	}{}
	cond, args := vis("f", 1)
	k := &d.Totals
	if err := s.db.QueryRow(ctx, `select count(*) filter (where severity = 'CRITICAL'), count(*) filter (where severity = 'HIGH'),
			count(*) filter (where severity = 'MEDIUM'), count(*) filter (where severity = 'LOW'),
			count(*) filter (where severity = 'UNKNOWN'), count(*) from findings f where f.status = 'open' and `+cond, args...).
		Scan(&k.Critical, &k.High, &k.Medium, &k.Low, &k.Unknown, &k.Open); err != nil {
		fail(err)
		return
	}
	o := &d.Overdue
	if err := s.db.QueryRow(ctx, `select * from `+openCountsSQL("f.due_at < now() and "+cond)+` x`, args...).
		Scan(&o.Critical, &o.High, &o.Medium, &o.Low, &o.Unknown, &o.Open); err != nil {
		fail(err)
		return
	}
	// the caller's own, in the projects they can still see: the same findings as GET /findings?assignee=me
	cond, args = vis("f", 2)
	if err := s.db.QueryRow(ctx, `select count(*), count(*) filter (where f.due_at < now()) from findings f
		where f.status = 'open' and f.assignee_id = $1 and `+cond, append([]any{c.User.ID}, args...)...).Scan(&d.Mine.Open, &d.Mine.Overdue); err != nil {
		fail(err)
		return
	}
	// Open on day D = first seen before the end of D and not fixed before then (accepted and false-positive
	// findings are left out). Days are in JASCA_TZ.
	tz := s.cfg.Loc.String()
	cond, args = vis("f", 2)
	rows, err := s.db.Query(ctx, `select to_char(d, 'YYYY-MM-DD'),
			count(f.id) filter (where f.severity = 'CRITICAL'), count(f.id) filter (where f.severity = 'HIGH'),
			count(f.id) filter (where f.severity = 'MEDIUM'), count(f.id) filter (where f.severity = 'LOW')
		from generate_series((now() at time zone $1)::date::timestamp - interval '29 days', (now() at time zone $1)::date::timestamp, interval '1 day') d
		left join findings f on f.status in ('open', 'fixed') and f.first_seen_at < (d + interval '1 day') at time zone $1
			and (f.fixed_at is null or f.fixed_at >= (d + interval '1 day') at time zone $1) and `+cond+`
		group by d order by d`, append([]any{tz}, args...)...)
	if err != nil {
		fail(err)
		return
	}
	if d.Trend, err = pgx.CollectRows(rows, pgx.RowToStructByPos[trendPoint]); err != nil {
		fail(err)
		return
	}
	cond, args = vis("f", 1)
	if d.Oldest, err = collect[dashFinding](ctx, s, dashFindingSQL+`f.status = 'open' and f.severity = 'CRITICAL' and `+cond+
		` order by f.first_seen_at, f.id limit 10`, args...); err != nil {
		fail(err)
		return
	}
	if d.NewlyKnown, err = collect[dashFinding](ctx, s, dashFindingSQL+`f.status = 'open' and f.origin in ('recheck', 'advisory')
		and f.first_seen_at > now() - interval '7 days' and `+cond+` order by f.first_seen_at desc, f.id limit 10`, args...); err != nil {
		fail(err)
		return
	}
	cond, args = vis("e", 1)
	if d.Expiring, err = collect[exception](ctx, s, exceptionCols+`where e.status = 'approved'
		and e.expires_at > now() and e.expires_at <= now() + interval '14 days' and `+cond+` order by e.expires_at, e.id limit 50`, args...); err != nil {
		fail(err)
		return
	}
	cond, args = vis("sc", 1)
	if d.RecentScans, err = collect[dashScan](ctx, s, `select sc.id, p.key, t.name, sc.source, sc.status, sc.summary, sc.policy, sc.created_at
		from scans sc join projects p on p.id = sc.project_id join targets t on t.id = sc.target_id
		where `+cond+` order by sc.created_at desc, sc.id desc limit 10`, args...); err != nil {
		fail(err)
		return
	}
	writeJSON(w, 200, d)
}
