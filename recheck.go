package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/spsp4755/jasca/internal/formats"
	"github.com/spsp4755/jasca/internal/trivy"
)

func init() { routeRegistrars = append(routeRegistrars, (*server).recheckRoutes) }

func (s *server) recheckRoutes() {
	s.registerJob("recheck", s.runRecheck)
	s.handle("GET /api/v1/admin/recheck", permAdmin, s.handleRecheckList)
	s.handle("POST /api/v1/admin/recheck", permAdmin, s.handleRecheckStart)
}

type recheckRun struct {
	ID          int64      `json:"id" db:"id"`
	Reason      string     `json:"reason" db:"reason"`
	State       string     `json:"state" db:"state"`
	Total       int        `json:"total" db:"total"`
	Done        int        `json:"done" db:"done"`
	NewFindings int        `json:"new_findings" db:"new_findings"`
	StartedAt   time.Time  `json:"started_at" db:"started_at"`
	FinishedAt  *time.Time `json:"finished_at" db:"finished_at"`
	Error       string     `json:"error" db:"error"`
}

const recheckRunCols = `id, reason, state, total, done, new_findings, started_at, finished_at, error`

var errRecheckRunning = errors.New("a recheck run is already running")

// latestInventorySQL is the newest done scan of target t that has packages: the target's current inventory, used by
// the recheck and the advisory matcher alike (a SARIF or recheck scan row has no packages and never counts)
const latestInventorySQL = `(select sc.id from scans sc where sc.target_id = t.id and sc.status = 'done'
	and exists (select 1 from packages p where p.scan_id = sc.id) order by sc.id desc limit 1)`

// startRecheck creates a run with one item per target that has an inventory and is not excluded, and queues its
// job. A manual start fails with errRecheckRunning while a run is running; a new DB ("trivydb") cancels it instead.
func (s *server) startRecheck(ctx context.Context, reason string) (int64, error) {
	var runID int64
	err := s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `select pg_advisory_xact_lock(7342009)`); err != nil { // one start at a time
			return err
		}
		if reason == "manual" {
			var running bool
			if err := tx.QueryRow(ctx, `select exists(select 1 from recheck_runs where state = 'running')`).Scan(&running); err != nil {
				return err
			}
			if running {
				return errRecheckRunning
			}
		} else if _, err := tx.Exec(ctx, `update recheck_runs set state = 'canceled', finished_at = now(),
			error = '새 DB가 올라와 재평가를 다시 시작했습니다.' where state = 'running'`); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `insert into recheck_runs(reason) values($1) returning id`, reason).Scan(&runID); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `insert into recheck_items(run_id, target_id)
			select $1, t.id from targets t where not t.recheck_excluded and `+latestInventorySQL+` is not null`, runID)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `update recheck_runs set total = $2 where id = $1`, runID, tag.RowsAffected()); err != nil {
			return err
		}
		_, err = s.enqueue(ctx, tx, "recheck", nil, map[string]int64{"run_id": runID}, prioRecheck)
		return err
	})
	return runID, err
}

func (s *server) handleRecheckList(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	rows, _ := s.db.Query(r.Context(), `select `+recheckRunCols+` from recheck_runs order by id desc limit 50`)
	runs, err := pgx.CollectRows(rows, pgx.RowToStructByName[recheckRun])
	if err != nil {
		writeInternal(w, "recheck list", err)
		return
	}
	writeJSON(w, 200, runs)
}

func (s *server) handleRecheckStart(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	id, err := s.startRecheck(ctx, "manual")
	if errors.Is(err, errRecheckRunning) {
		writeErr(w, 409, "conflict", "재평가가 이미 진행 중입니다. 끝난 뒤 다시 시작하세요.")
		return
	}
	if err != nil {
		writeInternal(w, "recheck start", err)
		return
	}
	rows, _ := s.db.Query(ctx, `select `+recheckRunCols+` from recheck_runs where id = $1`, id)
	run, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByName[recheckRun])
	if err != nil {
		writeInternal(w, "recheck start", err)
		return
	}
	s.audit(ctx, c, "recheck.start", nil, "", map[string]any{"run_id": id, "total": run.Total})
	writeJSON(w, 201, run)
}

// runRecheck works through the run's queued items in target order. Each item's result and state are committed
// together, so a restart resumes with the next item. It yields to any queued job of priority > 0.
func (s *server) runRecheck(ctx context.Context, j *job) error {
	var p struct {
		RunID int64 `json:"run_id"`
	}
	if err := json.Unmarshal(j.Payload, &p); err != nil {
		return err
	}
	err := s.recheckItems(ctx, p.RunID)
	if err != nil && !errors.Is(err, errJobYield) && ctx.Err() == nil {
		if _, e := s.db.Exec(context.WithoutCancel(ctx), `update recheck_runs set state = 'failed', finished_at = now(),
			error = '재평가 중 오류가 발생했습니다.' where id = $1 and state = 'running'`, p.RunID); e != nil {
			log.Printf("recheck run %d: mark failed: %v", p.RunID, e)
		}
	}
	return err
}

func (s *server) recheckItems(ctx context.Context, runID int64) error {
	for {
		var state string
		if err := s.db.QueryRow(ctx, `select state from recheck_runs where id = $1`, runID).Scan(&state); err != nil {
			return err
		}
		if state != "running" {
			if state == "canceled" { // superseded by a newer DB: still tell projects what this run found
				s.emitNewKnown(ctx, runID)
			}
			return nil
		}
		var targetID int64
		err := s.db.QueryRow(ctx, `select target_id from recheck_items where run_id = $1 and state = 'queued'
			order by target_id limit 1`, runID).Scan(&targetID)
		if errors.Is(err, pgx.ErrNoRows) {
			return s.finishRecheck(ctx, runID)
		}
		if err != nil {
			return err
		}
		var higher bool
		if err := s.db.QueryRow(ctx, `select exists(select 1 from jobs where state = 'queued' and priority > 0
			and run_after <= now())`).Scan(&higher); err != nil {
			return err
		}
		if higher {
			return errJobYield
		}
		if err := s.recheckTarget(ctx, runID, targetID); err != nil {
			if ctx.Err() != nil {
				return err // the item stays queued and is redone after the restart
			}
			log.Printf("recheck run %d target %d: %v", runID, targetID, err)
			if err := s.endItem(ctx, s.db, runID, targetID, "failed", 0); err != nil {
				return err
			}
		}
	}
}

// endItem marks a queued item done, failed or skipped and counts it in its run (no-op if it is not queued).
func (s *server) endItem(ctx context.Context, db interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, runID, targetID int64, state string, newFindings int) error {
	_, err := db.Exec(ctx, `with i as (update recheck_items set state = $3 where run_id = $1 and target_id = $2
			and state = 'queued' returning 1)
		update recheck_runs set done = done + (select count(*) from i), new_findings = new_findings + $4
		where id = $1 and exists (select 1 from i)`, runID, targetID, state, newFindings)
	return err
}

func (s *server) finishRecheck(ctx context.Context, runID int64) error {
	var failed int
	if err := s.db.QueryRow(ctx, `select count(*) from recheck_items where run_id = $1 and state = 'failed'`, runID).Scan(&failed); err != nil {
		return err
	}
	msg := ""
	if failed > 0 {
		msg = fmt.Sprintf("대상 %d개를 재평가하지 못했습니다. 서버 로그를 확인하세요.", failed)
	}
	tag, err := s.db.Exec(ctx, `update recheck_runs set state = 'done', finished_at = now(), error = $2
		where id = $1 and state = 'running'`, runID, msg)
	if err == nil && tag.RowsAffected() == 1 {
		s.emitNewKnown(ctx, runID)
	}
	return err
}

func recheckRef(runID int64) string { return fmt.Sprintf("recheck-run-%d", runID) }

// emitNewKnown sends new_known once per project with the number of findings the run added there.
func (s *server) emitNewKnown(ctx context.Context, runID int64) {
	rows, _ := s.db.Query(ctx, `select sc.project_id, count(*) from scans sc join scan_findings sf on sf.scan_id = sc.id
		where sc.source = 'recheck' and sc.ref = $1 group by sc.project_id order by sc.project_id`, recheckRef(runID))
	type pc struct {
		Project int64
		Count   int
	}
	got, err := pgx.CollectRows(rows, pgx.RowToStructByPos[pc])
	if err != nil {
		log.Printf("recheck run %d: new_known: %v", runID, err)
		return
	}
	for _, g := range got {
		s.emit(ctx, g.Project, "new_known", map[string]any{"run_id": runID, "count": g.Count})
	}
}

// recheckTarget evaluates the target's latest package inventory with the current DB and adds the vulnerability
// findings the target does not have yet (origin "recheck"). Nothing is resolved or touched.
func (s *server) recheckTarget(ctx context.Context, runID, targetID int64) error {
	var projectID int64
	var scanID *int64
	var summary map[string]any
	err := s.db.QueryRow(ctx, `select t.project_id, sc.id, sc.summary from targets t
		left join scans sc on sc.id = `+latestInventorySQL+` where t.id = $1`, targetID).Scan(&projectID, &scanID, &summary)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && scanID == nil) { // the inventory is gone
		return s.endItem(ctx, s.db, runID, targetID, "skipped", 0)
	}
	if err != nil {
		return err
	}
	rows, _ := s.db.Query(ctx, `select distinct purl, name, version, ecosystem, path, src_name, src_version from packages where scan_id = $1
		order by name, version, path`, *scanID)
	inv, err := pgx.CollectRows(rows, pgx.RowToStructByPos[formats.Package])
	if err != nil {
		return err
	}
	found, err := s.sbomFindings(ctx, fmt.Sprintf("recheck-%d-*.json", targetID), summary, inv)
	if err != nil {
		return err
	}
	byFP := map[string]formats.Finding{}
	for _, fd := range found {
		byFP[string(fd.Fingerprint)] = fd
	}
	return s.tx(ctx, func(tx pgx.Tx) error {
		var queued bool
		if err := tx.QueryRow(ctx, `select true from recheck_items where run_id = $1 and target_id = $2 and state = 'queued'
			for update`, runID, targetID).Scan(&queued); errors.Is(err, pgx.ErrNoRows) {
			return nil
		} else if err != nil {
			return err
		}
		fps := make([][]byte, 0, len(byFP))
		for k := range byFP {
			fps = append(fps, []byte(k))
		}
		rows, _ := tx.Query(ctx, `select fingerprint from findings where target_id = $1 and fingerprint = any($2)`, targetID, fps)
		have, err := pgx.CollectRows(rows, pgx.RowTo[[]byte])
		if err != nil {
			return err
		}
		for _, h := range have {
			delete(byFP, string(h))
		}
		var fresh []formats.Finding
		for _, k := range slices.Sorted(maps.Keys(byFP)) {
			fresh = append(fresh, byFP[k])
		}
		added := 0
		if len(fresh) > 0 {
			var rs int64
			if err := tx.QueryRow(ctx, `insert into scans(project_id, target_id, source, format, ref, status, finished_at)
				values($1, $2, 'recheck', 'trivy-sbom', $3, 'done', now()) returning id`, projectID, targetID, recheckRef(runID)).Scan(&rs); err != nil {
				return err
			}
			ids, err := s.upsertFindings(ctx, tx, projectID, targetID, rs, fresh, "recheck")
			if err != nil {
				return err
			}
			added = len(ids)
			if err := reapplyExceptions(ctx, tx, "f.target_id = $1", targetID); err != nil { // same rule as a scan
				return err
			}
			if _, err := applyDue(ctx, tx, "f.target_id = $1", targetID); err != nil {
				return err
			}
			var c sevCounts
			if err := tx.QueryRow(ctx, openCountsSQL("f.target_id = $1"), targetID).
				Scan(&c.Critical, &c.High, &c.Medium, &c.Low, &c.Unknown, &c.Open); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `update scans set summary = $2 where id = $1`, rs, map[string]int{"critical": c.Critical,
				"high": c.High, "medium": c.Medium, "low": c.Low, "unknown": c.Unknown, "open": c.Open}); err != nil {
				return err
			}
		}
		return s.endItem(ctx, tx, runID, targetID, "done", added)
	})
}

// sbomFindings evaluates a package inventory with the installed Trivy DB (trivy sbom on a CycloneDX built from
// it, with the OS component taken from summary["os"] or a distro= purl) and returns the vulnerability findings, one
// per file path the package had, so the fingerprints match a real scan's. Used by the recheck and CycloneDX uploads.
func (s *server) sbomFindings(ctx context.Context, tmpName string, summary map[string]any, inv []formats.Package) ([]formats.Finding, error) {
	var pkgs []trivy.Package
	paths := map[[2]string][]string{} // name+version -> the files they were found in; trivy sbom drops them
	seen := map[trivy.Package]bool{}
	for _, ip := range inv {
		p := trivy.Package{PURL: ip.PURL, Name: ip.Name, Version: ip.Version, Ecosystem: ip.Ecosystem, SrcName: ip.SrcName, SrcVersion: ip.SrcVersion}
		if !seen[p] {
			seen[p] = true
			pkgs = append(pkgs, p)
		}
		k := [2]string{p.Name, p.Version}
		paths[k] = append(paths[k], ip.Path)
	}
	bom, err := trivy.CycloneDXWithOS(osForRecheck(summary, pkgs), pkgs)
	if err != nil {
		return nil, err
	}
	root := filepath.Join(s.cfg.DataDir, "work")
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(root, tmpName)
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(bom)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	conf, err := s.trivyConf(ctx) // the same filters as a scan, or this would add back what the scan left out
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	s.trivy.mu.Lock() // never while a DB bundle is being installed
	err = trivy.Run(ctx, s.trivyOptions(conf), "sbom", f.Name(), &out)
	s.trivy.mu.Unlock()
	if err != nil {
		return nil, err
	}
	parser, _ := formats.Get("trivy")
	rep, err := parser.Parse(&out)
	if err != nil {
		return nil, err
	}
	byFP := map[string]formats.Finding{}
	for _, fd := range rep.Findings {
		if fd.Kind != "vuln" {
			continue
		}
		ps := paths[[2]string{fd.PkgName, fd.PkgVersion}]
		if len(ps) == 0 {
			ps = []string{fd.PkgPath}
		}
		for _, p := range slices.Compact(ps) {
			fd.PkgPath = p
			fd.Fingerprint = formats.Fingerprint(fd)
			byFP[string(fd.Fingerprint)] = fd
		}
	}
	var fs []formats.Finding
	for _, k := range slices.Sorted(maps.Keys(byFP)) {
		fs = append(fs, byFP[k])
	}
	return fs, nil
}

// osForRecheck is the scan's stored OS (summary.os), else the one a distro= purl qualifier names.
func osForRecheck(summary map[string]any, pkgs []trivy.Package) *trivy.OSInfo {
	if o, ok := summary["os"].(map[string]any); ok {
		fam, _ := o["family"].(string)
		name, _ := o["name"].(string)
		if fam != "" {
			return &trivy.OSInfo{Family: fam, Name: name}
		}
	}
	for _, p := range pkgs {
		u, err := url.Parse(p.PURL)
		if err != nil || u.Scheme != "pkg" {
			continue
		}
		typ, rest, _ := strings.Cut(u.Opaque, "/")
		ns, _, _ := strings.Cut(rest, "/")
		d := u.Query().Get("distro")
		if (typ == "apk" || typ == "deb" || typ == "rpm") && ns != "" && d != "" {
			return &trivy.OSInfo{Family: ns, Name: strings.TrimPrefix(d, ns+"-")}
		}
	}
	return nil
}
