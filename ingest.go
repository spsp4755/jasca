package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"maps"
	"runtime/debug"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/spsp4755/jasca/internal/formats"
)

type ingestInput struct {
	ProjectID                           int64
	TargetKind, TargetName, Ref, Source string
	Report                              *formats.Report
	Raw                                 []byte // the decoded upload; nil = nothing to keep and no duplicate check
	UserID, TokenID                     *int64
	ScanID                              *int64 // pre-created queued scan for server/harbor jobs: finished instead of inserted
}

type ingestResult struct {
	ProjectID, ScanID, TargetID int64
	Summary                     map[string]int // open findings of the target: critical high medium low unknown open
	New, Fixed, Reopened        []int64        // finding ids
	Policy                      policyResult
	Duplicate                   bool
}

// errScanCanceled: the pre-created scan (ingestInput.ScanID) was canceled while it ran; nothing was written.
var errScanCanceled = errors.New("scan was canceled")

// afterIngest runs after a new scan is committed and its policy stored (never for a duplicate). Hooks log their
// own errors; they cannot fail the upload. Append from an init().
var afterIngest []func(ctx context.Context, s *server, r *ingestResult)

// ingest stores one parsed report in one transaction: target, scan, packages, catalog, findings, auto-resolve.
// Then it evaluates the policy, trims old raw reports and runs the afterIngest hooks.
func (s *server) ingest(ctx context.Context, in ingestInput) (*ingestResult, error) {
	rep := in.Report
	res := &ingestResult{ProjectID: in.ProjectID}
	var sum, gz []byte
	if in.Raw != nil {
		h := sha256.Sum256(in.Raw)
		sum, gz = h[:], gzipBytes(in.Raw)
	}
	err := s.tx(ctx, func(tx pgx.Tx) error {
		// the upsert locks the target row until commit, so ingests of one target run one after another
		if err := tx.QueryRow(ctx, `insert into targets(project_id, kind, name) values($1, $2, $3)
			on conflict (project_id, kind, name) do update set kind = excluded.kind returning id`,
			in.ProjectID, in.TargetKind, in.TargetName).Scan(&res.TargetID); err != nil {
			return err
		}
		if sum != nil && in.ScanID == nil {
			err := tx.QueryRow(ctx, `select id, summary - 'os' from scans where target_id = $1 and report_sha256 = $2
				and status = 'done' and created_at > now() - interval '10 minutes' order by id desc limit 1`,
				res.TargetID, sum).Scan(&res.ScanID, &res.Summary)
			if err == nil {
				res.Duplicate = true
				return nil
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		var err error
		if in.ScanID != nil {
			// finished_at must be set here, in this tx: the new_only policy rule compares it with first_seen_at
			err = tx.QueryRow(ctx, `update scans set target_id = $3, format = $4, ref = $5, report_sha256 = $6, raw = $7,
				status = 'done', error = '', finished_at = now()
				where id = $1 and project_id = $2 and status in ('queued', 'running') returning id`,
				*in.ScanID, in.ProjectID, res.TargetID, rep.Format, in.Ref, sum, gz).Scan(&res.ScanID)
			if errors.Is(err, pgx.ErrNoRows) {
				var status string
				if err := tx.QueryRow(ctx, `select status from scans where id = $1 and project_id = $2`, *in.ScanID, in.ProjectID).Scan(&status); err != nil {
					return fmt.Errorf("pre-created scan %d: %w", *in.ScanID, err)
				}
				if status == "canceled" {
					return errScanCanceled
				}
				return fmt.Errorf("pre-created scan %d is %s, not queued or running", *in.ScanID, status)
			}
		} else {
			err = tx.QueryRow(ctx, `insert into scans(project_id, target_id, source, format, ref, report_sha256, raw, status,
					created_by_user, created_by_token, finished_at)
				values($1, $2, $3, $4, $5, $6, $7, 'done', $8, $9, now()) returning id`,
				in.ProjectID, res.TargetID, in.Source, rep.Format, in.Ref, sum, gz, in.UserID, in.TokenID).Scan(&res.ScanID)
		}
		if err != nil {
			return err
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"packages"}, []string{"scan_id", "purl", "name", "version", "ecosystem", "path", "src_name", "src_version"},
			pgx.CopyFromSlice(len(rep.Packages), func(i int) ([]any, error) {
				p := rep.Packages[i]
				return []any{res.ScanID, p.PURL, p.Name, p.Version, p.Ecosystem, p.Path, p.SrcName, p.SrcVersion}, nil
			})); err != nil {
			return err
		}
		if res.New, err = s.upsertFindings(ctx, tx, in.ProjectID, res.TargetID, res.ScanID, rep.Findings, "scan"); err != nil {
			return err
		}
		// back in this scan after being fixed: open again (accepted / false_positive keep their status)
		rows, _ := tx.Query(ctx, `update findings set status = 'open', fixed_at = null, reopened_count = reopened_count + 1
			where status = 'fixed' and id in (select finding_id from scan_findings where scan_id = $1) returning id`, res.ScanID)
		if res.Reopened, err = pgx.CollectRows(rows, pgx.RowTo[int64]); err != nil {
			return err
		}
		// a complete scan of kind:tool fixes this target's open findings of that kind and tool that it no longer has
		rows, _ = tx.Query(ctx, `update findings f set status = 'fixed', fixed_at = now()
			where f.target_id = $1 and f.status = 'open' and f.kind || ':' || f.tool = any($2)
			and not exists (select 1 from scan_findings sf where sf.scan_id = $3 and sf.finding_id = f.id) returning f.id`,
			res.TargetID, slices.Collect(maps.Keys(rep.Complete)), res.ScanID)
		if res.Fixed, err = pgx.CollectRows(rows, pgx.RowTo[int64]); err != nil {
			return err
		}
		var c sevCounts
		if err := tx.QueryRow(ctx, openCountsSQL("f.target_id = $1"), res.TargetID).
			Scan(&c.Critical, &c.High, &c.Medium, &c.Low, &c.Unknown, &c.Open); err != nil {
			return err
		}
		res.Summary = map[string]int{"critical": c.Critical, "high": c.High, "medium": c.Medium, "low": c.Low, "unknown": c.Unknown, "open": c.Open}
		stored := map[string]any{}
		for k, v := range res.Summary {
			stored[k] = v
		}
		if rep.OS != nil { // the recheck task rebuilds the OS component from this
			stored["os"] = map[string]string{"family": rep.OS.Family, "name": rep.OS.Name}
		}
		if _, err := tx.Exec(ctx, `update scans set summary = $2 where id = $1`, res.ScanID, stored); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `update targets set last_scan_at = now() where id = $1`, res.TargetID)
		return err
	})
	if err != nil {
		return nil, err
	}
	// the scan is committed: a client that hangs up now must not leave it without a policy or skip the hooks
	ctx = context.WithoutCancel(ctx)
	res.Policy = s.evaluatePolicy(ctx, in.ProjectID, res.ScanID)
	if res.Duplicate {
		return res, nil
	}
	if _, err := s.db.Exec(ctx, `update scans set policy = $2 where id = $1`, res.ScanID, res.Policy); err != nil {
		log.Printf("ingest: store policy of scan %d: %v", res.ScanID, err)
	}
	if err := s.trimRaw(ctx, res.TargetID); err != nil {
		log.Printf("ingest: trim raw reports of target %d: %v", res.TargetID, err)
	}
	for _, h := range afterIngest {
		runHook(ctx, s, res, h)
	}
	return res, nil
}

// runHook runs one afterIngest hook; a panic is logged so the upload, already committed, still succeeds.
func runHook(ctx context.Context, s *server, res *ingestResult, h func(context.Context, *server, *ingestResult)) {
	defer func() {
		if v := recover(); v != nil {
			log.Printf("afterIngest hook panicked for scan %d: %v\n%s", res.ScanID, v, debug.Stack())
		}
	}()
	h(ctx, s, res)
}

// trimRaw drops the raw report of the target's scans that are neither among the newest raw_per_target nor
// younger than raw_days (setting "retention"). The scan rows stay.
func (s *server) trimRaw(ctx context.Context, targetID int64) error {
	ret := struct {
		RawPerTarget int `json:"raw_per_target"`
		RawDays      int `json:"raw_days"`
	}{20, 90}
	if _, err := s.getSetting(ctx, "retention", &ret); err != nil {
		return err
	}
	_, err := s.db.Exec(ctx, `update scans set raw = null where target_id = $1 and raw is not null
		and created_at < now() - make_interval(days => $3)
		and id not in (select id from scans where target_id = $1 order by created_at desc, id desc limit $2)`,
		targetID, ret.RawPerTarget, ret.RawDays)
	return err
}

func gzipBytes(b []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(b) // a bytes.Buffer never fails
	zw.Close()
	return buf.Bytes()
}
