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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/spsp4755/jasca/internal/formats"
	"github.com/spsp4755/jasca/internal/trivy"
)

func init() { routeRegistrars = append(routeRegistrars, (*server).scanJobRoutes) }

func (s *server) scanJobRoutes() {
	s.registerJob("server_scan", s.runServerScan)
	s.handle("POST /api/v1/projects/{key}/scan-jobs", permProj("member"), s.handleScanJobCreate)
	s.handle("POST /api/v1/scans/{id}/cancel", permObj("scan", "member"), s.handleScanCancel)
}

type scanJobPayload struct {
	Kind   string `json:"kind"` // fs | image
	Target string `json:"target"`
}

func (s *server) workDir(scanID int64) string {
	return filepath.Join(s.cfg.DataDir, "work", fmt.Sprint(scanID))
}

// sweepWork removes what a crash, a cancel or a deleted project left in DATA_DIR/work (and half-installed Trivy
// DBs): everything except the uploads of scans whose job is still queued or running. Call it before the HTTP
// server and the workers start, so no upload or job is writing there.
func (s *server) sweepWork(ctx context.Context) {
	rows, _ := s.db.Query(ctx, `select scan_id::text from jobs where scan_id is not null and state in ('queued', 'running')`)
	live, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		log.Printf("sweep work: %v", err)
		return
	}
	root := filepath.Join(s.cfg.DataDir, "work")
	ents, _ := os.ReadDir(root)
	for _, e := range ents {
		if !slices.Contains(live, e.Name()) {
			os.RemoveAll(filepath.Join(root, e.Name()))
		}
	}
	ents, _ = os.ReadDir(s.trivyCacheDir())
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".incoming-") {
			os.RemoveAll(filepath.Join(s.trivyCacheDir(), e.Name()))
		}
	}
}

// handleScanJobCreate streams the multipart file to DATA_DIR/work, then creates a queued scan and its job.
func (s *server) handleScanJobCreate(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	max := s.cfg.MaxScanUploadMB << 20
	tooLarge := func() {
		writeErr(w, 413, "too_large", fmt.Sprintf("파일은 %dMB 이하만 올릴 수 있습니다.", s.cfg.MaxScanUploadMB))
	}
	r.Body = http.MaxBytesReader(w, r.Body, max+1<<20) // + room for the other form fields
	mr, err := r.MultipartReader()
	if err != nil {
		badRequest(w, "multipart/form-data 형식으로 file, target, kind를 보내세요.")
		return
	}
	root := filepath.Join(s.cfg.DataDir, "work")
	if err := os.MkdirAll(root, 0o755); err != nil {
		writeInternal(w, "scan job: work dir", err)
		return
	}
	tmp, err := os.MkdirTemp(root, "incoming-")
	if err != nil {
		writeInternal(w, "scan job: temp dir", err)
		return
	}
	defer os.RemoveAll(tmp) // gone already once it is renamed to work/<scan>
	var p scanJobPayload
	var size int64 = -1
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			tooLarge()
			return
		}
		if err != nil {
			badRequest(w, "업로드를 읽지 못했습니다.")
			return
		}
		switch part.FormName() {
		case "file":
			if size >= 0 {
				badRequest(w, "파일은 하나만 올리세요.")
				return
			}
			f, err := os.Create(filepath.Join(tmp, "upload"))
			if err != nil {
				writeInternal(w, "scan job: create upload", err)
				return
			}
			size, err = io.Copy(f, io.LimitReader(part, max+1))
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if _, ok := errors.AsType[*http.MaxBytesError](err); ok || size > max {
				tooLarge()
				return
			}
			if err != nil {
				badRequest(w, "업로드를 읽지 못했습니다.")
				return
			}
		case "target", "kind":
			b, err := io.ReadAll(io.LimitReader(part, 4096))
			if err != nil {
				badRequest(w, "업로드를 읽지 못했습니다.")
				return
			}
			if part.FormName() == "target" {
				p.Target = strings.TrimSpace(string(b))
			} else {
				p.Kind = string(b)
			}
		default:
			io.Copy(io.Discard, part)
		}
	}
	if p.Kind != "fs" && p.Kind != "image" {
		badRequest(w, "kind는 fs(압축 파일) 또는 image(docker save 이미지 tar)로 지정하세요.")
		return
	}
	if p.Target == "" || utf8.RuneCountInString(p.Target) > 512 {
		badRequest(w, "대상 이름(target)은 1~512자로 지정하세요.")
		return
	}
	if size <= 0 {
		badRequest(w, "스캔할 파일(file)을 올리세요.")
		return
	}
	var scanID int64
	err = s.tx(ctx, func(tx pgx.Tx) error {
		var targetID int64
		if err := tx.QueryRow(ctx, `insert into targets(project_id, kind, name) values($1, $2, $3)
			on conflict (project_id, kind, name) do update set kind = excluded.kind returning id`,
			c.Project.ID, p.Kind, p.Target).Scan(&targetID); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `insert into scans(project_id, target_id, source, format, status, created_by_user)
			values($1, $2, 'server', 'trivy', 'queued', $3) returning id`, c.Project.ID, targetID, c.User.ID).Scan(&scanID); err != nil {
			return err
		}
		if _, err := s.enqueue(ctx, tx, "server_scan", &scanID, p, prioScan); err != nil {
			return err
		}
		return os.Rename(tmp, s.workDir(scanID)) // before the commit, so the worker always finds the file
	})
	if err != nil {
		if scanID != 0 {
			os.RemoveAll(s.workDir(scanID))
		}
		writeInternal(w, "scan job: create", err)
		return
	}
	s.audit(ctx, c, "scan.job", &c.Project.ID, p.Kind+":"+p.Target, map[string]any{"scan_id": scanID, "bytes": size})
	writeJSON(w, 201, map[string]any{"scan_id": scanID})
}

// handleScanCancel: the requester, a project owner or an admin may cancel a queued or running scan.
func (s *server) handleScanCancel(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	id := pathID(r)
	var createdBy *int64
	if err := s.db.QueryRow(ctx, `select created_by_user from scans where id = $1`, id).Scan(&createdBy); err != nil {
		writeInternal(w, "scan cancel", err)
		return
	}
	if c.User == nil || (c.Role != "owner" && (createdBy == nil || *createdBy != c.User.ID)) {
		writeErr(w, 403, "forbidden", "스캔을 요청한 사람, 프로젝트 owner, 관리자만 취소할 수 있습니다.")
		return
	}
	tag, err := s.db.Exec(ctx, `update scans set status = 'canceled', error = '사용자가 취소했습니다.', finished_at = now()
		where id = $1 and status in ('queued', 'running')`, id)
	if err != nil {
		writeInternal(w, "scan cancel", err)
		return
	}
	if tag.RowsAffected() == 0 {
		writeErr(w, 409, "conflict", "이미 끝난 스캔은 취소할 수 없습니다.")
		return
	}
	rows, _ := s.db.Query(ctx, `select id from jobs where scan_id = $1 and state in ('queued', 'running')`, id)
	jobIDs, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		writeInternal(w, "scan cancel: jobs", err)
		return
	}
	for _, j := range jobIDs {
		if err := s.cancelJob(ctx, j); err != nil {
			writeInternal(w, "scan cancel: job", err)
			return
		}
	}
	os.RemoveAll(s.workDir(id)) // a queued job never runs its cleanup; a running one is stopping anyway
	s.audit(ctx, c, "scan.cancel", &c.Project.ID, "", map[string]any{"scan_id": id})
	w.WriteHeader(204)
}

// runServerScan runs Trivy on an uploaded file and ingests the report into the pre-created scan.
func (s *server) runServerScan(ctx context.Context, j *job) error {
	if j.ScanID == nil {
		return errors.New("server_scan job without a scan")
	}
	scanID := *j.ScanID
	defer os.RemoveAll(s.workDir(scanID))
	var p scanJobPayload
	if err := json.Unmarshal(j.Payload, &p); err != nil {
		return err
	}
	var projectID int64
	err := s.db.QueryRow(ctx, `update scans set status = 'running' where id = $1 and status in ('queued', 'running')
		returning project_id`, scanID).Scan(&projectID)
	if errors.Is(err, pgx.ErrNoRows) {
		return errJobCanceled // canceled before it started
	}
	if err != nil {
		return err
	}
	conf, err := s.trivyConf(ctx) // a scan never runs without the admin's filters because they could not be read
	opts := s.trivyOptions(conf)
	if err == nil {
		err = s.serverScan(ctx, j, projectID, p, opts)
	}
	if err == nil || errors.Is(err, errScanCanceled) || errors.Is(context.Cause(ctx), errJobCanceled) {
		if err != nil {
			return errJobCanceled
		}
		return nil
	}
	msg := "스캔에 실패했습니다."
	if ae, ok := errors.AsType[*archiveError](err); ok {
		msg = ae.msg
	} else if errors.Is(err, context.DeadlineExceeded) {
		msg = fmt.Sprintf("제한 시간(%d분)을 넘겨 스캔을 중단했습니다.", int(opts.Timeout.Minutes()))
	} else if errors.Is(err, errTrivyRun) {
		msg = "Trivy 실행에 실패했습니다. 이미지 tar(docker save) 또는 압축 파일이 맞는지 확인하세요."
	} else if ctx.Err() != nil {
		msg = "서버가 재시작되어 스캔이 중단되었습니다. 다시 올려 주세요."
	}
	dbctx := context.WithoutCancel(ctx)
	if _, uerr := s.db.Exec(dbctx, `update scans set status = 'failed', error = $2, finished_at = now()
		where id = $1 and status in ('queued', 'running')`, scanID, msg); uerr != nil {
		log.Printf("server scan %d: mark failed: %v", scanID, uerr)
	}
	s.emit(dbctx, projectID, "scan_failed", map[string]any{"scan_id": scanID, "target": p.Target, "error": msg})
	return err
}

var errTrivyRun = errors.New("trivy failed")

func (s *server) serverScan(ctx context.Context, j *job, projectID int64, p scanJobPayload, opts trivy.Options) error {
	if opts.Timeout > 0 { // the whole scan: unpacking, Trivy, storing the result
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}
	work := s.workDir(*j.ScanID)
	input := filepath.Join(work, "upload")
	if _, err := os.Stat(input); os.IsNotExist(err) { // removed when a restart interrupted an earlier run
		return &archiveError{"업로드한 파일이 없습니다(서버 재시작 등). 다시 올려 주세요."}
	}
	if p.Kind == "fs" {
		src := filepath.Join(work, "src")
		if err := extractArchive(ctx, input, src, s.cfg.MaxExtractMB<<20); err != nil {
			return err
		}
		os.Remove(input) // frees the disk before trivy runs
		input = src
	}
	out, err := os.Create(filepath.Join(work, "report.json"))
	if err != nil {
		return err
	}
	defer out.Close()
	// shortcut: no s.trivy.mu here (a scan may take SCAN_TIMEOUT_MIN and would block DB uploads); a scan that opens
	// the DB in the instant between InstallBundle's two renames fails with a Trivy error and is simply retried.
	db, _ := trivy.Status(s.trivyCacheDir()) // without a java-db, JAR/WAR/EAR files are skipped (shown on the admin Trivy page)
	opts.NoJavaDB = !db.JavaDB
	err = trivy.Run(ctx, opts, p.Kind, input, out)
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("%w (%v)", context.Cause(ctx), err)
		}
		log.Printf("server scan %d: %v", *j.ScanID, err)
		return fmt.Errorf("%w: %v", errTrivyRun, err)
	}
	// keep the raw report like an upload when it fits the report limit
	var raw []byte
	var rd io.Reader = out
	if fi, err := out.Stat(); err == nil && fi.Size() <= s.cfg.MaxReportMB<<20 {
		if raw, err = os.ReadFile(out.Name()); err != nil {
			return err
		}
		rd = bytes.NewReader(raw)
	} else if _, err := out.Seek(0, io.SeekStart); err != nil {
		return err
	}
	parser, _ := formats.Get("trivy")
	rep, err := parser.Parse(rd)
	if err != nil {
		return fmt.Errorf("%w: parse report: %v", errTrivyRun, err)
	}
	for _, sc := range opts.Scanners { // trivy JSON does not say which scanners ran
		rep.Complete[sc+":trivy"] = true
	}
	ref := ""
	if p.Kind == "image" {
		ref = rep.Ref
	}
	_, err = s.ingest(ctx, ingestInput{ProjectID: projectID, TargetKind: p.Kind, TargetName: p.Target, Ref: ref,
		Source: "server", Report: rep, Raw: raw, UserID: j.CreatedBy, ScanID: j.ScanID})
	return err
}
