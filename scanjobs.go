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
	Ref    string `json:"ref,omitempty"` // the version the uploader named; an image's own tag is used without it
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
	if !s.trivyDBReady() { // before the body: nobody uploads 2GB to learn this
		writeErr(w, 409, "no_trivy_db", "취약점 DB가 아직 설치되지 않아 스캔할 수 없습니다. 관리자가 관리 → Trivy DB에서 db.tar.gz를 올려야 합니다.")
		return
	}
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
		case "target", "kind", "ref":
			b, err := io.ReadAll(io.LimitReader(part, 4096))
			if err != nil {
				badRequest(w, "업로드를 읽지 못했습니다.")
				return
			}
			switch part.FormName() {
			case "target":
				p.Target = strings.TrimSpace(string(b))
			case "ref":
				p.Ref = strings.TrimSpace(string(b))
			default:
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
	if p.Target == "" || utf8.RuneCountInString(p.Target) > 512 || len(p.Ref) > 512 {
		badRequest(w, "대상 이름(target)은 1~512자, 버전(ref)은 512자 이하로 지정하세요.")
		return
	}
	if size == 0 {
		badRequest(w, "빈 파일입니다. 내용이 있는 파일을 올리세요.")
		return
	}
	if size < 0 {
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
		writeErr(w, 403, "forbidden", "스캔을 요청한 사람, 프로젝트 소유자, 관리자만 취소할 수 있습니다.")
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
	} else if errors.Is(err, trivy.ErrInput) {
		msg = "이 파일을 컨테이너 이미지로 읽지 못했습니다. docker save 또는 podman save로 만든 tar가 맞는지, 파일 종류를 맞게 골랐는지 확인하세요."
	} else if errors.Is(err, errTrivyRun) { // the cause is in the server log; it is rarely the file
		msg = "Trivy 실행에 실패했습니다. 다시 시도해도 같으면 관리자에게 서버 로그 확인을 요청하세요."
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

// What a finished scan says it could not examine (summary.warnings), and why a scan that examined nothing does not
// pass the policy.
const (
	warnJavaFiles    = "Java DB가 설치되지 않아 JAR/WAR/EAR 파일 %d개는 검사하지 않았습니다. 관리자가 관리 → Trivy DB에서 javadb.tar.gz를 올린 뒤 다시 스캔하세요."
	warnJavaImage    = "Java DB가 설치되지 않아 이미지 안의 JAR/WAR/EAR 파일은 검사하지 않았습니다. 관리자가 관리 → Trivy DB에서 javadb.tar.gz를 올린 뒤 다시 스캔하세요."
	warnNothing      = "검사할 수 있는 패키지나 설정 파일을 찾지 못했습니다. 지원 형식: 패키지 잠금 파일(package-lock.json, go.mod, pom.xml, requirements.txt 등), JAR/WAR/EAR(Java DB 필요), 컨테이너 이미지. 파일 종류와 압축한 폴더가 맞는지 확인하세요."
	notJudgedNothing = "검사한 패키지나 설정 파일이 없어 정책을 통과로 판정하지 않았습니다."
)

func (s *server) serverScan(ctx context.Context, j *job, projectID int64, p scanJobPayload, opts trivy.Options) error {
	if opts.Timeout > 0 { // the whole scan: unpacking, Trivy (both passes), storing the result
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}
	work := s.workDir(*j.ScanID)
	input := filepath.Join(work, "upload")
	if _, err := os.Stat(input); os.IsNotExist(err) { // removed when a restart interrupted an earlier run
		return &archiveError{"업로드한 파일이 없습니다(서버 재시작 등). 다시 올려 주세요."}
	}
	var jars []string // Java archives of a source upload: trivy fs never opens them
	if p.Kind == "fs" {
		src := filepath.Join(work, "src")
		if err := extractArchive(ctx, input, src, s.cfg.MaxExtractMB<<20); err != nil {
			return err
		}
		os.Remove(input) // frees the disk before trivy runs
		input = src
		var err error
		if jars, err = sourceTree(ctx, src); err != nil {
			return err
		}
	}
	if !slices.Contains(opts.Scanners, "vuln") || (len(opts.PkgTypes) > 0 && !slices.Contains(opts.PkgTypes, "library")) {
		jars = nil // the admin switched library vulnerabilities off: nothing to run, nothing to warn about
	}
	out, err := os.Create(filepath.Join(work, "report.json"))
	if err != nil {
		return err
	}
	defer out.Close()
	// shortcut: no s.trivy.mu here (a scan may take SCAN_TIMEOUT_MIN and would block DB uploads); a scan that opens
	// the DB in the instant between InstallBundle's two renames fails with a Trivy error and is simply retried.
	run := func(o trivy.Options, kind, input string, out *os.File) error {
		err := trivy.Run(ctx, o, kind, input, out)
		if err != nil && ctx.Err() != nil {
			return fmt.Errorf("%w (%v)", context.Cause(ctx), err)
		}
		if err != nil && !errors.Is(err, trivy.ErrNoJavaDB) {
			log.Printf("server scan %d: %v", *j.ScanID, err)
		}
		return err
	}
	var warnings []string
	err = run(opts, p.Kind, input, out)
	if errors.Is(err, trivy.ErrNoJavaDB) && p.Kind == "image" { // scan everything else and say what was left out
		if err = out.Truncate(0); err == nil {
			_, err = out.Seek(0, io.SeekStart)
		}
		if err != nil {
			return err
		}
		opts.NoJavaDB = true
		warnings = append(warnings, warnJavaImage)
		err = run(opts, p.Kind, input, out)
	}
	if err != nil {
		if ctx.Err() != nil {
			return err
		}
		return fmt.Errorf("%w: %w", errTrivyRun, err)
	}
	var jout *os.File // the report of the Java pass
	if db, _ := trivy.Status(s.trivyCacheDir()); len(jars) > 0 && !db.JavaDB {
		warnings = append(warnings, fmt.Sprintf(warnJavaFiles, len(jars)))
	} else if len(jars) > 0 {
		// rootfs also reads node_modules, site-packages and binaries, which the lock files already covered: it gets
		// the Java archives alone, at the paths they had, and looks for vulnerabilities only
		jdir := filepath.Join(work, "jars")
		for _, rel := range jars {
			if err := os.MkdirAll(filepath.Dir(filepath.Join(jdir, rel)), 0o755); err != nil {
				return err
			}
			if err := os.Rename(filepath.Join(input, rel), filepath.Join(jdir, rel)); err != nil {
				return err
			}
		}
		if jout, err = os.Create(filepath.Join(work, "java.json")); err != nil {
			return err
		}
		defer jout.Close()
		jopts := opts
		jopts.Scanners = []string{"vuln"}
		if err := run(jopts, "rootfs", jdir, jout); err != nil {
			if ctx.Err() != nil {
				return err
			}
			return fmt.Errorf("%w: %w", errTrivyRun, err)
		}
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
	var jraw []byte
	if jout != nil {
		if _, err := jout.Seek(0, io.SeekStart); err != nil {
			return err
		}
		jrep, err := parser.Parse(jout)
		if err != nil {
			return fmt.Errorf("%w: parse java report: %v", errTrivyRun, err)
		}
		rep.Merge(jrep)
		if fi, err := jout.Stat(); raw == nil || err != nil || fi.Size()+int64(len(raw)) > s.cfg.MaxReportMB<<20 {
			raw = nil
		} else if jraw, err = os.ReadFile(jout.Name()); err != nil {
			return err
		}
	}
	if raw != nil { // one report for both passes, named after the target instead of the work directory
		if raw, err = trivy.Report(raw, jraw, p.Target); err != nil {
			return fmt.Errorf("%w: rewrite report: %v", errTrivyRun, err)
		}
	}
	// no package, no finding, no result of any kind: nothing was examined, which is not the same as clean.
	// Such a scan is not marked complete either, so a wrong file sent to a target does not resolve its open findings.
	notJudged := ""
	if len(rep.Packages) == 0 && len(rep.Findings) == 0 && len(rep.Complete) == 0 {
		warnings, notJudged = append(warnings, warnNothing), notJudgedNothing
	} else {
		for _, sc := range opts.Scanners { // trivy JSON does not say which scanners ran
			rep.Complete[sc+":trivy"] = true
		}
	}
	ref := p.Ref
	if ref == "" && p.Kind == "image" {
		ref = rep.Ref
	}
	_, err = s.ingest(ctx, ingestInput{ProjectID: projectID, TargetKind: p.Kind, TargetName: p.Target, Ref: ref,
		Source: "server", Report: rep, Raw: raw, UserID: j.CreatedBy, ScanID: j.ScanID, Warnings: warnings, NotJudged: notJudged})
	return err
}
