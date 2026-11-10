package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/spsp4755/jasca/internal/trivy"
)

func init() { routeRegistrars = append(routeRegistrars, (*server).trivyRoutes) }

// trivyState is per-server Trivy state; its zero value is ready (server.trivy).
type trivyState struct {
	mu      sync.Mutex // held by DB installs and by each recheck item: InstallBundle is not concurrency-safe
	verMu   sync.Mutex
	version string // cached `trivy --version`
}

// trivySettings is the setting "trivy": what the admin chose for every server-side Trivy run (file scans, CycloneDX
// uploads, the recheck). A value stored before the options existed has only scanners.
type trivySettings struct {
	Scanners          []string `json:"scanners"`
	IgnoreUnfixed     bool     `json:"ignore_unfixed"`
	Severities        []string `json:"severities"` // all five = no filter
	PkgTypes          []string `json:"pkg_types"`
	IncludeDevDeps    bool     `json:"include_dev_deps"`
	DetectionPriority string   `json:"detection_priority"`
	SkipDirs          []string `json:"skip_dirs"`
	SkipFiles         []string `json:"skip_files"`
	TimeoutMin        int      `json:"timeout_min"` // 0 = JASCA_SCAN_TIMEOUT_MIN
}

var (
	trivyScannerNames = []string{"vuln", "secret", "misconfig"}
	trivySeverities   = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
	trivyPkgTypes     = []string{"os", "library"}
	trivyPriorities   = []string{"precise", "comprehensive"}
)

// withDefaults fills what is unset and puts the lists in Trivy's order. Every slice is its own copy.
func (st trivySettings) withDefaults() trivySettings {
	pick := func(all, sel, def []string) []string {
		out := slices.DeleteFunc(slices.Clone(all), func(x string) bool { return !slices.Contains(sel, x) })
		if len(out) == 0 {
			return slices.Clone(def)
		}
		return out
	}
	st.Scanners = pick(trivyScannerNames, st.Scanners, []string{"vuln", "secret"})
	st.Severities = pick(trivySeverities, st.Severities, trivySeverities)
	st.PkgTypes = pick(trivyPkgTypes, st.PkgTypes, trivyPkgTypes)
	if !slices.Contains(trivyPriorities, st.DetectionPriority) {
		st.DetectionPriority = "precise"
	}
	st.SkipDirs, st.SkipFiles = append([]string{}, st.SkipDirs...), append([]string{}, st.SkipFiles...)
	return st
}

// validate says in Korean what is wrong with a PUT, or "".
func (st trivySettings) validate() string {
	subset := func(all, sel []string) bool {
		seen := map[string]bool{}
		for _, x := range sel {
			if !slices.Contains(all, x) || seen[x] {
				return false
			}
			seen[x] = true
		}
		return true
	}
	switch {
	case len(st.Scanners) == 0:
		return "스캐너를 하나 이상 고르세요."
	case !subset(trivyScannerNames, st.Scanners):
		return "scanners는 vuln, secret, misconfig 중에서 겹치지 않게 고르세요."
	case !subset(trivySeverities, st.Severities):
		return "심각도는 CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN 중에서 겹치지 않게 고르세요."
	case !subset(trivyPkgTypes, st.PkgTypes):
		return "패키지 종류는 os, library 중에서 겹치지 않게 고르세요."
	case !slices.Contains(trivyPriorities, st.DetectionPriority):
		return "탐지 방식은 precise 또는 comprehensive입니다."
	case st.TimeoutMin < 0 || st.TimeoutMin > 240:
		return "제한 시간은 1~240분으로 정하세요. 0이면 서버 기본값을 씁니다."
	}
	for _, l := range []struct {
		name string
		pats []string
	}{{"제외할 디렉터리", st.SkipDirs}, {"제외할 파일", st.SkipFiles}} {
		if len(l.pats) > 50 {
			return l.name + " 패턴은 50개까지 넣을 수 있습니다."
		}
		for _, p := range l.pats {
			if n := utf8.RuneCountInString(p); n < 1 || n > 200 || !utf8.ValidString(p) || strings.ContainsFunc(p, unicode.IsControl) {
				return l.name + " 패턴은 한 줄에 하나씩, 1~200자로 쓰세요. 탭 같은 제어 문자는 쓸 수 없습니다."
			}
		}
	}
	return ""
}

// trivyConf is the stored setting with the defaults filled in.
func (s *server) trivyConf(ctx context.Context) (trivySettings, error) {
	var st trivySettings
	if _, err := s.getSetting(ctx, "trivy", &st); err != nil {
		return trivySettings{}.withDefaults(), err
	}
	return st.withDefaults(), nil
}

// trivyOptions turns the setting into the options of one Trivy run, the time limit included. What is at Trivy's own
// default adds no flag.
func (s *server) trivyOptions(st trivySettings) trivy.Options {
	o := trivy.Options{Bin: s.cfg.TrivyBin, CacheDir: s.trivyCacheDir(), Scanners: st.Scanners, Timeout: s.cfg.ScanTimeout,
		IgnoreUnfixed: st.IgnoreUnfixed, IncludeDevDeps: st.IncludeDevDeps, SkipDirs: st.SkipDirs, SkipFiles: st.SkipFiles}
	if st.TimeoutMin > 0 {
		o.Timeout = time.Duration(st.TimeoutMin) * time.Minute
	}
	if len(st.Severities) < len(trivySeverities) {
		o.Severities = st.Severities
	}
	if len(st.PkgTypes) < len(trivyPkgTypes) {
		o.PkgTypes = st.PkgTypes
	}
	if st.DetectionPriority != "precise" {
		o.DetectionPriority = st.DetectionPriority
	}
	return o
}

func (st trivySettings) asMap() map[string]any {
	b, _ := json.Marshal(st)
	var m map[string]any
	json.Unmarshal(b, &m)
	return m
}

func (s *server) trivyCacheDir() string { return filepath.Join(s.cfg.DataDir, "trivy") }

// trivyDBReady: a vulnerability DB is installed, so Trivy can run (it refuses a first run with --skip-db-update).
func (s *server) trivyDBReady() bool {
	_, err := trivy.Status(s.trivyCacheDir())
	return err == nil
}

func (s *server) trivyRoutes() {
	s.handle("GET /api/v1/admin/trivy", permAdmin, s.handleTrivyGet)
	s.handle("PUT /api/v1/admin/trivy", permAdmin, s.handleTrivyPut)
	s.handle("POST /api/v1/admin/trivy/db", permAdmin, s.handleTrivyDB)
}

// trivyVersion runs `trivy --version` once and caches the version (a failure is retried next time).
func (s *server) trivyVersion(ctx context.Context) string {
	s.trivy.verMu.Lock()
	defer s.trivy.verMu.Unlock()
	if s.trivy.version == "" {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, s.cfg.TrivyBin, "--version").Output()
		if err == nil {
			first, _, _ := strings.Cut(string(out), "\n")
			s.trivy.version = strings.TrimSpace(strings.TrimPrefix(first, "Version:"))
		}
	}
	return s.trivy.version
}

func (s *server) trivyStatus(ctx context.Context) map[string]any {
	conf, err := s.trivyConf(ctx)
	if err != nil {
		log.Printf("trivy settings: %v", err)
	}
	st := conf.asMap() // the options, flat next to the DB status
	st["db_version"], st["updated_at"], st["next_update"], st["java_db"] = 0, nil, nil, nil
	st["trivy_version"], st["default_timeout_min"] = s.trivyVersion(ctx), int(s.cfg.ScanTimeout.Minutes())
	db, err := trivy.Status(s.trivyCacheDir())
	if err == nil {
		st["db_version"], st["updated_at"], st["next_update"] = db.Version, db.UpdatedAt.UTC(), db.NextUpdate.UTC()
	}
	if db.JavaDB { // also before the vulnerability DB is there
		st["java_db"] = map[string]any{"updated_at": db.JavaUpdatedAt.UTC()}
	}
	return st
}

func (s *server) handleTrivyGet(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	writeJSON(w, 200, s.trivyStatus(r.Context()))
}

func (s *server) handleTrivyPut(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	in, err := s.trivyConf(r.Context()) // an omitted field keeps its stored value
	if err != nil {
		writeInternal(w, "trivy settings", err)
		return
	}
	if err := readJSON(r, 128<<10, &in); err != nil { // two lists of 50 patterns of 200 characters fit
		writeBodyErr(w, err)
		return
	}
	if msg := in.validate(); msg != "" {
		badRequest(w, msg)
		return
	}
	in = in.withDefaults()
	if err := s.putSetting(r.Context(), "trivy", in); err != nil {
		writeInternal(w, "trivy settings", err)
		return
	}
	s.audit(r.Context(), c, "trivy.settings", nil, "", in.asMap())
	writeJSON(w, 200, s.trivyStatus(r.Context()))
}

// handleTrivyDB installs an uploaded db.tar.gz or javadb.tar.gz (multipart "file"); which one it is comes from the
// content and goes back as "kind". A new vulnerability DB starts a recheck run (recheck_run_id). A Java DB does not:
// it only lets later scans read JAR files, and the recheck evaluates stored package lists, which it does not change.
// A bad bundle is rejected and the old DB stays.
func (s *server) handleTrivyDB(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxScanUploadMB<<20)
	mr, err := r.MultipartReader()
	if err != nil {
		badRequest(w, "multipart/form-data 형식으로 file을 보내세요.")
		return
	}
	for {
		part, err := mr.NextPart()
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			writeErr(w, 413, "too_large", "파일이 너무 큽니다.")
			return
		}
		if err != nil { // io.EOF included: no file part
			badRequest(w, "DB 파일(file)을 올리세요.")
			return
		}
		if part.FormName() != "file" {
			io.Copy(io.Discard, part)
			continue
		}
		// spool first: the lock (which recheck items wait on) is held only for the install, not the upload
		kind, st, err := s.installBundle(part)
		if err != nil {
			s.audit(ctx, c, "trivy.db_upload_failed", nil, "", map[string]any{"error": err.Error()})
			if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
				writeErr(w, 413, "too_large", "파일이 너무 큽니다.")
				return
			}
			if errors.Is(err, trivy.ErrTooLarge) {
				writeErr(w, 413, "too_large", fmt.Sprintf("DB 번들을 풀면 %dMB를 넘습니다.", s.cfg.MaxExtractMB))
				return
			}
			writeErr(w, 400, "bad_bundle", "올바른 Trivy DB 번들(db.tar.gz 또는 javadb.tar.gz)이 아닙니다. 기존 DB를 그대로 사용합니다.")
			return
		}
		out := s.trivyStatus(ctx)
		out["kind"], out["recheck_run_id"] = kind, 0
		if kind == "java-db" {
			s.audit(ctx, c, "trivy.db_upload", nil, kind, map[string]any{"updated_at": st.JavaUpdatedAt})
		} else {
			s.audit(ctx, c, "trivy.db_upload", nil, kind, map[string]any{"version": st.Version, "updated_at": st.UpdatedAt})
			runID, err := s.startRecheck(context.WithoutCancel(ctx), "trivydb") // the new DB is live even if the client left
			if err != nil {
				writeInternal(w, "trivy db: start recheck", err)
				return
			}
			out["recheck_run_id"] = runID
		}
		writeJSON(w, 200, out)
		return
	}
}

// installBundle copies the upload to a temp file under DATA_DIR/work, then installs it holding s.trivy.mu.
func (s *server) installBundle(r io.Reader) (string, trivy.DBStatus, error) {
	root := filepath.Join(s.cfg.DataDir, "work")
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", trivy.DBStatus{}, err
	}
	f, err := os.CreateTemp(root, "trivydb-*.tar.gz")
	if err != nil {
		return "", trivy.DBStatus{}, err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := io.Copy(f, r); err != nil {
		return "", trivy.DBStatus{}, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", trivy.DBStatus{}, err
	}
	s.trivy.mu.Lock()
	defer s.trivy.mu.Unlock()
	return trivy.InstallBundle(s.trivyCacheDir(), f, s.cfg.MaxExtractMB<<20)
}
