package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/spsp4755/jasca/internal/trivy"
)

func init() { routeRegistrars = append(routeRegistrars, (*server).trivyRoutes) }

// trivyState is per-server Trivy state; its zero value is ready (server.trivy).
type trivyState struct {
	mu      sync.Mutex // held by DB installs and by each recheck item: InstallBundle is not concurrency-safe
	verMu   sync.Mutex
	version string // cached `trivy --version`
}

type trivySettings struct {
	Scanners []string `json:"scanners"`
}

func (s *server) trivyCacheDir() string { return filepath.Join(s.cfg.DataDir, "trivy") }

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
	st := map[string]any{"db_version": 0, "updated_at": nil, "next_update": nil, "java_db": nil,
		"scanners": s.trivyScanners(ctx), "trivy_version": s.trivyVersion(ctx)}
	if db, err := trivy.Status(s.trivyCacheDir()); err == nil {
		st["db_version"], st["updated_at"], st["next_update"] = db.Version, db.UpdatedAt.UTC(), db.NextUpdate.UTC()
		if db.JavaDB {
			st["java_db"] = map[string]any{"updated_at": db.JavaUpdatedAt.UTC()}
		}
	}
	return st
}

func (s *server) handleTrivyGet(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	writeJSON(w, 200, s.trivyStatus(r.Context()))
}

func (s *server) handleTrivyPut(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	var in trivySettings
	if err := readJSON(r, 4096, &in); err != nil {
		writeBodyErr(w, err)
		return
	}
	seen := map[string]bool{}
	for _, sc := range in.Scanners {
		if !slices.Contains(trivyScannerNames, sc) || seen[sc] {
			badRequest(w, "scanners는 vuln, secret, misconfig 중에서 겹치지 않게 고르세요.")
			return
		}
		seen[sc] = true
	}
	if len(in.Scanners) == 0 {
		badRequest(w, "스캐너를 하나 이상 고르세요.")
		return
	}
	if err := s.putSetting(r.Context(), "trivy", in); err != nil {
		writeInternal(w, "trivy settings", err)
		return
	}
	s.audit(r.Context(), c, "trivy.settings", nil, "", map[string]any{"scanners": in.Scanners})
	writeJSON(w, 200, s.trivyStatus(r.Context()))
}

// handleTrivyDB installs an uploaded db.tar.gz or javadb.tar.gz (multipart "file"), then starts a recheck run.
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
		s.audit(ctx, c, "trivy.db_upload", nil, kind, map[string]any{"version": st.Version, "updated_at": st.UpdatedAt})
		runID, err := s.startRecheck(context.WithoutCancel(ctx), "trivydb") // the new DB is live even if the client left
		if err != nil {
			writeInternal(w, "trivy db: start recheck", err)
			return
		}
		out := s.trivyStatus(ctx)
		out["kind"], out["recheck_run_id"] = kind, runID
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
