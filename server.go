package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5/pgxpool"
)

type server struct {
	db      *pgxpool.Pool
	cfg     config
	mux     *http.ServeMux
	secret  []byte      // settings['hmac_secret'], signs short-lived cookies
	routes  []routeInfo // every registered route with its perm, for tests
	objs    map[string]func(ctx context.Context, id string) (projectID int64, err error)
	limiter *limiter // local login attempts per IP

	oidcMu     sync.Mutex
	providers  map[string]*oidc.Provider // discovered Keycloak per issuer
	syncMu     sync.Mutex                // one Keycloak sync at a time
	loginDepts deptLog                   // the last 20 SSO logins' department outcomes
	jobs       jobRunner                 // jobs.go
	trivy      trivyState                // trivydb.go
	mcpLimiter *limiter                  // mcp.go: requests per API token
}

// reqCtx is what the middleware learned about the caller. User and Token are never both set.
type reqCtx struct {
	User    *user     // nil for token and anonymous requests
	Token   *apiToken // set for Bearer requests
	Project *project  // set by proj, upload and obj perms
	Role    string    // the user's role on Project ("" for tokens)
	IP      string
}

func newServer(ctx context.Context, cfg config, db *pgxpool.Pool) (*server, error) {
	if n := len(cfg.BootstrapPassword); n < 12 || n > 72 {
		return nil, errors.New("JASCA_BOOTSTRAP_PASSWORD must be set to 12-72 characters")
	}
	if err := migrate(ctx, db); err != nil {
		return nil, err
	}
	s := &server{db: db, cfg: cfg, mux: http.NewServeMux(), objs: map[string]func(context.Context, string) (int64, error){},
		limiter: newLimiter(20, time.Minute)}
	var err error
	if s.secret, err = s.loadSecret(ctx); err != nil {
		return nil, err
	}
	if err := s.bootstrapAdmin(ctx, cfg.BootstrapPassword); err != nil {
		return nil, fmt.Errorf("bootstrap admin: %w", err)
	}
	// /healthz is liveness (no DB); /readyz is readiness (the DB answers).
	s.handle("GET /healthz", permPublic, func(w http.ResponseWriter, r *http.Request, c *reqCtx) { io.WriteString(w, "ok") })
	s.handle("GET /readyz", permPublic, func(w http.ResponseWriter, r *http.Request, c *reqCtx) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := s.db.Ping(ctx); err != nil {
			http.Error(w, "db unavailable", 503)
			return
		}
		io.WriteString(w, "ok")
	})
	s.authLocalRoutes()
	s.projectRoutes()
	s.tokenRoutes()
	s.principalRoutes()
	s.ssoRoutes()
	s.syncRoutes()
	s.scanRoutes()
	s.findingRoutes()
	s.vulnRoutes()
	for _, reg := range routeRegistrars {
		reg(s)
	}
	s.handle("GET /", permPublic, s.serveWeb)
	return s, nil
}

// routeRegistrars lets feature files register their routes from init() without editing newServer.
var routeRegistrars []func(*server)

// ServeHTTP is the outer middleware: recover, then security headers, then the routes.
func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if v := recover(); v != nil {
			if v == http.ErrAbortHandler {
				panic(v)
			}
			log.Printf("panic %s %s: %v\n%s", r.Method, r.URL.Path, v, debug.Stack())
			writeErr(w, 500, "internal", "서버 오류가 발생했습니다.")
		}
	}()
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
	if secure(r) {
		h.Set("Strict-Transport-Security", "max-age=31536000")
	}
	if _, pattern := s.mux.Handler(r); pattern == "" && strings.HasPrefix(r.URL.Path, "/api/") {
		writeErr(w, 405, "method_not_allowed", "이 주소는 이 요청 방식을 지원하지 않습니다.") // the mux would answer in plain text
		return
	}
	s.mux.ServeHTTP(w, r)
}

// handle registers a route. Every route declares its permission; the wrapper runs, in order,
// session/token auth → CSRF on unsafe methods → perm → h.
func (s *server) handle(pattern string, p perm, h func(w http.ResponseWriter, r *http.Request, c *reqCtx)) {
	if err := p.validate(); err != nil {
		panic(fmt.Sprintf("route %q: %v", pattern, err))
	}
	s.routes = append(s.routes, routeInfo{pattern, p})
	s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		c := &reqCtx{IP: clientIP(r)}
		if err := s.authenticate(r, c); err != nil {
			log.Printf("auth %s: %v", r.URL.Path, err)
			writeErr(w, 500, "internal", "서버 오류가 발생했습니다.")
			return
		}
		safe := r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS"
		if !safe && c.Token == nil && !sameOrigin(r, c.User != nil) {
			writeErr(w, 403, "csrf", "다른 사이트에서 보낸 요청은 처리하지 않습니다.")
			return
		}
		if !s.authorize(w, r, p, c) {
			return
		}
		h(w, r, c)
	})
}

// sameOrigin accepts a state change only from this site. Without any browser marker the request is from a
// script or a server; that is fine unless a session cookie speaks for the caller.
func sameOrigin(r *http.Request, cookieAuthed bool) bool {
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" {
		return sfs == "same-origin" || sfs == "none"
	}
	src := r.Header.Get("Origin")
	if src == "" {
		src = r.Header.Get("Referer")
	}
	if src == "" {
		return !cookieAuthed
	}
	u, err := url.Parse(src)
	return err == nil && u.Host != "" && u.Host == r.Host
}

func secure(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

// clientIP is the last X-Forwarded-For entry (the one our own ingress added; earlier ones are client-supplied),
// else the socket address.
func clientIP(r *http.Request) string {
	xff := r.Header.Values("X-Forwarded-For")
	if len(xff) > 0 {
		parts := strings.Split(xff[len(xff)-1], ",")
		if ip := strings.TrimSpace(parts[len(parts)-1]); net.ParseIP(ip) != nil {
			return ip
		}
	}
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// writeErr writes {"error":code,"message":msg}; msg is Korean text for the user.
func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}

// readJSON decodes one JSON object of at most max bytes, rejecting unknown fields and trailing data.
// Pass its error to writeBodyErr, which tells 413 from 400.
func readJSON(r *http.Request, max int64, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, max))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after JSON body")
	}
	return nil
}

func writeBodyErr(w http.ResponseWriter, err error) {
	if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
		writeErr(w, 413, "too_large", "요청 본문이 너무 큽니다.")
		return
	}
	writeErr(w, 400, "bad_request", "잘못된 요청입니다.")
}

func writeInternal(w http.ResponseWriter, what string, err error) {
	log.Printf("%s: %v", what, err)
	writeErr(w, 500, "internal", "서버 오류가 발생했습니다.")
}
