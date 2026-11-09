package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

// Local login exists only for the bootstrap `admin` account (setup and emergencies); everyone else uses SSO.
const (
	bcryptCost   = 12
	lockAfter    = 5 // failed passwords in a row
	lockDuration = 15 * time.Minute
)

// dummyHash keeps the response time the same for unknown users.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("jasca-dummy-password"), bcryptCost)

func (s *server) authLocalRoutes() {
	s.handle("POST /api/v1/auth/local", permPublic, s.handleLocalLogin)
	s.handle("POST /api/v1/auth/logout", permUser, s.handleLogout)
	s.handle("GET /api/v1/me", permUser, func(w http.ResponseWriter, r *http.Request, c *reqCtx) { writeJSON(w, 200, c.User) })
}

// bootstrapAdmin creates the local admin on an empty database. A later start never changes its password.
func (s *server) bootstrapAdmin(ctx context.Context, password string) error {
	var exists bool
	if err := s.db.QueryRow(ctx, `select exists(select 1 from users where username='admin')`).Scan(&exists); err != nil || exists {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `insert into users(username, name, source, password_hash, system_role)
		values('admin', '관리자', 'local', $1, 'admin') on conflict (username) do nothing`, string(hash))
	return err
}

func (s *server) handleLocalLogin(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	if !s.limiter.allow(c.IP, time.Now()) {
		writeErr(w, 429, "rate_limited", "요청이 너무 많습니다. 잠시 후 다시 시도하세요.")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(r, 4<<10, &req); err != nil {
		writeBodyErr(w, err)
		return
	}
	name := strings.TrimSpace(req.Username)
	var id int64
	var source string
	var hash *string
	var active, locked bool
	err := s.db.QueryRow(ctx, `select id, source, password_hash, active, coalesce(locked_until > now(), false) from users where username=$1`, name).
		Scan(&id, &source, &hash, &active, &locked)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		writeInternal(w, "login", err)
		return
	}
	fail := func(reason string) {
		s.audit(ctx, c, "auth.login_failed", nil, name, map[string]any{"method": "local", "reason": reason})
	}
	if err == nil && locked {
		fail("locked")
		writeErr(w, 423, "locked", "로그인 실패가 반복되어 계정이 잠겼습니다. 15분 뒤에 다시 시도하세요.")
		return
	}
	usable := err == nil && source == "local" && active && hash != nil
	h := dummyHash
	if usable {
		h = []byte(*hash)
	}
	if bcrypt.CompareHashAndPassword(h, []byte(req.Password)) != nil || !usable {
		if usable { // count failures only where a password could work; an expired lock starts the count over
			_, err := s.db.Exec(ctx, `update users set
				failed_logins = case when locked_until <= now() then 1 else failed_logins + 1 end,
				locked_until = case when (case when locked_until <= now() then 1 else failed_logins + 1 end) >= $2
					then now() + make_interval(secs => $3::float8) when locked_until <= now() then null else locked_until end
				where id=$1`, id, lockAfter, lockDuration.Seconds())
			if err != nil {
				writeInternal(w, "login failure count", err)
				return
			}
		}
		fail("bad_credentials")
		writeErr(w, 401, "invalid_credentials", "아이디 또는 비밀번호가 올바르지 않습니다.")
		return
	}
	if _, err := s.db.Exec(ctx, `update users set failed_logins=0, locked_until=null, last_login_at=now() where id=$1`, id); err != nil {
		writeInternal(w, "login", err)
		return
	}
	token, err := s.startSession(ctx, id, r)
	if err != nil {
		writeInternal(w, "login session", err)
		return
	}
	if c.User, err = s.loadUser(ctx, id); err != nil {
		writeInternal(w, "login user", err)
		return
	}
	setSessionCookie(w, r, token)
	s.audit(ctx, c, "auth.login", nil, name, map[string]any{"method": "local"})
	writeJSON(w, 200, map[string]any{"user": c.User})
}

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	if ck, err := r.Cookie(sessionCookie); err == nil {
		if _, err := s.db.Exec(r.Context(), `delete from sessions where token_hash=$1`, tokenHash(ck.Value)); err != nil {
			writeInternal(w, "logout", err)
			return
		}
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: secure(r)})
	s.audit(r.Context(), c, "auth.logout", nil, c.User.Username, nil)
	w.WriteHeader(204)
}

// limiter is a token bucket per key: burst attempts at once, refilled at burst per window.
// shortcut: per-process limiter, fine at replicas 1
type limiter struct {
	mu      sync.Mutex
	burst   float64
	perSec  float64
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	at     time.Time
}

func newLimiter(burst int, window time.Duration) *limiter {
	return &limiter{burst: float64(burst), perSec: float64(burst) / window.Seconds(), buckets: map[string]*bucket{}}
}

func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.buckets) > 10000 { // forget keys that are full again, so the map cannot grow without bound
		for k, b := range l.buckets {
			if b.tokens+now.Sub(b.at).Seconds()*l.perSec >= l.burst {
				delete(l.buckets, k)
			}
		}
	}
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, at: now}
		l.buckets[key] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.at).Seconds()*l.perSec)
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
