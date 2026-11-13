package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Server-side sessions: the cookie holds a random token and only its SHA-256 is stored, so a session can be
// ended at once and a database leak gives no usable cookie.
const (
	sessionCookie = "jasca_session"
	sessionTTL    = 8 * time.Hour
)

// tokenHash is how session cookies and API tokens (the whole "jsc_..." string) are stored.
func tokenHash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// startSession stores a new session for userID and returns the cookie value. The browser's previous session
// ends, and with MAX_SESSIONS > 0 the oldest sessions beyond the limit end as 'replaced': those browsers are told
// why on the login page, and the new session carries a notice for its own user (takeNotice).
func (s *server) startSession(ctx context.Context, userID int64, r *http.Request) (string, error) {
	b := make([]byte, 32)
	rand.Read(b)
	token := base64.RawURLEncoding.EncodeToString(b)
	var live, ended int // the user's other open sessions before this login, and how many of them it ended
	err := s.tx(ctx, func(tx pgx.Tx) error {
		// two logins at once must not both slip under the limit
		if _, err := tx.Exec(ctx, `select 1 from users where id=$1 for update`, userID); err != nil {
			return err
		}
		if c, err := r.Cookie(sessionCookie); err == nil {
			if _, err := tx.Exec(ctx, `delete from sessions where token_hash=$1`, tokenHash(c.Value)); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `delete from sessions where user_id=$1 and (expires_at <= now()
			or (ended_reason = '' and $2::float8 > 0 and last_seen_at < now() - make_interval(secs => $2::float8)))`, userID, s.cfg.SessionIdle.Seconds()); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `select count(*) from sessions where user_id=$1 and ended_reason = ''`, userID).Scan(&live); err != nil {
			return err
		}
		if max := s.cfg.MaxSessions; max > 0 {
			tag, err := tx.Exec(ctx, `update sessions set ended_reason='replaced' where id in (select id from sessions
				where user_id=$1 and ended_reason = '' order by created_at desc, id desc offset $2)`, userID, max-1)
			if err != nil {
				return err
			}
			ended = int(tag.RowsAffected())
		}
		var notice any
		if live > 0 {
			notice = map[string]int{"ended": ended, "active": live - ended}
		}
		ua := r.UserAgent()
		if len(ua) > 512 {
			ua = ua[:512]
		}
		_, err := tx.Exec(ctx, `insert into sessions(token_hash, user_id, user_agent, ip, expires_at, notice) values($1, $2, $3, $4, $5, $6)`,
			tokenHash(token), userID, ua, clientIP(r), time.Now().Add(sessionTTL), notice)
		return err
	})
	if err == nil && ended > 0 {
		s.audit(ctx, &reqCtx{User: &user{ID: userID}, IP: clientIP(r)}, "auth.session_end", nil, "", map[string]any{"reason": "replaced", "count": ended})
	}
	return token, err
}

// takeNotice hands out, once, what the session's login had to tell its user. nil when there is nothing.
func (s *server) takeNotice(ctx context.Context, token string) []byte {
	var n []byte
	err := s.db.QueryRow(ctx, `with old as (select id, notice from sessions where token_hash=$1 and notice is not null for update)
		update sessions x set notice=null from old where x.id=old.id returning old.notice`, tokenHash(token)).Scan(&n)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		log.Printf("session notice: %v", err)
	}
	return n
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: secure(r), MaxAge: int(sessionTTL.Seconds())})
}

// sessionUser resolves a cookie value to its active user, or nil when the session is unknown, expired, idle,
// ended or the user is inactive. ended says why for a session that a newer login ended ("replaced").
// last_seen_at is written at most once a minute.
func (s *server) sessionUser(ctx context.Context, token string) (u *user, ended string, err error) {
	var id, uid int64
	var dead, stale bool
	err = s.db.QueryRow(ctx, `select s.id, s.user_id, s.ended_reason,
			s.expires_at <= now() or (s.ended_reason = '' and $2::float8 > 0 and s.last_seen_at < now() - make_interval(secs => $2::float8)),
			s.last_seen_at < now() - interval '1 minute'
		from sessions s join users u on u.id = s.user_id and u.active where s.token_hash=$1`,
		tokenHash(token), s.cfg.SessionIdle.Seconds()).Scan(&id, &uid, &ended, &dead, &stale)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	if dead {
		_, err := s.db.Exec(ctx, `delete from sessions where id=$1`, id)
		return nil, "", err
	}
	if ended != "" {
		return nil, ended, nil
	}
	if stale {
		if _, err := s.db.Exec(ctx, `update sessions set last_seen_at=now() where id=$1`, id); err != nil {
			return nil, "", err
		}
	}
	u, err = s.loadUser(ctx, uid)
	return u, "", err
}

// tokenAuth resolves a Bearer value to a live API token, or nil when it is unknown, revoked or expired.
func (s *server) tokenAuth(ctx context.Context, plain string) (*apiToken, error) {
	if !strings.HasPrefix(plain, "jsc_") {
		return nil, nil
	}
	t := &apiToken{}
	var stale bool
	err := s.db.QueryRow(ctx, `select id, project_id, name, prefix, scopes, expires_at, last_used_at, created_by, created_at, revoked_at,
			last_used_at is null or last_used_at < now() - interval '1 minute'
		from api_tokens where token_hash=$1 and revoked_at is null and expires_at > now()`, tokenHash(plain)).
		Scan(&t.ID, &t.ProjectID, &t.Name, &t.Prefix, &t.Scopes, &t.ExpiresAt, &t.LastUsedAt, &t.CreatedBy, &t.CreatedAt, &t.RevokedAt, &stale)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if stale {
		if _, err := s.db.Exec(ctx, `update api_tokens set last_used_at=now() where id=$1`, t.ID); err != nil {
			return nil, err
		}
	}
	return t, nil
}

// authenticate fills c.User (with c.Key for a personal MCP key) or c.Token. A Bearer header means token or key auth
// only; the cookie is then ignored. An invalid credential leaves them nil, and authorize answers 401 on non-public
// routes.
func (s *server) authenticate(r *http.Request, c *reqCtx) (err error) {
	if plain, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		if plain = strings.TrimSpace(plain); strings.HasPrefix(plain, mcpKeyPrefix) {
			c.User, c.Key, err = s.keyAuth(r.Context(), plain)
			return err
		}
		c.Token, err = s.tokenAuth(r.Context(), plain)
		return err
	}
	if ck, e := r.Cookie(sessionCookie); e == nil {
		c.User, c.Ended, err = s.sessionUser(r.Context(), ck.Value)
	}
	return err
}

func (s *server) loadUser(ctx context.Context, id int64) (*user, error) {
	u := &user{}
	err := s.db.QueryRow(ctx, `select id, username, name, email, system_role, source,
			array(select path from user_depts where user_id=u.id order by path),
			array(select path from user_groups where user_id=u.id order by path)
		from users u where id=$1`, id).Scan(&u.ID, &u.Username, &u.Name, &u.Email, &u.SystemRole, &u.Source, &u.Depts, &u.Groups)
	if err != nil {
		return nil, err
	}
	return u, nil
}

// signed encodes v as base64(json).base64(hmac) so a short-lived cookie (the SSO state) cannot be forged.
func (s *server) signed(v any) string {
	b, _ := json.Marshal(v)
	p := base64.RawURLEncoding.EncodeToString(b)
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(p))
	return p + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *server) unsigned(raw string, v any) bool {
	p, sig, ok := strings.Cut(raw, ".")
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(p))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !ok || subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(p)
	return err == nil && json.Unmarshal(b, v) == nil
}
