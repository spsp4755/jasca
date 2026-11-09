package main

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

const tokenMaxLife = 365 * 24 * time.Hour

func (s *server) tokenRoutes() {
	s.handle("GET /api/v1/projects/{key}/tokens", permProj("owner"), s.handleTokenList)
	s.handle("POST /api/v1/projects/{key}/tokens", permProj("owner"), s.handleTokenCreate)
	s.handle("DELETE /api/v1/projects/{key}/tokens/{id}", permProj("owner"), s.handleTokenRevoke)
}

func (s *server) handleTokenList(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	rows, _ := s.db.Query(r.Context(), `select id, project_id, name, prefix, scopes, expires_at, last_used_at, created_by, created_at, revoked_at
		from api_tokens where project_id=$1 order by id desc`, c.Project.ID)
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[apiToken])
	if err != nil {
		writeInternal(w, "token list", err)
		return
	}
	writeJSON(w, 200, list)
}

func (s *server) handleTokenCreate(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	var req struct {
		Name      string    `json:"name"`
		Scopes    []string  `json:"scopes"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := readJSON(r, 4<<10, &req); err != nil {
		writeBodyErr(w, err)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || utf8.RuneCountInString(req.Name) > 100 {
		badRequest(w, "토큰 이름은 1~100자로 입력하세요.")
		return
	}
	slices.Sort(req.Scopes)
	req.Scopes = slices.Compact(req.Scopes)
	if len(req.Scopes) == 0 || slices.ContainsFunc(req.Scopes, func(sc string) bool { return sc != "upload" && sc != "read" }) {
		badRequest(w, "권한 범위는 upload, read 중에서 고르세요.")
		return
	}
	if now := time.Now(); !req.ExpiresAt.After(now) || req.ExpiresAt.After(now.Add(tokenMaxLife)) {
		badRequest(w, "만료일은 지금 이후, 1년 이내로 지정하세요.")
		return
	}
	b := make([]byte, 32)
	rand.Read(b)
	plain := "jsc_" + base64.RawURLEncoding.EncodeToString(b)
	var id int64
	err := s.db.QueryRow(ctx, `insert into api_tokens(project_id, name, prefix, token_hash, scopes, expires_at, created_by)
		values($1, $2, $3, $4, $5, $6, $7) returning id`,
		c.Project.ID, req.Name, plain[:12], tokenHash(plain), req.Scopes, req.ExpiresAt.UTC(), c.User.ID).Scan(&id)
	if err != nil {
		writeInternal(w, "token create", err)
		return
	}
	s.audit(ctx, c, "token.create", &c.Project.ID, strconv.FormatInt(id, 10),
		map[string]any{"name": req.Name, "scopes": req.Scopes, "expires_at": req.ExpiresAt.UTC()})
	writeJSON(w, 201, map[string]any{"id": id, "token": plain})
}

// handleTokenRevoke revokes a token of this project; another project's token id is 404. Revoking twice is fine.
func (s *server) handleTokenRevoke(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 404, "not_found", "찾을 수 없습니다.")
		return
	}
	tag, err := s.db.Exec(ctx, `update api_tokens set revoked_at = coalesce(revoked_at, now()) where id=$1 and project_id=$2`, id, c.Project.ID)
	if err != nil {
		writeInternal(w, "token revoke", err)
		return
	}
	if tag.RowsAffected() == 0 {
		writeErr(w, 404, "not_found", "찾을 수 없습니다.")
		return
	}
	s.audit(ctx, c, "token.revoke", &c.Project.ID, strconv.FormatInt(id, 10), nil)
	w.WriteHeader(204)
}
