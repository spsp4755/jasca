package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// Personal MCP keys ("jsu_…"): a person issues one for their own agent, and the key then speaks for that person.
// Nothing about the person is copied into the key: role, project memberships and whether the account is active are
// read on every request, so lowering a role or disabling an account takes effect at once. A key works at /mcp and
// on the two upload routes (perm.key), nowhere else in the REST API.

const (
	mcpKeyPrefix   = "jsu_"
	mcpKeysPerUser = 20 // live keys; an agent per machine fits many times over
)

type mcpKey struct {
	ID         int64      `json:"id"`
	UserID     int64      `json:"user_id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	ReadOnly   bool       `json:"read_only"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	CreatedAt  time.Time  `json:"created_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

const mcpKeyCols = `k.id, k.user_id, k.name, k.prefix, k.read_only, k.expires_at, k.last_used_at, k.created_at, k.revoked_at`

func init() { routeRegistrars = append(routeRegistrars, (*server).mcpKeyRoutes) }

func (s *server) mcpKeyRoutes() {
	s.handle("GET /api/v1/me/mcp-keys", permUser, s.handleMCPKeyList)
	s.handle("POST /api/v1/me/mcp-keys", permUser, s.handleMCPKeyCreate)
	s.handle("DELETE /api/v1/me/mcp-keys/{id}", permUser, s.mcpKeyRevoke(false))
	s.handle("GET /api/v1/me/mcp-tools", permUser, s.handleMCPToolList)
	s.handle("GET /api/v1/admin/mcp-keys", permAdmin, s.handleMCPKeyListAll)
	s.handle("DELETE /api/v1/admin/mcp-keys/{id}", permAdmin, s.mcpKeyRevoke(true))
}

// keyAuth resolves a Bearer value to a live personal key and its active user, or nils when the key is unknown,
// revoked or expired, or its user is inactive.
func (s *server) keyAuth(ctx context.Context, plain string) (*user, *mcpKey, error) {
	var stale bool
	rows, _ := s.db.Query(ctx, `select `+mcpKeyCols+`, k.last_used_at is null or k.last_used_at < now() - interval '1 minute'
		from mcp_keys k join users u on u.id = k.user_id and u.active
		where k.key_hash = $1 and k.revoked_at is null and k.expires_at > now()`, tokenHash(plain))
	k, err := pgx.CollectExactlyOneRow(rows, func(row pgx.CollectableRow) (*mcpKey, error) {
		k := &mcpKey{}
		return k, row.Scan(&k.ID, &k.UserID, &k.Name, &k.Prefix, &k.ReadOnly, &k.ExpiresAt, &k.LastUsedAt, &k.CreatedAt, &k.RevokedAt, &stale)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if stale {
		if _, err := s.db.Exec(ctx, `update mcp_keys set last_used_at = now() where id = $1`, k.ID); err != nil {
			return nil, nil, err
		}
	}
	u, err := s.loadUser(ctx, k.UserID)
	return u, k, err
}

func (s *server) handleMCPKeyList(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	list, err := collect[mcpKey](r.Context(), s, `select `+mcpKeyCols+` from mcp_keys k where k.user_id = $1 order by k.id desc`, c.User.ID)
	if err != nil {
		writeInternal(w, "mcp key list", err)
		return
	}
	writeJSON(w, 200, list)
}

// handleMCPKeyListAll is the administrator's view: every key that is not long gone, with whose it is.
func (s *server) handleMCPKeyListAll(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	type row struct {
		mcpKey
		Username string `json:"username"`
		UserName string `json:"user_name"`
		Active   bool   `json:"user_active"`
	}
	rows, _ := s.db.Query(r.Context(), `select `+mcpKeyCols+`, u.username, u.name, u.active from mcp_keys k join users u on u.id = k.user_id
		where coalesce(k.revoked_at, k.expires_at) > now() - interval '90 days' order by k.id desc limit 1000`)
	list, err := pgx.CollectRows(rows, func(cr pgx.CollectableRow) (row, error) {
		var v row
		k := &v.mcpKey
		return v, cr.Scan(&k.ID, &k.UserID, &k.Name, &k.Prefix, &k.ReadOnly, &k.ExpiresAt, &k.LastUsedAt, &k.CreatedAt, &k.RevokedAt,
			&v.Username, &v.UserName, &v.Active)
	})
	if err != nil {
		writeInternal(w, "mcp key list", err)
		return
	}
	if list == nil {
		list = []row{}
	}
	writeJSON(w, 200, list)
}

func (s *server) handleMCPKeyCreate(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	var req struct {
		Name      string    `json:"name"`
		ReadOnly  bool      `json:"read_only"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := readJSON(r, 4<<10, &req); err != nil {
		writeBodyErr(w, err)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || utf8.RuneCountInString(req.Name) > 100 {
		badRequest(w, "키 이름은 1~100자로 입력하세요.")
		return
	}
	if now := time.Now(); !req.ExpiresAt.After(now) || req.ExpiresAt.After(now.Add(tokenMaxLife)) {
		badRequest(w, "만료일은 지금 이후, 1년 이내로 지정하세요.")
		return
	}
	b := make([]byte, 32)
	rand.Read(b)
	plain := mcpKeyPrefix + base64.RawURLEncoding.EncodeToString(b)
	var id int64
	err := s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `select 1 from users where id = $1 for update`, c.User.ID); err != nil { // two requests at once count once
			return err
		}
		var live int
		if err := tx.QueryRow(ctx, `select count(*) from mcp_keys where user_id = $1 and revoked_at is null and expires_at > now()`,
			c.User.ID).Scan(&live); err != nil {
			return err
		}
		if live >= mcpKeysPerUser {
			return errTooManyKeys
		}
		return tx.QueryRow(ctx, `insert into mcp_keys(user_id, name, prefix, key_hash, read_only, expires_at)
			values($1, $2, $3, $4, $5, $6) returning id`, c.User.ID, req.Name, plain[:12], tokenHash(plain), req.ReadOnly, req.ExpiresAt.UTC()).Scan(&id)
	})
	if errors.Is(err, errTooManyKeys) {
		writeErr(w, 409, "conflict", "쓸 수 있는 MCP 키는 20개까지입니다. 쓰지 않는 키를 폐기한 뒤 다시 만드세요.")
		return
	}
	if err != nil {
		writeInternal(w, "mcp key create", err)
		return
	}
	s.audit(ctx, c, "mcpkey.create", nil, req.Name, map[string]any{"key_id": id, "read_only": req.ReadOnly, "expires_at": req.ExpiresAt.UTC()})
	writeJSON(w, 201, map[string]any{"id": id, "key": plain})
}

var errTooManyKeys = errors.New("too many live MCP keys")

// mcpKeyRevoke revokes one of the caller's keys, or with any (the administrator's route) anyone's. Another person's
// key id is 404 on the personal route. Revoking twice is fine.
func (s *server) mcpKeyRevoke(any bool) func(http.ResponseWriter, *http.Request, *reqCtx) {
	return func(w http.ResponseWriter, r *http.Request, c *reqCtx) {
		s.revokeMCPKey(w, r, c, any)
	}
}

func (s *server) revokeMCPKey(w http.ResponseWriter, r *http.Request, c *reqCtx, admin bool) {
	ctx, id := r.Context(), pathID(r)
	var name, owner string
	err := s.db.QueryRow(ctx, `update mcp_keys k set revoked_at = coalesce(k.revoked_at, now()) from users u
		where k.id = $1 and u.id = k.user_id and ($2 or k.user_id = $3) returning k.name, u.username`, id, admin, c.User.ID).Scan(&name, &owner)
	if errors.Is(err, pgx.ErrNoRows) {
		notFoundErr(w)
		return
	}
	if err != nil {
		writeInternal(w, "mcp key revoke", err)
		return
	}
	s.audit(ctx, c, "mcpkey.revoke", nil, name, map[string]any{"key_id": id, "owner": owner})
	w.WriteHeader(204)
}

// handleMCPToolList tells the key page which tools a key of the signed-in person gets right now.
func (s *server) handleMCPToolList(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	type row struct {
		Name     string `json:"name"`
		Title    string `json:"title"`
		Group    string `json:"group"` // user | security | admin
		Write    bool   `json:"write"`
		Disabled bool   `json:"disabled"` // not for this person's role
	}
	out := []row{}
	for _, t := range mcpAllTools() {
		out = append(out, row{t.Name, t.title, mcpLevels[t.level], t.write, t.level > mcpLevel(c.User)})
	}
	writeJSON(w, 200, out)
}
