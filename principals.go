package main

import (
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

func (s *server) principalRoutes() {
	s.handle("GET /api/v1/principals", permUser, s.handlePrincipals)
}

type principal struct {
	Kind      string `json:"kind"`
	Principal string `json:"principal"`
	Display   string `json:"display"`
}

var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// handlePrincipals finds users and group/department paths for the member editor: up to 20, users first.
func (s *server) handlePrincipals(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if utf8.RuneCountInString(q) > 100 {
		badRequest(w, "검색어가 너무 깁니다.")
		return
	}
	like := "%" + likeEscaper.Replace(q) + "%"
	rows, _ := s.db.Query(r.Context(), `select kind, principal, display from (
		(select 1 as ord, 'user' as kind, id::text as principal, username as sort,
				case when name <> '' and name <> username then name || ' (' || username || ')' else username end as display
			from users where active and (username ilike $1 or name ilike $1 or email ilike $1) order by username limit 20)
		union all
		(select 2, 'group', path, path, path from (select path from kc_groups where not deleted
			union select path from user_groups union select path from user_depts) g where path ilike $1 order by path limit 20)
		) x order by ord, sort limit 20`, like)
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[principal])
	if err != nil {
		writeInternal(w, "principals", err)
		return
	}
	writeJSON(w, 200, list)
}
