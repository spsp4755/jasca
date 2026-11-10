package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/spsp4755/jasca/internal/formats"
)

func (s *server) vulnRoutes() {
	s.handle("GET /api/v1/vulns/{id}", permUser, s.handleVulnGet)
}

// vulnUpsertSQL adds a catalog row or fills its empty fields; it never replaces stored text, because any project's
// upload writes here and the text is shown to (and given to the AI for) everyone. The catalog holds no severity.
var vulnUpsertSQL = func() string {
	sets := []string{}
	for _, c := range []struct{ col, empty string }{{"title", "''"}, {"description", "''"}, {"cvss_vector", "''"},
		{"refs", "'{}'"}, {"cwe_ids", "'{}'"}, {"cvss_score", ""}, {"published_at", ""}, {"last_modified_at", ""}} {
		cur := "vulns." + c.col
		if c.empty != "" {
			cur = "nullif(" + cur + ", " + c.empty + ")"
		}
		sets = append(sets, fmt.Sprintf("%[1]s = coalesce(%[2]s, excluded.%[1]s)", c.col, cur))
	}
	return `insert into vulns(id, title, description, cvss_score, cvss_vector, refs, cwe_ids, published_at, last_modified_at)
		values($1, $2, $3, $4, $5, coalesce($6::text[], '{}'), coalesce($7::text[], '{}'), $8, $9)
		on conflict (id) do update set ` + strings.Join(sets, ", ")
}()

// pastOnly drops a date in the future: an uploaded report's dates are not trusted.
func pastOnly(t *time.Time) *time.Time {
	if t != nil && t.After(time.Now()) {
		return nil
	}
	return t
}

// upsertVulns gives every vuln finding's id a catalog row.
func upsertVulns(ctx context.Context, tx pgx.Tx, fs []formats.Finding) error {
	byID := map[string]*formats.VulnInfo{}
	for _, f := range fs {
		if f.Kind == "vuln" && f.RuleID != "" && byID[f.RuleID] == nil {
			byID[f.RuleID] = f.Vuln
		}
	}
	ids := slices.Sorted(maps.Keys(byID)) // one lock order for concurrent ingests touching the same rows
	return sendBatches(ctx, tx, len(ids), func(b *pgx.Batch, i int) {
		v := byID[ids[i]]
		if v == nil {
			v = &formats.VulnInfo{}
		}
		b.Queue(vulnUpsertSQL, ids[i], v.Title, v.Description, v.CVSSScore, v.CVSSVector, v.Refs, v.CWEs, pastOnly(v.Published), pastOnly(v.Modified))
	})
}

type vulnAffected struct {
	ProjectKey   string `json:"project_key"`
	Target       string `json:"target"`
	FindingID    int64  `json:"finding_id"`
	Severity     string `json:"severity"`
	Status       string `json:"status"`
	PkgName      string `json:"pkg_name"`
	PkgVersion   string `json:"pkg_version"`
	FixedVersion string `json:"fixed_version"`
}

type vulnView struct {
	ID             string         `json:"id"`
	Title          string         `json:"title"`
	Description    string         `json:"description"`
	CVSSScore      *float64       `json:"cvss_score"`
	CVSSVector     string         `json:"cvss_vector"`
	Refs           []string       `json:"refs"`
	CWEIDs         []string       `json:"cwe_ids"`
	PublishedAt    *time.Time     `json:"published_at"`
	LastModifiedAt *time.Time     `json:"last_modified_at"`
	AIGuide        string         `json:"ai_guide"`
	AIGuideAt      *time.Time     `json:"ai_guide_at"`
	Advisory       bool           `json:"advisory"` // the id is an internal advisory (GET /advisories/{id}), not a public CVE
	Affected       []vulnAffected `json:"affected"`
}

// handleVulnGet returns the shared catalog entry with the findings of it that the caller can see (at most 1000).
func (s *server) handleVulnGet(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	var v vulnView
	err := s.db.QueryRow(ctx, `select id, title, description, cvss_score::float8, cvss_vector, refs, cwe_ids, published_at,
			last_modified_at, ai_guide, ai_guide_at, exists (select 1 from advisories a where a.id = vulns.id) from vulns where id = $1`, r.PathValue("id")).
		Scan(&v.ID, &v.Title, &v.Description, &v.CVSSScore, &v.CVSSVector, &v.Refs, &v.CWEIDs, &v.PublishedAt,
			&v.LastModifiedAt, &v.AIGuide, &v.AIGuideAt, &v.Advisory)
	if errors.Is(err, pgx.ErrNoRows) {
		writeErr(w, 404, "not_found", "취약점 정보를 찾을 수 없습니다.")
		return
	}
	if err != nil {
		writeInternal(w, "vuln get", err)
		return
	}
	cond, args := s.callerProjectsSQL(c, "f", 2)
	rows, _ := s.db.Query(ctx, `select p.key, t.name, f.id, f.severity, f.status, f.pkg_name, f.pkg_version, f.fixed_version
		from findings f join targets t on t.id = f.target_id join projects p on p.id = f.project_id
		where f.rule_id = $1 and `+cond+` order by p.key, t.name, f.id limit 1000`, append([]any{v.ID}, args...)...)
	if v.Affected, err = pgx.CollectRows(rows, pgx.RowToStructByPos[vulnAffected]); err != nil {
		writeInternal(w, "vuln affected", err)
		return
	}
	writeJSON(w, 200, v)
}
