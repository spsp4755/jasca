package main

import (
	"bufio"
	"context"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/spsp4755/jasca/internal/versions"
)

func init() { routeRegistrars = append(routeRegistrars, (*server).packageRoutes) }

func (s *server) packageRoutes() {
	s.handle("GET /api/v1/packages", permUser, s.handlePackageSearch)
	s.handle("GET /api/v1/packages.csv", permUser, s.handlePackageCSV)
}

const (
	pkgMaxRows  = 1000 // the answer says truncated instead of paginating
	pkgMaxPaths = 5
)

// pkgHit is one package of a target's current inventory: one row per target, ecosystem, name and version.
type pkgHit struct {
	ProjectKey     string    `json:"project_key"`
	ProjectName    string    `json:"project_name"`
	TargetID       int64     `json:"target_id"`
	TargetKind     string    `json:"target_kind"`
	TargetName     string    `json:"target_name"`
	Ecosystem      string    `json:"ecosystem"`
	Name           string    `json:"name"`
	Version        string    `json:"version"`
	Paths          []string  `json:"paths"` // the first pkgMaxPaths of path_count
	PathCount      int       `json:"path_count"`
	ScanID         int64     `json:"scan_id"` // the scan the inventory is from
	ScanAt         time.Time `json:"scan_at"`
	OpenFindings   int       `json:"open_findings"`   // of this target for this name and version; 0 = none known yet
	WorstSeverity  string    `json:"worst_severity"`  // "" without open findings
	VersionUnknown bool      `json:"version_unknown"` // the version could not be compared with the condition
}

type pkgTotals struct {
	Matched                 int `json:"matched"`         // rows that meet the condition, before the cap
	VersionUnknown          int `json:"version_unknown"` // rows kept because their version could not be compared
	Projects                int `json:"projects"`        // of the matched rows
	Targets                 int `json:"targets"`
	TargetsSearched         int `json:"targets_searched"` // visible targets that have an inventory
	TargetsWithoutInventory int `json:"targets_without_inventory"`
}

type pkgResult struct {
	Items      []pkgHit  `json:"items"`
	Truncated  bool      `json:"truncated"`
	Ecosystems []string  `json:"ecosystems"` // of every name match, whatever the ecosystem and version filters
	Totals     pkgTotals `json:"totals"`
}

const versionCondHelp = "버전 조건을 읽지 못했습니다. <2.17.1, >=2.0 <2.17.1, 2.14.1처럼 입력하세요."

// searchPackages finds packages by name in the current inventory (latestInventorySQL) of the targets the caller can
// see. msg is set when a query parameter is invalid. The version condition is evaluated here, per row and with the
// row's ecosystem: a version it cannot be compared with is kept and flagged, never dropped.
func (s *server) searchPackages(ctx context.Context, c *reqCtx, q url.Values) (res *pkgResult, msg string, err error) {
	name, cond, eco := strings.TrimSpace(q.Get("q")), strings.TrimSpace(q.Get("version")), q.Get("ecosystem")
	switch n := utf8.RuneCountInString(name); {
	case n < 2:
		return nil, "패키지 이름을 2자 이상 입력하세요.", nil
	case n > 200 || len(cond) > 200:
		return nil, "검색어가 너무 깁니다.", nil
	}
	if cond != "" {
		if _, err := versions.Matches(eco, "0", cond); err != nil {
			return nil, versionCondHelp, nil
		}
	}
	vis, args := s.callerProjectsSQL(c, "t", 1)
	w := &where{conds: []string{vis}, args: args}
	if v := q.Get("project"); v != "" {
		w.add("t.project_id = (select id from projects where key = ?)", v)
	}
	// The inventory scan of each visible target first, then the names inside those scans only.
	inv := `select t.id, t.project_id, t.kind, t.name, ` + latestInventorySQL + ` as scan_id from targets t where ` + w.sql()
	res = &pkgResult{Items: []pkgHit{}}
	t := &res.Totals
	if err := s.db.QueryRow(ctx, `select count(scan_id), count(*) - count(scan_id) from (`+inv+`) i`, w.args...).
		Scan(&t.TargetsSearched, &t.TargetsWithoutInventory); err != nil {
		return nil, "", err
	}
	args = append(w.args, "%"+likeEscaper.Replace(name)+"%")
	rows, err := s.db.Query(ctx, `with inv as materialized (`+inv+`)
		select pr.key, pr.name, i.id, i.kind, i.name, p.ecosystem, p.name, p.version,
			coalesce(array_agg(distinct p.path) filter (where p.path <> ''), '{}'), sc.id, coalesce(sc.finished_at, sc.created_at)
		from inv i join packages p on p.scan_id = i.scan_id join scans sc on sc.id = i.scan_id
			join projects pr on pr.id = i.project_id
		where p.name ilike $`+strconv.Itoa(len(args))+`
		group by pr.key, pr.name, i.id, i.kind, i.name, p.ecosystem, p.name, p.version, sc.id
		order by pr.key, i.name, i.id, p.name, p.version, p.ecosystem`, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	ecos, projects, targets := map[string]bool{}, map[string]bool{}, map[int64]bool{}
	for rows.Next() {
		var h pkgHit
		if err := rows.Scan(&h.ProjectKey, &h.ProjectName, &h.TargetID, &h.TargetKind, &h.TargetName, &h.Ecosystem, &h.Name,
			&h.Version, &h.Paths, &h.ScanID, &h.ScanAt); err != nil {
			return nil, "", err
		}
		ecos[h.Ecosystem] = true
		if eco != "" && h.Ecosystem != eco {
			continue
		}
		if cond != "" {
			ok, err := versions.Matches(h.Ecosystem, h.Version, cond)
			if h.VersionUnknown = err != nil; !ok && !h.VersionUnknown {
				continue
			}
		}
		if h.VersionUnknown {
			t.VersionUnknown++
		} else {
			t.Matched++
			projects[h.ProjectKey], targets[h.TargetID] = true, true
		}
		if len(res.Items) == pkgMaxRows {
			res.Truncated = true
			continue
		}
		h.PathCount = len(h.Paths)
		h.Paths = h.Paths[:min(pkgMaxPaths, len(h.Paths))]
		res.Items = append(res.Items, h)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	t.Projects, t.Targets = len(projects), len(targets)
	res.Ecosystems = append([]string{}, slices.Sorted(maps.Keys(ecos))...) // [] in JSON, never null
	return res, "", s.addPkgFindings(ctx, res.Items)
}

// addPkgFindings fills the open findings of each row's target for its package name and version.
func (s *server) addPkgFindings(ctx context.Context, items []pkgHit) error {
	type key struct {
		target        int64
		name, version string
	}
	at := map[key][]int{}
	var targets []int64
	var names []string
	for i, h := range items {
		k := key{h.TargetID, h.Name, h.Version}
		at[k] = append(at[k], i) // the same name and version in two ecosystems share the findings
		targets, names = append(targets, h.TargetID), append(names, h.Name)
	}
	rows, err := s.db.Query(ctx, `select f.target_id, f.pkg_name, f.pkg_version, count(*),
			(array['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'])[min(`+sevRankSQL+`)]
		from findings f where f.status = 'open' and f.target_id = any($1) and f.pkg_name = any($2)
		group by f.target_id, f.pkg_name, f.pkg_version`, targets, names)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k key
		var n int
		var worst string
		if err := rows.Scan(&k.target, &k.name, &k.version, &n, &worst); err != nil {
			return err
		}
		for _, i := range at[k] {
			items[i].OpenFindings, items[i].WorstSeverity = n, worst
		}
	}
	return rows.Err()
}

func (s *server) handlePackageSearch(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	res, msg, err := s.searchPackages(r.Context(), c, r.URL.Query())
	switch {
	case err != nil:
		writeInternal(w, "package search", err)
	case msg != "":
		badRequest(w, msg)
	default:
		writeJSON(w, 200, res)
	}
}

// handlePackageCSV is the same rows as the search, capped the same way.
func (s *server) handlePackageCSV(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	res, msg, err := s.searchPackages(r.Context(), c, r.URL.Query())
	if err != nil {
		writeInternal(w, "package csv", err)
		return
	}
	if msg != "" {
		badRequest(w, msg)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="packages.csv"`)
	bw := bufio.NewWriter(w)
	defer bw.Flush()
	bw.WriteString("\ufeff") // Excel reads Hangul as UTF-8 only with a BOM
	line := func(cells ...string) {
		for i, v := range cells {
			if i > 0 {
				bw.WriteByte(',')
			}
			bw.WriteString(csvCell(v))
		}
		bw.WriteString("\r\n")
	}
	line("프로젝트", "프로젝트 이름", "대상 종류", "대상", "패키지", "버전", "패키지 종류", "위치", "위치 수", "열린 취약점",
		"가장 높은 심각도", "버전 비교", "기준 스캔", "기준 스캔 시각")
	for _, h := range res.Items {
		compared := ""
		if h.VersionUnknown {
			compared = "비교하지 못함"
		}
		line(h.ProjectKey, h.ProjectName, h.TargetKind, h.TargetName, h.Name, h.Version, h.Ecosystem, strings.Join(h.Paths, "\n"),
			strconv.Itoa(h.PathCount), strconv.Itoa(h.OpenFindings), h.WorstSeverity, compared, itoa(h.ScanID),
			h.ScanAt.In(s.cfg.Loc).Format(time.RFC3339))
	}
}
