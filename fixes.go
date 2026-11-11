package main

import (
	"cmp"
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/spsp4755/jasca/internal/versions"
)

func init() { routeRegistrars = append(routeRegistrars, (*server).fixRoutes) }

func (s *server) fixRoutes() {
	s.handle("GET /api/v1/projects/{key}/fixes", permProj("viewer"), s.handleFixes)
}

// fixMaxFindings caps the open vulnerability findings one plan groups, most severe first (a var for the tests).
var fixMaxFindings = 5000

type fixFinding struct {
	ID           int64  `json:"id"`
	RuleID       string `json:"rule_id"`
	Severity     string `json:"severity"`
	Title        string `json:"title"`
	TargetID     int64  `json:"target_id"`
	Target       string `json:"target"`
	PkgPath      string `json:"pkg_path"`
	FixedVersion string `json:"fixed_version"`
}

type fixTarget struct {
	ID    int64    `json:"id"`
	Kind  string   `json:"kind"`
	Name  string   `json:"name"`
	Paths []string `json:"paths"` // the files the package was found in, when the report names them
}

// fixGroup is one package at one installed version, with every open vulnerability finding of it in the project.
type fixGroup struct {
	Package   string `json:"package"`
	Ecosystem string `json:"ecosystem"` // "" when no package inventory of the target names it
	Installed string `json:"installed"`
	// Recommended is the highest of all fixed versions the findings list: that version or a higher one resolves
	// every finding counted in Resolves, whatever release line each listed version belongs to. "" when the versions
	// could not be compared (unknown ecosystem, a version that does not parse, nothing above the installed
	// version); then FixedVersions is all there is to say.
	Recommended   string       `json:"recommended"`
	FixedVersions []string     `json:"fixed_versions"` // as the scanners wrote them, without duplicates
	Resolves      sevCounts    `json:"resolves"`       // findings with a fixed version, by severity; open = all of them
	NoFix         int          `json:"no_fix"`         // findings of the group without a fixed version
	Targets       []fixTarget  `json:"targets"`
	Findings      []fixFinding `json:"findings"` // most severe first

	rank int // severity rank of the worst finding the upgrade resolves (of any finding when it resolves none)
}

type fixPlan struct {
	Groups      []*fixGroup `json:"groups"`        // an upgrade resolves something: worst severity, then most resolved first
	NoFixGroups []*fixGroup `json:"no_fix_groups"` // no finding has a fixed version: upgrading does not help yet
	Totals      struct {
		OpenVulns int `json:"open_vulns"`
		Fixable   int `json:"fixable"` // open vulnerability findings with a fixed version
		NoFix     int `json:"no_fix"`
		// open findings this plan does not cover, by kind: misconfig, secret, sast
		OtherKinds map[string]int `json:"other_kinds"`
		// targets with a package inventory: 0 means no scan has looked at packages, so "no vulnerabilities" says nothing
		InventoryTargets int `json:"inventory_targets"`
	} `json:"totals"`
	Limit     int  `json:"limit"`
	Truncated bool `json:"truncated"` // more than Limit open vulnerability findings: the groups hold the most severe ones
}

// recommend fills Recommended (see there).
func (g *fixGroup) recommend() {
	if len(g.FixedVersions) == 0 || !versions.Known(g.Ecosystem) {
		return
	}
	best := ""
	for _, v := range g.FixedVersions {
		v = strings.TrimLeft(v, ">= ") // some sources write ">=4.17.19"
		if best != "" {
			c, err := versions.Compare(g.Ecosystem, v, best)
			if err != nil {
				return
			}
			if c <= 0 {
				continue
			}
		}
		best = v
	}
	if c, err := versions.Compare(g.Ecosystem, best, g.Installed); err == nil && c > 0 {
		g.Recommended = best
	}
}

// fixPlan groups the project's open vulnerability findings (of one target when targetID > 0) by the package
// upgrade that resolves them. The ecosystem, needed to compare versions, is the one the target's current package
// inventory gives the package.
func (s *server) fixPlan(ctx context.Context, projectID, targetID int64) (*fixPlan, error) {
	p := &fixPlan{Groups: []*fixGroup{}, NoFixGroups: []*fixGroup{}, Limit: fixMaxFindings}
	t := &p.Totals
	var misconfig, secret, sast int
	if err := s.db.QueryRow(ctx, `select count(*) filter (where kind = 'vuln'), count(*) filter (where kind = 'vuln' and fixed_version <> ''),
			count(*) filter (where kind = 'misconfig'), count(*) filter (where kind = 'secret'), count(*) filter (where kind = 'sast'),
			(select count(*) from targets t where t.project_id = $1 and ($2 = 0 or t.id = $2) and `+latestInventorySQL+` is not null)
		from findings where project_id = $1 and status = 'open' and ($2 = 0 or target_id = $2)`, projectID, targetID).
		Scan(&t.OpenVulns, &t.Fixable, &misconfig, &secret, &sast, &t.InventoryTargets); err != nil {
		return nil, err
	}
	t.NoFix = t.OpenVulns - t.Fixable
	t.OtherKinds = map[string]int{"misconfig": misconfig, "secret": secret, "sast": sast}
	p.Truncated = t.OpenVulns > fixMaxFindings

	rows, err := s.db.Query(ctx, `with inv as materialized (select t.id, t.kind, t.name, `+latestInventorySQL+` as scan_id
			from targets t where t.project_id = $1)
		select f.id, f.rule_id, f.severity, f.title, t.id, t.name, f.pkg_path, f.fixed_version, t.kind, f.pkg_name, f.pkg_version,
			coalesce((select p.ecosystem from packages p where p.scan_id = t.scan_id and p.name = f.pkg_name
				and p.version = f.pkg_version order by (p.path = f.pkg_path) desc, p.ecosystem limit 1), '')
		from findings f join inv t on t.id = f.target_id
		where f.project_id = $1 and f.status = 'open' and f.kind = 'vuln' and ($2 = 0 or f.target_id = $2)`+
		findingOrder+` limit $3`, projectID, targetID, fixMaxFindings)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type key struct{ pkg, version, eco string }
	groups := map[key]*fixGroup{}
	for rows.Next() {
		var f fixFinding
		var kind string
		var k key
		if err := rows.Scan(&f.ID, &f.RuleID, &f.Severity, &f.Title, &f.TargetID, &f.Target, &f.PkgPath, &f.FixedVersion,
			&kind, &k.pkg, &k.version, &k.eco); err != nil {
			return nil, err
		}
		g := groups[k]
		if g == nil {
			g = &fixGroup{Package: k.pkg, Ecosystem: k.eco, Installed: k.version, FixedVersions: []string{}}
			groups[k] = g
		}
		g.Findings = append(g.Findings, f)
		i := slices.IndexFunc(g.Targets, func(t fixTarget) bool { return t.ID == f.TargetID })
		if i < 0 {
			i = len(g.Targets)
			g.Targets = append(g.Targets, fixTarget{f.TargetID, kind, f.Target, []string{}})
		}
		if tg := &g.Targets[i]; f.PkgPath != "" && f.PkgPath != f.Target && !slices.Contains(tg.Paths, f.PkgPath) {
			tg.Paths = append(tg.Paths, f.PkgPath)
		}
		rank := cmp.Or(severityRank[f.Severity], 5)
		if f.FixedVersion == "" {
			g.NoFix++
			if g.Resolves.Open == 0 {
				g.rank = cmp.Or(g.rank, rank) // rows come most severe first
			}
			continue
		}
		if g.Resolves.Open == 0 {
			g.rank = rank
		}
		g.Resolves.Open++
		switch f.Severity {
		case "CRITICAL":
			g.Resolves.Critical++
		case "HIGH":
			g.Resolves.High++
		case "MEDIUM":
			g.Resolves.Medium++
		case "LOW":
			g.Resolves.Low++
		default:
			g.Resolves.Unknown++
		}
		for _, v := range strings.Split(f.FixedVersion, ",") {
			if v = strings.TrimSpace(v); v != "" && !slices.Contains(g.FixedVersions, v) {
				g.FixedVersions = append(g.FixedVersions, v)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, g := range groups {
		if g.Resolves.Open == 0 {
			p.NoFixGroups = append(p.NoFixGroups, g)
			continue
		}
		g.recommend()
		p.Groups = append(p.Groups, g)
	}
	for _, g := range groups {
		slices.SortFunc(g.Targets, func(a, b fixTarget) int { return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Kind, b.Kind)) })
	}
	for _, list := range [][]*fixGroup{p.Groups, p.NoFixGroups} {
		slices.SortFunc(list, func(a, b *fixGroup) int {
			return cmp.Or(cmp.Compare(a.rank, b.rank), cmp.Compare(b.Resolves.Open, a.Resolves.Open), cmp.Compare(len(b.Findings), len(a.Findings)),
				cmp.Compare(a.Package, b.Package), cmp.Compare(a.Installed, b.Installed), cmp.Compare(a.Ecosystem, b.Ecosystem))
		})
	}
	return p, nil
}

func (s *server) handleFixes(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	var targetID int64
	if v := r.URL.Query().Get("target_id"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			badRequest(w, "target_id는 숫자여야 합니다.")
			return
		}
		targetID = n
	}
	p, err := s.fixPlan(r.Context(), c.Project.ID, targetID)
	if err != nil {
		writeInternal(w, "fixes", err)
		return
	}
	writeJSON(w, 200, p)
}
