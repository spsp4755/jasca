// Command loadtest fills an empty JASCA database with a production-sized data set and measures a running server on
// it. It is a tool for maintainers (docs/maintaining.md "부하 시험"), not part of the server.
//
//	go run ./scripts/loadtest seed    -db <dsn> [-targets 2000]
//	go run ./scripts/loadtest upload  -db <dsn> -base http://127.0.0.1:18411
//	go run ./scripts/loadtest scans   -db <dsn> -base http://127.0.0.1:18411
//	go run ./scripts/loadtest measure -db <dsn> -base http://127.0.0.1:18411
package main

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/spsp4755/jasca/internal/formats"
)

//go:embed seed.sql
var seedSQL string

var (
	dsn  = flag.String("db", os.Getenv("JASCA_LOADTEST_DATABASE_URL"), "the load-test database (never a real one: seed fills it, measure adds sessions)")
	base = flag.String("base", "http://127.0.0.1:18411", "the server running on that database")
	ctx  = context.Background()
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		log.Fatal("usage: loadtest seed|upload|scans|measure [flags]")
	}
	cmd := os.Args[1]
	os.Args = os.Args[1:]
	targets := flag.Int("targets", 2000, "seed: how many targets (projects are a tenth of it)")
	n := flag.Int("n", 0, "upload: reports to push (60); measure: requests per page and user (9)")
	users := flag.Int("users", 20, "measure: concurrent users")
	out := flag.String("out", "", "measure: also write the numbers to this JSON file")
	flag.Parse()
	if *dsn == "" {
		log.Fatal("-db (or JASCA_LOADTEST_DATABASE_URL) is required")
	}
	db, err := pgx.Connect(ctx, *dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close(ctx)
	switch cmd {
	case "seed":
		seed(db, *targets)
	case "upload":
		upload(db, cmp.Or(*n, 60))
	case "scans":
		serverScans(db)
	case "measure":
		measure(db, cmp.Or(*n, 9), *users, *out)
	default:
		log.Fatalf("unknown command %q", cmd)
	}
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// --- seed ---

func seed(db *pgx.Conn, targets int) {
	exec := func(sql string) {
		_, err := db.PgConn().Exec(ctx, sql).ReadAll()
		must(err)
	}
	exec(fmt.Sprintf(`select set_config('lt.targets', '%d', false), set_config('lt.projects', '%d', false), set_config('lt.users', '%d', false)`,
		targets, max(targets/10, 5), max(targets*15/100, 300)))
	start := time.Now()
	for _, step := range strings.Split(seedSQL, "-- step: ")[1:] {
		name, sql, _ := strings.Cut(step, "\n")
		t := time.Now()
		switch {
		case strings.HasSuffix(name, "(go)"):
			rawReports(db)
		case strings.HasSuffix(name, "(chunked)"): // 100 targets a statement: short transactions and a progress line
			for lo := 1; lo <= targets; lo += 100 {
				exec(strings.NewReplacer(":lo", fmt.Sprint(lo), ":hi", fmt.Sprint(lo+99)).Replace(sql))
				fmt.Printf("\r%-28s %d/%d", name, min(lo+99, targets), targets)
			}
			fmt.Print("\r" + strings.Repeat(" ", 50) + "\r")
		default:
			exec(sql)
		}
		fmt.Printf("%-28s %6.1fs\n", name, time.Since(t).Seconds())
	}
	// A live database is vacuumed as it grows. Without it after a bulk load the counts, which are index-only scans,
	// visit every row and the first measurements are several times too slow.
	t := time.Now()
	exec("vacuum (analyze)")
	fmt.Printf("%-28s %6.1fs\n", "vacuum and statistics", time.Since(t).Seconds())
	// the seed computes fingerprints in SQL: they must be the ones the server computes, or every upload would
	// see a target full of strangers
	rows, _ := db.Query(ctx, `(select kind, rule_id, pkg_name, pkg_path, location, fingerprint from findings where kind = 'vuln' limit 50)
		union all (select kind, rule_id, pkg_name, pkg_path, location, fingerprint from findings where kind = 'misconfig' limit 50)`)
	var f formats.Finding
	var fp []byte
	_, err := pgx.ForEachRow(rows, []any{&f.Kind, &f.RuleID, &f.PkgName, &f.PkgPath, &f.Location, &fp}, func() error {
		if !bytes.Equal(fp, formats.Fingerprint(f)) {
			return fmt.Errorf("seeded fingerprint of %s %s differs from formats.Fingerprint: fix seed.sql", f.Kind, f.RuleID)
		}
		return nil
	})
	must(err)
	fmt.Printf("seeded in %.0fs\n", time.Since(start).Seconds())
	sizes(db)
}

// sizes prints the row counts and the size of the large tables.
func sizes(db *pgx.Conn) {
	rows, _ := db.Query(ctx, `select c.relname, c.reltuples::bigint, pg_size_pretty(pg_total_relation_size(c.oid)), pg_total_relation_size(c.oid)
		from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = current_schema() and c.relkind = 'r'
		order by 4 desc limit 12`)
	var name, pretty string
	var n, b int64
	fmt.Printf("%-16s %12s %10s\n", "table", "rows", "size")
	_, err := pgx.ForEachRow(rows, []any{&name, &n, &pretty, &b}, func() error {
		fmt.Printf("%-16s %12d %10s\n", name, n, pretty)
		return nil
	})
	must(err)
	must(db.QueryRow(ctx, `select pg_size_pretty(pg_database_size(current_database()))`).Scan(&pretty))
	fmt.Printf("%-16s %12s %10s\n", "database", "", pretty)
}

// rawReports stores, per stack, the gzipped Trivy report of it (lt_raw): what a kept scan carries as its raw report.
func rawReports(db *pgx.Conn) {
	_, err := db.Exec(ctx, `create temp table lt_raw (tpl int primary key, raw bytea)`)
	must(err)
	for tpl := 1; tpl <= 40; tpl++ {
		rows, _ := db.Query(ctx, `select p.eco, p.name, p.ver, p.purl, p.path, p.src_name, p.src_ver from lt_tpl t
			join lt_pkg p on p.id = t.pkg where t.tpl = $1 order by p.eco, p.path, p.name`, tpl)
		pkgs, err := pgx.CollectRows(rows, pgx.RowToStructByPos[pkg])
		must(err)
		rows, _ = db.Query(ctx, `select v.cve, p.name, p.ver, v.fixed, p.path, v.sev, u.title, u.description, p.purl from lt_tpl t
			join lt_pkg p on p.id = t.pkg join lt_vuln v on v.pkg = p.id and not v.old join vulns u on u.id = v.cve where t.tpl = $1`, tpl)
		vulns, err := pgx.CollectRows(rows, pgx.RowToStructByPos[vuln])
		must(err)
		var osFamily string
		must(db.QueryRow(ctx, `select os from lt_stack where tpl = $1`, tpl).Scan(&osFamily))
		_, err = db.Exec(ctx, `insert into lt_raw values($1, $2)`, tpl, gz(trivyReport("registry.example.internal/svc:1.0", "image", osFamily, pkgs, vulns)))
		must(err)
	}
}

func gz(b []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(b)
	zw.Close()
	return buf.Bytes()
}

// --- a Trivy report, with the fields and the bulk of a real one ---

type pkg struct{ Eco, Name, Ver, PURL, Path, SrcName, SrcVer string }
type vuln struct{ ID, Pkg, Ver, Fixed, Path, Sev, Title, Desc, PURL string }

var osNames = map[string]string{"alpine": "3.12.0", "debian": "12.1"}

func trivyReport(artifact, kind, osFamily string, pkgs []pkg, vulns []vuln) []byte {
	type result struct {
		Target, Class, Type string
		Packages            []map[string]any
		Vulnerabilities     []map[string]any `json:",omitempty"`
	}
	var results []*result
	at := map[[2]string]*result{}
	get := func(eco, path string) *result {
		k := [2]string{eco, path}
		if at[k] == nil {
			r := &result{Target: path, Class: "lang-pkgs", Type: map[string]string{"maven": "pom"}[eco]}
			if r.Type == "" {
				r.Type = eco
			}
			if eco == "alpine" || eco == "debian" {
				r.Target, r.Class = fmt.Sprintf("%s (%s %s)", artifact, eco, osNames[eco]), "os-pkgs"
			}
			at[k] = r
			results = append(results, r)
		}
		return at[k]
	}
	layer := map[string]string{"Digest": "sha256:" + strings.Repeat("ab", 32), "DiffID": "sha256:" + strings.Repeat("cd", 32)}
	for _, p := range pkgs {
		if kind != "image" && (p.Eco == "alpine" || p.Eco == "debian") {
			continue
		}
		r := get(p.Eco, p.Path)
		m := map[string]any{"ID": p.Name + "@" + p.Ver, "Name": p.Name, "Identifier": map[string]string{"PURL": p.PURL, "UID": fmt.Sprintf("%x", sha256.Sum256([]byte(p.PURL)))[:16]},
			"Version": p.Ver, "Licenses": []string{"MIT"}, "Layer": layer}
		if p.SrcName != "" {
			m["SrcName"], m["SrcVersion"] = p.SrcName, p.SrcVer
		}
		r.Packages = append(r.Packages, m)
	}
	for _, v := range vulns {
		eco := purlEco(v.PURL)
		if kind != "image" && (eco == "alpine" || eco == "debian") {
			continue
		}
		r := get(eco, v.Path)
		r.Vulnerabilities = append(r.Vulnerabilities, map[string]any{"VulnerabilityID": v.ID, "PkgName": v.Pkg, "PkgIdentifier": map[string]string{"PURL": v.PURL},
			"InstalledVersion": v.Ver, "FixedVersion": v.Fixed, "Status": "fixed", "Layer": layer, "SeveritySource": "nvd",
			"PrimaryURL": "https://avd.aquasec.com/nvd/" + strings.ToLower(v.ID), "Title": v.Title, "Description": v.Desc, "Severity": v.Sev,
			"DataSource": map[string]string{"ID": "ghsa", "Name": "GitHub Security Advisory", "URL": "https://github.com/advisories"},
			"CweIDs":     []string{"CWE-20"}, "CVSS": map[string]any{"nvd": map[string]any{"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "V3Score": 7.5}},
			"References":    []string{"https://nvd.nist.gov/vuln/detail/" + v.ID, "https://www.cve.org/CVERecord?id=" + v.ID, "https://github.com/advisories?query=" + v.ID},
			"PublishedDate": "2024-03-01T10:15:00Z", "LastModifiedDate": "2025-01-10T08:00:00Z"})
	}
	rep := struct { // in Trivy's order: the server tells the format from the head of the file
		SchemaVersion int
		CreatedAt     string
		ArtifactName  string
		ArtifactType  string
		Metadata      map[string]any `json:",omitempty"`
		Results       []*result
	}{2, time.Now().Format(time.RFC3339), artifact, "filesystem", nil, results}
	switch kind {
	case "image":
		rep.ArtifactType = "container_image"
		if osFamily != "" {
			rep.Metadata = map[string]any{"OS": map[string]string{"Family": osFamily, "Name": osNames[osFamily]}, "ImageID": "sha256:" + strings.Repeat("ef", 32)}
		}
	case "repo":
		rep.ArtifactType = "repository"
	}
	b, err := json.MarshalIndent(rep, "", "  ")
	must(err)
	return b
}

// purlEco is the ecosystem a purl's type stands for in the seed.
func purlEco(purl string) string {
	t, _, _ := strings.Cut(strings.TrimPrefix(purl, "pkg:"), "/")
	return map[string]string{"npm": "npm", "maven": "maven", "pypi": "pip", "golang": "gomod", "deb": "debian", "apk": "alpine"}[t]
}

// --- sessions for seeded users, written the way the server stores them ---

// session signs a seeded user in and returns the cookie.
func session(db *pgx.Conn, userID int64) *http.Cookie {
	b := make([]byte, 32)
	rand.Read(b)
	token := base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(token))
	_, err := db.Exec(ctx, `insert into sessions(token_hash, user_id, user_agent, ip, expires_at) values($1, $2, 'loadtest', '127.0.0.1', now() + interval '8 hours')`, h[:], userID)
	must(err)
	return &http.Cookie{Name: "jasca_session", Value: token}
}
