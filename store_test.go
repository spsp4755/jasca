package main

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDBSettings(t *testing.T) {
	env := map[string]string{"JASCA_DB_HOST": "db.example.internal", "JASCA_DB_PORT": "15432", "JASCA_DB_DATABASE": "svc db",
		"JASCA_DB_USER": "jasca_app", "JASCA_DB_PASSWORD": `p@ss'w\rd #1/?`, "JASCA_DB_SCHEMA": "jasca",
		"JASCA_DB_SSLMODE": "disable", "JASCA_DB_MAX_CONNS": "7"}
	get := func(k string) string { return env[k] }
	c, err := configFrom(get)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := pgxpool.ParseConfig(c.DatabaseURL)
	if err != nil {
		t.Fatal(err)
	}
	cc := pc.ConnConfig
	if cc.Host != "db.example.internal" || cc.Port != 15432 || cc.Database != "svc db" || cc.User != "jasca_app" ||
		cc.Password != env["JASCA_DB_PASSWORD"] || cc.TLSConfig != nil || pc.MaxConns != 7 || c.DBSchema != "jasca" {
		t.Errorf("parsed %s:%d/%q user %q password %q tls %v max %d schema %q", cc.Host, cc.Port, cc.Database, cc.User,
			cc.Password, cc.TLSConfig != nil, pc.MaxConns, c.DBSchema)
	}
	env["JASCA_DATABASE_URL"] = "postgres://x@y/z"
	if _, err := configFrom(get); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Errorf("URL together with JASCA_DB_*: %v", err)
	}
	delete(env, "JASCA_DATABASE_URL")
	delete(env, "JASCA_DB_DATABASE")
	if _, err := configFrom(get); err == nil || !strings.Contains(err.Error(), "JASCA_DB_DATABASE") {
		t.Errorf("JASCA_DB_* without the database: %v", err)
	}
	// only the schema: the connection still comes from JASCA_DATABASE_URL or PG*
	if c, err := configFrom(func(k string) string { return map[string]string{"JASCA_DB_SCHEMA": "s"}[k] }); err != nil || c.DatabaseURL != "" || c.DBSchema != "s" {
		t.Errorf("schema alone: %+v, %v", c.DatabaseURL, err)
	}
}

// With JASCA_DB_SCHEMA everything is created in that schema and nothing in public.
func TestOpenDBSchema(t *testing.T) {
	url := os.Getenv("JASCA_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("JASCA_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	const schema = `Jasca "Co"` // a name that only works quoted
	q := pgx.Identifier{schema}.Sanitize()
	drop := `drop schema if exists ` + q + ` cascade`
	if _, err := admin.Exec(ctx, `drop schema public cascade; create schema public; `+drop+`; create schema `+q); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Exec(ctx, drop) })
	db, err := openDB(ctx, url, schema)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	cfg, _ := configFrom(func(string) string { return "" })
	cfg.BootstrapPassword, cfg.DataDir = testBootstrapPassword, t.TempDir()
	if _, err := newServer(ctx, cfg, db); err != nil {
		t.Fatal(err)
	}
	var in, public, users int
	if err := admin.QueryRow(ctx, `select count(*) filter (where schemaname = $1), count(*) filter (where schemaname = 'public')
		from pg_tables`, schema).Scan(&in, &public); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `select count(*) from users`).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if in < 10 || public != 0 || users != 1 {
		t.Errorf("tables in the schema %d, in public %d, users %d", in, public, users)
	}
	if _, err := openDB(ctx, url, "no_such_schema"); err == nil || !strings.Contains(err.Error(), "JASCA_DB_SCHEMA") {
		t.Errorf("missing schema: %v", err)
	}
}
