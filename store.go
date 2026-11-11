package main

import (
	"cmp"
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"path"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// openDB connects with the connection string (URL or keyword/value), or the standard PG* variables when it is empty.
// With a schema, every connection works in that schema only: a database handed out by a DBA usually comes with one
// schema the account may create tables in, and it is not always the account's default.
func openDB(ctx context.Context, dsn, schema string) (*pgxpool.Pool, error) {
	pc, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	if schema != "" {
		// SET after connecting, not a startup parameter: connection poolers refuse startup parameters they do not know
		set := "set search_path to " + pgx.Identifier{schema}.Sanitize()
		pc.AfterConnect = func(ctx context.Context, c *pgx.Conn) error { _, err := c.Exec(ctx, set); return err }
	}
	db, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, err
	}
	// The DB may start after the app in k8s; retry for a minute before giving up.
	for i := 0; ; i++ {
		if err = db.Ping(ctx); err == nil || i == 30 {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err == nil && schema != "" {
		// a schema that is missing or closed to the account drops out of the search path silently; say so here,
		// not as "no schema has been selected to create in" from the first migration
		var cur *string
		var create bool
		err = db.QueryRow(ctx, `select current_schema(),
			coalesce((select has_schema_privilege(oid, 'CREATE') from pg_namespace where nspname = current_schema()), false)`).Scan(&cur, &create)
		if err == nil && cur == nil {
			err = fmt.Errorf("JASCA_DB_SCHEMA: schema %q does not exist in database %q, or user %q has no USAGE privilege on it",
				schema, pc.ConnConfig.Database, pc.ConnConfig.User)
		} else if err == nil && !create {
			err = fmt.Errorf("JASCA_DB_SCHEMA: user %q has no CREATE privilege on schema %q", pc.ConnConfig.User, schema)
		}
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	log.Printf("database %s:%d/%s as %s, schema %s", pc.ConnConfig.Host, pc.ConnConfig.Port, pc.ConnConfig.Database,
		pc.ConnConfig.User, cmp.Or(schema, "(default)"))
	return db, nil
}

// migrate applies the embedded migrations in name order, each in its own transaction, under an advisory lock
// so that two starting processes cannot both apply one.
func migrate(ctx context.Context, db *pgxpool.Pool) error {
	conn, err := db.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `select pg_advisory_lock(7342001)`); err != nil {
		return err
	}
	defer conn.Exec(context.Background(), `select pg_advisory_unlock(7342001)`)
	if _, err := conn.Exec(ctx, `create table if not exists schema_migrations(name text primary key)`); err != nil {
		return err
	}
	names, err := fs.Glob(migrationFS, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, file := range names {
		name := path.Base(file)
		sql, err := migrationFS.ReadFile(file)
		if err != nil {
			return err
		}
		err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, `insert into schema_migrations(name) values($1) on conflict do nothing`, name)
			if err != nil || tag.RowsAffected() == 0 {
				return err
			}
			_, err = tx.Exec(ctx, string(sql))
			return err
		})
		if err != nil {
			return fmt.Errorf("migration %s: %w", name, err)
		}
	}
	return nil
}

func (s *server) tx(ctx context.Context, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, s.db, fn)
}
