package main

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// openDB connects with JASCA_DATABASE_URL, or the standard PG* variables when it is empty.
func openDB(ctx context.Context, url string) (*pgxpool.Pool, error) {
	db, err := pgxpool.New(ctx, url)
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
	if err != nil {
		db.Close()
		return nil, err
	}
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
