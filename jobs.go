package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
)

// MINIMAL jobs.go (Task 10): Task 9 owns the real one; keep its version at merge. Same signatures.

type job struct {
	ID        int64
	Kind      string
	ScanID    *int64
	Payload   json.RawMessage
	CreatedBy *int64
}

var jobFns = map[string]func(ctx context.Context, s *server, j *job) error{}

// registerJob sets the handler for a job kind. Call it from a routeRegistrar (startup, single goroutine).
func (s *server) registerJob(kind string, fn func(ctx context.Context, j *job) error) {
	jobFns[kind] = func(ctx context.Context, _ *server, j *job) error { return fn(ctx, j) }
}

func (s *server) enqueue(ctx context.Context, tx pgx.Tx, kind string, scanID *int64, payload any, priority int) (int64, error) {
	var id int64
	err := tx.QueryRow(ctx, `insert into jobs(kind, scan_id, payload, priority) values($1, $2, $3, $4) returning id`,
		kind, scanID, payload, priority).Scan(&id)
	return id, err
}

// jobLoop runs queued jobs one at a time until ctx ends.
func (s *server) jobLoop(ctx context.Context) {
	for ctx.Err() == nil {
		if !s.runOneJob(ctx) {
			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
			}
		}
	}
}

func (s *server) runOneJob(ctx context.Context) bool {
	j := &job{}
	err := s.db.QueryRow(ctx, `update jobs set state = 'running', started_at = now(), attempts = attempts + 1 where id = (
		select id from jobs where state = 'queued' and run_after <= now() order by priority desc, run_after, id
		for update skip locked limit 1) returning id, kind, scan_id, payload, created_by`).Scan(&j.ID, &j.Kind, &j.ScanID, &j.Payload, &j.CreatedBy)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) && ctx.Err() == nil {
			log.Printf("jobs: pick: %v", err)
		}
		return false
	}
	fn := jobFns[j.Kind]
	if fn == nil {
		err = errors.New("no handler for job kind " + j.Kind)
	} else {
		err = fn(ctx, s, j)
	}
	msg, state := "", "done"
	if err != nil {
		msg, state = err.Error(), "failed"
		log.Printf("job %d (%s): %v", j.ID, j.Kind, err)
	}
	if _, err := s.db.Exec(context.WithoutCancel(ctx), `update jobs set state = $2, error = $3, finished_at = now() where id = $1`, j.ID, state, msg); err != nil {
		log.Printf("jobs: finish %d: %v", j.ID, err)
	}
	return true
}
