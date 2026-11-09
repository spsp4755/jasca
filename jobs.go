package main

// MINIMAL jobs.go created by Task 11 because Task 9 had not merged: keep Task 9's version at merge.
// It only provides the signatures other tasks rely on and a single polling worker.

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

type job struct {
	ID        int64
	Kind      string
	ScanID    *int64
	Payload   json.RawMessage
	CreatedBy *int64
}

var jobFns sync.Map // kind -> func(context.Context, *job) error

var jobWake = make(chan struct{}, 1)

func init() { routeRegistrars = append(routeRegistrars, (*server).startJobWorker) }

func (s *server) registerJob(kind string, fn func(ctx context.Context, j *job) error) {
	jobFns.Store(kind, fn)
}

func (s *server) enqueue(ctx context.Context, tx pgx.Tx, kind string, scanID *int64, payload any, priority int) (int64, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	var id int64
	err = tx.QueryRow(ctx, `insert into jobs(kind, scan_id, payload, priority) values($1, $2, $3, $4) returning id`, kind, scanID, b, priority).Scan(&id)
	select {
	case jobWake <- struct{}{}:
	default:
	}
	return id, err
}

func (s *server) startJobWorker() {
	go func() {
		for {
			ran, err := s.runNextJob(context.Background())
			if err != nil && strings.Contains(err.Error(), "closed pool") {
				return
			}
			if err != nil {
				log.Printf("jobs: %v", err)
			}
			if !ran {
				select {
				case <-jobWake:
				case <-time.After(500 * time.Millisecond):
				}
			}
		}
	}()
}

func (s *server) runNextJob(ctx context.Context) (bool, error) {
	var j job
	err := s.db.QueryRow(ctx, `update jobs set state='running', started_at=now(), attempts=attempts+1 where id = (
			select id from jobs where state='queued' and run_after <= now() order by priority desc, run_after, id
			for update skip locked limit 1) returning id, kind, scan_id, payload, created_by`).Scan(&j.ID, &j.Kind, &j.ScanID, &j.Payload, &j.CreatedBy)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	state, msg := "done", ""
	if fn, ok := jobFns.Load(j.Kind); !ok {
		state, msg = "failed", "no handler"
	} else if err := fn.(func(context.Context, *job) error)(ctx, &j); err != nil {
		state, msg = "failed", err.Error()
	}
	_, err = s.db.Exec(ctx, `update jobs set state=$2, error=$3, finished_at=now() where id=$1`, j.ID, state, msg)
	return true, err
}
