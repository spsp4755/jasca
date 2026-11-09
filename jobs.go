package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// job is one row of the jobs table as a handler sees it.
type job struct {
	ID        int64
	Kind      string
	ScanID    *int64
	Payload   json.RawMessage
	CreatedBy *int64
}

// jobRunner is the per-server job registry; its zero value is ready (server.jobs).
type jobRunner struct {
	mu      sync.Mutex
	fns     map[string]func(ctx context.Context, j *job) error
	cancels map[int64]context.CancelCauseFunc // running jobs
	wake    chan struct{}
}

var (
	// errJobCanceled: a handler returns it (or its ctx ends with it) to mark the job canceled, not failed.
	errJobCanceled = errors.New("job canceled")
	// errJobYield: a handler returns it to go back in the queue so a higher-priority job runs first.
	errJobYield = errors.New("job yields to a higher-priority job")
)

// registerJob sets the handler for a job kind. Call it from a routeRegistrar.
func (s *server) registerJob(kind string, fn func(ctx context.Context, j *job) error) {
	s.jobs.mu.Lock()
	defer s.jobs.mu.Unlock()
	if s.jobs.fns == nil {
		s.jobs.fns = map[string]func(context.Context, *job) error{}
	}
	s.jobs.fns[kind] = fn
}

func (s *server) jobWake() chan struct{} {
	s.jobs.mu.Lock()
	defer s.jobs.mu.Unlock()
	if s.jobs.wake == nil {
		s.jobs.wake = make(chan struct{}, 1)
	}
	return s.jobs.wake
}

// Job priorities, highest first. A recheck run yields to any queued job above prioRecheck, so new scans and
// Harbor reports never wait for a whole run.
const (
	prioScan    = 10 // server_scan
	prioHarbor  = 10 // harbor_fetch
	prioAI      = 5
	prioRecheck = 0
)

// enqueue queues a job, in tx when given (it then runs only after the commit), else directly. created_by is the
// scan's creator when scanID is set.
func (s *server) enqueue(ctx context.Context, tx pgx.Tx, kind string, scanID *int64, payload any, priority int) (int64, error) {
	if payload == nil {
		payload = map[string]any{}
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	q := `insert into jobs(kind, scan_id, payload, priority, created_by)
		values($1, $2, $3, $4, (select created_by_user from scans where id = $2)) returning id`
	var row pgx.Row
	if tx != nil {
		row = tx.QueryRow(ctx, q, kind, scanID, json.RawMessage(b), priority)
	} else {
		row = s.db.QueryRow(ctx, q, kind, scanID, json.RawMessage(b), priority)
	}
	var id int64
	if err := row.Scan(&id); err != nil {
		return 0, err
	}
	select {
	case s.jobWake() <- struct{}{}:
	default:
	}
	return id, nil
}

// jobLoop is the single worker. It first re-queues jobs a previous process left running, then runs queued jobs
// one at a time, highest priority first, until ctx ends. Started from main.
func (s *server) jobLoop(ctx context.Context) {
	// a server scan that was running at three starts in a row most likely killed the process (memory): stop it
	rows, _ := s.db.Query(ctx, `with dead as (update jobs set state = 'failed', finished_at = now(),
			error = 'stopped after 3 interrupted attempts' where state = 'running' and kind = 'server_scan' and attempts >= 3 returning scan_id)
		update scans set status = 'failed', finished_at = now(), error = '스캔이 세 번 연속 중단되어(메모리 부족 등) 더 실행하지 않습니다. 더 작은 파일로 다시 올려 주세요.'
		where id in (select scan_id from dead) and status in ('queued', 'running') returning id`)
	dead, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		log.Printf("jobs: fail interrupted scans: %v", err)
	}
	for _, id := range dead {
		os.RemoveAll(s.workDir(id))
	}
	if _, err := s.db.Exec(ctx, `update jobs set state = 'queued', started_at = null where state = 'running'`); err != nil {
		log.Printf("jobs: re-queue running: %v", err)
	}
	wake := s.jobWake()
	for ctx.Err() == nil {
		ran, err := s.runNextJob(ctx)
		if err != nil && ctx.Err() == nil {
			log.Printf("jobs: %v", err)
		}
		if ran && err == nil {
			continue
		}
		select {
		case <-ctx.Done():
		case <-wake:
		case <-time.After(2 * time.Second):
		}
	}
}

// runNextJob runs the next queued job, if any. A job whose ctx ends because the process stops stays running and is
// re-queued at the next start, so handlers must be safe to run again.
func (s *server) runNextJob(ctx context.Context) (bool, error) {
	j := &job{}
	err := s.db.QueryRow(ctx, `update jobs set state = 'running', started_at = now(), attempts = attempts + 1
		where id = (select id from jobs where state = 'queued' and run_after <= now()
			order by priority desc, run_after, id limit 1 for update skip locked)
		returning id, kind, scan_id, payload, created_by`).Scan(&j.ID, &j.Kind, &j.ScanID, &j.Payload, &j.CreatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	jctx, cancel := context.WithCancelCause(ctx)
	s.jobs.mu.Lock()
	fn := s.jobs.fns[j.Kind]
	if s.jobs.cancels == nil {
		s.jobs.cancels = map[int64]context.CancelCauseFunc{}
	}
	s.jobs.cancels[j.ID] = cancel
	s.jobs.mu.Unlock()
	defer func() {
		s.jobs.mu.Lock()
		delete(s.jobs.cancels, j.ID)
		s.jobs.mu.Unlock()
		cancel(nil)
	}()

	err = runJobFn(jctx, fn, j)
	dbctx := context.WithoutCancel(ctx)
	state, msg := "done", ""
	switch {
	case errors.Is(err, errJobYield):
		_, err := s.db.Exec(dbctx, `update jobs set state = 'queued', started_at = null where id = $1`, j.ID)
		return true, err
	case errors.Is(err, errJobCanceled) || errors.Is(err, errScanCanceled) || errors.Is(context.Cause(jctx), errJobCanceled):
		state = "canceled"
	case err != nil && ctx.Err() != nil:
		return true, nil // shutting down: left running, re-queued at the next start
	case err != nil:
		state, msg = "failed", err.Error()
		log.Printf("job %d (%s) failed: %v", j.ID, j.Kind, err)
	}
	_, err = s.db.Exec(dbctx, `update jobs set state = $2, error = $3, finished_at = now() where id = $1`, j.ID, state, msg)
	return true, err
}

func runJobFn(ctx context.Context, fn func(context.Context, *job) error, j *job) (err error) {
	if fn == nil {
		return fmt.Errorf("no handler for job kind %q", j.Kind)
	}
	defer func() {
		if v := recover(); v != nil {
			log.Printf("job %d (%s) panicked: %v\n%s", j.ID, j.Kind, v, debug.Stack())
			err = fmt.Errorf("panic: %v", v)
		}
	}()
	return fn(ctx, j)
}

// cancelJob stops job id: a running one has its ctx canceled (the runner then marks it canceled), a queued one is
// marked canceled right away.
func (s *server) cancelJob(ctx context.Context, id int64) error {
	s.jobs.mu.Lock()
	cancel := s.jobs.cancels[id]
	s.jobs.mu.Unlock()
	if cancel != nil {
		cancel(errJobCanceled)
	}
	_, err := s.db.Exec(ctx, `update jobs set state = 'canceled', finished_at = now() where id = $1 and state = 'queued'`, id)
	return err
}
