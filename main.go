package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata" // air-gapped images may lack zoneinfo
)

var version = "dev"

type config struct {
	Addr, DatabaseURL, DBSchema, DataDir, BootstrapPassword, TrivyBin string
	Loc                                                               *time.Location // JASCA_TZ
	SessionIdle, ScanTimeout                                          time.Duration  // 0 idle means sessions never idle out
	MaxSessions                                                       int            // per user; 0 = unlimited
	MaxReportMB, MaxScanUploadMB, MaxExtractMB                        int64
}

func loadConfig() (config, error) { return configFrom(os.Getenv) }

func configFrom(getenv func(string) string) (config, error) {
	var errs []error
	str := func(k, def string) string {
		if v := getenv("JASCA_" + k); v != "" {
			return v
		}
		return def
	}
	num := func(k string, def int) int {
		v := getenv("JASCA_" + k)
		if v == "" {
			return def
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			errs = append(errs, fmt.Errorf("JASCA_%s must be 0 or a positive whole number: %q", k, v))
		}
		return n
	}
	c := config{
		Addr:              str("ADDR", "0.0.0.0:8080"),
		DatabaseURL:       getenv("JASCA_DATABASE_URL"),
		DBSchema:          getenv("JASCA_DB_SCHEMA"),
		DataDir:           str("DATA_DIR", "/data"),
		BootstrapPassword: getenv("JASCA_BOOTSTRAP_PASSWORD"),
		TrivyBin:          str("TRIVY_BIN", "/usr/local/bin/trivy"),
		SessionIdle:       time.Duration(num("SESSION_IDLE_MIN", 30)) * time.Minute,
		ScanTimeout:       time.Duration(num("SCAN_TIMEOUT_MIN", 15)) * time.Minute,
		MaxSessions:       num("MAX_SESSIONS", 3),
		MaxReportMB:       int64(num("MAX_REPORT_MB", 50)),
		MaxScanUploadMB:   int64(num("MAX_SCAN_UPLOAD_MB", 2048)),
		MaxExtractMB:      int64(num("MAX_EXTRACT_MB", 4096)),
	}
	loc, err := time.LoadLocation(str("TZ", "Asia/Seoul"))
	if err != nil {
		errs = append(errs, fmt.Errorf("JASCA_TZ: %w", err))
	}
	c.Loc = loc
	if dsn, err := dbDSN(getenv); err != nil {
		errs = append(errs, err)
	} else if dsn != "" && c.DatabaseURL != "" {
		errs = append(errs, errors.New("set either JASCA_DATABASE_URL or the JASCA_DB_* values, not both"))
	} else if dsn != "" {
		c.DatabaseURL = dsn
	}
	return c, errors.Join(errs...)
}

// dbDSN builds the connection string from the separate values a DBA hands over (host, port, database, user, password),
// in keyword/value form so that a password needs no URL encoding. Empty when none of them is set.
func dbDSN(getenv func(string) string) (string, error) {
	var b strings.Builder
	for _, kv := range [][2]string{{"host", "HOST"}, {"port", "PORT"}, {"dbname", "DATABASE"}, {"user", "USER"},
		{"password", "PASSWORD"}, {"sslmode", "SSLMODE"}, {"pool_max_conns", "MAX_CONNS"}} {
		if v := getenv("JASCA_DB_" + kv[1]); v != "" {
			b.WriteString(kv[0] + "='" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(v) + "' ")
		}
	}
	if b.Len() > 0 {
		for _, k := range []string{"HOST", "DATABASE", "USER"} {
			if getenv("JASCA_DB_"+k) == "" {
				return "", fmt.Errorf("JASCA_DB_%s must be set together with the other JASCA_DB_* values", k)
			}
		}
	}
	return b.String(), nil
}

func main() {
	cfg, err := loadConfig()
	if len(os.Args) > 1 && os.Args[1] == "--healthcheck" {
		_, port, _ := net.SplitHostPort(cfg.Addr)
		resp, err2 := (&http.Client{Timeout: 3 * time.Second}).Get("http://127.0.0.1:" + port + "/healthz")
		if err != nil || err2 != nil || resp.StatusCode != 200 {
			os.Exit(1)
		}
		return
	}
	if err != nil {
		log.Fatal(err)
	}
	time.Local = time.UTC // pgx returns timestamptz in time.Local; JSON times must be UTC (display zone is cfg.Loc)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	db, err := openDB(ctx, cfg.DatabaseURL, cfg.DBSchema)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer db.Close()
	s, err := newServer(ctx, cfg, db)
	if err != nil {
		log.Fatal(err)
	}
	s.sweepWork(ctx)
	go s.syncLoop(ctx)
	go s.notifyLoop(ctx)
	go s.retentionLoop(ctx)
	for _, w := range workerStarters {
		go w(ctx, s)
	}
	go s.jobLoop(ctx)
	srv := &http.Server{Addr: cfg.Addr, Handler: s, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		<-ctx.Done()
		log.Printf("shutting down")
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(sctx); err != nil {
			log.Printf("shutdown: %v", err)
		}
	}()
	log.Printf("jasca %s listening on %s", version, cfg.Addr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}
	<-drained // ListenAndServe returns as soon as Shutdown starts; wait for in-flight requests
}
