package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
)

// getSetting decodes settings[key] into dst. It reports false (and leaves dst alone) when the key is unset.
func (s *server) getSetting(ctx context.Context, key string, dst any) (bool, error) {
	var raw []byte
	err := s.db.QueryRow(ctx, `select value from settings where key=$1`, key).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(raw, dst)
}

func (s *server) putSetting(ctx context.Context, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `insert into settings(key, value) values($1, $2)
		on conflict (key) do update set value=excluded.value, updated_at=now()`, key, json.RawMessage(b))
	return err
}

// mergeSetting sets only the top-level fields fields marshals to, keeping the other stored ones (a secret the
// request left out, or a sync result written meanwhile).
func (s *server) mergeSetting(ctx context.Context, key string, fields any) error {
	b, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `insert into settings(key, value) values($1, $2)
		on conflict (key) do update set value=settings.value || excluded.value, updated_at=now()`, key, json.RawMessage(b))
	return err
}

// loadSecret returns settings['hmac_secret'], creating 32 random bytes on first start.
func (s *server) loadSecret(ctx context.Context) ([]byte, error) {
	b := make([]byte, 32)
	rand.Read(b)
	j, _ := json.Marshal(b)
	if _, err := s.db.Exec(ctx, `insert into settings(key, value) values('hmac_secret', $1) on conflict do nothing`, json.RawMessage(j)); err != nil {
		return nil, err
	}
	if _, err := s.getSetting(ctx, "hmac_secret", &b); err != nil {
		return nil, err
	}
	return b, nil
}
