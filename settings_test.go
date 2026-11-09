package main

import (
	"bytes"
	"context"
	"testing"
)

func TestSettings(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	type ret struct {
		RawPerTarget int `json:"raw_per_target"`
		RawDays      int `json:"raw_days"`
	}
	var r ret
	if ok, err := s.getSetting(ctx, "retention", &r); ok || err != nil {
		t.Fatalf("missing setting: %v %v", ok, err)
	}
	for _, want := range []ret{{20, 90}, {5, 30}} {
		if err := s.putSetting(ctx, "retention", want); err != nil {
			t.Fatal(err)
		}
		if ok, err := s.getSetting(ctx, "retention", &r); !ok || err != nil || r != want {
			t.Fatalf("got %+v %v %v, want %+v", r, ok, err, want)
		}
	}
}

func TestHMACSecretPersists(t *testing.T) {
	s := testServer(t)
	if len(s.secret) != 32 {
		t.Fatalf("secret length %d", len(s.secret))
	}
	s2, err := newServer(context.Background(), s.cfg, s.db)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s.secret, s2.secret) {
		t.Error("secret changed on restart")
	}
}
