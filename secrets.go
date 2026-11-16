package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"strings"
)

// Integration secrets at rest. With JASCA_SECRET_KEY set they are stored as "enc:v1:" + base64(nonce | AES-256-GCM
// ciphertext) in the place the plain text used to sit, so a database dump or a DBA no longer reads them. Without
// the key they stay plain, as before. The key is not in the database: lose it and the secrets are entered again.
//
// settings['hmac_secret'] is deliberately not in this set: it only signs the 10-minute SSO state cookie, which an
// attacker would also have to plant in the victim's browser, and an unreadable copy would break every start.
const encPrefix = "enc:v1:"

// secretFields names what is encrypted: per settings key its top-level fields, and under "channel" the fields of a
// notify_channels.config.
var secretFields = map[string][]string{
	"sso": {"client_secret"}, "sync": {"client_secret"}, "smtp": {"password"}, "ai": {"api_key"}, "channel": {"webhook_url"},
}

// newAEAD derives the AES-256-GCM cipher from JASCA_SECRET_KEY; nil for no key.
func newAEAD(key string) cipher.AEAD {
	if key == "" {
		return nil
	}
	k := sha256.Sum256([]byte(key))
	b, _ := aes.NewCipher(k[:]) // a 32-byte key cannot fail
	a, _ := cipher.NewGCM(b)
	return a
}

// seal encrypts v. Unchanged without a key, for "" and for what is already sealed (a value starting with the
// prefix is always taken as ciphertext).
func (s *server) seal(v string) string {
	if s.aead == nil || v == "" || strings.HasPrefix(v, encPrefix) {
		return v
	}
	nonce := make([]byte, s.aead.NonceSize())
	rand.Read(nonce)
	return encPrefix + base64.RawStdEncoding.EncodeToString(s.aead.Seal(nonce, nonce, []byte(v), nil))
}

// open returns the plain text of a stored value: v itself when it was stored plain, false when it is sealed and
// there is no key or not the key it was sealed with.
func (s *server) open(v string) (string, bool) {
	enc, sealed := strings.CutPrefix(v, encPrefix)
	if !sealed {
		return v, true
	}
	b, err := base64.RawStdEncoding.DecodeString(enc)
	if s.aead == nil || err != nil || len(b) < s.aead.NonceSize() {
		return "", false
	}
	n := s.aead.NonceSize()
	p, err := s.aead.Open(nil, b[:n], b[n:], nil)
	return string(p), err == nil
}

// eachSecret calls fn for every non-empty string field of the JSON object raw that secretFields lists under what,
// stores what fn returns and reports whether anything changed.
func eachSecret(raw []byte, what string, fn func(field, v string) string) ([]byte, bool) {
	fields := secretFields[what]
	var m map[string]json.RawMessage
	if len(fields) == 0 || json.Unmarshal(raw, &m) != nil {
		return raw, false
	}
	changed := false
	for _, f := range fields {
		var v string
		if json.Unmarshal(m[f], &v) != nil || v == "" {
			continue
		}
		if nv := fn(f, v); nv != v {
			m[f], _ = json.Marshal(nv)
			changed = true
		}
	}
	if !changed {
		return raw, false
	}
	out, _ := json.Marshal(m)
	return out, true
}

// sealJSON encrypts the secret fields of a settings value or channel config on its way into the database.
func (s *server) sealJSON(raw []byte, what string) []byte {
	out, _ := eachSecret(raw, what, func(_, v string) string { return s.seal(v) })
	return out
}

// openJSON decrypts them on the way out. A field that cannot be decrypted reads as "" (the admin screen then shows
// it as not set, to be entered again) and is logged once by name, never by value.
func (s *server) openJSON(raw []byte, what string) []byte {
	out, _ := eachSecret(raw, what, func(f, v string) string {
		p, ok := s.open(v)
		if !ok {
			if _, logged := s.undecryptable.LoadOrStore(what+"."+f, true); !logged {
				log.Printf("secrets: cannot decrypt %s.%s: JASCA_SECRET_KEY is missing or not the key it was saved with. Restore the key or enter the value again on the administration screen", what, f)
			}
		}
		return p
	})
	return out
}

// storedSecrets calls fn with every stored JSON value that can hold a secret; a non-nil return is written back.
func (s *server) storedSecrets(ctx context.Context, fn func(what string, raw []byte) []byte) error {
	for _, t := range []struct{ sel, upd string }{
		{`select key, key, value from settings`, `update settings set value = $2 where key = $1`},
		{`select id::text, 'channel', config from notify_channels`, `update notify_channels set config = $2 where id = $1::bigint`},
	} {
		type row struct {
			ID, What string
			Raw      []byte
		}
		rows, err := collect[row](ctx, s, t.sel)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if nv := fn(r.What, r.Raw); nv != nil {
				if _, err := s.db.Exec(ctx, t.upd, r.ID, json.RawMessage(nv)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// encryptStored runs at start: with a key it encrypts what is still stored plain (an upgrade, or the first start
// after the key was added); either way it logs where the stored secrets stand, naming those it cannot read.
func (s *server) encryptStored(ctx context.Context) error {
	n := 0
	if s.aead != nil {
		if err := s.storedSecrets(ctx, func(what string, raw []byte) []byte {
			out, changed := eachSecret(raw, what, func(_, v string) string {
				nv := s.seal(v)
				if nv != v {
					n++
				}
				return nv
			})
			if !changed {
				return nil
			}
			return out
		}); err != nil {
			return err
		}
	}
	mode, _, bad, err := s.secretsState(ctx)
	if err != nil {
		return err
	}
	if mode == "plain" {
		log.Printf("secrets: JASCA_SECRET_KEY is not set: integration secrets are stored in the database unencrypted")
	} else if n > 0 {
		log.Printf("secrets: encrypted %d stored secret(s) with JASCA_SECRET_KEY", n)
	}
	if bad > 0 { // name each one now, not at its first use
		return s.storedSecrets(ctx, func(what string, raw []byte) []byte { s.openJSON(raw, what); return nil })
	}
	return nil
}

// secretsState tells the system status page how the integration secrets are stored. mode is "encrypted" when
// JASCA_SECRET_KEY is set (new and existing values are encrypted) and "plain" when it is not; total counts the
// stored non-empty secrets; undecryptable counts those that are encrypted but unreadable with the current key (or
// with no key), which must be entered again or the key restored.
func (s *server) secretsState(ctx context.Context) (mode string, total, undecryptable int, err error) {
	mode = "plain"
	if s.aead != nil {
		mode = "encrypted"
	}
	err = s.storedSecrets(ctx, func(what string, raw []byte) []byte {
		eachSecret(raw, what, func(_, v string) string {
			total++
			if _, ok := s.open(v); !ok {
				undecryptable++
			}
			return v
		})
		return nil
	})
	return
}
