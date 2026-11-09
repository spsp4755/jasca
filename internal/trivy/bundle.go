package trivy

import (
	"archive/tar"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type DBStatus struct {
	Version               int
	UpdatedAt, NextUpdate time.Time
	JavaDB                bool
	JavaUpdatedAt         time.Time
}

type meta struct {
	Version               int
	UpdatedAt, NextUpdate time.Time
}

func readMeta(dir string) (meta, error) {
	var m meta
	b, err := os.ReadFile(filepath.Join(dir, "metadata.json"))
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, err
	}
	if m.Version < 1 || m.UpdatedAt.IsZero() {
		return m, errors.New("invalid metadata.json")
	}
	return m, nil
}

func Status(cacheDir string) (DBStatus, error) {
	m, err := readMeta(filepath.Join(cacheDir, "db"))
	if err != nil {
		return DBStatus{}, err
	}
	st := DBStatus{Version: m.Version, UpdatedAt: m.UpdatedAt, NextUpdate: m.NextUpdate}
	if j, err := readMeta(filepath.Join(cacheDir, "java-db")); err == nil {
		st.JavaDB, st.JavaUpdatedAt = true, j.UpdatedAt
	}
	return st, nil
}

// InstallBundle extracts a trivy-db or trivy-java-db tar.gz, validates it, then swaps it in.
// kind is "db" or "java-db". On any failure the existing directory is untouched.
func InstallBundle(cacheDir string, r io.Reader, maxBytes int64) (kind string, st DBStatus, err error) {
	if err = os.MkdirAll(cacheDir, 0o755); err != nil {
		return
	}
	var rnd [6]byte
	rand.Read(rnd[:])
	inc := filepath.Join(cacheDir, ".incoming-"+hex.EncodeToString(rnd[:]))
	if err = os.Mkdir(inc, 0o755); err != nil {
		return
	}
	defer os.RemoveAll(inc)

	gz, err := gzip.NewReader(r)
	if err != nil {
		return "", st, err
	}
	// maxBytes bounds the decompressed size; +1 lets us detect overflow.
	tr := tar.NewReader(io.LimitReader(gz, maxBytes+1))
	var total int64
	sizes := map[string]int64{}
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", st, e
		}
		if h.Typeflag == tar.TypeDir {
			continue
		}
		// only these flat regular files are allowed; anything else (paths, links, extras) is rejected
		if h.Typeflag != tar.TypeReg || (h.Name != "trivy.db" && h.Name != "trivy-java.db" && h.Name != "metadata.json") {
			return "", st, fmt.Errorf("unexpected entry %q", h.Name)
		}
		f, e := os.OpenFile(filepath.Join(inc, h.Name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if e != nil {
			return "", st, e
		}
		n, e := io.Copy(f, tr)
		f.Close()
		if e != nil {
			return "", st, e
		}
		if total += n; total > maxBytes {
			return "", st, errors.New("bundle exceeds size limit")
		}
		sizes[h.Name] = n
	}
	if _, e := io.Copy(io.Discard, gz); e != nil { // verifies the gzip trailer
		return "", st, e
	}
	dbFile := "trivy.db"
	kind = "db"
	if _, ok := sizes["trivy-java.db"]; ok {
		dbFile, kind = "trivy-java.db", "java-db"
	}
	if _, ok := sizes["metadata.json"]; !ok {
		return "", st, errors.New("metadata.json missing")
	}
	if sizes[dbFile] <= 1<<20 {
		return "", st, fmt.Errorf("%s missing or too small", dbFile)
	}
	if _, e := readMeta(inc); e != nil {
		return "", st, e
	}

	dst, prev := filepath.Join(cacheDir, kind), filepath.Join(cacheDir, kind+".prev")
	os.RemoveAll(prev)
	hadOld := true
	if e := os.Rename(dst, prev); e != nil {
		if !os.IsNotExist(e) {
			return "", st, e
		}
		hadOld = false
	}
	if e := os.Rename(inc, dst); e != nil {
		if hadOld {
			os.Rename(prev, dst)
		}
		return "", st, e
	}
	os.RemoveAll(prev)
	st, err = Status(cacheDir)
	return kind, st, err
}
