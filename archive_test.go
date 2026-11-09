package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

type arEnt struct {
	name, body, link string
	typ              byte // tar type; 0 = regular file
	mode             int64
}

func mkTarGz(t *testing.T, gz bool, ents ...arEnt) []byte {
	t.Helper()
	var b bytes.Buffer
	var tw *tar.Writer
	var zw *gzip.Writer
	if gz {
		zw = gzip.NewWriter(&b)
		tw = tar.NewWriter(zw)
	} else {
		tw = tar.NewWriter(&b)
	}
	for _, e := range ents {
		h := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if e.mode != 0 {
			h.Mode = e.mode
		}
		if e.typ != 0 {
			h.Typeflag, h.Linkname, h.Size = e.typ, e.link, 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(e.body))
	}
	tw.Close()
	if gz {
		zw.Close()
	}
	return b.Bytes()
}

func mkZip(t *testing.T, ents ...arEnt) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for _, e := range ents {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		h.SetMode(0o644)
		if e.mode != 0 {
			h.SetMode(os.FileMode(e.mode))
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(e.body))
	}
	zw.Close()
	return b.Bytes()
}

// runExtract writes archive bytes to a file and extracts them into <tmp>/root/src. It returns the src dir.
func runExtract(t *testing.T, ar []byte, maxBytes int64) (string, error) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "root")
	os.MkdirAll(root, 0o755)
	in := filepath.Join(root, "upload")
	if err := os.WriteFile(in, ar, 0o644); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "src")
	return src, extractArchive(context.Background(), in, src, maxBytes)
}

func wantArchiveErr(t *testing.T, err error) {
	t.Helper()
	if _, ok := errors.AsType[*archiveError](err); !ok {
		t.Fatalf("want archiveError, got %v", err)
	}
}

func TestExtractRejectsTraversal(t *testing.T) {
	for name, ar := range map[string][]byte{
		"tar":       mkTarGz(t, false, arEnt{name: "ok.txt", body: "x"}, arEnt{name: "a/../../evil.txt", body: "evil"}),
		"zip":       mkZip(t, arEnt{name: "ok.txt", body: "x"}, arEnt{name: "../evil.txt", body: "evil"}),
		"backslash": mkZip(t, arEnt{name: `..\evil.txt`, body: "evil"}),
	} {
		t.Run(name, func(t *testing.T) {
			src, err := runExtract(t, ar, 1<<20)
			wantArchiveErr(t, err)
			if _, err := os.Stat(filepath.Join(filepath.Dir(src), "evil.txt")); err == nil {
				t.Fatal("file written outside the root")
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(filepath.Dir(src)), "evil.txt")); err == nil {
				t.Fatal("file written outside the root")
			}
		})
	}
}

func TestExtractRejectsAbsolute(t *testing.T) {
	for name, ar := range map[string][]byte{
		"tar":   mkTarGz(t, true, arEnt{name: "/tmp/jasca-evil.txt", body: "evil"}),
		"zip":   mkZip(t, arEnt{name: "/tmp/jasca-evil.txt", body: "evil"}),
		"drive": mkZip(t, arEnt{name: "C:/evil.txt", body: "evil"}),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := runExtract(t, ar, 1<<20)
			wantArchiveErr(t, err)
		})
	}
	if _, err := os.Stat("/tmp/jasca-evil.txt"); err == nil {
		t.Fatal("absolute path was written")
	}
}

func TestExtractSkipsSymlinkOutside(t *testing.T) {
	ar := mkTarGz(t, true,
		arEnt{name: "link", typ: tar.TypeSymlink, link: "/etc"},
		arEnt{name: "hard", typ: tar.TypeLink, link: "/etc/passwd"},
		arEnt{name: "link/passwd", body: "through the link"}, // would write into /etc if the symlink existed
		arEnt{name: "dir/", typ: tar.TypeDir},
		arEnt{name: "dir/app.js", body: "ok"})
	src, err := runExtract(t, ar, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"link", "hard"} {
		if fi, err := os.Lstat(filepath.Join(src, n)); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("%s created as a symlink", n)
		} else if err == nil && n == "hard" {
			t.Fatal("hardlink created")
		}
	}
	if b, _ := os.ReadFile(filepath.Join(src, "dir/app.js")); string(b) != "ok" {
		t.Fatalf("regular file: %q", b)
	}
	// a zip symlink entry is skipped too
	zb := &bytes.Buffer{}
	zw := zip.NewWriter(zb)
	h := &zip.FileHeader{Name: "zl"}
	h.SetMode(os.ModeSymlink | 0o777)
	w, _ := zw.CreateHeader(h)
	w.Write([]byte("/etc"))
	zw.Close()
	src, err = runExtract(t, zb.Bytes(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(src, "zl")); err == nil {
		t.Fatal("zip symlink created")
	}
}

func TestExtractRejectsBomb(t *testing.T) {
	zeros := string(make([]byte, 3<<20))
	zipBomb := mkZip(t, arEnt{name: "zeros.bin", body: zeros})
	if len(zipBomb) > 64<<10 {
		t.Fatalf("test zip is not small: %d", len(zipBomb))
	}
	for name, ar := range map[string][]byte{
		"zip":        zipBomb,
		"tgz":        mkTarGz(t, true, arEnt{name: "zeros.bin", body: zeros}),
		"many small": mkZip(t, arEnt{name: "a", body: zeros[:600<<10]}, arEnt{name: "b", body: zeros[:600<<10]}),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := runExtract(t, ar, 1<<20)
			wantArchiveErr(t, err)
		})
	}
}

func TestExtractRejectsTooManyEntries(t *testing.T) {
	old := maxExtractEntries
	maxExtractEntries = 5
	t.Cleanup(func() { maxExtractEntries = old })
	var ents []arEnt
	for i := range 6 {
		ents = append(ents, arEnt{name: string(rune('a'+i)) + ".txt", body: "x"})
	}
	for name, ar := range map[string][]byte{"zip": mkZip(t, ents...), "tar": mkTarGz(t, true, ents...)} {
		t.Run(name, func(t *testing.T) {
			_, err := runExtract(t, ar, 1<<20)
			wantArchiveErr(t, err)
		})
	}
	if _, err := runExtract(t, mkZip(t, ents[:5]...), 1<<20); err != nil {
		t.Fatalf("5 entries: %v", err)
	}
}

func TestExtractFormatsAndModes(t *testing.T) {
	ents := []arEnt{{name: "bin/run.sh", body: "#!/bin/sh", mode: 0o4777}, {name: "conf.txt", body: "c", mode: 0o666}}
	for name, ar := range map[string][]byte{
		"zip": mkZip(t, ents...), "tar": mkTarGz(t, false, ents...), "tgz": mkTarGz(t, true, ents...),
	} {
		t.Run(name, func(t *testing.T) {
			src, err := runExtract(t, ar, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			for f, want := range map[string]os.FileMode{"bin/run.sh": 0o755, "conf.txt": 0o644} {
				fi, err := os.Stat(filepath.Join(src, f))
				if err != nil || fi.Mode() != want {
					t.Fatalf("%s: %v %v", f, err, fi)
				}
			}
		})
	}
	_, err := runExtract(t, []byte("\x89PNG\r\n\x1a\nnot an archive at all"), 1<<20)
	wantArchiveErr(t, err)
}

// synthZip builds a bogus local header, n minimal central-directory records and an end record that declares
// declared entries. zip64 puts the counts in a zip64 end record instead.
func synthZip(n int, declared uint64, zip64 bool) []byte {
	le := binary.LittleEndian
	b := append([]byte("PK\x03\x04"), make([]byte, 26)...)
	cdStart := len(b)
	for range n {
		h := make([]byte, 46)
		le.PutUint32(h, 0x02014b50)
		le.PutUint16(h[28:], 1)
		b = append(append(b, h...), 'a')
	}
	cdSize := len(b) - cdStart
	end := make([]byte, 22)
	le.PutUint32(end, 0x06054b50)
	if zip64 {
		pos := len(b)
		r := make([]byte, 56)
		le.PutUint32(r, 0x06064b50)
		le.PutUint64(r[4:], 44)
		le.PutUint64(r[24:], declared)
		le.PutUint64(r[32:], declared)
		le.PutUint64(r[40:], uint64(cdSize))
		le.PutUint64(r[48:], uint64(cdStart))
		loc := make([]byte, 20)
		le.PutUint32(loc, 0x07064b50)
		le.PutUint64(loc[8:], uint64(pos))
		le.PutUint32(loc[16:], 1)
		b = append(append(b, r...), loc...)
		le.PutUint16(end[8:], 0xFFFF)
		le.PutUint16(end[10:], 0xFFFF)
		le.PutUint32(end[12:], 0xFFFFFFFF)
		le.PutUint32(end[16:], 0xFFFFFFFF)
	} else {
		le.PutUint16(end[8:], uint16(declared))
		le.PutUint16(end[10:], uint16(declared))
		le.PutUint32(end[12:], uint32(cdSize))
		le.PutUint32(end[16:], uint32(cdStart))
	}
	return append(b, end...)
}

// TestZipEntryCapBeforeParse: the entry cap is enforced from the end record and a streaming walk of the central
// directory, before zip.NewReader would load every record into memory. (zip.NewReader itself would report these
// bogus archives as corrupt, so errArchiveMany proves the pre-check fired.)
func TestZipEntryCapBeforeParse(t *testing.T) {
	old := maxExtractEntries
	maxExtractEntries = 5
	t.Cleanup(func() { maxExtractEntries = old })
	for name, c := range map[string]struct {
		ar   []byte
		many bool
	}{
		"declared over cap":     {synthZip(7, 7, false), true},
		"count lies (mod 2^16)": {synthZip(7, 1, false), true},
		"zip64 declared":        {synthZip(7, 7, true), true},
		"zip64 count lies":      {synthZip(7, 1, true), true},
		"under cap":             {synthZip(3, 3, false), false},
		"zip64 under cap":       {synthZip(3, 3, true), false},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := runExtract(t, c.ar, 1<<20)
			if c.many != (err == errArchiveMany) {
				t.Fatalf("got %v", err)
			}
		})
	}
	// real archives written by Go pass: a small one, and one with 70000 entries (Go writes zip64 end records then)
	maxExtractEntries = old
	var ents []arEnt
	for i := range 70000 {
		ents = append(ents, arEnt{name: fmt.Sprintf("d/%d", i)})
	}
	for _, ar := range [][]byte{mkZip(t, arEnt{name: "a", body: "x"}), mkZip(t, ents...)} {
		if err := zipPrecheck(bytes.NewReader(ar), int64(len(ar))); err != nil {
			t.Fatalf("%d bytes: %v", len(ar), err)
		}
	}
	maxExtractEntries = 69999
	big := mkZip(t, ents...)
	if err := zipPrecheck(bytes.NewReader(big), int64(len(big))); err != errArchiveMany {
		t.Fatalf("real zip64 over cap: %v", err)
	}
}
