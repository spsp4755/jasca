package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// maxExtractEntries caps the entries of an uploaded archive (a var so tests can lower it).
var maxExtractEntries = 200000

// archiveError is a rejected archive. Its text is Korean and shown to the user as the scan error.
type archiveError struct{ msg string }

func (e *archiveError) Error() string { return e.msg }

var (
	errArchiveCorrupt = &archiveError{"압축 파일이 손상되어 풀지 못했습니다."}
	errArchivePath    = &archiveError{"압축 파일에 절대 경로나 '..'로 밖을 가리키는 항목이 있어 거부했습니다."}
	errArchiveBomb    = &archiveError{"압축을 풀면 허용 용량을 넘습니다."}
	errArchiveMany    = &archiveError{"압축 파일의 항목이 너무 많습니다(최대 200,000개)."}
	errArchiveType    = &archiveError{"zip, tar, tar.gz(tgz) 압축 파일만 스캔할 수 있습니다."}
)

// extractArchive unpacks a zip, tar or tar.gz (told apart by magic bytes, not the name) into dst, in Go only.
// Absolute paths, ".." and anything resolving outside dst are rejected; symlinks, hardlinks and special files
// are skipped; modes become 0644 or 0755. maxBytes bounds the bytes written. The caller removes dst on failure.
func extractArchive(ctx context.Context, archive, dst string, maxBytes int64) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	x := &extractor{ctx: ctx, root: filepath.Clean(dst), left: maxBytes}
	switch {
	case bytes.HasPrefix(head, []byte("PK\x03\x04")) || bytes.HasPrefix(head, []byte("PK\x05\x06")):
		fi, err := f.Stat()
		if err != nil {
			return err
		}
		zr, err := zip.NewReader(f, fi.Size())
		if err != nil && !errors.Is(err, zip.ErrInsecurePath) { // insecure names are rejected below, entry by entry
			return errArchiveCorrupt
		}
		if len(zr.File) > maxExtractEntries {
			return errArchiveMany
		}
		for _, zf := range zr.File {
			if err := x.zipEntry(zf); err != nil {
				return err
			}
		}
		return nil
	case bytes.HasPrefix(head, []byte{0x1f, 0x8b}):
		gz, err := gzip.NewReader(f)
		if err != nil {
			return errArchiveCorrupt
		}
		return x.tar(gz)
	case len(head) >= 262 && string(head[257:262]) == "ustar":
		return x.tar(f)
	}
	return errArchiveType
}

type extractor struct {
	ctx     context.Context
	root    string
	left    int64 // bytes still allowed
	entries int
}

func (x *extractor) next(name string) (string, error) {
	if x.entries++; x.entries > maxExtractEntries {
		return "", errArchiveMany
	}
	if err := x.ctx.Err(); err != nil {
		return "", err
	}
	name = strings.ReplaceAll(name, `\`, "/")
	if strings.HasPrefix(name, "/") || (len(name) > 1 && name[1] == ':') {
		return "", errArchivePath
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." {
			return "", errArchivePath
		}
	}
	p := filepath.Join(x.root, filepath.FromSlash(name))
	if rel, err := filepath.Rel(x.root, p); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errArchivePath
	}
	return p, nil
}

func (x *extractor) file(p string, mode os.FileMode, r io.Reader) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return errArchiveCorrupt
	}
	perm := os.FileMode(0o644)
	if mode&0o111 != 0 {
		perm = 0o755
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return errArchiveCorrupt
	}
	n, err := io.Copy(f, io.LimitReader(r, x.left+1))
	f.Close()
	if x.left -= n; x.left < 0 {
		return errArchiveBomb
	}
	if err != nil {
		return errArchiveCorrupt
	}
	return nil
}

func (x *extractor) zipEntry(zf *zip.File) error {
	p, err := x.next(zf.Name)
	if err != nil {
		return err
	}
	m := zf.Mode()
	switch {
	case m&os.ModeSymlink != 0:
		return nil
	case m.IsDir() || strings.HasSuffix(zf.Name, "/"):
		return os.MkdirAll(p, 0o755)
	case !m.IsRegular():
		return nil
	}
	rc, err := zf.Open()
	if err != nil {
		return errArchiveCorrupt
	}
	defer rc.Close()
	return x.file(p, m, rc)
}

func (x *extractor) tar(r io.Reader) error {
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil && !errors.Is(err, tar.ErrInsecurePath) {
			return errArchiveCorrupt
		}
		p, err := x.next(h.Name)
		if err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(p, 0o755); err != nil {
				return errArchiveCorrupt
			}
		case tar.TypeReg:
			if err := x.file(p, h.FileInfo().Mode(), tr); err != nil {
				return err
			}
		} // symlinks, hardlinks, devices and fifos are skipped
	}
}
