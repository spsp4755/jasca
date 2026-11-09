package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
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
		if err := zipPrecheck(f, fi.Size()); err != nil {
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
		if err := os.MkdirAll(p, 0o755); err != nil {
			return errArchiveCorrupt
		}
		return nil
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

// zipPrecheck enforces maxExtractEntries before zip.NewReader, which keeps a *zip.File (~230 bytes) for every
// central-directory record and reads records until a bad one, whatever count the end record declares. So it
// checks the declared count (zip64 too) and then counts the records the way zip.NewReader will find them, by
// streaming them from both directory starts it may use.
func zipPrecheck(r io.ReaderAt, size int64) error {
	le := binary.LittleEndian
	tail := make([]byte, min(size, 22+65535))
	tailAt := size - int64(len(tail))
	if _, err := r.ReadAt(tail, tailAt); err != nil && err != io.EOF {
		return errArchiveCorrupt
	}
	i := len(tail) - 22 // the last end signature whose comment fits, as zip.NewReader picks it
	for ; i >= 0; i-- {
		if string(tail[i:i+4]) == "PK\x05\x06" && i+22+int(le.Uint16(tail[i+20:])) <= len(tail) {
			break
		}
	}
	if i < 0 {
		return errArchiveCorrupt
	}
	end := tail[i : i+22]
	endAt := tailAt + int64(i)
	records, dirSize, dirOff := uint64(le.Uint16(end[10:])), uint64(le.Uint32(end[12:])), uint64(le.Uint32(end[16:]))
	// zip64 when a field is saturated (dirSize 0xFFFF too, as zip.NewReader checks it) and a locator is present
	loc, rec := make([]byte, 20), make([]byte, 56)
	if (records == 0xFFFF || dirSize == 0xFFFF || dirSize == 0xFFFFFFFF || dirOff == 0xFFFFFFFF) && endAt >= 20 {
		if _, err := r.ReadAt(loc, endAt-20); err == nil && le.Uint32(loc) == 0x07064b50 && le.Uint32(loc[16:]) == 1 {
			at := le.Uint64(loc[8:])
			if at > uint64(size) {
				return errArchiveCorrupt
			}
			if _, err := r.ReadAt(rec, int64(at)); err != nil || le.Uint32(rec) != 0x06064b50 {
				return errArchiveCorrupt
			}
			records, dirSize, dirOff, endAt = le.Uint64(rec[32:]), le.Uint64(rec[40:]), le.Uint64(rec[48:]), int64(at)
		}
	}
	if dirOff > uint64(size) {
		return errArchiveCorrupt
	}
	if records > uint64(maxExtractEntries) || dirSize > 256<<20 {
		return errArchiveMany
	}
	for _, start := range []int64{int64(dirOff), endAt - int64(dirSize)} { // as written, and after a prepended stub
		if start < 0 || start >= size {
			continue
		}
		br := bufio.NewReaderSize(io.NewSectionReader(r, start, size-start), 64<<10)
		h := make([]byte, 46)
		for n := 0; ; {
			if _, err := io.ReadFull(br, h); err != nil || le.Uint32(h) != 0x02014b50 {
				break
			}
			if n++; n > maxExtractEntries {
				return errArchiveMany
			}
			if _, err := br.Discard(int(le.Uint16(h[28:])) + int(le.Uint16(h[30:])) + int(le.Uint16(h[32:]))); err != nil {
				break
			}
		}
	}
	return nil
}
