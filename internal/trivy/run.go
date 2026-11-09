// Package trivy runs the Trivy CLI safely, installs offline DB bundles and writes CycloneDX.
package trivy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

const maxOutput = 512 << 20

type Options struct {
	Bin, CacheDir string
	Scanners      []string
	Timeout       time.Duration
}

// Args builds the argv (without the binary). Every flag and value is its own element; no shell is involved.
func Args(kind, input string, o Options) []string {
	scanners := strings.Join(o.Scanners, ",")
	if kind == "sbom" {
		scanners = "vuln"
	}
	a := []string{kind, "--format", "json", "--list-all-pkgs", "--skip-db-update", "--skip-java-db-update",
		"--skip-check-update", "--offline-scan", "--cache-dir", o.CacheDir, "--scanners", scanners, "--quiet"}
	if kind == "image" {
		return append(a, "--input", input)
	}
	return append(a, input)
}

var errTooBig = errors.New("trivy output exceeds 512MB")

type capWriter struct {
	w io.Writer
	n int64
}

func (c *capWriter) Write(p []byte) (int, error) {
	if c.n+int64(len(p)) > maxOutput {
		return 0, errTooBig
	}
	c.n += int64(len(p))
	return c.w.Write(p)
}

// tailBuf keeps only the last 4KB written.
type tailBuf struct{ b []byte }

func (t *tailBuf) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > 4096 {
		t.b = append([]byte(nil), t.b[len(t.b)-4096:]...)
	}
	return len(p), nil
}

func Run(ctx context.Context, o Options, kind, input string, stdout io.Writer) error {
	switch kind {
	case "fs", "image", "sbom":
	default:
		return fmt.Errorf("trivy: unknown kind %q", kind)
	}
	if o.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.Timeout)
		defer cancel()
	}
	var se tailBuf
	cmd := exec.CommandContext(ctx, o.Bin, Args(kind, input, o)...)
	cmd.Stdout = &capWriter{w: stdout}
	cmd.Stderr = &se
	err := cmd.Run()
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		err = fmt.Errorf("%w: %v", ctx.Err(), err)
	}
	return fmt.Errorf("trivy %s: %w: %s", kind, err, strings.TrimSpace(string(se.b)))
}
