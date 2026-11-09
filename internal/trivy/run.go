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
	NoJavaDB      bool // no java-db installed: skip Java archives, or Trivy 0.76.1 fails the scan at the first JAR
}

// Args builds the argv (without the binary). Every flag and value is its own element; no shell is involved.
func Args(kind, input string, o Options) []string {
	scanners := strings.Join(o.Scanners, ",")
	if kind == "sbom" || scanners == "" {
		scanners = "vuln"
	}
	// --skip-version-check/--disable-telemetry: otherwise every run calls check.trivy.dev. --cache-backend memory: the
	// fs layer cache would grow with every image and is never pruned; the DB itself still comes from --cache-dir.
	a := []string{kind, "--format", "json", "--list-all-pkgs", "--skip-db-update", "--skip-java-db-update",
		"--offline-scan", "--cache-dir", o.CacheDir, "--cache-backend", "memory", "--skip-version-check", "--disable-telemetry",
		"--scanners", scanners, "--quiet"}
	if kind != "sbom" { // sbom has no misconfig checks and rejects the flag
		a = append(a, "--skip-check-update")
		if o.NoJavaDB {
			for _, g := range []string{"**/*.jar", "**/*.war", "**/*.ear", "**/*.par"} {
				a = append(a, "--skip-files", g)
			}
		}
	}
	if kind == "image" {
		return append(a, "--input", input)
	}
	return append(a, input)
}

var errTooBig = errors.New("trivy output exceeds 512MB")

type capWriter struct {
	w        io.Writer
	n        int64
	overflow bool
}

func (c *capWriter) Write(p []byte) (int, error) {
	if c.n+int64(len(p)) > maxOutput {
		c.overflow = true
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
	cw := &capWriter{w: stdout}
	cmd.Stdout = cw
	cmd.Stderr = &se
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	if cw.overflow {
		return errTooBig
	}
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		err = fmt.Errorf("%w: %v", ctx.Err(), err)
	}
	return fmt.Errorf("trivy %s: %w: %s", kind, err, strings.TrimSpace(string(se.b)))
}
