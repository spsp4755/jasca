// Package trivy runs the Trivy CLI safely, installs offline DB bundles and writes CycloneDX.
package trivy

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os/exec"
	"slices"
	"strings"
	"time"
)

const maxOutput = 512 << 20

type Options struct {
	Bin, CacheDir string
	Scanners      []string
	Timeout       time.Duration
	NoJavaDB      bool // skip Java archives: without a java-db Trivy 0.76.1 fails an image scan at the first JAR (ErrNoJavaDB)
	// Chosen by the admin; a zero value adds no flag. The caller validates the values.
	IgnoreUnfixed, IncludeDevDeps bool
	Severities, PkgTypes          []string
	DetectionPriority             string
	SkipDirs, SkipFiles           []string // glob patterns, fs and image only
}

// listArg is --flag=value for one of Trivy's list flags, which parse their value as a CSV line: a value with a comma
// or a quote goes in quoted. Glued to the flag, a value that starts with "-" can never be read as a flag.
func listArg(flag, v string) string {
	var b strings.Builder
	w := csv.NewWriter(&b)
	w.Write([]string{v})
	w.Flush()
	return flag + "=" + strings.TrimSuffix(b.String(), "\n")
}

// Args builds the argv (without the binary). Every flag and value is its own element or one --flag=value element; no
// shell is involved. Only flags the subcommand has in Trivy 0.76.1 are passed (sbom has no files to skip and no
// misconfig checks; only fs has --include-dev-deps). fs reads lock files and never opens a JAR; rootfs and image read
// built artifacts (JAR/WAR/EAR, node_modules, site-packages, Go binaries) and no lock files.
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
	if o.IgnoreUnfixed {
		a = append(a, "--ignore-unfixed")
	}
	if len(o.Severities) > 0 {
		a = append(a, "--severity="+strings.Join(o.Severities, ","))
	}
	if len(o.PkgTypes) > 0 {
		a = append(a, "--pkg-types="+strings.Join(o.PkgTypes, ","))
	}
	if o.DetectionPriority != "" {
		a = append(a, "--detection-priority="+o.DetectionPriority)
	}
	if o.Timeout > 0 { // Trivy's own limit is 5m by default; a minute more than ours, so ours fires first and is the one reported
		a = append(a, "--timeout="+(o.Timeout+time.Minute).String())
	}
	if kind != "sbom" {
		a = append(a, "--skip-check-update")
		for _, d := range o.SkipDirs {
			a = append(a, listArg("--skip-dirs", d))
		}
		if o.NoJavaDB {
			for _, g := range []string{"**/*.jar", "**/*.war", "**/*.ear", "**/*.par"} {
				a = append(a, "--skip-files="+g)
			}
		}
		for _, f := range o.SkipFiles {
			a = append(a, listArg("--skip-files", f))
		}
	}
	if kind == "fs" && o.IncludeDevDeps {
		a = append(a, "--include-dev-deps")
	}
	if kind == "image" {
		return append(a, "--input", input)
	}
	return append(a, input)
}

var errTooBig = errors.New("trivy output exceeds 512MB")

// What Trivy 0.76.1 says on stderr, as errors a caller can tell apart from every other failure.
var (
	ErrInput    = errors.New("trivy cannot read the file as a container image") // "unable to initialize archive image"
	ErrNoJavaDB = errors.New("a Java archive was met and no Java DB is installed")
)

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
	case "fs", "rootfs", "image", "sbom":
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
	msg := strings.TrimSpace(string(se.b))
	if strings.Contains(msg, "unable to initialize archive image") {
		err = fmt.Errorf("%w: %w", ErrInput, err)
	} else if strings.Contains(msg, "Unable to initialize the Java DB") {
		err = fmt.Errorf("%w: %w", ErrNoJavaDB, err)
	}
	return fmt.Errorf("trivy %s: %w: %s", kind, err, msg)
}

// Report is the report as it is stored and downloaded: ArtifactName, where Trivy wrote the server's work path, becomes
// name, and the results of the Java archive pass (extra, nil when there was none) follow the others. SchemaVersion
// and ArtifactName go first because format detection reads only the head of a report.
func Report(main, extra []byte, name string) ([]byte, error) {
	var m map[string]json.RawMessage
	var a, b struct{ Results []json.RawMessage }
	if err := json.Unmarshal(main, &m); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(main, &a); err != nil {
		return nil, err
	}
	if extra != nil {
		if err := json.Unmarshal(extra, &b); err != nil {
			return nil, err
		}
	}
	m["ArtifactName"], _ = json.Marshal(name)
	if rs := append(a.Results, b.Results...); len(rs) > 0 {
		m["Results"], _ = json.Marshal(rs)
	}
	var compact, out bytes.Buffer
	compact.WriteByte('{')
	for _, k := range append([]string{"SchemaVersion", "ArtifactName"}, slices.Sorted(maps.Keys(m))...) {
		v, ok := m[k]
		if !ok {
			continue
		}
		delete(m, k)
		if compact.Len() > 1 {
			compact.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		compact.Write(kb)
		compact.WriteByte(':')
		compact.Write(v)
	}
	compact.WriteByte('}')
	if err := json.Indent(&out, compact.Bytes(), "", "  "); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
