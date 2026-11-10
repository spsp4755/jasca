// faketrivy stands in for the trivy binary in tests. Environment:
//
//	FAKETRIVY_OUT        file printed as the report for fs, rootfs, image and sbom
//	FAKETRIVY_OUT_ROOTFS file printed as the report for rootfs instead
//	FAKETRIVY_LOG        each call appends "<kind> <input> [files=...]" (fs and rootfs list the files they were given)
//	FAKETRIVY_WAIT_CALL  on this call number (1-based, counted in the log) wait for FAKETRIVY_WAIT_FILE to exist
//	FAKETRIVY_FAIL       exit 2 with this text on stderr
//	FAKETRIVY_NEED_JAVA  fail like Trivy 0.76.1 at a JAR without a Java DB, unless Java archives are skipped
//	FAKETRIVY_ARGS       file that gets the last call's arguments, one per line
package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "--version" {
		fmt.Println("Version: 0.76.1-fake")
		return
	}
	if len(args) < 2 {
		os.Exit(1)
	}
	kind, input := args[0], args[len(args)-1]
	line := kind + " " + input
	if kind == "fs" || kind == "rootfs" {
		var files []string
		filepath.WalkDir(input, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				r, _ := filepath.Rel(input, p)
				files = append(files, filepath.ToSlash(r))
			}
			return nil
		})
		line += " files=" + strings.Join(files, ",")
	}
	if log := os.Getenv("FAKETRIVY_LOG"); log != "" {
		f, _ := os.OpenFile(log, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		fmt.Fprintln(f, line)
		f.Close()
		b, _ := os.ReadFile(log)
		n := strings.Count(string(b), "\n")
		if w, _ := strconv.Atoi(os.Getenv("FAKETRIVY_WAIT_CALL")); w == n {
			for {
				if _, err := os.Stat(os.Getenv("FAKETRIVY_WAIT_FILE")); err == nil {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
		}
	}
	if p := os.Getenv("FAKETRIVY_ARGS"); p != "" {
		os.WriteFile(p, []byte(strings.Join(args, "\n")), 0o644)
	}
	if msg := os.Getenv("FAKETRIVY_FAIL"); msg != "" {
		fmt.Fprintln(os.Stderr, "fake failure: "+msg)
		os.Exit(2)
	}
	if os.Getenv("FAKETRIVY_NEED_JAVA") != "" && !strings.Contains(strings.Join(args, " "), "--skip-files=**/*.jar") {
		fmt.Fprintln(os.Stderr, "FATAL post analysis error: Unable to initialize the Java DB: Java DB update failed")
		os.Exit(1)
	}
	out := os.Getenv("FAKETRIVY_OUT")
	if p := os.Getenv("FAKETRIVY_OUT_ROOTFS"); p != "" && kind == "rootfs" {
		out = p
	}
	b, err := os.ReadFile(out)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	os.Stdout.Write(b)
}
