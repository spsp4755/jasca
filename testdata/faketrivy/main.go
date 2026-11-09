// faketrivy stands in for the trivy binary in tests. Environment:
//
//	FAKETRIVY_OUT        file printed as the report for fs, image and sbom
//	FAKETRIVY_LOG        each call appends "<kind> <input> [files=...]" (fs lists the extracted files)
//	FAKETRIVY_WAIT_CALL  on this call number (1-based, counted in the log) wait for FAKETRIVY_WAIT_FILE to exist
//	FAKETRIVY_FAIL       exit 2 with an error on stderr
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
	if kind == "fs" {
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
	if os.Getenv("FAKETRIVY_FAIL") != "" {
		fmt.Fprintln(os.Stderr, "fake failure")
		os.Exit(2)
	}
	b, err := os.ReadFile(os.Getenv("FAKETRIVY_OUT"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	os.Stdout.Write(b)
}
