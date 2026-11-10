package main

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:web/dist
var webFS embed.FS

// webFiles is the built React app; a var so tests can swap in their own files.
var webFiles fs.FS = func() fs.FS { f, _ := fs.Sub(webFS, "web/dist"); return f }()

// serveWeb serves the app's files. Unknown non-API paths get index.html for client-side routing.
func (s *server) serveWeb(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeErr(w, 404, "not_found", "없는 API입니다.")
		return
	}
	// An MCP client that gets a 401 looks for OAuth metadata here; the app's HTML would read as broken JSON to it.
	if strings.HasPrefix(r.URL.Path, "/.well-known/") {
		writeErr(w, 404, "not_found", "찾을 수 없습니다.")
		return
	}
	if name := strings.TrimPrefix(path.Clean(r.URL.Path), "/"); name != "" {
		if st, err := fs.Stat(webFiles, name); err == nil && !st.IsDir() {
			if strings.HasPrefix(name, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			http.ServeFileFS(w, r, webFiles, name)
			return
		}
	}
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeFileFS(w, r, webFiles, "index.html")
}
