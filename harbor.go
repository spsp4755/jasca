package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/spsp4755/jasca/internal/formats"
)

func init() { routeRegistrars = append(routeRegistrars, (*server).harborRoutes) }

func (s *server) harborRoutes() {
	s.registerJob("harbor_fetch", s.harborFetch)
	s.handle("GET /api/v1/admin/harbor", permAdmin, s.handleHarborList)
	s.handle("POST /api/v1/admin/harbor", permAdmin, s.handleHarborCreate)
	s.handle("PUT /api/v1/admin/harbor/{id}", permAdmin, s.handleHarborPut)
	s.handle("DELETE /api/v1/admin/harbor/{id}", permAdmin, s.handleHarborDelete)
	s.handle("POST /api/v1/admin/harbor/{id}/test", permAdmin, s.handleHarborTest)
	s.handle("GET /api/v1/admin/harbor/{id}/mappings", permAdmin, s.handleHarborMappingsGet)
	s.handle("PUT /api/v1/admin/harbor/{id}/mappings", permAdmin, s.handleHarborMappingsPut)
	s.handle("GET /api/v1/admin/harbor/unmapped", permAdmin, s.handleHarborUnmapped)
	s.handle("POST /api/v1/admin/harbor/unmapped/{id}/assign", permAdmin, s.handleHarborAssign)
	s.handle("POST /api/v1/hooks/harbor/{id}", permPublic, s.handleHarborHook)
}

var harborHTTP = &http.Client{Timeout: 30 * time.Second, CheckRedirect: noRedirect}

// noRedirect: outbound calls carry credentials, so a redirect to another host is never followed.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

type harborLinkBody struct {
	Name, BaseURL, RobotUser, RobotSecret string
}

func (b *harborLinkBody) UnmarshalJSON(d []byte) error {
	var v struct {
		Name        string `json:"name"`
		BaseURL     string `json:"base_url"`
		RobotUser   string `json:"robot_user"`
		RobotSecret string `json:"robot_secret"`
	}
	dec := json.NewDecoder(strings.NewReader(string(d)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return err
	}
	*b = harborLinkBody{strings.TrimSpace(v.Name), strings.TrimRight(strings.TrimSpace(v.BaseURL), "/"), strings.TrimSpace(v.RobotUser), v.RobotSecret}
	return nil
}

func (b harborLinkBody) valid() bool {
	u, err := url.Parse(b.BaseURL)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.RawQuery == "" && u.User == nil &&
		b.Name != "" && b.RobotUser != "" && len(b.Name) <= 200
}

const harborBadLink = "이름, Harbor 주소(http 또는 https), 로봇 계정을 확인하세요."

func harborID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 404, "not_found", "찾을 수 없습니다.")
	}
	return id, err == nil
}

func (s *server) handleHarborList(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	rows, _ := s.db.Query(r.Context(), `select id, name, base_url, robot_user, robot_secret <> '', created_at from harbor_links order by id`)
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var name, base, user string
		var set bool
		var at time.Time
		if err := rows.Scan(&id, &name, &base, &user, &set, &at); err != nil {
			writeInternal(w, "harbor list", err)
			return
		}
		out = append(out, map[string]any{"id": id, "name": name, "base_url": base, "robot_user": user, "robot_secret_set": set, "created_at": at.UTC()})
	}
	if err := rows.Err(); err != nil {
		writeInternal(w, "harbor list", err)
		return
	}
	writeJSON(w, 200, out)
}

func (s *server) handleHarborCreate(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	var b harborLinkBody
	if err := readJSON(r, 1<<16, &b); err != nil {
		writeBodyErr(w, err)
		return
	}
	if !b.valid() {
		badRequest(w, harborBadLink)
		return
	}
	raw := make([]byte, 32)
	rand.Read(raw)
	secret := base64.RawURLEncoding.EncodeToString(raw)
	h := sha256.Sum256([]byte(secret))
	var id int64
	err := s.db.QueryRow(r.Context(), `insert into harbor_links(name, base_url, robot_user, robot_secret, webhook_secret_hash)
		values($1, $2, $3, $4, $5) returning id`, b.Name, b.BaseURL, b.RobotUser, b.RobotSecret, h[:]).Scan(&id)
	if err != nil {
		writeInternal(w, "harbor create", err)
		return
	}
	s.audit(r.Context(), c, "harbor.link_create", nil, b.Name, map[string]any{"id": id, "base_url": b.BaseURL})
	writeJSON(w, 201, map[string]any{"id": id, "webhook_secret": secret,
		"webhook_url": strings.TrimRight(s.publicBase(r), "/") + "/api/v1/hooks/harbor/" + strconv.FormatInt(id, 10)})
}

func (s *server) publicBase(r *http.Request) string {
	var sso ssoSettings
	s.getSetting(r.Context(), "sso", &sso)
	return s.publicURL(r, sso)
}

func (s *server) handleHarborPut(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	id, ok := harborID(w, r)
	if !ok {
		return
	}
	var b harborLinkBody
	if err := readJSON(r, 1<<16, &b); err != nil {
		writeBodyErr(w, err)
		return
	}
	if !b.valid() {
		badRequest(w, harborBadLink)
		return
	}
	tag, err := s.db.Exec(r.Context(), `update harbor_links set name=$2, base_url=$3, robot_user=$4,
		robot_secret = case when $5 = '' then robot_secret else $5 end where id=$1`, id, b.Name, b.BaseURL, b.RobotUser, b.RobotSecret)
	if err != nil {
		writeInternal(w, "harbor put", err)
		return
	}
	if tag.RowsAffected() == 0 {
		writeErr(w, 404, "not_found", "찾을 수 없습니다.")
		return
	}
	s.audit(r.Context(), c, "harbor.link_update", nil, b.Name, map[string]any{"id": id, "secret_changed": b.RobotSecret != ""})
	w.WriteHeader(204)
}

func (s *server) handleHarborDelete(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	id, ok := harborID(w, r)
	if !ok {
		return
	}
	var name string
	if err := s.db.QueryRow(r.Context(), `delete from harbor_links where id=$1 returning name`, id).Scan(&name); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, 404, "not_found", "찾을 수 없습니다.")
		} else {
			writeInternal(w, "harbor delete", err)
		}
		return
	}
	s.audit(r.Context(), c, "harbor.link_delete", nil, name, map[string]any{"id": id})
	w.WriteHeader(204)
}

type harborLink struct {
	ID                    int64
	BaseURL, User, Secret string
}

func (s *server) loadHarborLink(ctx context.Context, id int64) (*harborLink, error) {
	l := &harborLink{ID: id}
	err := s.db.QueryRow(ctx, `select base_url, robot_user, robot_secret from harbor_links where id=$1`, id).Scan(&l.BaseURL, &l.User, &l.Secret)
	return l, err
}

// get calls base_url + p with the robot account. The host is always the link's; nothing from an event is used.
func (l *harborLink) get(ctx context.Context, p string, report bool) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", l.BaseURL+p, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(l.User, l.Secret)
	if report {
		req.Header.Set("X-Accept-Vulnerabilities", "application/vnd.security.vulnerability.report; version=1.1")
	}
	return harborHTTP.Do(req)
}

func (s *server) handleHarborTest(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	id, ok := harborID(w, r)
	if !ok {
		return
	}
	l, err := s.loadHarborLink(r.Context(), id)
	if err != nil {
		writeErr(w, 404, "not_found", "찾을 수 없습니다.")
		return
	}
	resp, err := l.get(r.Context(), "/api/v2.0/systeminfo", false)
	msg := ""
	if err != nil {
		msg = "연결하지 못했습니다."
	} else {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode != 200 {
			msg = fmt.Sprintf("Harbor가 %d로 응답했습니다. 주소와 로봇 계정을 확인하세요.", resp.StatusCode)
		}
	}
	if msg != "" {
		writeJSON(w, 200, map[string]string{"error": msg})
		return
	}
	writeJSON(w, 200, map[string]string{})
}

func (s *server) handleHarborMappingsGet(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	id, ok := harborID(w, r)
	if !ok {
		return
	}
	rows, _ := s.db.Query(r.Context(), `select harbor_project, repo_pattern, project_id from harbor_mappings where link_id=$1
		order by harbor_project, repo_pattern = '*', length(repo_pattern) desc, repo_pattern`, id)
	out := []map[string]any{}
	for rows.Next() {
		var hp, pat string
		var pid int64
		if err := rows.Scan(&hp, &pat, &pid); err != nil {
			writeInternal(w, "harbor mappings", err)
			return
		}
		out = append(out, map[string]any{"harbor_project": hp, "repo_pattern": pat, "project_id": pid})
	}
	writeJSON(w, 200, out)
}

func (s *server) handleHarborMappingsPut(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	id, ok := harborID(w, r)
	if !ok {
		return
	}
	var rows []struct {
		HarborProject string `json:"harbor_project"`
		RepoPattern   string `json:"repo_pattern"`
		ProjectID     int64  `json:"project_id"`
	}
	if err := readJSON(r, 1<<20, &rows); err != nil {
		writeBodyErr(w, err)
		return
	}
	for i := range rows {
		rows[i].HarborProject = strings.TrimSpace(rows[i].HarborProject)
		if rows[i].RepoPattern == "" {
			rows[i].RepoPattern = "*"
		}
		if _, err := path.Match(rows[i].RepoPattern, ""); err != nil || rows[i].HarborProject == "" {
			badRequest(w, "Harbor 프로젝트와 올바른 저장소 패턴을 입력하세요.")
			return
		}
	}
	err := s.tx(r.Context(), func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(r.Context(), `select count(*) from harbor_links where id=$1`, id).Scan(&n); err != nil || n == 0 {
			return errors.Join(err, pgx.ErrNoRows)
		}
		if _, err := tx.Exec(r.Context(), `delete from harbor_mappings where link_id=$1`, id); err != nil {
			return err
		}
		for _, m := range rows {
			if _, err := tx.Exec(r.Context(), `insert into harbor_mappings(link_id, harbor_project, repo_pattern, project_id) values($1,$2,$3,$4)
				on conflict do nothing`, id, m.HarborProject, m.RepoPattern, m.ProjectID); err != nil {
				return err
			}
		}
		return nil
	})
	var pe *pgconn.PgError
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		writeErr(w, 404, "not_found", "찾을 수 없습니다.")
	case errors.As(err, &pe) && pe.Code == "23503":
		badRequest(w, "존재하지 않는 프로젝트가 있습니다.")
	case err != nil:
		writeInternal(w, "harbor mappings put", err)
	default:
		s.audit(r.Context(), c, "harbor.mappings_put", nil, strconv.FormatInt(id, 10), map[string]any{"rows": len(rows)})
		w.WriteHeader(204)
	}
}

func (s *server) handleHarborUnmapped(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	rows, _ := s.db.Query(r.Context(), `select id, link_id, harbor_project, repository, digest, tag, received_at from harbor_unmapped
		order by received_at desc, id desc limit 500`)
	out := []map[string]any{}
	for rows.Next() {
		var id, link int64
		var hp, repo, digest, tag string
		var at time.Time
		if err := rows.Scan(&id, &link, &hp, &repo, &digest, &tag, &at); err != nil {
			writeInternal(w, "harbor unmapped", err)
			return
		}
		out = append(out, map[string]any{"id": id, "link_id": link, "harbor_project": hp, "repository": repo, "digest": digest, "tag": tag, "received_at": at.UTC()})
	}
	writeJSON(w, 200, out)
}

type harborFetchPayload struct {
	LinkID        int64  `json:"link_id"`
	HarborProject string `json:"harbor_project"`
	Repository    string `json:"repository"`
	Digest        string `json:"digest"`
	Tag           string `json:"tag"`
	ProjectID     int64  `json:"project_id"`
}

func (s *server) handleHarborAssign(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	id, ok := harborID(w, r)
	if !ok {
		return
	}
	var body struct {
		ProjectID int64 `json:"project_id"`
	}
	if err := readJSON(r, 1<<10, &body); err != nil {
		writeBodyErr(w, err)
		return
	}
	var p harborFetchPayload
	var bad bool
	err := s.tx(r.Context(), func(tx pgx.Tx) error {
		p.ProjectID = body.ProjectID
		err := tx.QueryRow(r.Context(), `delete from harbor_unmapped where id=$1 returning link_id, harbor_project, repository, digest, tag`, id).
			Scan(&p.LinkID, &p.HarborProject, &p.Repository, &p.Digest, &p.Tag)
		if err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(r.Context(), `select count(*) from projects where id=$1`, body.ProjectID).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			bad = true
			return errors.New("no such project") // rolls back: the unmapped row stays
		}
		if _, err := tx.Exec(r.Context(), `insert into harbor_mappings(link_id, harbor_project, repo_pattern, project_id) values($1,$2,$3,$4)
			on conflict do nothing`, p.LinkID, p.HarborProject, escapePattern(p.Repository), body.ProjectID); err != nil {
			return err
		}
		_, err = s.enqueue(r.Context(), tx, "harbor_fetch", nil, p, prioHarbor)
		return err
	})
	switch {
	case bad:
		badRequest(w, "존재하지 않는 프로젝트입니다.")
	case errors.Is(err, pgx.ErrNoRows):
		writeErr(w, 404, "not_found", "찾을 수 없습니다.")
	case err != nil:
		writeInternal(w, "harbor assign", err)
	default:
		s.audit(r.Context(), c, "harbor.assign", &body.ProjectID, p.Repository, map[string]any{"link_id": p.LinkID, "digest": p.Digest})
		w.WriteHeader(204)
	}
}

// escapePattern makes a repository name a literal path.Match pattern.
func escapePattern(s string) string {
	return strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`, `[`, `\[`).Replace(s)
}

type harborEventBody struct {
	Type      string `json:"type"`
	EventData struct {
		Resources []struct {
			Digest string `json:"digest"`
			Tag    string `json:"tag"`
		} `json:"resources"`
		Repository struct {
			Namespace    string `json:"namespace"`
			RepoFullName string `json:"repo_full_name"`
		} `json:"repository"`
	} `json:"event_data"`
}

// handleHarborHook: the Authorization header is the link's webhook secret (stored as SHA-256, compared in constant time).
func (s *server) handleHarborHook(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	ctx := r.Context()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var want []byte
	if err == nil {
		err = s.db.QueryRow(ctx, `select webhook_secret_hash from harbor_links where id=$1`, id).Scan(&want)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			writeInternal(w, "harbor hook", err) // a DB failure is ours, not a bad secret: Harbor should retry
			return
		}
	}
	got := sha256.Sum256([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))
	if err != nil {
		want = make([]byte, 32) // unknown link: same work, same answer
	}
	if subtle.ConstantTimeCompare(got[:], want) != 1 || err != nil {
		writeErr(w, 401, "unauthorized", "웹훅 비밀값이 맞지 않습니다.")
		return
	}
	var ev harborEventBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&ev); err != nil {
		writeBodyErr(w, err)
		return
	}
	if ev.Type != "SCANNING_COMPLETED" {
		w.WriteHeader(202)
		return
	}
	repo, ns := ev.EventData.Repository.RepoFullName, ev.EventData.Repository.Namespace
	if repo == "" || ns == "" {
		badRequest(w, "저장소 정보가 없습니다.")
		return
	}
	var pats []struct {
		pat string
		pid int64
	}
	rows, _ := s.db.Query(ctx, `select repo_pattern, project_id from harbor_mappings where link_id=$1 and harbor_project=$2
		order by repo_pattern = '*', length(repo_pattern) desc, repo_pattern`, id, ns)
	for rows.Next() {
		var p struct {
			pat string
			pid int64
		}
		rows.Scan(&p.pat, &p.pid)
		pats = append(pats, p)
	}
	rows.Close()
	short := strings.TrimPrefix(repo, ns+"/")
	pid := int64(0)
	for _, p := range pats { // most specific pattern first; a pattern may name the repo with or without the Harbor project
		if m, _ := path.Match(p.pat, repo); m {
			pid = p.pid
		} else if m, _ := path.Match(p.pat, short); m {
			pid = p.pid
		}
		if pid != 0 {
			break
		}
	}
	err = s.tx(ctx, func(tx pgx.Tx) error {
		for _, res := range ev.EventData.Resources {
			if res.Digest == "" {
				continue
			}
			if pid == 0 {
				if _, err := tx.Exec(ctx, `insert into harbor_unmapped(link_id, harbor_project, repository, digest, tag) values($1,$2,$3,$4,$5)
					on conflict (link_id, repository, digest) do update set tag = excluded.tag, received_at = now()`, id, ns, repo, res.Digest, res.Tag); err != nil {
					return err
				}
				continue
			}
			if _, err := s.enqueue(ctx, tx, "harbor_fetch", nil, harborFetchPayload{id, ns, repo, res.Digest, res.Tag, pid}, prioHarbor); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		writeInternal(w, "harbor hook", err)
		return
	}
	w.WriteHeader(202)
}

// harborFetch downloads Harbor's own vulnerability report for one artifact and ingests it. No SBOM, so the target
// is excluded from recheck and advisory matching.
func (s *server) harborFetch(ctx context.Context, j *job) error {
	var p harborFetchPayload
	if err := json.Unmarshal(j.Payload, &p); err != nil {
		return err
	}
	l, err := s.loadHarborLink(ctx, p.LinkID)
	if err != nil {
		return fmt.Errorf("harbor link %d: %w", p.LinkID, err)
	}
	// Harbor wants the repository without its project, with "/" escaped twice
	rest := url.PathEscape(url.PathEscape(strings.TrimPrefix(p.Repository, p.HarborProject+"/")))
	resp, err := l.get(ctx, "/api/v2.0/projects/"+url.PathEscape(p.HarborProject)+"/repositories/"+rest+"/artifacts/"+url.PathEscape(p.Digest)+"/additions/vulnerabilities", true)
	if err != nil {
		return fmt.Errorf("harbor request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("harbor answered %d", resp.StatusCode)
	}
	max := s.cfg.MaxReportMB << 20
	raw, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return err
	}
	if int64(len(raw)) > max {
		return fmt.Errorf("harbor report is larger than %dMB", s.cfg.MaxReportMB)
	}
	hp, _ := formats.Get("harbor")
	rep, err := hp.Parse(strings.NewReader(string(raw)))
	if err != nil {
		return fmt.Errorf("harbor report: %w", err)
	}
	u, _ := url.Parse(l.BaseURL)
	ref := p.Tag
	if ref == "" {
		ref = p.Digest
	}
	res, err := s.ingest(ctx, ingestInput{ProjectID: p.ProjectID, TargetKind: "image", TargetName: u.Host + "/" + p.Repository,
		Ref: ref, Source: "harbor", Report: rep, Raw: raw, UserID: j.CreatedBy})
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(ctx, `update targets set recheck_excluded = true where id=$1`, res.TargetID); err != nil {
		return err
	}
	s.audit(ctx, nil, "harbor.fetch", &p.ProjectID, p.Repository, map[string]any{"scan_id": res.ScanID, "digest": p.Digest, "duplicate": res.Duplicate})
	return nil
}
