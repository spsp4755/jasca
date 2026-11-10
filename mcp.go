package main

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// The MCP (Model Context Protocol) server: read-only tools over one project's data for AI agents, at POST /mcp.
//
// Transport: Streamable HTTP without streams. Every POST is one JSON-RPC message and gets one application/json
// answer (202 for a notification). There is no SSE and no session, so GET and DELETE answer 405.
//
// One endpoint serves both protocol eras, the way the 2026-07-28 specification describes a dual-era server: a
// request that carries its protocol version in params._meta is a 2026-07-28 request (no handshake, headers checked
// against the body, server/discover); any other request speaks the older handshake protocol (initialize, ping).
//
// The caller is always a project API token with the read scope, never a session, and every tool answers for that
// token's project only: there is no project argument. The tools run the REST handlers in-process and reshape
// their JSON for a model, so each query, its limits and its order exist once.

const (
	mcpModern  = "2026-07-28"
	mcpMaxBody = 64 << 10

	metaVersion    = "io.modelcontextprotocol/protocolVersion"
	metaClientCaps = "io.modelcontextprotocol/clientCapabilities"
	metaServerInfo = "io.modelcontextprotocol/serverInfo"

	rpcParseError     = -32700
	rpcInvalidRequest = -32600
	rpcNoMethod       = -32601
	rpcInvalidParams  = -32602
	rpcInternal       = -32603
	rpcHeaderMismatch = -32020
	rpcBadVersion     = -32022

	mcpInstructions = "Read-only vulnerability data of one JASCA project: the project the API token belongs to. " +
		"Start with project_summary, then list_findings. Ids for get_finding and get_scan come from the list tools."
)

// mcpLegacy are the handshake-era versions, newest first. 2025-03-26 is what the specification assumes for a request
// without an MCP-Protocol-Version header; its JSON-RPC batches are not accepted.
var mcpLegacy = []string{"2025-11-25", "2025-06-18", "2025-03-26"}

func init() { routeRegistrars = append(routeRegistrars, (*server).mcpRoutes) }

func (s *server) mcpRoutes() {
	s.mcpLimiter = newLimiter(300, time.Minute)
	// permPublic in the route table only: handleMCP does its own token-only auth, as the Harbor hook does with its secret.
	s.handle("POST /mcp", permPublic, s.handleMCP)
	for _, m := range []string{"GET", "DELETE"} { // unregistered, GET would get the web app's index.html
		s.handle(m+" /mcp", permPublic, func(w http.ResponseWriter, r *http.Request, c *reqCtx) {
			w.Header().Set("Allow", "POST")
			writeErr(w, 405, "method_not_allowed", "MCP 엔드포인트는 POST만 받습니다.")
		})
	}
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// writeRPC answers one JSON-RPC request; id is nil when the request's id could not be read.
func writeRPC(w http.ResponseWriter, status int, id json.RawMessage, result any, e *rpcError) {
	msg := map[string]any{"jsonrpc": "2.0"}
	if id != nil {
		msg["id"] = id
	}
	if e != nil {
		msg["error"] = e
	} else {
		msg["result"] = result
	}
	writeJSON(w, status, msg)
}

// mcpHeader undoes the "=?base64?…?=" wrapping a client must use for header values that are not plain ASCII.
func mcpHeader(v string) string {
	if b, ok := strings.CutPrefix(v, "=?base64?"); ok && strings.HasSuffix(b, "?=") {
		if raw, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(b, "?=")); err == nil {
			return string(raw)
		}
	}
	return v
}

func (s *server) handleMCP(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	// A page of another site must not reach this endpoint from a browser, token or not (the DNS-rebinding rule).
	if r.Header.Get("Origin") != "" && !sameOrigin(r, true) {
		writeErr(w, 403, "forbidden", "다른 사이트에서 보낸 요청은 처리하지 않습니다.")
		return
	}
	if c.Token == nil { // a session is not enough here: an agent presents a project token
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeErr(w, 401, "unauthorized", "유효한 API 토큰이 필요합니다. Authorization: Bearer jsc_… 헤더로 보내세요.")
		return
	}
	if !slices.Contains(c.Token.Scopes, "read") {
		writeErr(w, 403, "forbidden", "이 API 토큰에는 읽기(read) 권한이 없습니다. 읽기 권한 토큰을 만들어 쓰세요.")
		return
	}
	if !s.mcpLimiter.allow(itoa(c.Token.ID), time.Now()) {
		w.Header().Set("Retry-After", "1")
		writeErr(w, 429, "rate_limited", "요청이 너무 많습니다. 잠시 후 다시 시도하세요.")
		return
	}
	pr, err := s.projectByID(r.Context(), c.Token.ProjectID)
	if err != nil {
		writeInternal(w, "mcp project", err)
		return
	}
	c.Project = pr
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, mcpMaxBody))
	if err != nil {
		writeBodyErr(w, err)
		return
	}

	var req struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	if !json.Valid(raw) {
		writeRPC(w, 400, nil, nil, &rpcError{Code: rpcParseError, Message: "Parse error: the body is not JSON"})
		return
	}
	err = json.Unmarshal(raw, &req)
	id := req.ID // absent in a notification; in a request a string or a number, never null
	if err != nil || req.JSONRPC != "2.0" || req.Method == "" || len(id) > 0 && !strings.ContainsRune(`"-0123456789`, rune(id[0])) {
		writeRPC(w, 400, nil, nil, &rpcError{Code: rpcInvalidRequest,
			Message: "Invalid request: the body must be one JSON-RPC 2.0 request or notification (no batches)"})
		return
	}
	if len(id) == 0 { // a notification (notifications/initialized, notifications/cancelled): nothing to do or say
		w.WriteHeader(202)
		return
	}
	fail := func(status, code int, msg string, data any) {
		writeRPC(w, status, id, nil, &rpcError{Code: code, Message: msg, Data: data})
	}

	var p struct {
		Meta      map[string]json.RawMessage `json:"_meta"`
		Version   string                     `json:"protocolVersion"` // initialize
		Name      *string                    `json:"name"`            // tools/call
		Arguments json.RawMessage            `json:"arguments"`       // tools/call
	}
	if len(req.Params) > 0 && json.Unmarshal(req.Params, &p) != nil {
		fail(200, rpcInvalidParams, "Invalid params: params must be an object with the fields the method defines", nil)
		return
	}

	// Which era: the body decides, the MCP-Protocol-Version header must agree with it.
	hv, bv := r.Header.Get("MCP-Protocol-Version"), ""
	modern := p.Meta[metaVersion] != nil
	if modern {
		json.Unmarshal(p.Meta[metaVersion], &bv)
	}
	unsupported := func(v string) {
		fail(400, rpcBadVersion, "Unsupported protocol version",
			map[string]any{"supported": append([]string{mcpModern}, mcpLegacy...), "requested": v})
	}
	switch {
	case modern && hv != bv:
		fail(400, rpcHeaderMismatch, fmt.Sprintf("Header mismatch: MCP-Protocol-Version header %q does not match %q in params._meta", hv, bv), nil)
		return
	case modern && bv != mcpModern:
		unsupported(bv)
		return
	case modern && p.Meta[metaClientCaps] == nil:
		fail(400, rpcInvalidParams, "Invalid params: params._meta lacks "+metaClientCaps, nil)
		return
	case !modern && hv == mcpModern:
		fail(400, rpcInvalidParams, "Invalid params: a "+mcpModern+" request carries "+metaVersion+" in params._meta", nil)
		return
	case !modern && hv != "" && !slices.Contains(mcpLegacy, hv):
		unsupported(hv)
		return
	}
	handshake := req.Method == "initialize" || req.Method == "ping" // gone from the modern protocol
	if !(req.Method == "tools/list" || req.Method == "tools/call" || handshake && !modern || req.Method == "server/discover" && modern) {
		status := 200 // handshake-era clients read the error from the body
		if modern {
			status = 404 // the 2026-07-28 transport's rule
		}
		fail(status, rpcNoMethod, "Method not found: "+clip(req.Method, 80), nil)
		return
	}
	if modern { // the standard headers mirror the body so that proxies can route on them; a mismatch is refused
		if h := r.Header.Get("Mcp-Method"); h != req.Method {
			fail(400, rpcHeaderMismatch, fmt.Sprintf("Header mismatch: Mcp-Method header %q does not match method %q", h, req.Method), nil)
			return
		}
		if h := mcpHeader(r.Header.Get("Mcp-Name")); req.Method == "tools/call" && p.Name != nil && h != *p.Name {
			fail(400, rpcHeaderMismatch, fmt.Sprintf("Header mismatch: Mcp-Name header %q does not match tool name %q", h, *p.Name), nil)
			return
		}
	}

	info := map[string]any{"name": "jasca", "title": "JASCA", "version": version}
	caps := map[string]any{"tools": map[string]any{}}
	done := func(res map[string]any) {
		if modern {
			res["resultType"] = "complete"
			res["_meta"] = map[string]any{metaServerInfo: info}
		}
		writeRPC(w, 200, id, res, nil)
	}
	cacheable := func(res map[string]any) map[string]any { // the same for every caller, and it changes only with an upgrade
		if modern {
			res["ttlMs"], res["cacheScope"] = 300000, "public"
		}
		return res
	}
	switch req.Method {
	case "initialize":
		if p.Version == "" {
			fail(200, rpcInvalidParams, "Invalid params: protocolVersion is required", nil)
			return
		}
		v := mcpLegacy[0] // an unknown version gets our latest; the client decides whether it can speak it
		if slices.Contains(mcpLegacy, p.Version) {
			v = p.Version
		}
		done(map[string]any{"protocolVersion": v, "capabilities": caps, "serverInfo": info, "instructions": mcpInstructions})
	case "ping":
		done(map[string]any{})
	case "server/discover":
		done(cacheable(map[string]any{"supportedVersions": append([]string{mcpModern}, mcpLegacy...), "capabilities": caps,
			"instructions": mcpInstructions}))
	case "tools/list":
		done(cacheable(map[string]any{"tools": mcpTools}))
	case "tools/call":
		if p.Name == nil {
			fail(200, rpcInvalidParams, "Invalid params: name is required", nil)
			return
		}
		i := slices.IndexFunc(mcpTools, func(t mcpTool) bool { return t.Name == *p.Name })
		if i < 0 {
			fail(200, rpcInvalidParams, "Unknown tool: "+clip(*p.Name, 80), nil)
			return
		}
		out, err := mcpTools[i].run(&mcpCall{s: s, c: c, r: r}, p.Arguments)
		text := func(t string) []map[string]string { return []map[string]string{{"type": "text", "text": t}} }
		if te, ok := errors.AsType[toolError](err); ok {
			done(map[string]any{"content": text(string(te)), "isError": true})
			return
		}
		b, jerr := json.Marshal(out)
		if err = cmp.Or(err, jerr); err != nil {
			log.Printf("mcp %s: %v", *p.Name, err)
			fail(200, rpcInternal, "Internal error", nil)
			return
		}
		res := map[string]any{"content": text(string(b)), "isError": false}
		if cmp.Or(bv, hv) >= "2025-06-18" { // older clients do not know structuredContent
			res["structuredContent"] = json.RawMessage(b)
		}
		done(res)
	}
}

// --- tools ---

type mcpTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Annotations map[string]bool `json:"annotations"`
	run         func(m *mcpCall, args json.RawMessage) (any, error)
}

// mcpCall is one tool call: the caller's reqCtx (its token and project) is what the REST handlers are run with.
type mcpCall struct {
	s *server
	c *reqCtx
	r *http.Request
}

// toolError is a failure the model can act on (a bad argument, an id that does not exist). It is returned as a tool
// result with isError, in English; anything else a tool returns as an error is an internal error.
type toolError string

func (e toolError) Error() string { return string(e) }

func toolErrorf(format string, a ...any) error { return toolError(fmt.Sprintf(format, a...)) }

var errRESTNotFound = errors.New("REST handler answered 404")

// restWriter collects what a REST handler writes.
type restWriter struct {
	header http.Header
	code   int
	body   bytes.Buffer
}

func (w *restWriter) Header() http.Header         { return w.header }
func (w *restWriter) WriteHeader(code int)        { w.code = code }
func (w *restWriter) Write(b []byte) (int, error) { return w.body.Write(b) }

// rest runs a REST handler in-process as the call's token and decodes its JSON answer into out. id is the handler's
// {id} path value ("" when it has none), q its query. A 404 is errRESTNotFound; a 400 is the model's to fix.
func (m *mcpCall) rest(h func(http.ResponseWriter, *http.Request, *reqCtx), id string, q url.Values, out any) error {
	req, err := http.NewRequestWithContext(m.r.Context(), "GET", "/?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	req.SetPathValue("id", id)
	w := &restWriter{header: http.Header{}, code: 200}
	h(w, req, m.c)
	switch w.code {
	case 200:
		return json.Unmarshal(w.body.Bytes(), out)
	case 404:
		return errRESTNotFound
	case 400:
		var e struct{ Message string }
		json.Unmarshal(w.body.Bytes(), &e)
		return toolErrorf("Invalid arguments: %s", e.Message)
	}
	return fmt.Errorf("REST handler answered %d: %s", w.code, w.body.String())
}

// own checks that object id of kind (an obj permission kind) belongs to the token's project, with the resolver
// REST's obj permissions use. Another project's id answers exactly like one that does not exist.
func (m *mcpCall) own(kind, what string, id *int64) error {
	if id == nil || *id < 1 {
		return toolErrorf("Invalid arguments: id is required and must be a positive integer (an id from the list tools).")
	}
	pid, err := m.s.objs[kind](m.r.Context(), itoa(*id))
	if errors.Is(err, pgx.ErrNoRows) || err == nil && pid != m.c.Project.ID {
		return toolErrorf("%s %d not found in this project.", what, *id)
	}
	return err
}

// toolArgs decodes a tool's arguments into v. Unknown names and wrong types come back as tool errors in plain words.
func toolArgs(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if err == nil {
		return nil
	}
	if te, ok := errors.AsType[*json.UnmarshalTypeError](err); ok && te.Field != "" {
		want := map[reflect.Kind]string{reflect.Int: "an integer", reflect.Int64: "an integer", reflect.Bool: "true or false",
			reflect.String: "a string", reflect.Slice: "a list of strings"}[te.Type.Kind()]
		return toolErrorf("Invalid arguments: %q must be %s.", te.Field, cmp.Or(want, "of the type in the tool's input schema"))
	}
	if name, ok := strings.CutPrefix(err.Error(), "json: unknown field "); ok {
		return toolErrorf("Invalid arguments: unknown argument %s. See the tool's input schema.", name)
	}
	return toolErrorf("Invalid arguments: arguments must be an object.")
}

// enumArg checks that every value of argument name is one of allowed.
func enumArg(name string, allowed []string, values ...string) error {
	for _, v := range values {
		if !slices.Contains(allowed, v) {
			return toolErrorf("Invalid arguments: %s must be one of %s, got %q.", name, strings.Join(allowed, ", "), v)
		}
	}
	return nil
}

// limitArg is the limit argument: def when absent, an error outside 1..max.
func limitArg(n *int, def, max int) (int, error) {
	if n == nil {
		return def, nil
	}
	if *n < 1 || *n > max {
		return 0, toolErrorf("Invalid arguments: limit must be between 1 and %d.", max)
	}
	return *n, nil
}

// Cursors are the REST cursors behind a letter, so that no client takes one for a number: as a number "1.10" would
// come back as 1.1, another position in the list.
func cursorOut(rest string) string {
	if rest == "" {
		return ""
	}
	return "c" + rest
}

func cursorIn(arg string) (string, error) {
	rest, ok := strings.CutPrefix(arg, "c")
	if !ok || rest == "" {
		return "", toolErrorf("Invalid arguments: cursor must be the next_cursor value of the previous call.")
	}
	return rest, nil
}

// sec drops the fraction of a second: a model has no use for microseconds.
func sec(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	return new(t.Truncate(time.Second))
}

// targetID resolves a target argument: the target's name, or kind:name when two kinds share the name.
func (m *mcpCall) targetID(name string) (int64, error) {
	var list []targetView
	if err := m.rest(m.s.handleTargetList, "", nil, &list); err != nil {
		return 0, err
	}
	list = slices.DeleteFunc(list, func(t targetView) bool { return t.Name != name && t.Kind+":"+t.Name != name })
	switch len(list) {
	case 0:
		return 0, toolErrorf("Target %q not found in this project. Call list_targets for the names.", name)
	case 1:
		return list[0].ID, nil
	}
	return 0, toolErrorf("%d targets are named %q. Pass kind:name, for example %q.", len(list), name, list[0].Kind+":"+list[0].Name)
}

var (
	mcpSeverities = policySeverities
	mcpStatuses   = []string{"open", "fixed", "accepted", "false_positive"}
	mcpKinds      = []string{"vuln", "misconfig", "secret", "sast"}
	mcpExStatuses = []string{"pending", "approved", "rejected", "expired", "revoked"}
)

// --- project_summary, list_targets ---

func mcpProjectSummary(m *mcpCall, raw json.RawMessage) (any, error) {
	if err := toolArgs(raw, &struct{}{}); err != nil {
		return nil, err
	}
	var pv projectView
	var targets []targetView
	var pol policy
	if err := cmp.Or(m.rest(m.s.handleProjectGet, "", nil, &pv), m.rest(m.s.handleTargetList, "", nil, &targets),
		m.rest(m.s.handlePolicyGet, "", nil, &pol)); err != nil {
		return nil, err
	}
	line := "disabled: every scan passes"
	if pol.Enabled {
		line = fmt.Sprintf("a scan fails when its target has more than %d open findings of severity %s or higher", pol.MaxCount, pol.MinSeverity)
		if pol.NewOnly {
			line += ", counting only findings new in that scan"
		}
		if pol.FixableOnly {
			line += ", counting only findings with a fixed version"
		}
		line += "; findings under an approved exception are not counted"
	}
	return struct {
		Key          string     `json:"key"`
		Name         string     `json:"name"`
		OpenFindings sevCounts  `json:"open_findings"`
		Targets      int        `json:"targets"`
		LastScanAt   *time.Time `json:"last_scan_at,omitempty"`
		Policy       string     `json:"policy"`
	}{pv.Key, pv.Name, pv.Counts, len(targets), sec(pv.LastScanAt), line}, nil
}

func mcpListTargets(m *mcpCall, raw json.RawMessage) (any, error) {
	var a struct {
		Limit *int `json:"limit"`
	}
	if err := toolArgs(raw, &a); err != nil {
		return nil, err
	}
	limit, err := limitArg(a.Limit, 100, 500)
	if err != nil {
		return nil, err
	}
	var list []targetView
	if err := m.rest(m.s.handleTargetList, "", nil, &list); err != nil {
		return nil, err
	}
	type target struct {
		Name       string     `json:"name"`
		Kind       string     `json:"kind"`
		LastScanAt *time.Time `json:"last_scan_at,omitempty"`
		sevCounts             // open findings: critical … unknown, open = all of them
	}
	out := struct {
		Total   int      `json:"total"`
		Targets []target `json:"targets"`
	}{len(list), []target{}}
	for _, t := range list[:min(limit, len(list))] {
		out.Targets = append(out.Targets, target{t.Name, t.Kind, sec(t.LastScanAt), t.Counts})
	}
	return out, nil
}

// --- findings ---

type mcpFinding struct {
	ID               int64     `json:"id"`
	Severity         string    `json:"severity"`
	RuleID           string    `json:"rule_id"`
	Title            string    `json:"title,omitempty"`
	Package          string    `json:"package,omitempty"`
	InstalledVersion string    `json:"installed_version,omitempty"`
	FixedVersion     string    `json:"fixed_version,omitempty"`
	Target           string    `json:"target"`
	Status           string    `json:"status"`
	FirstSeen        time.Time `json:"first_seen"`
}

func mcpFindingRow(f findingView) mcpFinding {
	return mcpFinding{f.ID, f.Severity, f.RuleID, clip(f.Title, 200), f.PkgName, f.PkgVersion, f.FixedVersion, f.TargetName,
		f.Status, f.FirstSeenAt.Truncate(time.Second)}
}

func mcpListFindings(m *mcpCall, raw json.RawMessage) (any, error) {
	var a struct {
		Severity []string `json:"severity"`
		Status   string   `json:"status"`
		Kind     string   `json:"kind"`
		Target   string   `json:"target"`
		Query    string   `json:"query"`
		Fixable  *bool    `json:"fixable"`
		Limit    *int     `json:"limit"`
		Cursor   string   `json:"cursor"`
	}
	if err := toolArgs(raw, &a); err != nil {
		return nil, err
	}
	a.Status = cmp.Or(a.Status, "open")
	limit, err := limitArg(a.Limit, 50, 200)
	if err = cmp.Or(err, enumArg("severity", mcpSeverities, a.Severity...), enumArg("status", mcpStatuses, a.Status)); err != nil {
		return nil, err
	}
	q := url.Values{"status": {a.Status}, "limit": {strconv.Itoa(limit)}}
	if len(a.Severity) > 0 {
		q.Set("severity", strings.Join(a.Severity, ","))
	}
	if a.Kind != "" {
		if err := enumArg("kind", mcpKinds, a.Kind); err != nil {
			return nil, err
		}
		q.Set("kind", a.Kind)
	}
	if a.Target != "" {
		id, err := m.targetID(a.Target)
		if err != nil {
			return nil, err
		}
		q.Set("target_id", itoa(id))
	}
	if utf8.RuneCountInString(a.Query) > 200 {
		return nil, toolErrorf("Invalid arguments: query must be at most 200 characters.")
	}
	if a.Query != "" {
		q.Set("q", a.Query)
	}
	if a.Fixable != nil {
		q.Set("fixable", strconv.FormatBool(*a.Fixable))
	}
	if a.Cursor != "" {
		cur, err := cursorIn(a.Cursor)
		if err != nil {
			return nil, err
		}
		q.Set("cursor", cur)
	}
	var page struct {
		Items      []findingView `json:"items"`
		NextCursor string        `json:"next_cursor"`
		Total      int           `json:"total"`
	}
	base := &where{}
	base.add("f.project_id = ?", m.c.Project.ID)
	list := func(w http.ResponseWriter, r *http.Request, c *reqCtx) { m.s.writeFindings(w, r, base) }
	if err := m.rest(list, "", q, &page); err != nil {
		return nil, err
	}
	out := struct {
		Total      int          `json:"total"`
		Findings   []mcpFinding `json:"findings"`
		NextCursor string       `json:"next_cursor,omitempty"`
	}{page.Total, []mcpFinding{}, cursorOut(page.NextCursor)}
	for _, f := range page.Items {
		out.Findings = append(out.Findings, mcpFindingRow(f))
	}
	return out, nil
}

func mcpGetFinding(m *mcpCall, raw json.RawMessage) (any, error) {
	var a struct {
		ID *int64 `json:"id"`
	}
	if err := cmp.Or(toolArgs(raw, &a), m.own("finding", "Finding", a.ID)); err != nil {
		return nil, err
	}
	var f findingView
	if err := m.rest(m.s.handleFindingGet, itoa(*a.ID), nil, &f); err != nil {
		return nil, err
	}
	out := struct {
		mcpFinding
		Kind            string          `json:"kind"`
		Tool            string          `json:"tool"`
		Origin          string          `json:"origin"`
		Location        string          `json:"location,omitempty"`
		PackagePath     string          `json:"package_path,omitempty"`
		LastSeen        time.Time       `json:"last_seen"`
		FixedAt         *time.Time      `json:"fixed_at,omitempty"`
		VulnerabilityID string          `json:"vulnerability_id,omitempty"`
		Exception       *mcpException   `json:"exception,omitempty"`
		Details         json.RawMessage `json:"details,omitempty"`
	}{mcpFinding: mcpFindingRow(f), Kind: f.Kind, Tool: f.Tool, Origin: f.Origin, Location: f.Location, PackagePath: f.PkgPath,
		LastSeen: f.LastSeenAt.Truncate(time.Second), FixedAt: sec(f.FixedAt)}
	if f.Kind == "vuln" && f.Tool != "advisory" { // an internal advisory has no catalog entry
		out.VulnerabilityID = f.RuleID
	}
	if n := len(f.Details); n > len("{}") && n <= 8<<10 { // the scanner's extras: message, resolution, line numbers
		out.Details = f.Details
	}
	if f.ExceptionID != nil {
		ex, err := m.s.loadException(m.r.Context(), *f.ExceptionID)
		if err != nil {
			return nil, err
		}
		out.Exception = new(mcpExceptionRow(*ex))
	}
	return out, nil
}

func mcpGetVulnerability(m *mcpCall, raw json.RawMessage) (any, error) {
	var a struct {
		ID string `json:"id"`
	}
	if err := toolArgs(raw, &a); err != nil {
		return nil, err
	}
	id := strings.ToUpper(strings.TrimSpace(a.ID))
	if id == "" {
		return nil, toolErrorf("Invalid arguments: id is required, for example CVE-2024-1234.")
	}
	var v vulnView
	err := m.rest(m.s.handleVulnGet, id, nil, &v)
	// The catalog is shared by all projects: an entry no finding of this project points at is not this token's to read.
	if errors.Is(err, errRESTNotFound) || err == nil && len(v.Affected) == 0 {
		return nil, toolErrorf("Vulnerability %s not found in this project.", clip(id, 60))
	}
	if err != nil {
		return nil, err
	}
	type affected struct {
		FindingID        int64  `json:"finding_id"`
		Target           string `json:"target"`
		Severity         string `json:"severity"`
		Status           string `json:"status"`
		Package          string `json:"package,omitempty"`
		InstalledVersion string `json:"installed_version,omitempty"`
		FixedVersion     string `json:"fixed_version,omitempty"`
	}
	out := struct {
		ID            string     `json:"id"`
		Title         string     `json:"title,omitempty"`
		Description   string     `json:"description,omitempty"`
		CVSSScore     *float64   `json:"cvss_score,omitempty"`
		CVSSVector    string     `json:"cvss_vector,omitempty"`
		CWEIDs        []string   `json:"cwe_ids,omitempty"`
		PublishedAt   *time.Time `json:"published_at,omitempty"`
		References    []string   `json:"references,omitempty"`
		AffectedTotal int        `json:"affected_total"`
		Affected      []affected `json:"affected"`
	}{ID: v.ID, Title: v.Title, Description: clip(v.Description, 4000), CVSSScore: v.CVSSScore, CVSSVector: v.CVSSVector,
		CWEIDs: v.CWEIDs, PublishedAt: sec(v.PublishedAt), References: v.Refs[:min(20, len(v.Refs))], AffectedTotal: len(v.Affected)}
	for _, f := range v.Affected[:min(200, len(v.Affected))] {
		out.Affected = append(out.Affected, affected{f.FindingID, f.Target, f.Severity, f.Status, f.PkgName, f.PkgVersion, f.FixedVersion})
	}
	return out, nil
}

// --- scans ---

type mcpScan struct {
	ID            int64      `json:"id"`
	Target        string     `json:"target"`
	Source        string     `json:"source"`
	Status        string     `json:"status"`
	Error         string     `json:"error,omitempty"`
	Ref           string     `json:"ref,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	Summary       *sevCounts `json:"summary,omitempty"`       // open findings of the target right after the scan
	PolicyPassed  *bool      `json:"policy_passed,omitempty"` // absent until the scan is done
	PolicyReasons []string   `json:"policy_reasons,omitempty"`
}

func mcpScanRow(v scanView) mcpScan {
	out := mcpScan{ID: v.ID, Target: v.TargetName, Source: v.Source, Status: v.Status, Error: clip(v.Error, 500), Ref: v.Ref,
		CreatedAt: v.CreatedAt.Truncate(time.Second)}
	if v.Status == "done" {
		out.Summary = &sevCounts{}
		json.Unmarshal(v.Summary, out.Summary)
	}
	var pol *policyResult
	if json.Unmarshal(v.Policy, &pol); pol != nil {
		out.PolicyPassed, out.PolicyReasons = &pol.Passed, pol.Reasons
	}
	return out
}

func mcpListScans(m *mcpCall, raw json.RawMessage) (any, error) {
	var a struct {
		Target string `json:"target"`
		Limit  *int   `json:"limit"`
		Cursor string `json:"cursor"`
	}
	if err := toolArgs(raw, &a); err != nil {
		return nil, err
	}
	limit, err := limitArg(a.Limit, 20, 100)
	if err != nil {
		return nil, err
	}
	q := url.Values{"limit": {strconv.Itoa(limit)}}
	if a.Cursor != "" {
		cur, err := cursorIn(a.Cursor)
		if err != nil {
			return nil, err
		}
		q.Set("before", cur)
	}
	if a.Target != "" {
		id, err := m.targetID(a.Target)
		if err != nil {
			return nil, err
		}
		q.Set("target_id", itoa(id))
	}
	var page struct {
		Items      []scanView `json:"items"`
		NextBefore *int64     `json:"next_before"`
	}
	if err := m.rest(m.s.handleScanList, "", q, &page); err != nil {
		return nil, err
	}
	out := struct {
		Scans      []mcpScan `json:"scans"`
		NextCursor string    `json:"next_cursor,omitempty"`
	}{Scans: []mcpScan{}}
	for _, v := range page.Items {
		out.Scans = append(out.Scans, mcpScanRow(v))
	}
	if page.NextBefore != nil {
		out.NextCursor = cursorOut(itoa(*page.NextBefore))
	}
	return out, nil
}

func mcpGetScan(m *mcpCall, raw json.RawMessage) (any, error) {
	var a struct {
		ID *int64 `json:"id"`
	}
	if err := cmp.Or(toolArgs(raw, &a), m.own("scan", "Scan", a.ID)); err != nil {
		return nil, err
	}
	var v struct {
		scanView
		Diff scanDiff `json:"diff"`
	}
	if err := m.rest(m.s.handleScanGet, itoa(*a.ID), nil, &v); err != nil {
		return nil, err
	}
	out := struct {
		mcpScan
		Format     string     `json:"format"`
		CreatedBy  string     `json:"created_by,omitempty"`
		FinishedAt *time.Time `json:"finished_at,omitempty"`
		Compare    *scanDiff  `json:"compared_to_previous,omitempty"` // absent for a target's first scan
	}{mcpScan: mcpScanRow(v.scanView), Format: v.Format, CreatedBy: v.CreatedBy, FinishedAt: sec(v.FinishedAt)}
	if v.Diff.PreviousScanID != nil {
		out.Compare = &v.Diff
	}
	return out, nil
}

// --- exceptions ---

type mcpException struct {
	ID          int64     `json:"id"`
	Scope       string    `json:"scope"` // finding, project_vuln (a CVE in this project), global_vuln (a CVE everywhere)
	VulnID      *string   `json:"vuln_id,omitempty"`
	FindingID   *int64    `json:"finding_id,omitempty"`
	RuleID      *string   `json:"rule_id,omitempty"` // of the finding, for scope finding
	Package     *string   `json:"package,omitempty"`
	Severity    *string   `json:"severity,omitempty"`
	Resolution  string    `json:"resolution"`
	Status      string    `json:"status"`
	Reason      string    `json:"reason"`
	RequestedBy string    `json:"requested_by,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func mcpExceptionRow(e exception) mcpException {
	return mcpException{e.ID, e.Scope, e.VulnID, e.FindingID, e.FindingRule, e.FindingPkg, e.FindingSeverity, e.Resolution, e.Status,
		clip(e.Reason, 500), e.RequestedByName, e.ExpiresAt.Truncate(time.Second)}
}

func mcpListExceptions(m *mcpCall, raw json.RawMessage) (any, error) {
	var a struct {
		Status string `json:"status"`
		Limit  *int   `json:"limit"`
	}
	if err := toolArgs(raw, &a); err != nil {
		return nil, err
	}
	limit, err := limitArg(a.Limit, 50, 200)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	if a.Status != "" {
		if err := enumArg("status", mcpExStatuses, a.Status); err != nil {
			return nil, err
		}
		q.Set("status", a.Status)
	}
	var list []exception
	if err := m.rest(m.s.handleExceptionList, "", q, &list); err != nil {
		return nil, err
	}
	out := struct {
		Total      int            `json:"total"`
		Exceptions []mcpException `json:"exceptions"`
	}{len(list), []mcpException{}}
	for _, e := range list[:min(limit, len(list))] {
		out.Exceptions = append(out.Exceptions, mcpExceptionRow(e))
	}
	return out, nil
}

// --- the tool list ---

func enumJSON(vs []string) string { b, _ := json.Marshal(vs); return string(b) }

func limitSchema(def, max int) string {
	return fmt.Sprintf(`{"type": "integer", "minimum": 1, "maximum": %d, "default": %d, "description": "Maximum number of rows to return."}`, max, def)
}

const idSchema = `{"type": "object", "additionalProperties": false, "required": ["id"], "properties": {"id": {"type": "integer", "minimum": 1, "description": %q}}}`

// mcpTools is what tools/list answers, in this order. Names, descriptions and schemas are what the model reads.
var mcpTools = func() []mcpTool {
	readOnly := map[string]bool{"readOnlyHint": true, "openWorldHint": false}
	tool := func(name, desc, schema string, run func(*mcpCall, json.RawMessage) (any, error)) mcpTool {
		return mcpTool{name, desc, json.RawMessage(schema), readOnly, run}
	}
	return []mcpTool{
		tool("project_summary",
			"Overview of the project this API token belongs to: key and name, open findings by severity, number of scan "+
				"targets, time of the latest scan, and the policy that decides whether a scan passes. Call this first.",
			`{"type": "object", "additionalProperties": false, "properties": {}}`, mcpProjectSummary),
		tool("list_findings",
			"List the project's findings (vulnerabilities, misconfigurations, leaked secrets, SAST results), most severe "+
				"first. Returns open findings unless status says otherwise. Narrow down with the filters, then call "+
				"get_finding for one finding's details. total counts all matches; pass next_cursor as cursor for the next page.",
			`{"type": "object", "additionalProperties": false, "properties": {
				"severity": {"type": "array", "items": {"type": "string", "enum": `+enumJSON(mcpSeverities)+`}, "description": "Only findings of these severities."},
				"status": {"type": "string", "enum": `+enumJSON(mcpStatuses)+`, "default": "open", "description": "Finding status. accepted and false_positive are findings under an approved exception."},
				"kind": {"type": "string", "enum": `+enumJSON(mcpKinds)+`, "description": "Only this kind: vuln (vulnerable package), misconfig, secret or sast."},
				"target": {"type": "string", "description": "Only findings of this scan target: its exact name from list_targets."},
				"query": {"type": "string", "maxLength": 200, "description": "Case-insensitive text to find in the rule id (such as a CVE id), package name or title."},
				"fixable": {"type": "boolean", "description": "true: only findings with a fixed version available. false: only findings without one."},
				"limit": `+limitSchema(50, 200)+`,
				"cursor": {"type": "string", "description": "next_cursor from the previous call with the same filters."}}}`,
			mcpListFindings),
		tool("get_finding",
			"Everything about one finding: severity, rule id, package with installed and fixed version, target, file "+
				"location, status, the exception covering it (if any), scanner details, and for a vulnerability the "+
				"vulnerability_id to pass to get_vulnerability.",
			fmt.Sprintf(idSchema, "Finding id from list_findings or get_vulnerability."), mcpGetFinding),
		tool("get_vulnerability",
			"Look up a vulnerability found in this project by its CVE or advisory id: title, description, CVSS, CWE, "+
				"references, and every finding of it in this project (target, status, installed and fixed version).",
			`{"type": "object", "additionalProperties": false, "required": ["id"], "properties": {
				"id": {"type": "string", "description": "Vulnerability id such as CVE-2024-1234 or GHSA-xxxx-xxxx-xxxx: a rule_id of a vuln finding."}}}`,
			mcpGetVulnerability),
		tool("list_targets",
			"List the project's scan targets (container images, repositories, file systems, SBOMs) by name, each with "+
				"its kind, the time of its last scan and its open findings by severity. The names are what the target "+
				"filter of list_findings and list_scans takes.",
			`{"type": "object", "additionalProperties": false, "properties": {"limit": `+limitSchema(100, 500)+`}}`, mcpListTargets),
		tool("list_scans",
			"List the project's scans, newest first: target, source (upload, server, harbor, recheck), status, ref (image "+
				"tag or commit), the target's open findings right after the scan, and whether the scan passed the policy, "+
				"with the reasons when it failed. Pass next_cursor as cursor for older scans.",
			`{"type": "object", "additionalProperties": false, "properties": {
				"target": {"type": "string", "description": "Only scans of this scan target: its exact name from list_targets."},
				"limit": `+limitSchema(20, 100)+`,
				"cursor": {"type": "string", "description": "next_cursor from the previous call."}}}`,
			mcpListScans),
		tool("get_scan",
			"One scan with its comparison to the previous scan of the same target: how many findings are new, fixed and "+
				"unchanged. Use it to see what a build or release changed.",
			fmt.Sprintf(idSchema, "Scan id from list_scans."), mcpGetScan),
		tool("list_exceptions",
			"List the exceptions (accepted risks and false positives) that apply to the project, newest first: what is "+
				"excepted, scope, resolution, status, reason, who requested it and when it expires. Company-wide exceptions "+
				"(scope global_vuln) are included. Findings under an approved exception do not count against the policy.",
			`{"type": "object", "additionalProperties": false, "properties": {
				"status": {"type": "string", "enum": `+enumJSON(mcpExStatuses)+`, "description": "Only exceptions in this state. All states when omitted."},
				"limit": `+limitSchema(50, 200)+`}}`,
			mcpListExceptions),
	}
}()
