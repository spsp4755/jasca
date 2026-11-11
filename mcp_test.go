package main

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

type rpcReply struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  map[string]any  `json:"result"`
	Error   *struct {
		Code    int            `json:"code"`
		Message string         `json:"message"`
		Data    map[string]any `json:"data"`
	} `json:"error"`
}

// mcpPost sends body to POST /mcp as a script would (no browser headers) with tok ("" = no Authorization) and h.
func mcpPost(t *testing.T, s *server, tok string, body any, h http.Header) (*httptest.ResponseRecorder, rpcReply) {
	t.Helper()
	hh := http.Header{"Content-Type": {"application/json"}, "Accept": {"application/json, text/event-stream"}}
	maps.Copy(hh, h)
	auth := []any{hh}
	if tok != "" {
		auth = append(auth, tok)
	}
	rec := do(t, s, "POST", "/mcp", body, auth...)
	var rp rpcReply
	json.Unmarshal(rec.Body.Bytes(), &rp) // the caller checks what it expects; not every answer is JSON-RPC
	return rec, rp
}

func rpcReq(method string, params any) map[string]any {
	m := map[string]any{"jsonrpc": "2.0", "id": 7, "method": method}
	if params != nil {
		m["params"] = params
	}
	return m
}

// mcpOld sends a request the way a handshake-era client (2025-11-25) does after initialize: the version is only a header.
func mcpOld(t *testing.T, s *server, tok, method string, params any) (*httptest.ResponseRecorder, rpcReply) {
	t.Helper()
	return mcpPost(t, s, tok, rpcReq(method, params), http.Header{"Mcp-Protocol-Version": {"2025-11-25"}})
}

func modernMeta() map[string]any {
	return map[string]any{"io.modelcontextprotocol/protocolVersion": "2026-07-28",
		"io.modelcontextprotocol/clientInfo":         map[string]any{"name": "test", "version": "1"},
		"io.modelcontextprotocol/clientCapabilities": map[string]any{}}
}

// mcpNew sends a 2026-07-28 request: version and capabilities in params._meta, mirrored in the standard headers.
func mcpNew(t *testing.T, s *server, tok, method string, params map[string]any) (*httptest.ResponseRecorder, rpcReply) {
	t.Helper()
	p := map[string]any{"_meta": modernMeta()}
	maps.Copy(p, params)
	h := http.Header{"Mcp-Protocol-Version": {"2026-07-28"}, "Mcp-Method": {method}}
	if n, ok := params["name"].(string); ok {
		h.Set("Mcp-Name", n)
	}
	return mcpPost(t, s, tok, rpcReq(method, p), h)
}

// toolRaw calls a tool as a modern client and returns the result object; a JSON-RPC error fails the test.
func toolRaw(t *testing.T, s *server, tok, name string, args map[string]any) (map[string]any, string) {
	t.Helper()
	rec, rp := mcpNew(t, s, tok, "tools/call", map[string]any{"name": name, "arguments": args})
	if rec.Code != 200 || rp.Error != nil || rp.Result == nil {
		t.Fatalf("%s %v: %d %s", name, args, rec.Code, rec.Body.String())
	}
	content, _ := rp.Result["content"].([]any)
	if len(content) != 1 {
		t.Fatalf("%s: want one content block: %s", name, rec.Body.String())
	}
	block, _ := content[0].(map[string]any)
	text, _ := block["text"].(string)
	if block["type"] != "text" || text == "" {
		t.Fatalf("%s: content block %v", name, block)
	}
	return rp.Result, text
}

// callTool runs a tool that must succeed and decodes its JSON text; structuredContent must carry the same value.
func callTool[T any](t *testing.T, s *server, tok, name string, args map[string]any) T {
	t.Helper()
	res, text := toolRaw(t, s, tok, name, args)
	if res["isError"] == true {
		t.Fatalf("%s %v: tool error %s", name, args, text)
	}
	var v T
	var plain any
	if err := json.Unmarshal([]byte(text), &v); err != nil {
		t.Fatalf("%s: text is not JSON: %s", name, text)
	}
	json.Unmarshal([]byte(text), &plain)
	if !reflect.DeepEqual(plain, res["structuredContent"]) {
		t.Errorf("%s: structuredContent %v differs from text %s", name, res["structuredContent"], text)
	}
	return v
}

// toolErr runs a tool that must fail inside the tool: a result with isError and a message, not a JSON-RPC error.
func toolErr(t *testing.T, s *server, tok, name string, args map[string]any) string {
	t.Helper()
	res, text := toolRaw(t, s, tok, name, args)
	if res["isError"] != true || res["structuredContent"] != nil {
		t.Fatalf("%s %v: want a tool error, got %v", name, args, res)
	}
	return text
}

type mcpSeeded struct {
	tok                 string
	pid                 int64
	scan1, scan2, scan3 int64
	exception           int64
}

// mcpSeed fills project key: target <key>-api (image) scanned twice and <key>-web (repo) once, and an approved
// exception on the api target's CVE-2024-2222. Open afterwards: CVE-2024-1111 CRITICAL on web, CVE-2024-3333 HIGH
// and DS002 MEDIUM on api; CVE-2024-1111 on api is fixed by the second scan.
func mcpSeed(t *testing.T, s *server, key string) mcpSeeded {
	t.Helper()
	pid, tok := mkToken(t, s, key, "read", "upload")
	api := "target=" + key + "-api&kind=image&scanners=vuln,misconfig&ref="
	crit := tv{ID: "CVE-2024-1111", Pkg: "openssl", Sev: "CRITICAL", Fixed: "3.0.9", Title: "heap overflow", Desc: "A long description."}
	low := tv{ID: "CVE-2024-2222", Pkg: "zlib", Sev: "LOW"}
	f := mcpSeeded{tok: tok, pid: pid}
	f.scan1 = mustUpload(t, s, key, api+"v1", trivyDoc("x", []tv{crit, low}, []string{"DS002"}), tok).ScanID
	f.scan2 = mustUpload(t, s, key, api+"v2", trivyDoc("x", []tv{low, {ID: "CVE-2024-3333", Pkg: "curl", Fixed: "8.1"}}, []string{"DS002"}), tok).ScanID
	f.scan3 = mustUpload(t, s, key, "target="+key+"-web&kind=repo&scanners=vuln", trivyDoc("x", []tv{crit}, nil), tok).ScanID
	u := mkUser(t, s, "req-"+key, "")
	fid := qint64(t, s, `select id from findings where project_id=$1 and rule_id='CVE-2024-2222'`, pid)
	f.exception = qint64(t, s, `insert into exceptions(scope, project_id, finding_id, resolution, reason, status, requested_by, expires_at)
		values('finding', $1, $2, 'accepted', 'not reachable in `+key+`', 'approved', $3, now() + interval '30 days') returning id`, pid, fid, u.ID)
	sqlExec(t, s, `update findings set status='accepted', exception_id=$1 where id=$2`, f.exception, fid)
	return f
}

func findingID(t *testing.T, s *server, pid int64, rule, target string) int64 {
	t.Helper()
	return qint64(t, s, `select f.id from findings f join targets t on t.id=f.target_id where f.project_id=$1 and f.rule_id=$2 and t.name=$3`, pid, rule, target)
}

var mcpToolNames = []string{"project_summary", "list_findings", "get_finding", "get_vulnerability", "list_targets",
	"list_scans", "get_scan", "list_exceptions", "search_packages"}

func TestMCPInitialize(t *testing.T) {
	s := testServer(t)
	_, tok := mkToken(t, s, "shop", "read")
	for _, tc := range []struct{ ask, want string }{
		{"2025-11-25", "2025-11-25"}, {"2025-06-18", "2025-06-18"}, {"2025-03-26", "2025-03-26"},
		{"1999-01-01", "2025-11-25"}, // unknown: the server offers its latest handshake version
		{"2026-07-28", "2025-11-25"}, // that version has no initialize; asking for it with one gets the latest that does
	} {
		// the initialize POST carries no MCP-Protocol-Version header: nothing is negotiated yet
		rec, rp := mcpPost(t, s, tok, rpcReq("initialize", map[string]any{"protocolVersion": tc.ask,
			"capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "c", "version": "1"}}), nil)
		info, _ := rp.Result["serverInfo"].(map[string]any)
		if rec.Code != 200 || rp.Result["protocolVersion"] != tc.want || info["name"] != "jasca" || info["version"] != version ||
			!reflect.DeepEqual(rp.Result["capabilities"], map[string]any{"tools": map[string]any{}}) || rp.Result["instructions"] != mcpInstructions {
			t.Errorf("initialize %s: %d %s", tc.ask, rec.Code, rec.Body.String())
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") || rec.Header().Get("Mcp-Session-Id") != "" {
			t.Errorf("initialize %s: headers %v", tc.ask, rec.Header())
		}
		if string(rp.ID) != "7" || rp.JSONRPC != "2.0" || rp.Result["resultType"] != nil {
			t.Errorf("initialize %s: envelope %s", tc.ask, rec.Body.String())
		}
	}
	if rec, rp := mcpPost(t, s, tok, rpcReq("initialize", map[string]any{}), nil); rp.Error == nil || rp.Error.Code != -32602 {
		t.Errorf("initialize without a version: %d %s", rec.Code, rec.Body.String())
	}
	// notifications get 202 and no body, whatever they are
	for _, m := range []string{"notifications/initialized", "notifications/cancelled"} {
		rec, _ := mcpPost(t, s, tok, map[string]any{"jsonrpc": "2.0", "method": m}, http.Header{"Mcp-Protocol-Version": {"2025-11-25"}})
		if rec.Code != 202 || rec.Body.Len() != 0 {
			t.Errorf("%s: %d %q", m, rec.Code, rec.Body.String())
		}
	}
	if rec, rp := mcpOld(t, s, tok, "ping", nil); rec.Code != 200 || rp.Result == nil || len(rp.Result) != 0 {
		t.Errorf("ping: %d %s", rec.Code, rec.Body.String())
	}
	// string ids come back as strings
	if _, rp := mcpPost(t, s, tok, map[string]any{"jsonrpc": "2.0", "id": "a-1", "method": "ping"}, nil); string(rp.ID) != `"a-1"` {
		t.Errorf("string id: %s", rp.ID)
	}
	// a handshake-era request without the version header is served (the spec's 2025-03-26 assumption)
	if rec, rp := mcpPost(t, s, tok, rpcReq("tools/list", nil), nil); rec.Code != 200 || rp.Result["tools"] == nil {
		t.Errorf("tools/list without a version header: %d %s", rec.Code, rec.Body.String())
	}
	// an unknown version header is refused with the list of supported ones
	rec, rp := mcpPost(t, s, tok, rpcReq("tools/list", nil), http.Header{"Mcp-Protocol-Version": {"2024-11-05"}})
	if rec.Code != 400 || rp.Error == nil || rp.Error.Code != -32022 || rp.Error.Data["requested"] != "2024-11-05" {
		t.Errorf("unsupported header version: %d %s", rec.Code, rec.Body.String())
	}
}

func TestMCPModernEra(t *testing.T) {
	s := testServer(t)
	_, tok := mkToken(t, s, "shop", "read")
	all := []any{"2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"}

	rec, rp := mcpNew(t, s, tok, "server/discover", nil)
	meta, _ := rp.Result["_meta"].(map[string]any)
	info, _ := meta["io.modelcontextprotocol/serverInfo"].(map[string]any)
	if rec.Code != 200 || !reflect.DeepEqual(rp.Result["supportedVersions"], all) || rp.Result["resultType"] != "complete" ||
		!reflect.DeepEqual(rp.Result["capabilities"], map[string]any{"tools": map[string]any{}}) || info["name"] != "jasca" ||
		rp.Result["cacheScope"] != "public" || rp.Result["ttlMs"] == nil || rp.Result["instructions"] != mcpInstructions {
		t.Errorf("server/discover: %d %s", rec.Code, rec.Body.String())
	}
	rec, rp = mcpNew(t, s, tok, "tools/list", nil)
	tools, _ := rp.Result["tools"].([]any)
	if rec.Code != 200 || rp.Result["resultType"] != "complete" || rp.Result["cacheScope"] != "public" || rp.Result["ttlMs"] == nil ||
		rp.Result["_meta"] == nil || len(tools) != len(mcpToolNames) {
		t.Errorf("modern tools/list: %d %s", rec.Code, rec.Body.String())
	}
	res, _ := toolRaw(t, s, tok, "project_summary", nil)
	if res["resultType"] != "complete" || res["_meta"] == nil {
		t.Errorf("modern tools/call lacks resultType or serverInfo: %v", res)
	}

	body := func(method string, meta map[string]any, extra map[string]any) map[string]any {
		p := map[string]any{"_meta": meta}
		maps.Copy(p, extra)
		return rpcReq(method, p)
	}
	hdr := func(kv ...string) http.Header {
		h := http.Header{}
		for i := 0; i < len(kv); i += 2 {
			h.Set(kv[i], kv[i+1])
		}
		return h
	}
	future := modernMeta()
	future["io.modelcontextprotocol/protocolVersion"] = "2030-01-01"
	noCaps := modernMeta()
	delete(noCaps, "io.modelcontextprotocol/clientCapabilities")
	call := map[string]any{"name": "project_summary", "arguments": map[string]any{}}
	const v = "2026-07-28"
	for name, tc := range map[string]struct {
		body       map[string]any
		h          http.Header
		status, rc int
	}{
		"unsupported version":      {body("tools/list", future, nil), hdr("Mcp-Protocol-Version", "2030-01-01", "Mcp-Method", "tools/list"), 400, -32022},
		"header disagrees":         {body("tools/list", modernMeta(), nil), hdr("Mcp-Protocol-Version", "2025-11-25", "Mcp-Method", "tools/list"), 400, -32020},
		"no version header":        {body("tools/list", modernMeta(), nil), hdr("Mcp-Method", "tools/list"), 400, -32020},
		"no Mcp-Method":            {body("tools/list", modernMeta(), nil), hdr("Mcp-Protocol-Version", v), 400, -32020},
		"Mcp-Method disagrees":     {body("tools/list", modernMeta(), nil), hdr("Mcp-Protocol-Version", v, "Mcp-Method", "tools/call"), 400, -32020},
		"no Mcp-Name":              {body("tools/call", modernMeta(), call), hdr("Mcp-Protocol-Version", v, "Mcp-Method", "tools/call"), 400, -32020},
		"Mcp-Name disagrees":       {body("tools/call", modernMeta(), call), hdr("Mcp-Protocol-Version", v, "Mcp-Method", "tools/call", "Mcp-Name", "list_scans"), 400, -32020},
		"no client capabilities":   {body("tools/list", noCaps, nil), hdr("Mcp-Protocol-Version", v, "Mcp-Method", "tools/list"), 400, -32602},
		"modern header, no _meta":  {rpcReq("tools/list", nil), hdr("Mcp-Protocol-Version", v, "Mcp-Method", "tools/list"), 400, -32602},
		"unknown method":           {body("resources/list", modernMeta(), nil), hdr("Mcp-Protocol-Version", v, "Mcp-Method", "resources/list"), 404, -32601},
		"initialize is not modern": {body("initialize", modernMeta(), nil), hdr("Mcp-Protocol-Version", v, "Mcp-Method", "initialize"), 404, -32601},
		"ping is not modern":       {body("ping", modernMeta(), nil), hdr("Mcp-Protocol-Version", v, "Mcp-Method", "ping"), 404, -32601},
	} {
		rec, rp := mcpPost(t, s, tok, tc.body, tc.h)
		if rec.Code != tc.status || rp.Error == nil || rp.Error.Code != tc.rc || string(rp.ID) != "7" {
			t.Errorf("%s: %d %s, want %d %d", name, rec.Code, rec.Body.String(), tc.status, tc.rc)
		}
		if tc.rc == -32022 && (!reflect.DeepEqual(rp.Error.Data["supported"], all) || rp.Error.Data["requested"] != "2030-01-01") {
			t.Errorf("%s: data %v", name, rp.Error.Data)
		}
	}
	// a Base64-wrapped Mcp-Name is decoded before it is compared
	rec, rp = mcpPost(t, s, tok, body("tools/call", modernMeta(), call),
		hdr("Mcp-Protocol-Version", v, "Mcp-Method", "tools/call", "Mcp-Name", "=?base64?cHJvamVjdF9zdW1tYXJ5?="))
	if rec.Code != 200 || rp.Result["isError"] == true || rp.Error != nil {
		t.Errorf("base64 Mcp-Name: %d %s", rec.Code, rec.Body.String())
	}
}

func TestMCPToolsList(t *testing.T) {
	s := testServer(t)
	_, tok := mkToken(t, s, "shop", "read")
	rec, rp := mcpOld(t, s, tok, "tools/list", nil)
	if rec.Code != 200 || rp.Error != nil || rp.Result["nextCursor"] != nil || rp.Result["resultType"] != nil {
		t.Fatalf("tools/list: %d %s", rec.Code, rec.Body.String())
	}
	type tool struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		InputSchema struct {
			Type       string `json:"type"`
			Properties map[string]struct {
				Type        string   `json:"type"`
				Description string   `json:"description"`
				Enum        []string `json:"enum"`
				Items       *struct {
					Type string   `json:"type"`
					Enum []string `json:"enum"`
				} `json:"items"`
			} `json:"properties"`
			Required             []string `json:"required"`
			AdditionalProperties *bool    `json:"additionalProperties"`
		} `json:"inputSchema"`
		Annotations map[string]any `json:"annotations"`
	}
	raw, _ := json.Marshal(rp.Result["tools"])
	var tools []tool
	if err := json.Unmarshal(raw, &tools); err != nil {
		t.Fatalf("tools do not fit the Tool shape: %v\n%s", err, raw)
	}
	var names []string
	for _, tl := range tools {
		names = append(names, tl.Name)
		sc := tl.InputSchema
		if len(tl.Description) < 40 || sc.Type != "object" || sc.AdditionalProperties == nil || *sc.AdditionalProperties ||
			tl.Annotations["readOnlyHint"] != true || tl.Annotations["openWorldHint"] != false {
			t.Errorf("%s: description, schema root or annotations: %+v", tl.Name, tl)
		}
		for arg, p := range sc.Properties {
			known := slices.Contains([]string{"string", "integer", "boolean", "array"}, p.Type)
			if !known || p.Description == "" || p.Type == "array" && (p.Items == nil || p.Items.Type != "string" || len(p.Items.Enum) == 0) {
				t.Errorf("%s.%s: %+v", tl.Name, arg, p)
			}
		}
		for _, r := range sc.Required {
			if _, ok := sc.Properties[r]; !ok {
				t.Errorf("%s: required %q is not a property", tl.Name, r)
			}
		}
		if strings.HasPrefix(tl.Name, "list_") {
			if sc.Properties["limit"].Type != "integer" {
				t.Errorf("%s: a list tool needs a limit", tl.Name)
			}
		}
	}
	if !slices.Equal(names, mcpToolNames) {
		t.Errorf("tools %v, want %v", names, mcpToolNames)
	}
}

func TestMCPTools(t *testing.T) {
	s := testServer(t)
	f := mcpSeed(t, s, "shop")
	tok := f.tok
	type counts struct{ Critical, High, Medium, Low, Unknown, Open int }

	sum := callTool[struct {
		Key, Name    string
		OpenFindings counts `json:"open_findings"`
		Targets      int
		LastScanAt   time.Time `json:"last_scan_at"`
		Policy       string
	}](t, s, tok, "project_summary", nil)
	if sum.Key != "shop" || sum.Name != "shop" || sum.OpenFindings != (counts{1, 1, 1, 0, 0, 3}) || sum.Targets != 2 ||
		time.Since(sum.LastScanAt) > time.Minute || !strings.Contains(sum.Policy, "CRITICAL") || strings.Contains(sum.Policy, "\n") {
		t.Errorf("project_summary: %+v", sum)
	}

	type row struct {
		ID               int64
		Severity         string
		RuleID           string `json:"rule_id"`
		Title, Package   string
		InstalledVersion string `json:"installed_version"`
		FixedVersion     string `json:"fixed_version"`
		Target, Status   string
		FirstSeen        time.Time `json:"first_seen"`
	}
	type page struct {
		Total      int
		Findings   []row
		NextCursor string `json:"next_cursor"`
	}
	rules := func(p page) string {
		var out []string
		for _, r := range p.Findings {
			out = append(out, r.RuleID)
		}
		return strings.Join(out, " ")
	}
	open := callTool[page](t, s, tok, "list_findings", nil)
	if open.Total != 3 || rules(open) != "CVE-2024-1111 CVE-2024-3333 DS002" || open.NextCursor != "" {
		t.Fatalf("list_findings: %+v", open)
	}
	if r := open.Findings[0]; r.ID == 0 || r.Severity != "CRITICAL" || r.Title != "heap overflow" || r.Package != "openssl" ||
		r.InstalledVersion != "1.0" || r.FixedVersion != "3.0.9" || r.Target != "shop-web" || r.Status != "open" || time.Since(r.FirstSeen) > time.Minute {
		t.Errorf("list_findings row: %+v", r)
	}
	for _, tc := range []struct {
		args map[string]any
		want string
	}{
		{map[string]any{"severity": []string{"HIGH", "CRITICAL"}}, "CVE-2024-1111 CVE-2024-3333"},
		{map[string]any{"status": "fixed"}, "CVE-2024-1111"},
		{map[string]any{"status": "accepted"}, "CVE-2024-2222"},
		{map[string]any{"status": "false_positive"}, ""},
		{map[string]any{"kind": "misconfig"}, "DS002"},
		{map[string]any{"target": "shop-api"}, "CVE-2024-3333 DS002"},
		{map[string]any{"query": "CURL"}, "CVE-2024-3333"},
		{map[string]any{"fixable": true}, "CVE-2024-1111 CVE-2024-3333"},
		{map[string]any{"fixable": false}, "DS002"},
		{map[string]any{"severity": []string{"MEDIUM"}, "kind": "vuln"}, ""},
	} {
		if p := callTool[page](t, s, tok, "list_findings", tc.args); rules(p) != tc.want || p.Total != len(p.Findings) || p.Findings == nil {
			t.Errorf("list_findings %v: %q (total %d), want %q", tc.args, rules(p), p.Total, tc.want)
		}
	}
	// the cursor walks the whole list, most severe first
	var walked []string
	for cur, n := "", 0; ; n++ {
		args := map[string]any{"limit": 2}
		if cur != "" {
			args["cursor"] = cur
		}
		p := callTool[page](t, s, tok, "list_findings", args)
		walked = append(walked, rules(p))
		if cur = p.NextCursor; cur == "" || n > 5 {
			break
		}
	}
	if got := strings.TrimSpace(strings.Join(walked, " ")); got != "CVE-2024-1111 CVE-2024-3333 DS002" {
		t.Errorf("cursor walk: %q", got)
	}
	// a cursor must not read as a number: a client that turned "1.10" into 1.1 would land elsewhere in the list
	if p := callTool[page](t, s, tok, "list_findings", map[string]any{"limit": 1}); json.Valid([]byte(p.NextCursor)) {
		t.Errorf("next_cursor %q is a JSON value on its own", p.NextCursor)
	}

	type exRef struct {
		ID                         int64
		Resolution, Status, Reason string
		ExpiresAt                  time.Time `json:"expires_at"`
	}
	type detail struct {
		row
		Kind, Tool, Location, Origin string
		LastSeen                     time.Time `json:"last_seen"`
		VulnerabilityID              string    `json:"vulnerability_id"`
		Exception                    *exRef
		Details                      map[string]any
	}
	acc := callTool[detail](t, s, tok, "get_finding", map[string]any{"id": findingID(t, s, f.pid, "CVE-2024-2222", "shop-api")})
	if acc.RuleID != "CVE-2024-2222" || acc.Kind != "vuln" || acc.Tool != "trivy" || acc.Origin != "scan" || acc.Status != "accepted" ||
		acc.VulnerabilityID != "CVE-2024-2222" || acc.Target != "shop-api" || acc.Package != "zlib" || acc.LastSeen.IsZero() ||
		acc.Exception == nil || acc.Exception.ID != f.exception || acc.Exception.Resolution != "accepted" || acc.Exception.Status != "approved" ||
		acc.Exception.Reason != "not reachable in shop" || acc.Exception.ExpiresAt.Before(time.Now()) {
		t.Errorf("get_finding (accepted): %+v", acc)
	}
	mis := callTool[detail](t, s, tok, "get_finding", map[string]any{"id": findingID(t, s, f.pid, "DS002", "shop-api")})
	if mis.Kind != "misconfig" || mis.Location != "Dockerfile" || mis.VulnerabilityID != "" || mis.Exception != nil || mis.Severity != "MEDIUM" {
		t.Errorf("get_finding (misconfig): %+v", mis)
	}

	type vuln struct {
		ID, Title, Description string
		Affected               []struct {
			FindingID                int64 `json:"finding_id"`
			Target, Severity, Status string
			FixedVersion             string `json:"fixed_version"`
		}
	}
	v := callTool[vuln](t, s, tok, "get_vulnerability", map[string]any{"id": "cve-2024-1111"})
	if v.ID != "CVE-2024-1111" || v.Title != "heap overflow" || v.Description != "A long description." || len(v.Affected) != 2 ||
		v.Affected[0].Target != "shop-api" || v.Affected[0].Status != "fixed" || v.Affected[1].Target != "shop-web" ||
		v.Affected[1].Status != "open" || v.Affected[1].FixedVersion != "3.0.9" || v.Affected[1].FindingID != open.Findings[0].ID {
		t.Errorf("get_vulnerability: %+v", v)
	}

	tg := callTool[struct {
		Total   int
		Targets []struct {
			Name, Kind string
			LastScanAt time.Time `json:"last_scan_at"`
			counts
		}
	}](t, s, tok, "list_targets", nil)
	if tg.Total != 2 || len(tg.Targets) != 2 || tg.Targets[0].Name != "shop-api" || tg.Targets[0].Kind != "image" ||
		tg.Targets[0].counts != (counts{0, 1, 1, 0, 0, 2}) || tg.Targets[1].Name != "shop-web" || tg.Targets[1].Kind != "repo" ||
		tg.Targets[1].counts != (counts{1, 0, 0, 0, 0, 1}) || tg.Targets[0].LastScanAt.IsZero() {
		t.Errorf("list_targets: %+v", tg)
	}
	if one := callTool[struct {
		Total   int
		Targets []any
	}](t, s, tok, "list_targets", map[string]any{"limit": 1}); one.Total != 2 || len(one.Targets) != 1 {
		t.Errorf("list_targets limit 1: %+v", one)
	}

	type scan struct {
		ID                          int64
		Target, Source, Status, Ref string
		CreatedAt                   time.Time `json:"created_at"`
		Summary                     *counts
		PolicyPassed                *bool    `json:"policy_passed"`
		PolicyReasons               []string `json:"policy_reasons"`
	}
	type scans struct {
		Scans      []scan
		NextCursor string `json:"next_cursor"`
	}
	sl := callTool[scans](t, s, tok, "list_scans", nil)
	if len(sl.Scans) != 3 || sl.Scans[0].ID != f.scan3 || sl.Scans[2].ID != f.scan1 || sl.NextCursor != "" {
		t.Fatalf("list_scans: %+v", sl)
	}
	first, second := sl.Scans[2], sl.Scans[1]
	if first.Target != "shop-api" || first.Source != "upload" || first.Status != "done" || first.Ref != "v1" || first.CreatedAt.IsZero() ||
		first.Summary == nil || *first.Summary != (counts{1, 0, 1, 1, 0, 3}) || first.PolicyPassed == nil || *first.PolicyPassed ||
		len(first.PolicyReasons) != 1 || !strings.Contains(first.PolicyReasons[0], "CRITICAL") {
		t.Errorf("list_scans first scan: %+v", first)
	}
	if second.PolicyPassed == nil || !*second.PolicyPassed || len(second.PolicyReasons) != 0 || second.Ref != "v2" {
		t.Errorf("list_scans second scan: %+v", second)
	}
	if p := callTool[scans](t, s, tok, "list_scans", map[string]any{"target": "shop-api"}); len(p.Scans) != 2 || p.Scans[0].ID != f.scan2 {
		t.Errorf("list_scans by target: %+v", p)
	}
	p1 := callTool[scans](t, s, tok, "list_scans", map[string]any{"limit": 2})
	p2 := callTool[scans](t, s, tok, "list_scans", map[string]any{"limit": 2, "cursor": p1.NextCursor})
	if len(p1.Scans) != 2 || p1.NextCursor == "" || json.Valid([]byte(p1.NextCursor)) || len(p2.Scans) != 1 || p2.Scans[0].ID != f.scan1 || p2.NextCursor != "" {
		t.Errorf("list_scans pages: %+v then %+v", p1, p2)
	}

	gs := callTool[struct {
		scan
		Format  string
		Compare struct {
			PreviousScanID        int64 `json:"previous_scan_id"`
			New, Fixed, Unchanged int
		} `json:"compared_to_previous"`
	}](t, s, tok, "get_scan", map[string]any{"id": f.scan2})
	if gs.ID != f.scan2 || gs.Target != "shop-api" || gs.Format != "trivy" || gs.Compare.PreviousScanID != f.scan1 ||
		gs.Compare.New != 1 || gs.Compare.Fixed != 1 || gs.Compare.Unchanged != 2 {
		t.Errorf("get_scan: %+v", gs)
	}

	type exList struct {
		Total      int
		Exceptions []struct {
			ID                                         int64
			Scope, Resolution, Status, Reason, Package string
			FindingID                                  int64     `json:"finding_id"`
			Rule                                       string    `json:"rule_id"`
			RequestedBy                                string    `json:"requested_by"`
			ExpiresAt                                  time.Time `json:"expires_at"`
		}
	}
	ex := callTool[exList](t, s, tok, "list_exceptions", nil)
	if ex.Total != 1 || len(ex.Exceptions) != 1 {
		t.Fatalf("list_exceptions: %+v", ex)
	}
	if e := ex.Exceptions[0]; e.ID != f.exception || e.Scope != "finding" || e.Resolution != "accepted" || e.Status != "approved" ||
		e.Reason != "not reachable in shop" || e.FindingID != acc.ID || e.Rule != "CVE-2024-2222" || e.Package != "zlib" ||
		e.RequestedBy != "req-shop" || e.ExpiresAt.Before(time.Now()) {
		t.Errorf("list_exceptions row: %+v", e)
	}
	if p := callTool[exList](t, s, tok, "list_exceptions", map[string]any{"status": "pending"}); p.Total != 0 || p.Exceptions == nil {
		t.Errorf("list_exceptions pending: %+v", p)
	}

	// search_packages: the latest inventory of each target, with the open findings of each package
	type pkgs struct {
		Total                   int
		TargetsSearched         int `json:"targets_searched"`
		TargetsWithoutInventory int `json:"targets_without_inventory"`
		Truncated               bool
		Packages                []struct {
			Name, Version, Ecosystem, Target string
			Paths                            []string
			OpenFindings                     int       `json:"open_findings"`
			WorstSeverity                    string    `json:"worst_severity"`
			VersionUnknown                   bool      `json:"version_unknown"`
			ScanID                           int64     `json:"scan_id"`
			ScannedAt                        time.Time `json:"scanned_at"`
		}
	}
	lib := callTool[pkgs](t, s, tok, "search_packages", map[string]any{"query": "LIB"})
	if lib.Total != 1 || len(lib.Packages) != 1 || lib.TargetsSearched != 2 || lib.TargetsWithoutInventory != 0 || lib.Truncated {
		t.Fatalf("search_packages LIB: %+v", lib)
	}
	// zlib's only finding is under an approved exception: nothing open
	if p := lib.Packages[0]; p.Name != "zlib" || p.Version != "1.0" || p.Ecosystem != "alpine" || p.Target != "shop-api" ||
		p.OpenFindings != 0 || p.WorstSeverity != "" || p.ScanID != f.scan2 || time.Since(p.ScannedAt) > time.Minute {
		t.Errorf("search_packages row: %+v", p)
	}
	if p := callTool[pkgs](t, s, tok, "search_packages", map[string]any{"query": "ssl", "version": "<2"}); len(p.Packages) != 1 ||
		p.Packages[0].Target != "shop-web" || p.Packages[0].OpenFindings != 1 || p.Packages[0].WorstSeverity != "CRITICAL" {
		t.Errorf("search_packages ssl <2: %+v", p)
	}
	if p := callTool[pkgs](t, s, tok, "search_packages", map[string]any{"query": "ssl", "version": ">=2"}); p.Total != 0 || p.Packages == nil {
		t.Errorf("search_packages ssl >=2: %+v", p)
	}
	sqlExec(t, s, `insert into packages(scan_id, name, version, ecosystem) values($1, 'lib-a', '1', 'npm'), ($1, 'lib-b', '1.x', 'npm')`, f.scan2)
	if p := callTool[pkgs](t, s, tok, "search_packages", map[string]any{"query": "lib", "limit": 2}); p.Total != 3 || len(p.Packages) != 2 || !p.Truncated {
		t.Errorf("search_packages limit: %+v", p)
	}
	if p := callTool[pkgs](t, s, tok, "search_packages", map[string]any{"query": "lib-", "version": "1"}); p.Total != 2 ||
		p.Packages[0].VersionUnknown || !p.Packages[1].VersionUnknown {
		t.Errorf("search_packages version_unknown: %+v", p)
	}

	// reads are not audited
	if n := qInt(t, s, `select count(*) from audit_log where action not in ('scan.upload')`); n != 0 {
		t.Errorf("%d audit rows after MCP reads", n)
	}
}

// A token of project A reads nothing of project B: B's ids answer exactly like ids that do not exist, lists hold
// only A's rows, and no answer mentions B.
func TestMCPIsolation(t *testing.T) {
	s := testServer(t)
	a, b := mcpSeed(t, s, "shop"), mcpSeed(t, s, "other")
	mustUpload(t, s, "other", "target=other-api&kind=image&scanners=vuln", trivyDoc("x", []tv{{ID: "CVE-2099-0001", Pkg: "other-only"}}, nil), b.tok)
	sqlExec(t, s, `insert into exceptions(scope, project_id, vuln_id, resolution, reason, status, expires_at)
		values('project_vuln', $1, 'CVE-2024-3333', 'false_positive', 'other says no', 'approved', now() + interval '9 days')`, b.pid)
	global := qint64(t, s, `insert into exceptions(scope, vuln_id, resolution, reason, status, expires_at)
		values('global_vuln', 'CVE-2024-7777', 'accepted', 'company-wide', 'approved', now() + interval '9 days') returning id`)

	const gone = "not found"
	for _, tc := range []struct {
		tool string
		args map[string]any
	}{
		{"get_finding", map[string]any{"id": findingID(t, s, b.pid, "CVE-2024-1111", "other-web")}},
		{"get_finding", map[string]any{"id": 99999999}},
		{"get_scan", map[string]any{"id": b.scan1}},
		{"get_scan", map[string]any{"id": 99999999}},
		{"get_vulnerability", map[string]any{"id": "CVE-2099-0001"}}, // in the catalog, but only B has it
		{"get_vulnerability", map[string]any{"id": "CVE-1999-0000"}}, // not in the catalog at all
		{"list_findings", map[string]any{"target": "other-api"}},
		{"list_scans", map[string]any{"target": "other-web"}},
	} {
		if msg := toolErr(t, s, a.tok, tc.tool, tc.args); !strings.Contains(strings.ToLower(msg), gone) {
			t.Errorf("%s %v: %q", tc.tool, tc.args, msg)
		}
	}
	// the two "no such vulnerability" answers differ only in the id, so the shared catalog cannot be probed
	m1 := toolErr(t, s, a.tok, "get_vulnerability", map[string]any{"id": "CVE-2099-0001"})
	m2 := toolErr(t, s, a.tok, "get_vulnerability", map[string]any{"id": "CVE-1999-0000"})
	if strings.ReplaceAll(m1, "CVE-2099-0001", "X") != strings.ReplaceAll(m2, "CVE-1999-0000", "X") {
		t.Errorf("catalog probe: %q vs %q", m1, m2)
	}

	var all strings.Builder
	for _, tc := range []struct {
		tool string
		args map[string]any
	}{
		{"project_summary", nil}, {"list_findings", map[string]any{"status": "open"}}, {"list_findings", map[string]any{"status": "fixed"}},
		{"list_findings", map[string]any{"status": "accepted"}}, {"list_findings", map[string]any{"query": "other"}},
		{"list_findings", map[string]any{"query": "CVE-2099"}}, {"get_vulnerability", map[string]any{"id": "CVE-2024-1111"}},
		{"get_vulnerability", map[string]any{"id": "CVE-2024-3333"}}, {"list_targets", nil}, {"list_scans", nil},
		{"get_scan", map[string]any{"id": a.scan2}}, {"list_exceptions", nil},
		{"search_packages", map[string]any{"query": "other"}}, {"search_packages", map[string]any{"query": "ssl"}},
	} {
		res, text := toolRaw(t, s, a.tok, tc.tool, tc.args)
		if res["isError"] == true {
			t.Errorf("%s %v: %s", tc.tool, tc.args, text)
		}
		all.WriteString(text + "\n")
	}
	for _, leak := range []string{"other", "CVE-2099-0001"} {
		if strings.Contains(all.String(), leak) {
			t.Errorf("project A's answers mention %q:\n%s", leak, all.String())
		}
	}
	// A sees its own exception and the company-wide one, which applies to its findings too
	ex := callTool[struct {
		Exceptions []struct {
			ID    int64
			Scope string
		}
	}](t, s, a.tok, "list_exceptions", nil)
	if len(ex.Exceptions) != 2 || ex.Exceptions[0].ID != global || ex.Exceptions[0].Scope != "global_vuln" || ex.Exceptions[1].ID != a.exception {
		t.Errorf("list_exceptions: %+v", ex)
	}
	if v := callTool[struct{ Affected []any }](t, s, a.tok, "get_vulnerability", map[string]any{"id": "CVE-2024-1111"}); len(v.Affected) != 2 {
		t.Errorf("get_vulnerability lists %d affected findings, want project A's 2", len(v.Affected))
	}
	// REST stays as closed to tokens as before: the handlers the tools share did not become token routes
	for _, p := range []string{"/api/v1/findings", "/api/v1/exceptions", "/api/v1/vulns/CVE-2024-1111", "/api/v1/findings/1", "/api/v1/scans/1"} {
		if rec := do(t, s, "GET", p, nil, a.tok); rec.Code != 403 {
			t.Errorf("GET %s with a token: %d", p, rec.Code)
		}
	}
}

func TestMCPAuth(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	pid, rd := mkToken(t, s, "shop", "read")
	_, up := mkToken(t, s, "shop", "upload")
	for name, when := range map[string]string{"expired": "expires_at = now() - interval '1 minute'", "revoked": "revoked_at = now()"} {
		sqlExec(t, s, `insert into api_tokens(project_id, name, prefix, token_hash, scopes, expires_at) values($1, $2, 'jsc_', $3, '{read}', now() + interval '1 day')`,
			pid, name, tokenHash("jsc_"+name))
		sqlExec(t, s, `update api_tokens set `+when+` where name = $1`, name)
	}
	ck := loginAs(t, s, mkUser(t, s, "root", "admin"))
	list := rpcReq("tools/list", nil)
	for name, tc := range map[string]struct {
		auth []any
		want int
	}{
		"no token":            {[]any{http.Header{}}, 401},
		"unknown token":       {[]any{"jsc_nope", http.Header{}}, 401},
		"not a jasca token":   {[]any{"abc", http.Header{}}, 401},
		"expired token":       {[]any{"jsc_expired", http.Header{}}, 401},
		"revoked token":       {[]any{"jsc_revoked", http.Header{}}, 401},
		"upload-only token":   {[]any{up, http.Header{}}, 403},
		"admin session":       {[]any{ck}, 401}, // a browser on the site: cookie and Sec-Fetch-Site: same-origin
		"session, no browser": {[]any{ck, http.Header{}}, 403},
		"session, other site": {[]any{ck, http.Header{"Origin": {"https://evil.example"}}}, 403},
		"token, other site":   {[]any{rd, http.Header{"Origin": {"https://evil.example"}}}, 403},
		"token, cross-site":   {[]any{rd, http.Header{"Origin": {"http://example.com"}, "Sec-Fetch-Site": {"cross-site"}}}, 403},
		"token, own origin":   {[]any{rd, http.Header{"Origin": {"http://example.com"}}}, 200},
		"token":               {[]any{rd, http.Header{}}, 200},
	} {
		rec := do(t, s, "POST", "/mcp", list, tc.auth...)
		if rec.Code != tc.want || (rec.Code == 401) != (rec.Header().Get("WWW-Authenticate") == "Bearer") {
			t.Errorf("%s: %d (WWW-Authenticate %q) %s, want %d", name, rec.Code, rec.Header().Get("WWW-Authenticate"), rec.Body.String(), tc.want)
		}
		if rec.Code != 200 && strings.Contains(rec.Body.String(), "project_summary") {
			t.Errorf("%s: refused but answered: %s", name, rec.Body.String())
		}
	}
	for _, m := range []string{"GET", "DELETE"} {
		for _, auth := range [][]any{{http.Header{}}, {rd, http.Header{}}} {
			if rec := do(t, s, m, "/mcp", nil, auth...); rec.Code != 405 || rec.Header().Get("Allow") != "POST" {
				t.Errorf("%s /mcp: %d Allow=%q %s", m, rec.Code, rec.Header().Get("Allow"), rec.Body.String())
			}
		}
	}

	// last_used_at moves as it does for REST
	sqlExec(t, s, `update api_tokens set last_used_at = now() - interval '2 hours' where token_hash = $1`, tokenHash(rd))
	mcpOld(t, s, rd, "ping", nil)
	var fresh bool
	if err := s.db.QueryRow(ctx, `select last_used_at > now() - interval '1 minute' from api_tokens where token_hash = $1`, tokenHash(rd)).Scan(&fresh); err != nil || !fresh {
		t.Errorf("last_used_at did not move (%v)", err)
	}
}

func TestMCPProtocolErrors(t *testing.T) {
	s := testServer(t)
	_, tok := mkToken(t, s, "shop", "read")
	for name, tc := range map[string]struct {
		body       any
		status, rc int
	}{
		"malformed JSON":     {`{"jsonrpc":"2.0","id":1,`, 400, -32700},
		"not an object":      {`"hello"`, 400, -32600},
		"batch":              {`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`, 400, -32600},
		"no jsonrpc version": {`{"id":1,"method":"ping"}`, 400, -32600},
		"null id":            {`{"jsonrpc":"2.0","id":null,"method":"ping"}`, 400, -32600},
		"object id":          {`{"jsonrpc":"2.0","id":{},"method":"ping"}`, 400, -32600},
		"a response":         {`{"jsonrpc":"2.0","id":1,"result":{}}`, 400, -32600},
		"unknown method":     {rpcReq("resources/list", nil), 200, -32601},
		"discover, no _meta": {rpcReq("server/discover", nil), 200, -32601},
		"unknown tool":       {rpcReq("tools/call", map[string]any{"name": "drop_database", "arguments": map[string]any{}}), 200, -32602},
		"tool without name":  {rpcReq("tools/call", map[string]any{"arguments": map[string]any{}}), 200, -32602},
		"params not object":  {rpcReq("tools/call", []int{1}), 200, -32602},
	} {
		rec, rp := mcpPost(t, s, tok, tc.body, nil)
		if rec.Code != tc.status || rp.Error == nil || rp.Error.Code != tc.rc || rp.Error.Message == "" || rp.JSONRPC != "2.0" || rp.Result != nil {
			t.Errorf("%s: %d %s, want %d %d", name, rec.Code, rec.Body.String(), tc.status, tc.rc)
		}
	}
	if _, rp := mcpPost(t, s, tok, rpcReq("tools/call", map[string]any{"name": "drop_database"}), nil); !strings.Contains(rp.Error.Message, "drop_database") {
		t.Errorf("unknown tool message: %+v", rp.Error)
	}

	// bad arguments are for the model to fix: a tool result with isError, in English, naming the argument
	for _, tc := range []struct {
		tool string
		args map[string]any
		want string
	}{
		{"list_findings", map[string]any{"limit": 0}, "limit"},
		{"list_findings", map[string]any{"limit": 201}, "limit"},
		{"list_findings", map[string]any{"limit": "ten"}, "limit"},
		{"list_findings", map[string]any{"severity": []string{"SEVERE"}}, "severity"},
		{"list_findings", map[string]any{"severity": "HIGH"}, "severity"},
		{"list_findings", map[string]any{"status": "closed"}, "status"},
		{"list_findings", map[string]any{"kind": "license"}, "kind"},
		{"list_findings", map[string]any{"project": "other"}, "project"},
		{"list_findings", map[string]any{"cursor": "zzz"}, "cursor"},
		{"list_findings", map[string]any{"query": strings.Repeat("a", 201)}, "query"},
		{"get_finding", nil, "id"},
		{"get_finding", map[string]any{"id": "12"}, "id"},
		{"get_scan", map[string]any{"id": -1}, "id"},
		{"get_vulnerability", map[string]any{"id": ""}, "id"},
		{"list_scans", map[string]any{"cursor": "abc"}, "cursor"},
		{"list_scans", map[string]any{"cursor": "cx"}, "before"}, // the REST handler's own check, passed on
		{"list_scans", map[string]any{"cursor": 3}, "cursor"},
		{"list_exceptions", map[string]any{"status": "open"}, "status"},
		{"search_packages", nil, "query"},
		{"search_packages", map[string]any{"query": "a"}, "query"},
		{"search_packages", map[string]any{"query": "zlib", "version": "<"}, "version"},
		{"search_packages", map[string]any{"query": "zlib", "limit": 1001}, "limit"},
		{"search_packages", map[string]any{"query": "zlib", "ecosystem": "npm"}, "ecosystem"},
		{"list_targets", map[string]any{"limit": 501}, "limit"},
		{"project_summary", map[string]any{"verbose": true}, "verbose"},
	} {
		if msg := toolErr(t, s, tok, tc.tool, tc.args); !strings.Contains(msg, tc.want) {
			t.Errorf("%s %v: %q does not name %q", tc.tool, tc.args, msg, tc.want)
		}
	}

	// the request body limit
	big := `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"` + strings.Repeat("x", 70<<10) + `"}}`
	if rec, _ := mcpPost(t, s, tok, big, nil); rec.Code != 413 {
		t.Errorf("70KB body: %d %s", rec.Code, rec.Body.String())
	}

	// one token cannot hammer the server
	s.mcpLimiter = newLimiter(3, time.Minute)
	_, tok2 := mkToken(t, s, "bulk", "read")
	for i := range 5 {
		rec, _ := mcpOld(t, s, tok, "ping", nil)
		if want := map[bool]int{true: 200, false: 429}[i < 3]; rec.Code != want || (want == 429) != (rec.Header().Get("Retry-After") != "") {
			t.Errorf("request %d: %d Retry-After=%q", i+1, rec.Code, rec.Header().Get("Retry-After"))
		}
	}
	if rec, _ := mcpOld(t, s, tok2, "ping", nil); rec.Code != 200 {
		t.Errorf("another token is limited too: %d", rec.Code)
	}
}
