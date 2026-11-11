// MCP over real HTTP: the settings section says where to connect, then a read token does what an agent does
// (handshake, tools/list, tools/call) in both protocol eras. Runs after ingest: it looks up a finding ingest uploaded.
const L = require("./lib.cjs");
L.run(async () => {
  const browser = await L.launch();
  const kim = await L.sso(browser, "kim");
  const page = kim.page;
  const key = "e2e-proj";

  // project settings: endpoint, client config, tool list
  await page.goto(`${L.BASE}/projects/${key}/settings`);
  const sec = page.locator("#mcp");
  await sec.getByRole("heading", { name: "MCP 연동" }).waitFor();
  const url = (await sec.locator(".secret-box code").innerText()).trim();
  L.ok(url === L.BASE + "/mcp", `settings show the MCP endpoint (${url})`);
  const server = JSON.parse(await sec.locator("pre").innerText()).mcpServers[`jasca-${key}`];
  L.ok(server.type === "http" && server.url === url && server.headers.Authorization === "Bearer <토큰>", "client config names the project, the endpoint and the token header");
  const shown = await sec.getByRole("table", { name: "MCP 도구" }).locator("tbody tr td:first-child").allInnerTexts();
  await sec.getByRole("link", { name: "API 토큰" }).click();
  L.ok(new URL(page.url()).hash === "#tokens", "the token link goes to the API token section");
  await L.shot(page, "mcp-settings");

  const token = (await kim.api.post(`/projects/${key}/tokens`, { name: "mcp-e2e", scopes: ["read"], expires_at: new Date(Date.now() + 864e5).toISOString() })).token;
  const post = async (body, headers = {}, tok = token) => {
    const r = await fetch(url, { method: "POST", body: JSON.stringify(body),
      headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", ...(tok ? { Authorization: "Bearer " + tok } : {}), ...headers } });
    const text = await r.text();
    return { status: r.status, type: r.headers.get("content-type") || "", challenge: r.headers.get("www-authenticate"), body: text ? JSON.parse(text) : null };
  };
  let id = 0;
  const req = (method, params) => ({ jsonrpc: "2.0", id: ++id, method, ...(params ? { params } : {}) });

  // who may not connect
  const anon = await post(req("tools/list"), {}, null);
  L.ok(anon.status === 401 && anon.challenge === "Bearer", "no token: 401 with WWW-Authenticate: Bearer");
  L.ok((await post(req("tools/list"), {}, L.state().token)).status === 403, "the upload-only CI token is refused (403)");
  L.ok((await fetch(url, { headers: { Authorization: "Bearer " + token } })).status === 405, "GET /mcp answers 405 (no SSE stream)");

  // handshake era (2025-11-25): initialize, initialized, then requests that carry the version header
  const old = { "MCP-Protocol-Version": "2025-11-25" };
  const init = await post(req("initialize", { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "jasca-e2e", version: "1" } }));
  L.ok(init.status === 200 && init.type.startsWith("application/json") && init.body.result.protocolVersion === "2025-11-25" &&
    init.body.result.serverInfo.name === "jasca" && JSON.stringify(init.body.result.capabilities) === '{"tools":{}}', "initialize negotiates 2025-11-25, tools only");
  L.ok((await post({ jsonrpc: "2.0", method: "notifications/initialized" }, old)).status === 202, "notifications/initialized: 202");
  const tools = (await post(req("tools/list"), old)).body.result.tools;
  L.ok(tools.length === 9 && tools.every((t) => t.annotations.readOnlyHint === true && t.inputSchema.type === "object"), "tools/list: 9 read-only tools with object schemas");
  L.ok(JSON.stringify(tools.map((t) => t.name)) === JSON.stringify(shown), "the settings page lists exactly the server's tools, in order");
  const call = async (name, args, headers = old, meta) => {
    const r = await post(req("tools/call", { name, arguments: args, ...(meta ? { _meta: meta } : {}) }), headers);
    if (r.status !== 200 || !r.body.result) throw new Error(`${name}: ${r.status} ${JSON.stringify(r.body)}`);
    return { ...r.body.result, data: r.body.result.isError ? null : JSON.parse(r.body.result.content[0].text) };
  };
  const sum = await call("project_summary", {});
  L.ok(sum.data.key === key && sum.data.targets >= 2 && sum.data.open_findings.open > 0 && JSON.stringify(sum.structuredContent) === JSON.stringify(sum.data),
    `project_summary: ${sum.data.open_findings.open} open findings on ${sum.data.targets} targets`);
  const found = await call("list_findings", { query: "CVE-2022-37434", status: "open" });
  const hit = found.data.findings.find((f) => f.rule_id === "CVE-2022-37434" && f.target === "alpine-app");
  L.ok(found.data.total >= 1 && !!hit, "list_findings finds the uploaded CVE-2022-37434 on alpine-app");
  const one = await call("get_finding", { id: hit.id });
  L.ok(one.data.vulnerability_id === "CVE-2022-37434" && one.data.kind === "vuln", "get_finding gives the details");
  const pkgs = await call("search_packages", { query: "ZLIB", version: "<99" });
  L.ok(pkgs.data.total >= 1 && pkgs.data.packages.some((p) => p.name === "zlib" && p.target === "alpine-app" && p.open_findings >= 1 && p.worst_severity),
    "search_packages finds zlib in alpine-app's inventory with its open findings");
  const miss = await call("get_finding", { id: 99999999 });
  L.ok(miss.isError === true && /not found/.test(miss.content[0].text), "an unknown id is a tool error the model can read");

  // 2026-07-28: no handshake, the version travels in _meta and in the headers
  const meta = { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientInfo": { name: "jasca-e2e", version: "1" },
    "io.modelcontextprotocol/clientCapabilities": {} };
  const disc = await post(req("server/discover", { _meta: meta }), { "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "server/discover" });
  L.ok(disc.status === 200 && disc.body.result.resultType === "complete" && disc.body.result.supportedVersions.includes("2026-07-28") &&
    disc.body.result.supportedVersions.includes("2025-11-25"), "server/discover lists both protocol eras");
  const vuln = await call("get_vulnerability", { id: "CVE-2022-37434" },
    { "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "get_vulnerability" }, meta);
  L.ok(vuln.resultType === "complete" && vuln.data.affected.some((a) => a.target === "alpine-app"), "2026-07-28 tools/call: get_vulnerability lists the affected target");
  const bad = await post(req("tools/list", { _meta: { ...meta, "io.modelcontextprotocol/protocolVersion": "2030-01-01" } }),
    { "MCP-Protocol-Version": "2030-01-01", "Mcp-Method": "tools/list" });
  L.ok(bad.status === 400 && bad.body.error.code === -32022 && bad.body.error.data.supported.length > 0, "an unknown protocol version is refused with the supported list");

  // the token list shows the token was used
  const used = (await kim.api.get(`/projects/${key}/tokens`)).find((t) => t.name === "mcp-e2e");
  L.ok(!!used.last_used_at, "the token's last use is recorded");
  await browser.close();
});
