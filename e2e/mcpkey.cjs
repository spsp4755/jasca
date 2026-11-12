// Personal MCP keys over real HTTP: a person issues a key on the MCP 키 page (shown once), and an agent with that key
// is that person: lee (a project member) works on a project, kim (security) decides lee's exception request, the
// administrator reads the service's status and cuts a key off. Runs after projects and ingest (lee is in e2e-proj).
const L = require("./lib.cjs");
L.run(async () => {
  const browser = await L.launch();
  const lee = await L.sso(browser, "lee");
  const page = lee.page;
  const url = L.BASE + "/mcp";

  // the page: reached from the user menu, a key is made in the dialog and its value is shown once, with the client config
  await page.locator(".usermenu-btn").click();
  await page.getByRole("link", { name: "MCP 키" }).click();
  await page.waitForURL(/\/account\/mcp$/);
  await page.getByRole("heading", { name: "MCP 키", level: 1 }).waitFor();
  const shownTools = async () => {
    const rows = page.getByRole("table", { name: "MCP 도구" }).locator("tbody tr");
    await rows.first().waitFor();
    return rows.evaluateAll((trs) => trs.map((tr) => ({ name: tr.cells[0].innerText.trim(), off: /전용/.test(tr.cells[3].innerText) })));
  };
  const leeTools = await shownTools();
  L.ok(leeTools.some((t) => t.name === "system_status" && t.off) && leeTools.some((t) => t.name === "create_project" && !t.off),
    "the page lists every tool and marks the ones above lee's role");
  await page.getByRole("button", { name: "키 만들기" }).first().click();
  const dlg = page.getByRole("dialog", { name: "MCP 키 만들기" });
  await dlg.getByLabel("이름").fill("e2e 에이전트");
  await dlg.getByRole("button", { name: "만들기", exact: true }).click();
  const made = page.getByRole("dialog", { name: "키를 만들었습니다" });
  const key = (await made.locator(".secret-box code").innerText()).trim();
  L.ok(/^jsu_[A-Za-z0-9_-]{40,}$/.test(key), "the new key is shown in the dialog");
  const conf = JSON.parse(await made.locator("pre").innerText()).mcpServers.jasca;
  L.ok(conf.type === "http" && conf.url === url && conf.headers.Authorization === "Bearer " + key, "the dialog gives the client config with the key filled in");
  await L.shot(page, "mcpkey-created");
  await made.getByRole("button", { name: "복사했습니다, 닫기" }).click();
  await page.getByRole("table", { name: "내 MCP 키" }).getByText("e2e 에이전트").waitFor();
  L.ok(!(await page.content()).includes(key), "after closing, the key is nowhere on the page");
  await page.reload();
  await page.getByRole("table", { name: "내 MCP 키" }).getByText("e2e 에이전트").waitFor();
  const listed = await lee.api.get("/me/mcp-keys");
  L.ok(listed.length === 1 && !JSON.stringify(listed).includes(key) && listed[0].prefix === key.slice(0, 12), "the key list carries the prefix only");
  await L.shot(page, "mcpkey-page");

  // an agent with a key
  let id = 0;
  const rpc = async (k, method, params) => {
    const r = await fetch(url, { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method, ...(params ? { params } : {}) }),
      headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", Authorization: "Bearer " + k, "MCP-Protocol-Version": "2025-11-25" } });
    const text = await r.text();
    return { status: r.status, body: text ? JSON.parse(text) : null };
  };
  const call = async (k, name, args = {}) => {
    const r = await rpc(k, "tools/call", { name, arguments: args });
    if (r.status !== 200 || !r.body.result) throw new Error(`${name}: ${r.status} ${JSON.stringify(r.body)}`);
    const res = r.body.result;
    return { error: res.isError ? res.content[0].text : "", data: res.isError ? null : JSON.parse(res.content[0].text) };
  };
  const init = await rpc(key, "initialize", { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "jasca-e2e", version: "1" } });
  L.ok(init.status === 200 && init.body.result.serverInfo.name === "jasca" && /whoami/.test(init.body.result.instructions), "initialize with a personal key");
  const tools = (await rpc(key, "tools/list")).body.result.tools.map((t) => t.name);
  L.ok(JSON.stringify(tools) === JSON.stringify(leeTools.filter((t) => !t.off).map((t) => t.name)), `tools/list gives lee exactly the ${tools.length} tools the page says`);
  const who = await call(key, "whoami");
  L.ok(who.data.username === "lee" && who.data.role === "user" && who.data.key_name === "e2e 에이전트" && who.data.departments.length > 0, "whoami: lee, a user, with the department");
  const projects = (await call(key, "list_projects")).data.projects;
  L.ok(projects.some((p) => p.key === "e2e-proj" && p.my_role === "member"), "list_projects shows the project lee's department is a member of");
  L.ok((await call(key, "project_summary", { project: "e2e-nope" })).error.includes("not found"), "a project lee cannot see is not found");

  // the key is nobody in the REST API, except for uploads
  const rest = await fetch(L.BASE + "/api/v1/projects", { headers: { Authorization: "Bearer " + key } });
  L.ok(rest.status === 403, "the key is refused by the REST API (403)");

  // lee's agent creates a project and works in it
  const made2 = await call(key, "create_project", { key: "e2e-mcpkey", name: "MCP 키 E2E", description: "에이전트가 만든 프로젝트" });
  L.ok(made2.data.key === "e2e-mcpkey" && made2.data.my_role === "owner", "create_project: lee owns the new project");
  const up = await L.ingest("e2e-mcpkey", key, L.fixture("trivy/image-alpine.json"), "?target=alpine-app&kind=image&ref=1.0&scanners=vuln");
  L.ok(up.status === 201 && up.body.scan_id > 0, "the key uploads a report over REST, as the upload command does");
  const small = await call(key, "upload_report", { project: "e2e-mcpkey", report: L.fixture("trivy/image-debian.json").toString(), target: "debian-app", kind: "image", ref: "2.0" });
  L.ok(small.data.scan_id > 0 && small.data.open_findings.open > 0, `upload_report: scan ${small.data.scan_id} with ${small.data.open_findings.open} open findings`);
  const cmds = (await call(key, "upload_commands", { project: "e2e-mcpkey" })).data;
  L.ok(cmds.scan_source_archive.includes(`${L.BASE}/api/v1/projects/e2e-mcpkey/scan-jobs`) && cmds.upload_report.includes("&kind=") && !JSON.stringify(cmds).includes(key),
    "upload_commands gives runnable commands with this site's address and without the key");
  const sum = (await call(key, "project_summary", { project: "e2e-mcpkey" })).data;
  L.ok(sum.targets === 2 && sum.my_role === "owner" && sum.open_findings.open > 0, `project_summary: ${sum.open_findings.open} open findings on 2 targets`);
  const first = (await call(key, "list_findings", { project: "e2e-mcpkey", limit: 2 })).data.findings;
  const mine = await call(key, "update_finding", { id: first[0].id, assignee: "me", due_date: "2031-03-31" });
  L.ok(mine.data.assignee && mine.data.due_at.startsWith("2031-03-31T14:59:59"), "update_finding: assigned to lee, due at the end of the day in the server's zone");
  L.ok((await call(key, "list_findings", { assignee: "me" })).data.findings.some((f) => f.id === first[0].id && f.project === "e2e-mcpkey"),
    "list_findings assignee me, across projects, names the project");
  const day = new Date(Date.now() + 30 * 864e5).toISOString().slice(0, 10);
  const asked = await call(key, "request_exception", { finding_ids: [first[1].id], resolution: "accepted", reason: "E2E: 외부에 노출되지 않는 이미지", expires_on: day });
  L.ok(asked.data.requested.length === 1 && asked.data.requested[0].status === "pending", "request_exception: pending");
  const exId = asked.data.requested[0].id;
  L.ok(/security or administrator/.test((await call(key, "decide_exception", { id: exId, decision: "approve" })).error), "lee's agent cannot decide: the tool says which role it needs");
  L.ok(/administrator role/.test((await call(key, "system_status")).error), "lee's agent has no administrator tools");
  const team = await call(key, "set_member", { project: "e2e-mcpkey", user: "park", role: "viewer" });
  L.ok(!team.error && team.data.members.some((m) => m.user === "park" && m.role === "viewer") && (await lee.api.get("/projects/e2e-mcpkey/members")).length === 2,
    "set_member added park as a viewer" + (team.error ? ": " + team.error : ""));

  // kim (security): a read-only key reads, a full key decides
  const kim = await L.sso(browser, "kim");
  const exp = new Date(Date.now() + 864e5).toISOString();
  const kimRO = (await kim.api.post("/me/mcp-keys", { name: "e2e-ro", read_only: true, expires_at: exp })).key;
  const kimKey = (await kim.api.post("/me/mcp-keys", { name: "e2e-sec", read_only: false, expires_at: exp })).key;
  const roTools = (await rpc(kimRO, "tools/list")).body.result.tools;
  L.ok(roTools.length > 10 && roTools.every((t) => t.annotations.readOnlyHint === true), `a read-only key lists ${roTools.length} tools, all read-only`);
  L.ok(/read-only/.test((await call(kimRO, "decide_exception", { id: exId, decision: "approve" })).error), "a read-only key cannot approve");
  L.ok((await call(kimRO, "list_exceptions", { project: "e2e-mcpkey", status: "pending" })).data.total === 1, "…but it sees the pending request (security sees every project)");
  const decided = await call(kimKey, "decide_exception", { id: exId, decision: "approve", note: "E2E 승인" });
  L.ok(decided.data.status === "approved", "kim's agent approves the request");
  L.ok((await call(key, "get_finding", { id: first[1].id })).data.status === "accepted", "the finding is accepted now");

  // the audit log has it all under the person, marked as done through a key
  const audit = (await lee.api.get("/audit?project=e2e-mcpkey")).items;
  L.ok(audit.some((e) => e.action === "project.create" && e.actor === "lee" && e.details.mcp_key === "e2e 에이전트") &&
    audit.some((e) => e.action === "exception.approve" && e.actor === "kim" && e.details.mcp_key === "e2e-sec"), "the audit log names the person and the key");

  // the administrator: status, logs, everyone's keys; revoking lee's key stops lee's agent at once
  const admin = await L.local(browser);
  const adminKey = (await admin.api.post("/me/mcp-keys", { name: "e2e-admin", read_only: false, expires_at: exp })).key;
  const st = (await call(adminKey, "system_status")).data;
  L.ok(st.version && st.database.server_version && Array.isArray(st.problems) && st.totals.live_mcp_keys >= 4 && st.keycloak.sso_enabled === true,
    `system_status: ${st.version}, PostgreSQL ${st.database.server_version}, ${st.problems.length} problems`);
  const logs = (await call(adminKey, "get_server_logs", { query: "listening" })).data;
  L.ok(logs.lines.some((l) => /listening on/.test(l)), "get_server_logs finds the start-up line");
  L.ok(!JSON.stringify((await call(adminKey, "get_settings")).data).includes(L.KC_CLIENT_SECRET), "get_settings carries no secret");
  const keys = (await call(adminKey, "list_mcp_keys", { user: "lee" })).data.keys;
  L.ok(keys.length === 1 && keys[0].name === "e2e 에이전트" && keys[0].state === "live", "list_mcp_keys shows lee's key");
  await admin.page.goto(L.BASE + "/admin/users");
  const row = admin.page.getByRole("table", { name: "전체 사용자의 MCP 키" }).locator("tbody tr", { hasText: "e2e 에이전트" });
  await row.waitFor();
  await L.shot(admin.page, "mcpkey-admin");
  admin.page.once("dialog", (d) => d.accept());
  await row.getByRole("button", { name: "폐기" }).click();
  await row.getByText("폐기됨").waitFor();
  L.ok((await rpc(key, "tools/list")).status === 401, "the key the administrator revoked is refused (401)");
  await admin.page.goto(L.BASE + "/admin/audit");
  await admin.page.getByRole("table", { name: "감사 로그" }).locator("tbody tr", { hasText: "MCP" }).first().waitFor();
  L.ok(await admin.page.getByRole("table", { name: "감사 로그" }).locator("tbody tr", { hasText: "MCP 키 폐기" }).count() >= 1, "the audit screen shows the revoke and marks agent actions");

  // lee revokes nothing of others, and a deleted key list entry stays as 폐기됨 on lee's page
  await page.reload();
  await page.getByRole("table", { name: "내 MCP 키" }).getByText("폐기됨").waitFor();
  await call(adminKey, "revoke_mcp_key", { id: (await call(adminKey, "list_mcp_keys", { user: "kim" })).data.keys.find((k) => k.name === "e2e-ro").id });
  L.ok((await rpc(kimRO, "tools/list")).status === 401, "revoke_mcp_key through MCP stops kim's read-only key");
  await browser.close();
});
