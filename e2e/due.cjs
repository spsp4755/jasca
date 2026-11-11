// Deadlines and assignees: the admin sets the days per severity, lee (member through the department) takes a finding,
// puts a missed deadline on record and hands it back to the policy, assigns the rest in bulk; park (viewer) only reads.
// Overdue shows on the list, the project, the home page, the CSV and MCP.
const L = require("./lib.cjs");
const DEFAULT = { enabled: true, days: { CRITICAL: 7, HIGH: 30, MEDIUM: 90, LOW: 180 } };
const DAY = 864e5;
L.run(async () => {
  const browser = await L.launch();
  const admin = await L.local(browser);
  const lee = await L.sso(browser, "lee");
  const park = await L.sso(browser, "park");
  const { key, token } = await L.project(admin.api, "e2e-due", "E2E Due");
  const dept = (await admin.api.get("/principals?q=" + encodeURIComponent("개발본부/플랫폼팀"))).find((p) => p.kind === "group").principal;
  const [adminMe, leeMe, parkMe] = [await admin.api.get("/me"), await lee.api.get("/me"), await park.api.get("/me")];
  const [leeName, parkName] = [leeMe.name || leeMe.username, parkMe.name || parkMe.username]; // what the screens show
  await admin.api.put(`/projects/${key}/members`, [{ principal_kind: "user", principal: String(adminMe.id), role: "owner" },
    { principal_kind: "group", principal: dept, role: "member" }, { principal_kind: "user", principal: String(parkMe.id), role: "viewer" }]);
  await admin.api.put("/admin/sla", DEFAULT); // whatever an earlier run left
  L.ok((await L.ingest(key, token, L.fixture("trivy/image-alpine.json"), "?target=alpine-app&kind=image&ref=1.0")).status < 300 &&
    (await L.ingest(key, token, L.fixture("trivy/fs-mixed.json"), "?target=mixed&kind=fs")).status < 300, "two reports uploaded");
  const CVE = "CVE-2022-37434"; // CRITICAL
  const find = async (api = lee.api) => (await api.get(`/findings?project=${key}&limit=200`)).items.find((i) => i.rule_id === CVE);
  const daysOf = (f) => (new Date(f.due_at) - new Date(f.first_seen_at)) / DAY;

  // a new finding has the default deadline without anyone saving a setting
  let f = await find();
  L.ok(f.due_at && Math.abs(daysOf(f) - 7) < 0.01 && f.due_manual === false && f.assignee === null, "a new CRITICAL finding is due 7 days after it was found, with nobody assigned");
  L.ok((await lee.api("GET", "/admin/sla")).status === 403, "the deadline setting is the admin's (403 for a member)");

  // 관리 → 기본 정책 → 조치 기한: a bad value cannot be saved, a good one asks first and tells how many deadlines moved
  const ap = admin.page;
  await ap.goto(`${L.BASE}/admin/default-policy`);
  const panel = ap.locator("section.panel").filter({ has: ap.getByRole("heading", { name: "조치 기한", exact: true }) });
  await panel.getByLabel("CRITICAL 기한(일)").fill("0");
  L.ok(await panel.getByRole("button", { name: "조치 기한 저장" }).isDisabled() && (await panel.getByRole("alert").innerText()).includes("1일부터 3650일"), "0 days is refused on the screen");
  await panel.getByLabel("CRITICAL 기한(일)").fill("3");
  await panel.locator(".due-days-row").filter({ hasText: "LOW" }).getByLabel("기한 없음").check();
  let asked = "";
  ap.once("dialog", (d) => { asked = d.message(); d.accept(); });
  await panel.getByRole("button", { name: "조치 기한 저장" }).click();
  const saved = ap.locator(".toast").filter({ hasText: "조치 기한을 저장했습니다" });
  await saved.waitFor();
  L.ok(asked.includes("다시 계산") && /\d+건의 기한이 바뀌었습니다/.test(await saved.innerText()), "saving asks first and says how many deadlines changed");
  f = await find();
  L.ok(Math.abs(daysOf(f) - 3) < 0.01, "the open finding follows the new days (3)");
  const low = (await lee.api.get(`/findings?project=${key}&severity=LOW&limit=5`)).items;
  L.ok(low.length > 0 && low.every((i) => i.due_at === null), "a severity set to 기한 없음 has no deadline");

  // lee: the list says the deadline in words, the drawer says where it comes from
  const lp = lee.page;
  await lp.goto(`${L.BASE}/projects/${key}`);
  const table = lp.getByRole("table", { name: "결과 목록" });
  const row = table.getByRole("row", { name: new RegExp(CVE) });
  const only = () => lp.waitForFunction((cve) => { const r = document.querySelectorAll("main table tbody tr"); return r.length === 1 && r[0].textContent.includes(cve); }, CVE); // the list is down to that one row
  await row.waitFor();
  L.ok(/^(2|3)일 남음$/.test(await row.locator(".deadline").innerText()), "the list reads the deadline as N일 남음: " + await row.locator(".deadline").innerText());
  L.ok(await table.getByRole("columnheader", { name: "담당자" }).count() === 1 && await table.getByRole("columnheader", { name: "기한" }).count() === 1, "담당자 and 기한 columns");
  await row.locator(".pkg-name").click();
  const drawer = lp.getByRole("dialog");
  const triage = drawer.getByRole("region", { name: "담당자와 기한" });
  await triage.getByText("정책: CRITICAL 3일").waitFor();
  L.ok(await lp.evaluate(() => document.activeElement?.tagName) === "DIALOG", "the drawer opens with focus on itself, not on a button that changes something");
  await triage.getByRole("button", { name: "나에게" }).click();
  await triage.locator(".assignee").filter({ hasText: leeName }).waitFor();
  L.ok(await triage.getByRole("button", { name: "지정 해제" }).count() === 1 && await triage.getByRole("button", { name: "나에게" }).count() === 0, "나에게: lee is the assignee, 지정 해제 is offered");

  // a deadline missed two days ago, put on record by hand (the date is a day in the server's display zone)
  const tz = (await lee.api.get("/auth/config")).tz || "Asia/Seoul";
  const dayIn = (ms) => new Intl.DateTimeFormat("en-CA", { timeZone: tz }).format(new Date(ms)); // YYYY-MM-DD
  await triage.getByLabel("기한 날짜").fill(dayIn(Date.now() - 2 * DAY));
  await triage.getByRole("button", { name: "기한 저장" }).click();
  await triage.getByText("직접 정함").waitFor();
  L.ok(await triage.locator(".deadline").innerText() === "2일 지남" && (await drawer.locator(".drawer-todo").innerText()).includes("조치 기한이 2일 지났습니다"),
    "a past date reads 2일 지남 and the 할 일 sentence says so");
  f = await find();
  L.ok(f.due_manual === true && dayIn(new Date(f.due_at).getTime()) === dayIn(Date.now() - 2 * DAY) && f.assignee?.id === leeMe.id, "the API has the manual deadline (end of that day) and the assignee");
  await L.shot(lp, "due-drawer-overdue");
  await lp.keyboard.press("Escape");
  await row.locator(".deadline-over").waitFor();
  L.ok((await row.innerText()).includes(leeName) && await row.locator(".deadline-over svg").count() === 1, "the row shows the assignee and the overdue deadline with an icon, not colour alone");

  // overdue is counted where the open counts are, and each number opens its list
  await lp.goto(`${L.BASE}/projects/${key}`);
  const chip = lp.locator(".counts-strip").getByRole("link", { name: /기한 지남/ });
  await chip.waitFor();
  L.ok(/기한 지남\s*1$/.test((await chip.innerText()).replace(/\s+/g, " ").trim()), "the project header counts 1 overdue");
  await chip.click();
  await only();
  L.ok(new URL(lp.url()).searchParams.get("due") === "overdue", "the chip opens the list filtered to the one overdue finding");
  await lp.goto(`${L.BASE}/`);
  const mine = lp.locator(".risk-mine");
  await mine.getByRole("link").first().waitFor();
  L.ok(/내 담당\s*\d+건 · 기한 지남 \d+건/.test((await mine.innerText()).replace(/\s+/g, " ")), "home 내 담당 counts my findings and the overdue ones: " + (await mine.innerText()).replace(/\s+/g, " "));
  const mineRow = table.getByRole("row", { name: new RegExp(`${CVE}.* ${key} `) }); // in a list of every project
  await lp.locator(".risk-late a").first().click();
  await mineRow.waitFor();
  L.ok(new URL(lp.url()).searchParams.get("due") === "overdue", "home 기한 지남 opens the overdue list");
  await lp.goto(`${L.BASE}/`);
  await lp.locator(".risk-mine").getByRole("link").first().click();
  await mineRow.waitFor();
  L.ok(new URL(lp.url()).searchParams.get("assignee") === "me", "home 내 담당 opens my findings");

  // filters and the deadline order live in the URL
  await lp.goto(`${L.BASE}/projects/${key}`);
  await row.waitFor();
  await lp.getByRole("combobox", { name: "담당자", exact: true }).selectOption("me");
  await only();
  L.ok(new URL(lp.url()).searchParams.get("assignee") === "me", "담당자 = 내 담당 leaves my one finding");
  await lp.getByRole("combobox", { name: "담당자", exact: true }).selectOption("none");
  await lp.waitForFunction((cve) => { const b = document.querySelector("main table tbody"); return !!b && b.rows.length > 1 && !b.textContent.includes(cve); }, CVE);
  L.ok(true, "담당자 미지정 lists the others and not mine");
  await lp.getByRole("combobox", { name: "담당자", exact: true }).selectOption("");
  await lp.getByRole("group", { name: "정렬" }).getByRole("button", { name: "기한 순" }).click();
  await lp.waitForFunction((cve) => { const b = document.querySelector("main table tbody"); return !!b && b.rows.length > 1 && b.rows[0].textContent.includes(cve); }, CVE);
  L.ok(new URL(lp.url()).searchParams.get("sort") === "due", "기한 순 puts the earliest deadline first and is kept in the URL");
  // 1024px: the two new columns are on screen; 처음 발견 gives way
  await lp.setViewportSize({ width: 1024, height: 800 });
  const box = await row.locator(".deadline").boundingBox();
  L.ok(!!box && box.x + box.width <= 1024 && !(await table.getByRole("columnheader", { name: "처음 발견" }).isVisible()), "at 1024px 기한 is inside the window and 처음 발견 is hidden");
  await L.shot(lp, "due-list-1024");
  await lp.setViewportSize({ width: 1440, height: 900 });

  // the same finding elsewhere: CSV and MCP
  const csv = await lee.api.get(`/findings.csv?project=${key}&due=overdue`);
  L.ok(csv.split("\r\n")[0].endsWith('"담당자","조치 기한"') && csv.includes(`"${leeName}"`) && csv.includes(CVE), "the CSV has 담당자 and 조치 기한");
  const mcp = await fetch(`${L.BASE}/mcp`, { method: "POST", headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "list_findings", arguments: { overdue: true } } }) });
  const tool = JSON.parse((await mcp.json()).result.content[0].text);
  L.ok(tool.total === 1 && tool.findings[0].rule_id === CVE && tool.findings[0].overdue === true && tool.findings[0].assignee === leeName && !!tool.findings[0].due_at,
    "MCP list_findings overdue:true returns it with assignee and due_at");

  // back to the policy
  await lp.goto(`${L.BASE}/projects/${key}?finding=${f.id}`);
  await triage.getByRole("button", { name: "정책 기한으로 되돌리기" }).click();
  await triage.getByText("직접 정함").waitFor({ state: "detached" });
  L.ok(/^(2|3)일 남음$/.test(await triage.locator(".deadline").innerText()) && (await find()).due_manual === false, "정책 기한으로 되돌리기 gives the policy deadline back");
  await lp.keyboard.press("Escape");

  // bulk: everything on the page to park, found through the search
  await lp.goto(`${L.BASE}/projects/${key}`);
  await row.waitFor();
  await lp.getByLabel("모두 선택").check();
  const n = await table.getByRole("row").count() - 1;
  L.ok((await lp.locator(".bulk").innerText()).includes(`${n}건 선택`), `the bar says ${n}건 선택`);
  await lp.locator(".bulk").getByRole("button", { name: "담당자 지정" }).click();
  const bulk = lp.getByRole("dialog", { name: "담당자 지정" });
  await bulk.getByRole("combobox").fill("park");
  await bulk.getByRole("option", { name: /park/ }).click();
  await bulk.getByRole("button", { name: /님에게 지정$/ }).click();
  await lp.locator(".toast").filter({ hasText: `${n}건을` }).waitFor();
  const all = (await lee.api.get(`/findings?project=${key}&limit=200`)).items;
  L.ok(all.length === n && all.every((i) => i.assignee?.id === parkMe.id), `all ${n} findings are park's now`);
  L.ok(await lp.locator(".bulk").count() === 0, "the selection is cleared after assigning");

  // park is a viewer: sees who and by when, cannot change either
  const pp = park.page;
  await pp.goto(`${L.BASE}/projects/${key}`);
  const prow = pp.getByRole("table", { name: "결과 목록" }).getByRole("row", { name: new RegExp(CVE) });
  await prow.waitFor();
  L.ok(await pp.getByRole("table", { name: "결과 목록" }).getByRole("checkbox").count() === 0 && (await prow.innerText()).includes(parkName), "a viewer sees the assignee and no checkboxes");
  await prow.locator(".pkg-name").click();
  const pt = pp.getByRole("dialog").getByRole("region", { name: "담당자와 기한" });
  await pt.getByText("정책: CRITICAL 3일").waitFor();
  L.ok(await pt.getByRole("button").count() === 0 && await pt.getByRole("combobox").count() === 0 && await pt.getByLabel("기한 날짜").count() === 0, "the viewer's drawer block is read-only");
  L.ok((await park.api("PATCH", `/findings/${f.id}`, { assignee_id: null })).status === 403 &&
    (await park.api("POST", "/findings/assign", { ids: [f.id], assignee_id: null })).status === 403, "the API refuses a viewer too (403)");
  await pp.keyboard.press("Escape");
  await pp.goto(`${L.BASE}/findings?assignee=me`);
  await pp.getByRole("table", { name: "결과 목록" }).getByRole("row", { name: new RegExp(`${CVE}.* ${key} `) }).waitFor();
  L.ok(true, "park finds the findings given to them under 내 담당");

  // the two notices can be subscribed to; the audit log names what happened in words
  const ch = await admin.api.post("/admin/channels", { kind: "mattermost", name: "e2e-due", enabled: true, config: { webhook_url: "http://127.0.0.1:9/hooks/e2e-due" } });
  await ap.goto(`${L.BASE}/projects/${key}/settings`);
  await ap.getByLabel("조치 기한 임박").first().waitFor();
  L.ok(await ap.getByLabel("조치 기한 지남").count() >= 1, "project settings offer 조치 기한 임박 and 조치 기한 지남");
  L.ok((await admin.api("PUT", `/projects/${key}/notify`, [{ channel_id: ch.id, events: ["due_soon", "overdue"] }])).status === 204, "the API takes the two events");
  await ap.goto(`${L.BASE}/admin/audit`);
  const audit = ap.getByRole("table", { name: "감사 로그" });
  await audit.getByText("결과 담당자 지정").first().waitFor();
  const text = await audit.innerText();
  L.ok(text.includes("결과 기한 변경") && text.includes("조치 기한 정책 변경") && text.includes(`담당자: ${parkName}`) && text.includes("정책 기한으로 되돌림: 예"), "the audit log reads in words");

  await admin.api.del(`/admin/channels/${ch.id}`);
  await admin.api.put("/admin/sla", DEFAULT);
  L.ok((await find()).due_at && Math.abs(daysOf(await find()) - 7) < 0.01, "the default days are back for the suites that follow");
  await browser.close();
});
