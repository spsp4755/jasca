// 관리 → 시스템 상태 and what goes with it: the rows and their order, the channels that receive operator alerts
// (관리 → 알림 채널 → 운영 알림), which vulnerability DB a server scan was checked against, and the banner every
// signed-in user sees while the vulnerability DB is stale.
const fs = require("fs");
const path = require("path");
const L = require("./lib.cjs");
L.run(async () => {
  const browser = await L.launch();
  const admin = await L.local(browser, { next: "/admin/system" });
  const page = admin.page, api = admin.api;
  await page.getByRole("heading", { name: "시스템 상태" }).waitFor();
  const list = page.locator(".sys-list");
  await list.waitFor();
  const st = await api.get("/admin/system");
  const rank = { bad: 0, warn: 1, ok: 2 };
  L.ok(st.checks.length >= 8 && st.checks.every((c) => c.label && c.value && c.state in rank && (c.state === "ok") === !c.action),
    `${st.checks.length} rows, each with a state and a value, and what to do when it is not 정상`);
  L.ok(st.checks.every((c, i) => i === 0 || rank[st.checks[i - 1].state] <= rank[c.state]), "rows that need attention come first");
  for (const key of ["app", "database", "data_volume", "trivy_db", "java_db", "scans", "recheck", "notifications", "server_log"])
    L.ok(st.checks.some((c) => c.key === key), `row ${key}`);
  L.ok(await list.locator("li").count() === st.checks.length, "the screen shows every row");
  const worst = st.checks[0].state;
  await page.locator(`.sys-summary.sys-${worst}`).waitFor();
  L.ok(true, "the verdict on top matches the worst row (" + worst + ")");
  await page.getByRole("button", { name: "다시 확인" }).click();
  await L.shot(page, "ops-system");

  // operator alerts: pick a channel on the 알림 채널 screen
  const ch = await api.post("/admin/channels", { kind: "mattermost", name: "e2e-ops", enabled: true, config: { webhook_url: "http://127.0.0.1:9/hooks/e2e-ops" } });
  await page.goto(L.BASE + "/admin/channels");
  const panel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "운영 알림" }) });
  await panel.getByRole("checkbox", { name: /e2e-ops/ }).check();
  await panel.getByRole("button", { name: "저장" }).click();
  await page.getByText("운영 알림을 받을 채널을 저장했습니다.").waitFor();
  L.ok((await api.get("/admin/ops-alerts")).channel_ids.includes(ch.id), "the chosen channel is stored");
  L.ok((await api.raw.put("/admin/ops-alerts", { channel_ids: [ch.id, 999999] })).status === 400, "a channel that does not exist is refused");
  L.ok((await api.get("/audit?limit=50")).items.some((e) => e.action === "ops_alerts.update"), "the change is in the audit log");
  await page.goto(L.BASE + "/admin/system");
  await page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "운영 알림" }) }).getByText("e2e-ops").waitFor();
  L.ok(true, "the status screen names the channel that is told");
  await api.put("/admin/ops-alerts", { channel_ids: [] });
  await api.del("/admin/channels/" + ch.id);

  // which DB a result was checked against (the scan suite ran server scans in e2e-scan)
  const meta = path.join(L.OUT, "data/trivy/db/metadata.json");
  const hasDB = fs.existsSync(meta);
  if (hasDB && (await api.get("/projects")).some((p) => p.key === "e2e-scan")) {
    const scans = (await api.get("/projects/e2e-scan/scans")).items;
    const server = scans.find((s) => s.source === "server" && s.status === "done");
    L.ok(server && !!server.summary.db_updated_at, "a server scan records the build time of the vulnerability DB");
    await page.goto(`${L.BASE}/scans/${server.id}`);
    await page.locator(".kv-row").filter({ hasText: "검사 기준 DB" }).getByText("생성").waitFor();
    L.ok((await api.get("/projects/e2e-scan/targets")).some((t) => t.db_checked_at), "its target says which DB it was checked against");
    await page.goto(L.BASE + "/reports/e2e-scan");
    await page.getByRole("columnheader", { name: "검사 기준 DB" }).waitFor();
    L.ok(true, "the scan page and the project report show it");
  }

  // a stale vulnerability DB: everyone is told, on every page
  const banner = (p) => p.getByRole("status").filter({ hasText: /취약점 DB가 \d+일 전 것입니다/ });
  if (hasDB) {
    L.ok(await banner(page).count() === 0, "no banner while the DB is current");
    const orig = fs.readFileSync(meta, "utf8");
    // rename, never write in place: the file may be a hard link to the kept DB copy (.out/keep)
    const put = (text) => { fs.writeFileSync(meta + ".tmp", text); fs.renameSync(meta + ".tmp", meta); };
    put(JSON.stringify({ Version: JSON.parse(orig).Version, UpdatedAt: "2026-01-05T00:00:00Z", NextUpdate: "2026-01-06T00:00:00Z" }));
    try {
      await page.goto(L.BASE + "/projects");
      await banner(page).getByRole("link", { name: "관리 → Trivy DB" }).waitFor();
      L.ok(true, "an administrator sees the banner with a link to 관리 → Trivy DB");
      await page.goto(L.BASE + "/admin/system");
      await list.locator("li").first().getByText("취약점 DB", { exact: true }).waitFor();
      L.ok(/문제/.test(await list.locator("li").first().innerText()) && (await api.get("/admin/system")).checks[0].key === "trivy_db", "the stale DB is the first row, as 문제");
      await L.shot(page, "ops-system-stale");
      await page.goto(L.BASE + "/");
      await page.waitForLoadState("networkidle");
      L.ok(await page.getByText("시스템 상태에 문제가").count() === 0, "home does not repeat what the banner already says");
      const kim = await L.sso(browser, "kim");
      await banner(kim.page).getByText("관리자에게 DB 갱신을 요청하세요.").waitFor();
      L.ok(await banner(kim.page).getByRole("link").count() === 0, "other users see the banner and are told to ask an administrator");
      L.ok((await kim.api.raw.get("/admin/system")).status === 403 && (await kim.api.raw.get("/admin/ops-alerts")).status === 403, "the status and alert routes are for administrators");
    } finally {
      put(orig);
    }
    await page.goto(L.BASE + "/projects");
    await page.locator("main h1").first().waitFor();
    L.ok(await banner(page).count() === 0, "the banner is gone once the DB is current again");
  } else {
    L.ok(st.checks[0].key === "trivy_db" && st.checks[0].state === "bad", "without a vulnerability DB the first row says so");
  }
  await browser.close();
});
