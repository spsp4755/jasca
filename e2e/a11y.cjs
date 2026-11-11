// axe (wcag2a + wcag2aa) on the main pages, light and dark. serious/critical violations fail; minor/moderate ones are listed.
const L = require("./lib.cjs");
const found = [], soft = [];

const axe = async (page, label, theme) => {
  await L.theme(page, theme);
  await L.sleep(250); // let transitions settle so contrast is measured on final colours
  // The CSP forbids inline scripts: inject through evaluate, not a <script> tag.
  if ((await page.evaluate(() => typeof window.axe)) !== "object") await page.evaluate(L.axeSource);
  const r = await page.evaluate(() => axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa"] } }));
  const name = `${label} [${theme}]`;
  const hard = r.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  for (const v of r.violations) (hard.includes(v) ? found : soft).push({ name, id: v.id, impact: v.impact, n: v.nodes.length,
    nodes: v.nodes.slice(0, 3).map((n) => n.target.join(" ") + " :: " + (n.any[0]?.message || n.all[0]?.message || n.none[0]?.message || "").slice(0, 140)) });
  if (!hard.length) return L.ok(true, `${name}: no serious/critical violations (${r.passes.length} rules passed)`);
  console.log(`not ok - ${name}: ${hard.map((v) => v.id + "x" + v.nodes.length).join(", ")}`);
};
const both = async (page, label) => { for (const t of ["light", "dark"]) await axe(page, label, t); await L.theme(page, "light"); };
const visit = async (page, p, label, ready) => {
  await page.goto(L.BASE + p);
  await page.locator("main h1, .login h1").first().waitFor();
  await page.waitForLoadState("networkidle");
  if (ready) await ready();
  await both(page, label || p);
};

L.run(async () => {
  const browser = await L.launch();
  const anon = await L.context(browser, "anon");
  const lp = await anon.newPage();
  await visit(lp, "/login", "login");
  await lp.goto(L.BASE + "/login?local=1");
  await lp.getByLabel("아이디").fill("x"); await lp.getByLabel("비밀번호").fill("wrong-wrong-1");
  await lp.getByRole("button", { name: "로그인" }).click();
  await lp.getByRole("alert").first().waitFor();
  await both(lp, "login local form with error");
  await visit(lp, "/login?next=%2F&error=expired", "login after the session ended");

  const kim = await L.sso(browser, "kim");
  const p = kim.page;
  await visit(p, "/", "home");
  await visit(p, "/projects", "projects");
  await visit(p, "/projects/e2e-proj", "project results", () => p.getByRole("table", { name: "결과 목록" }).waitFor());
  for (const tab of ["targets", "scans", "exceptions", "settings"]) await visit(p, `/projects/e2e-proj/${tab}`, `project ${tab}`);
  await visit(p, "/findings", "findings");
  await p.getByRole("table", { name: "결과 목록" }).getByRole("row").nth(1).locator(".pkg-name").click();
  await p.getByRole("dialog").first().waitFor();
  await both(p, "finding drawer");
  await p.keyboard.press("Escape");
  await visit(p, "/packages", "packages");
  await visit(p, "/packages?q=ssl&version=%3C99", "package search result", () => p.getByRole("table", { name: "찾은 패키지" }).waitFor());
  await visit(p, "/vulns/CVE-2022-37434", "vuln");
  await visit(p, "/scan", "scan upload");
  await visit(p, "/scan?tab=harbor", "scan harbor");
  await visit(p, "/exceptions", "exceptions");
  await visit(p, "/exceptions/approvals", "exception approvals");
  await visit(p, "/advisories", "advisories");
  await visit(p, "/advisories/new", "advisory form");
  await visit(p, "/advisories/JASCA-E2E-001", "advisory edit");
  await visit(p, "/reports", "reports");
  await visit(p, "/reports/e2e-proj", "project report");
  await visit(p, "/admin/default-policy", "kim: default policy");
  await p.keyboard.press("?");
  await p.getByRole("dialog").waitFor();
  await both(p, "shortcut help");

  const admin = await L.local(browser);
  for (const a of ["users", "sso", "sync", "default-policy", "trivy", "recheck", "harbor", "ai", "channels", "retention", "audit"]) await visit(admin.page, `/admin/${a}`, `admin ${a}`);
  await visit(admin.page, "/nonexistent", "not found");

  if (soft.length) console.log("minor/moderate (not failing):\n" + soft.map((s) => `  ${s.name}: ${s.id} (${s.impact}) x${s.n}`).join("\n"));
  if (found.length) {
    for (const f of found) console.log(`${f.name}: ${f.id} (${f.impact}) x${f.n}\n    ${f.nodes.join("\n    ")}`);
    throw new Error(`${found.length} serious/critical axe violation groups`);
  }
  await browser.close();
});
