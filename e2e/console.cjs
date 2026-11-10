// A page tour in fresh contexts, then every page error and console error recorded by any suite (lib.cjs drops allow-listed noise). Any left fails.
const fs = require("fs");
const L = require("./lib.cjs");
L.run(async () => {
  const browser = await L.launch();
  const tour = async (who, paths) => {
    const u = who === "admin" ? await L.local(browser) : await L.sso(browser, who);
    for (const p of paths) {
      await u.page.goto(L.BASE + p);
      await u.page.locator("main").first().waitFor(); // /admin for a plain user is an empty state without an h1
      await u.page.waitForLoadState("networkidle");
    }
    L.ok(true, `${who}: ${paths.length} pages toured`);
  };
  await tour("kim", ["/", "/projects", "/projects/e2e-proj", "/projects/e2e-proj/targets", "/projects/e2e-proj/scans", "/projects/e2e-proj/exceptions",
    "/projects/e2e-proj/settings", "/findings", "/vulns/CVE-2022-37434", "/scan", "/scan?tab=harbor", "/exceptions", "/exceptions/approvals",
    "/advisories", "/advisories/new", "/advisories/JASCA-E2E-001", "/reports", "/reports/e2e-proj", "/admin/default-policy"]);
  await tour("lee", ["/", "/projects", "/projects/e2e-proj", "/projects/e2e-proj/settings", "/findings", "/exceptions", "/advisories", "/reports", "/admin"]);
  await tour("admin", ["/admin/users", "/admin/sso", "/admin/sync", "/admin/default-policy", "/admin/trivy", "/admin/recheck", "/admin/harbor", "/admin/ai",
    "/admin/channels", "/admin/retention", "/admin/audit"]);
  await browser.close();
  const f = L.OUT + "/console-errors.log";
  const rows = fs.existsSync(f) ? fs.readFileSync(f, "utf8").split("\n").filter(Boolean) : [];
  const n = fs.readFileSync(L.OUT + "/net.log", "utf8").split("\n").filter(Boolean).length;
  L.ok(n > 100, `the suites ran with logging on (${n} requests)`);
  L.ok(!rows.length, "no page errors or unexpected console errors" + (rows.length ? ":\n  " + rows.slice(0, 12).join("\n  ") : ""));
});
