// Secrets never come back: every JSON response while an admin sets and browses all settings is scanned for the known secret values.
const fs = require("fs");
const L = require("./lib.cjs");
const SECRETS = {
  "SSO client secret": L.KC_CLIENT_SECRET,
  "sync client secret": L.KC_SYNC_SECRET,
  "Harbor robot secret": "robot-secret-e2e-7f3a91c4",
  "SMTP password": "smtp-pass-e2e-5b82d0e6",
  "AI API key": "sk-e2e-ai-key-c19d44a8",
};
L.run(async () => {
  for (const [k, v] of Object.entries(SECRETS)) L.ok(!!v && v.length >= 12, `${k} value known to the test`);
  const browser = await L.launch();
  const admin = await L.local(browser);
  const leaks = [], seen = [];
  const scan = (where, text) => { seen.push(where); for (const [k, v] of Object.entries(SECRETS)) if (text.includes(v)) leaks.push(`${k} in ${where}`); };
  admin.ctx.on("response", async (r) => {
    if (!/json/.test(r.headers()["content-type"] || "")) return;
    try { scan(`${r.request().method()} ${r.url().replace(L.BASE, "")}`, await r.text()); } catch { /* redirect or aborted */ }
  });
  const api = admin.api;
  const sweep = async (m, p, d) => { const r = await api(m, p, d); scan(`${m} ${p} (api)`, JSON.stringify(r.body)); return r; };

  // set every secret through the API (SSO and sync were set through the screens by the login suite)
  let r = await sweep("PUT", "/admin/smtp", { host: "smtp.example.test", port: 587, username: "mailer", password: SECRETS["SMTP password"], from: "jasca@example.test", tls: "starttls" });
  L.ok(r.status === 204, "SMTP password saved");
  r = await sweep("PUT", "/admin/ai", { base_url: "http://127.0.0.1:9/v1", model: "e2e", api_key: SECRETS["AI API key"], enabled: false });
  L.ok(r.status === 200, "AI key saved");
  r = await sweep("POST", "/admin/harbor", { name: "e2e-harbor", base_url: "http://127.0.0.1:9", robot_user: "robot$e2e", robot_secret: SECRETS["Harbor robot secret"] });
  L.ok(r.status < 300, "Harbor robot secret saved (" + r.status + ")");

  // read every admin route directly, then page through the admin screens as a browser does
  for (const p of ["/admin/sso", "/admin/sync", "/admin/smtp", "/admin/ai", "/admin/ai/prompts", "/admin/harbor", "/admin/channels", "/admin/trivy",
    "/admin/recheck", "/admin/retention", "/admin/default-policy", "/admin/users", "/admin/sync/logins", "/audit?limit=200", "/me"]) {
    const x = await sweep("GET", p);
    L.ok(x.status === 200, `GET ${p} readable`);
  }
  const sso = (await api("GET", "/admin/sso")).body;
  L.ok(sso.client_secret_set === true && !("client_secret" in sso && sso.client_secret), "SSO answer says client_secret_set, never the value");
  const page = admin.page;
  for (const p of ["users", "sso", "sync", "default-policy", "trivy", "recheck", "harbor", "ai", "channels", "retention", "audit"]) {
    await page.goto(`${L.BASE}/admin/${p}`);
    await page.locator(".admin-main h1, main h1").first().waitFor();
    await page.waitForLoadState("networkidle");
  }
  L.ok(await page.getByRole("table", { name: "감사 로그" }).getByText("메일(SMTP) 설정 변경").count() > 0, "the audit screen names actions in Korean");
  await page.goto(`${L.BASE}/projects`);
  await page.goto(`${L.BASE}/findings`);
  await page.waitForLoadState("networkidle");
  // the audit log mentions that a secret changed, not its value
  const audit = JSON.stringify((await api("GET", "/audit?limit=200")).body);
  L.ok(/smtp\.update/.test(audit), "audit log records the SMTP change");
  fs.appendFileSync(L.OUT + "/admin-seen.log", seen.join("\n") + "\n");
  L.ok(seen.length > 40, `${seen.length} JSON responses scanned`);
  const log = fs.readFileSync(L.OUT + "/server.log", "utf8");
  for (const [k, v] of Object.entries(SECRETS)) if (log.includes(v)) leaks.push(`${k} in the server log`);
  L.ok(!leaks.length, "no secret value in any JSON response or the server log" + (leaks.length ? ": " + leaks.join("; ") : ""));
  await browser.close();
});
