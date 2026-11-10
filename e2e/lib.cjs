// Shared setup for the browser tests: Playwright/Chromium location, sign-in helpers, API helper, request/console logs.
// Everything comes from the environment (run.sh loads e2e/.env); see README.md.
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const need = (k) => {
  const v = process.env[k];
  if (!v) { console.error(`${k} 환경 변수가 필요합니다 (e2e/README.md 참고).`); process.exit(2); }
  return v;
};
const OUT = path.join(__dirname, ".out");
fs.mkdirSync(path.join(OUT, "shots"), { recursive: true });
const SUITE = path.basename(process.argv[1] || "suite", ".cjs");
const BASE = process.env.JASCA_E2E_BASE || "http://localhost:" + (process.env.JASCA_E2E_ADDR || "127.0.0.1:18301").split(":").pop();
const PW = process.env.JASCA_E2E_USER_PASSWORD || process.env.JASCA_E2E_KC_USER_PASSWORD;

// Console errors that are expected noise, not bugs: {suites, text, url?}. Keep this list short and specific.
const CONSOLE_ALLOW = [
  // Every sign-in starts on the SPA, which asks GET /me first; the by-design 401 sends it to the login page and Chrome logs it.
  { suites: /./, text: /status of 401/, url: /\/api\/v1\/me$/ },
  // login.cjs, a11y.cjs and trivydb.cjs do things the server answers with a 4xx on purpose; Chrome logs every failed resource load.
  { suites: /^(login|a11y)$/, text: /status of (401|423)/, url: /\/api\/v1\/auth\/local$/ }, // 423: the locked account
  // login.cjs ends the session under a signed-in page; advisory.cjs opens an advisory that does not exist.
  { suites: /^login$/, text: /status of 401/, url: /\/api\/v1\/projects$/ },
  { suites: /^advisory$/, text: /status of 404/, url: /\/api\/v1\/advisories\/JASCA-E2E-NONE$/ },
  { suites: /^trivydb$/, text: /status of 400/, url: /\/api\/v1\/admin\/trivy(\/db)?$/ }, // bad bundle, bad option
  // exceptions.cjs opens a report and a finding as someone without access; the 404s are the point.
  { suites: /^exceptions$/, text: /status of 404/, url: /\/api\/v1\/(projects\/e2e-exc\/report|findings\/\d+)$/ },
];

const hooks = (ctx, who) => {
  const log = (url) => fs.appendFileSync(path.join(OUT, "net.log"), `${SUITE}\t${who}\t${url}\n`);
  ctx.on("request", (r) => log(r.url()));
  ctx.on("page", (pg) => lib.pages.push(pg));
  const bad = (kind, text, url = "") => {
    if (kind === "console" && CONSOLE_ALLOW.some((a) => a.suites.test(SUITE) && a.text.test(text) && (!a.url || a.url.test(url)))) return;
    fs.appendFileSync(path.join(OUT, "console-errors.log"), `${SUITE}\t${who}\t${kind}\t${text.replace(/\s+/g, " ").slice(0, 300)}\t${url}\n`);
  };
  ctx.on("console", (m) => m.type() === "error" && bad("console", m.text(), m.location().url));
  ctx.on("weberror", (e) => bad("pageerror", String(e.error())));
};

// One browser identity for pages and ctx.request: the server ends a session used from another User-Agent.
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 jasca-e2e";
const lib = {
  BASE, OUT, SUITE, PW,
  ADMIN: need("JASCA_E2E_ADMIN_PASSWORD"),
  KC_ISSUER: process.env.JASCA_E2E_KC_ISSUER,
  KC_CLIENT_SECRET: process.env.JASCA_E2E_KC_CLIENT_SECRET,
  KC_SYNC_SECRET: process.env.JASCA_E2E_KC_SYNC_SECRET,
  ok: (c, m) => { if (!c) throw new Error("FAIL: " + m); console.log("ok -", m); },
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  // Polls fn until it returns truthy (errors count as falsy) within ms.
  until: async (fn, msg, ms = 8000) => {
    const t = Date.now();
    for (;;) {
      let v; try { v = await fn(); } catch { v = false; }
      if (v) { console.log("ok -", msg); return v; }
      if (Date.now() - t > ms) throw new Error("FAIL (timeout): " + msg);
      await lib.sleep(150);
    }
  },
  launch: () => {
    const pw = process.env.JASCA_E2E_PLAYWRIGHT || "playwright-core";
    const chrome = process.env.JASCA_E2E_CHROME;
    const ld = process.env.JASCA_E2E_LD_LIBRARY_PATH;
    return require(pw).chromium.launch({
      ...(chrome ? { executablePath: chrome } : {}),
      env: { ...process.env, ...(ld ? { LD_LIBRARY_PATH: ld + (process.env.LD_LIBRARY_PATH ? ":" + process.env.LD_LIBRARY_PATH : "") } : {}) },
    });
  },
  axeSource: fs.readFileSync(require.resolve("axe-core/axe.min.js"), "utf8"),
  // A fresh browser context. The browser zone differs from the server's on purpose (dates must not shift).
  context: async (browser, who, o = {}) => {
    const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: "ko-KR", timezoneId: "America/New_York", userAgent: UA, ...o });
    hooks(ctx, who);
    return ctx;
  },
  // Keycloak sign-in through the real login form. Returns {ctx,page,api}.
  sso: async (browser, user, o = {}) => {
    const ctx = await lib.context(browser, user, o);
    const page = await ctx.newPage();
    await page.goto(BASE + (o.next || "/"));
    await page.getByRole("link", { name: /Keycloak으로 로그인/ }).click();
    await page.locator("#username").fill(user);
    await page.locator("#password").fill(PW);
    await page.locator("#kc-login").click();
    await page.locator(".sidebar").waitFor({ timeout: 15000 });
    return { ctx, page, api: lib.api(ctx), user };
  },
  local: async (browser, o = {}) => {
    const ctx = await lib.context(browser, "admin", o);
    const page = await ctx.newPage();
    const r = await ctx.request.post(BASE + "/api/v1/auth/local", { headers: { Origin: BASE }, data: { username: "admin", password: lib.ADMIN } });
    if (!r.ok()) throw new Error("admin login " + r.status());
    await page.goto(BASE + (o.next || "/"));
    await page.locator(".sidebar").waitFor();
    return { ctx, page, api: lib.api(ctx), user: "admin" };
  },
  // JSON API through the context's cookies: {get,post,patch,put,del}(path, body) -> body; api(m, p, body) -> {status, body}
  api: (ctx) => {
    const call = async (m, p, data) => {
      const r = await ctx.request.fetch(BASE + "/api/v1" + p, { method: m, headers: { Origin: BASE }, ...(data !== undefined ? { data } : {}), failOnStatusCode: false });
      const t = await r.text();
      let body = t; try { body = t ? JSON.parse(t) : null; } catch {}
      return { status: r.status(), body };
    };
    const strict = (m) => async (p, d) => { const r = await call(m, p, d); if (r.status >= 300) throw new Error(`${m} ${p} -> ${r.status} ${JSON.stringify(r.body)}`); return r.body; };
    return Object.assign(call, { get: strict("GET"), post: strict("POST"), patch: strict("PATCH"), put: strict("PUT"), del: strict("DELETE"),
      raw: { get: (p) => call("GET", p), post: (p, d) => call("POST", p, d), put: (p, d) => call("PUT", p, d), del: (p) => call("DELETE", p) } });
  },
  theme: (page, mode) => page.evaluate((m) => { try { localStorage.setItem("jasca.theme", m); } catch {} document.documentElement.dataset.theme = m; }, mode),
  shot: (page, name) => page.screenshot({ path: path.join(OUT, "shots", name + ".png") }),
  psql: (q) => execFileSync(process.env.JASCA_E2E_DOCKER || "docker",
    ["exec", need("JASCA_E2E_PG_CONTAINER"), "psql", "-tA", "-U", need("JASCA_E2E_PG_USER"), "-d", need("JASCA_E2E_PG_DB"), "-c", q]).toString().trim(),
  // Uploads a report like the CI snippet does (curl --data-binary with the project token). Returns {status, body}.
  ingest: async (key, token, buf, query = "") => {
    const r = await fetch(`${BASE}/api/v1/projects/${key}/scans${query}`, { method: "POST", headers: { Authorization: "Bearer " + token }, body: buf });
    const t = await r.text();
    let body = t; try { body = JSON.parse(t); } catch {}
    return { status: r.status, body };
  },
  fixture: (name) => fs.readFileSync(path.join(__dirname, "..", "internal", "formats", "testdata", name)),
  // A tiny project + upload token through the admin API. Returns {key, token}.
  project: async (api, key, name = key) => {
    await api.post("/projects", { key, name, description: "" });
    const t = await api.post(`/projects/${key}/tokens`, { name: "ci", scopes: ["upload", "read"], expires_at: new Date(Date.now() + 30 * 864e5).toISOString() });
    return { key, token: t.token };
  },
  // Small hand-off between suites (e.g. the token the projects suite created through the UI).
  state: (patch) => {
    const f = path.join(OUT, "state.json");
    let cur = {}; try { cur = JSON.parse(fs.readFileSync(f, "utf8")); } catch {}
    if (patch) fs.writeFileSync(f, JSON.stringify((cur = { ...cur, ...patch })));
    return cur;
  },
  run: (main) => main().then(() => process.exit(0), async (e) => {
    console.error(e.message.split("\n").slice(0, 12).join("\n"));
    for (const [i, pg] of lib.pages.entries()) await pg.screenshot({ path: path.join(OUT, "shots", `${SUITE}-fail-${i}.png`) }).catch(() => {});
    process.exit(1);
  }),
  pages: [],
};
module.exports = lib;
