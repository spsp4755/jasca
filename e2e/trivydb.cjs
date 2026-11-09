// Trivy DB upload through 관리 → Trivy DB: a bad bundle is refused with a Korean message, a good one is installed and a recheck run completes.
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");
const L = require("./lib.cjs");
L.run(async () => {
  const bundle = process.env.JASCA_E2E_TRIVY_BUNDLE;
  L.ok(!!bundle && fs.existsSync(bundle), "good DB bundle prepared by run.sh");
  const bad = path.join(L.OUT, "bad-db.tar.gz");
  fs.writeFileSync(bad, zlib.gzipSync(Buffer.from("this is not a trivy db bundle")));

  const browser = await L.launch();
  const admin = await L.local(browser, { next: "/admin/trivy" });
  const page = admin.page;
  const before = await admin.api.get("/admin/trivy");
  L.ok(before.db_version > 0, "the server starts with the copied DB (v" + before.db_version + ")");
  const runsBefore = (await admin.api.get("/admin/recheck")).length;

  await page.locator('input[type="file"]').setInputFiles(bad);
  await page.getByText(/올바른 Trivy DB 번들/).waitFor();
  L.ok(true, "bad bundle rejected with the Korean message, old DB kept");
  const same = await admin.api.get("/admin/trivy");
  L.ok(same.db_version === before.db_version && same.updated_at === before.updated_at, "DB status unchanged after the bad bundle");
  L.ok((await admin.api.get("/admin/recheck")).length === runsBefore, "no recheck run started for the bad bundle");

  await page.locator('input[type="file"]').setInputFiles(bundle);
  await page.getByText("DB를 적용했습니다. 재평가가 시작됩니다.").waitFor({ timeout: 120000 });
  L.ok(true, "good bundle installed");
  const run = await L.until(async () => {
    const runs = await admin.api.get("/admin/recheck");
    const r = runs.find((x) => x.reason === "trivydb");
    return r && r.state !== "running" && r;
  }, "recheck run of the new DB finishes", 180000);
  L.ok(run.state === "done" && run.total > 0 && run.done === run.total, `recheck run done (${run.done}/${run.total} targets, ${run.new_findings} new findings)`);
  await page.reload();
  await page.getByRole("table", { name: "재평가 실행 기록" }).getByText("Trivy DB 갱신").first().waitFor();
  L.ok(true, "run listed on the Trivy DB screen");
  await browser.close();
});
