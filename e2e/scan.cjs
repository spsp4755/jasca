// Server-side scan of a small tar.gz with the real Trivy binary and DB (run.sh skips this suite without them).
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");
const L = require("./lib.cjs");
L.run(async () => {
  const dir = fs.mkdtempSync(path.join(L.OUT, "scan-src-"));
  fs.writeFileSync(path.join(dir, "package-lock.json"), JSON.stringify({
    name: "e2e-app", version: "1.0.0", lockfileVersion: 3, requires: true,
    packages: { "": { name: "e2e-app", version: "1.0.0", dependencies: { lodash: "4.17.15" } },
      "node_modules/lodash": { version: "4.17.15", resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz" } } }));
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "e2e-app", version: "1.0.0", dependencies: { lodash: "4.17.15" } }));
  const tgz = path.join(L.OUT, "scan-src.tar.gz");
  execFileSync("tar", ["-czf", tgz, "-C", dir, "."]);

  const browser = await L.launch();
  const kim = await L.sso(browser, "kim");
  await kim.api.post("/projects", { key: "e2e-scan", name: "E2E Scan", description: "" });
  const page = kim.page;
  await page.goto(L.BASE + "/scan");
  await page.getByLabel(/^프로젝트/).selectOption("e2e-scan");
  await page.getByLabel(/^대상 이름/).fill("lodash-app");
  await page.locator('input[type="file"]').setInputFiles(tgz);
  await page.getByRole("button", { name: "스캔 시작" }).click();
  const prog = page.getByRole("status").filter({ hasText: /스캔 #\d+/ });
  await prog.waitFor();
  L.ok(true, "scan started from the 파일 업로드 tab");
  await prog.getByText(/완료|실패/).waitFor({ timeout: 120000 });
  const failed = await prog.getByText("실패").count();
  L.ok(!failed, "scan finished without failing" + (failed ? ": " + (await prog.innerText()) : ""));
  const id = Number((await prog.innerText()).match(/스캔 #(\d+)/)[1]);
  const scan = await kim.api.get(`/scans/${id}`);
  L.ok(scan.status === "done" && scan.source === "server", "scan is done, source server");
  const f = await kim.api.get(`/findings?project=e2e-scan&limit=100`);
  L.ok(f.items.some((i) => i.pkg_name === "lodash" && /^CVE-/.test(i.rule_id)), `real Trivy found CVEs in lodash 4.17.15 (${f.items.length} findings)`);
  await prog.getByRole("link", { name: "결과 보기" }).click();
  await page.waitForURL(new RegExp(`/scans/${id}$`));
  L.ok(true, "결과 보기 opens the scan");
  await L.shot(page, "scan-result");
  fs.rmSync(dir, { recursive: true, force: true });
  await browser.close();
});
