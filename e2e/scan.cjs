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
  const page = kim.page;
  await page.goto(L.BASE + "/scan");
  // the file alone fills in what it can: the kind from the archive's first entry, the target from the file name
  await page.locator('input[type="file"]').setInputFiles(tgz);
  await page.getByRole("radio", { name: "소스 코드·패키지" }).waitFor();
  L.ok(await page.getByRole("radio", { name: "소스 코드·패키지" }).isChecked(), "a source tar.gz is recognised as 소스 코드·패키지");
  L.ok((await page.getByLabel(/^대상 이름/).inputValue()) === "scan-src", "target name is taken from the file name");
  await page.getByLabel(/^대상 이름/).fill("lodash-app");
  // a project can be made right here instead of on the projects page first
  await page.getByRole("combobox", { name: /^프로젝트/ }).selectOption({ label: "+ 새 프로젝트 만들기" });
  await page.getByLabel(/새 프로젝트 이름/).fill("E2E Scan");
  L.ok((await page.getByLabel(/프로젝트 키/).inputValue()) === "e2e-scan", "the key is suggested from the name");
  await page.getByRole("button", { name: "스캔 시작" }).click();
  const run = page.locator(".scan-run");
  await run.waitFor();
  L.ok((await kim.api.get("/projects")).some((p) => p.key === "e2e-scan" && p.my_role === "owner"), "the new project was created from the scan page");
  await run.getByText(/검사를 마쳤습니다|스캔하지 못했습니다/).waitFor({ timeout: 120000 });
  const failed = await run.getByText("스캔하지 못했습니다").count();
  L.ok(!failed, "scan finished without failing" + (failed ? ": " + (await run.innerText()) : ""));
  L.ok(/HIGH/.test(await run.innerText()), "the result summary shows counts by severity (CRITICAL, HIGH, …)");
  await run.getByRole("link", { name: "결과 자세히 보기" }).click();
  await page.waitForURL(/\/scans\/\d+$/);
  const id = Number(page.url().match(/\/scans\/(\d+)$/)[1]);
  L.ok(true, "결과 자세히 보기 opens the scan");
  const scan = await kim.api.get(`/scans/${id}`);
  L.ok(scan.status === "done" && scan.source === "server" && scan.target_name === "lodash-app", "scan is done, source server, target lodash-app");
  const f = await kim.api.get(`/findings?project=e2e-scan&limit=100`);
  L.ok(f.items.some((i) => i.pkg_name === "lodash" && /^CVE-/.test(i.rule_id)), `real Trivy found CVEs in lodash 4.17.15 (${f.items.length} findings)`);
  await page.getByRole("heading", { name: "lodash-app" }).waitFor();
  await page.getByText("같은 대상·형식의 이전 스캔이 없습니다").waitFor();
  L.ok(await page.getByRole("tab", { name: /새로 발견/ }).count() === 0, "a first scan lists its results without the comparison tabs");
  await L.shot(page, "scan-result");
  fs.rmSync(dir, { recursive: true, force: true });
  await browser.close();
});
