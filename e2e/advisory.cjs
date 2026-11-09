// An internal advisory made in the UI matches a package uploaded earlier: the finding appears without a rescan.
const L = require("./lib.cjs");
L.run(async () => {
  const browser = await L.launch();
  const kim = await L.sso(browser, "kim");
  const { key, token } = await L.project(kim.api, "e2e-adv", "E2E Advisory");
  const up = await L.ingest(key, token, L.fixture("trivy/image-debian.json"), "?target=debian-app&kind=image&ref=1.0");
  L.ok(up.status < 300, "report with libssl1.1 uploaded");
  const before = await kim.api.get(`/findings?project=${key}&limit=200`);
  L.ok(!before.items.some((i) => i.rule_id === "JASCA-E2E-001"), "no advisory finding yet");
  const scans = (await kim.api.get(`/projects/${key}/scans`));
  const nScans = (scans.items ?? scans).length;

  const page = kim.page;
  await page.goto(L.BASE + "/advisories/new");
  await page.getByLabel(/^ID/).fill("JASCA-E2E-001");
  await page.getByLabel("심각도").selectOption("CRITICAL");
  await page.getByLabel("제목").fill("사내 점검 대상 libssl");
  await page.getByLabel("생태계").selectOption("debian");
  await page.getByLabel("패키지").fill("libssl1.1");
  await page.getByLabel("영향 범위").fill("<1.1.1z");
  await page.getByRole("button", { name: "영향 미리보기" }).click();
  const dlg = page.getByRole("dialog", { name: "영향 미리보기" });
  await dlg.getByRole("row", { name: new RegExp(key) }).waitFor();
  L.ok(true, "preview lists the uploaded libssl1.1 of the project");
  await dlg.getByRole("button", { name: "저장" }).click();
  await page.waitForURL(/\/advisories$/);

  const f = await L.until(async () => (await kim.api.get(`/findings?project=${key}&limit=200`)).items.find((i) => i.rule_id === "JASCA-E2E-001"), "advisory finding appears without a rescan", 15000);
  L.ok(f.severity === "CRITICAL" && f.pkg_name === "libssl1.1", "finding has the advisory's severity and package");
  const after = (await kim.api.get(`/projects/${key}/scans`));
  L.ok((after.items ?? after).length === nScans, "no new scan was made");
  await page.goto(`${L.BASE}/projects/${key}`);
  await page.getByRole("table", { name: "결과 목록" }).getByText("JASCA-E2E-001").first().waitFor();
  L.ok(true, "the project results screen shows it");
  await browser.close();
});
