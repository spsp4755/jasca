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
  await page.getByLabel(/^ID/).fill("E2");
  await page.getByRole("alert").filter({ hasText: "대문자로 시작하고 대문자·숫자·하이픈만 써서 3~41자로 입력하세요." }).waitFor();
  L.ok(await page.getByRole("button", { name: "영향 미리보기" }).isDisabled(), "an invalid ID says why next to the field while 영향 미리보기 is off");
  await page.getByLabel(/^ID/).fill("JASCA-E2E-001");
  await page.getByLabel("심각도").selectOption("CRITICAL");
  await page.getByLabel("제목").fill("사내 점검 대상 libssl");
  await page.getByLabel("패키지 종류").selectOption("debian");
  await page.getByLabel("패키지", { exact: true }).fill("libssl1.1");
  await page.getByLabel("영향 범위").fill("<1.1.1z");
  await page.getByRole("button", { name: "영향 미리보기" }).click();
  const dlg = page.getByRole("dialog", { name: "영향 미리보기" });
  await dlg.getByRole("row", { name: new RegExp(key) }).waitFor();
  L.ok(true, "preview lists the uploaded libssl1.1 of the project");
  L.ok(await dlg.getByRole("button", { name: "계속 수정" }).evaluate((el) => el === document.activeElement), "the preview opens with focus on 계속 수정, not on X or 저장");
  let posts = 0;
  page.on("request", (r) => { if (r.method() === "POST" && r.url().endsWith("/api/v1/advisories")) posts++; });
  await dlg.getByRole("button", { name: "저장" }).dblclick();
  await page.waitForURL(/\/advisories$/);
  await L.sleep(400);
  L.ok(posts === 1 && await page.getByText("이미 있습니다").count() === 0, `double-clicking 저장 creates the advisory once (${posts} request)`);

  const f = await L.until(async () => (await kim.api.get(`/findings?project=${key}&limit=200`)).items.find((i) => i.rule_id === "JASCA-E2E-001"), "advisory finding appears without a rescan", 15000);
  L.ok(f.severity === "CRITICAL" && f.pkg_name === "libssl1.1", "finding has the advisory's severity and package");
  const after = (await kim.api.get(`/projects/${key}/scans`));
  L.ok((after.items ?? after).length === nScans, "no new scan was made");
  await page.goto(`${L.BASE}/projects/${key}`);
  await page.getByRole("table", { name: "결과 목록" }).getByText("JASCA-E2E-001").first().waitFor();
  L.ok(true, "the project results screen shows it");

  // the vulnerability page says it is an internal advisory and links to it
  await page.goto(`${L.BASE}/vulns/JASCA-E2E-001`);
  await page.getByRole("link", { name: "사내 Advisory" }).first().waitFor();
  L.ok(!(await page.locator(".detail-side").innerText()).includes("공개일"), "an internal advisory's page is tagged 사내 Advisory instead of showing an empty 공개일");
  // switched off, the preview says what saving does: the finding is resolved, nothing new is created
  await page.goto(`${L.BASE}/advisories/JASCA-E2E-001`);
  await page.getByLabel(/사용 중/).uncheck();
  await page.getByRole("button", { name: "영향 미리보기" }).click();
  await dlg.getByText(/저장하면 이 Advisory로 생긴 결과 \d+건이 해결됨으로 바뀌고/).waitFor();
  L.ok(true, "with 사용 중 off the preview says the finding will be resolved");
  await dlg.getByRole("button", { name: "계속 수정" }).click(); // not saved: the a11y suite still finds the advisory in use
  // an advisory that does not exist: only the not-found state, nothing to delete
  await page.goto(`${L.BASE}/advisories/JASCA-E2E-NONE`);
  await page.getByText("Advisory를 찾을 수 없습니다").waitFor();
  L.ok(await page.getByRole("button", { name: "삭제" }).count() === 0, "a missing advisory shows the not-found state without a 삭제 button");
  await browser.close();
});
