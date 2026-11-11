// 조치 계획 tab: open vulnerabilities grouped by the package upgrade that resolves them. Own projects (e2e-fix*):
// two images that share a JAR, a package without a fix, one whose fixed versions cannot be compared, and a SARIF
// upload the plan does not cover. Checks the API, the screen (summary, rows, opened group, drawer, target filter,
// copy, links to the results list), a 1024px window, a viewer, the report table and the states without a plan.
const L = require("./lib.cjs");

const doc = (name, n, results) => Buffer.from(JSON.stringify({
  SchemaVersion: 2, ArtifactName: name, ArtifactType: "container_image", CreatedAt: `2026-01-0${n}T00:00:00Z`,
  Results: results.map(([type, vulns]) => ({
    Target: `app/${type}.lock`, Class: "lang-pkgs", Type: type,
    Vulnerabilities: vulns.map(([VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Severity]) =>
      ({ VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Severity, Title: `${PkgName}: ${VulnerabilityID}` })),
  })),
}));

L.run(async () => {
  const browser = await L.launch();
  const kim = await L.sso(browser, "kim", { permissions: ["clipboard-read", "clipboard-write"] });
  const page = kim.page;
  const { key, token } = await L.project(kim.api, "e2e-fix", "E2E Fixes");
  const rce = ["CVE-2021-44228", "log4j-core", "2.14.1", "2.15.0, 2.12.2", "CRITICAL"];
  const ups = [
    [doc("api", 1, [
      ["jar", [rce, ["CVE-2021-44832", "log4j-core", "2.14.1", "2.17.1, 2.12.4, 2.3.2", "MEDIUM"], ["CVE-2030-0001", "log4j-core", "2.14.1", "", "LOW"]]],
      ["npm", [["CVE-2021-23337", "lodash", "4.17.20", "4.17.21", "HIGH"], ["CVE-2030-0002", "left-pad", "1.3.0", "", "HIGH"]]],
      ["conan", [["CVE-2022-37434", "zlib", "1.2.11", "1.3.1, 1.2.13", "HIGH"]]], // no version comparator for this package type
    ]), "?target=e2e-fix-api&kind=image&ref=1.0"],
    [doc("worker", 2, [["jar", [rce]]]), "?target=e2e-fix-worker&kind=image&ref=1.0"],
    [L.fixture("sarif/semgrep.sarif"), "?target=e2e-fix-code&kind=repo"],
  ];
  for (const [buf, query] of ups) L.ok((await L.ingest(key, token, buf, query)).status < 300, `uploaded ${query}`);

  // API: the highest listed fixed version is recommended; what cannot be compared is listed as written
  const plan = await kim.api.get(`/projects/${key}/fixes`);
  const t = plan.totals;
  L.ok(t.open_vulns === 7 && t.fixable === 5 && t.no_fix === 2 && t.other_kinds.sast > 0 && t.inventory_targets === 2 && plan.truncated === false,
    `totals: 7 open vulnerabilities, 5 with a fix, 2 without, SAST results counted apart (${JSON.stringify(t)})`);
  const [log4j, lodash, zlib] = plan.groups;
  L.ok(plan.groups.length === 3 && log4j.package === "log4j-core" && log4j.ecosystem === "maven" && log4j.recommended === "2.17.1" &&
    log4j.resolves.open === 3 && log4j.resolves.critical === 2 && log4j.no_fix === 1 && log4j.targets.length === 2 && log4j.findings.length === 4,
    "log4j-core 2.14.1 → 2.17.1 (the highest fix of any finding) resolves 3 findings on 2 targets; 1 has no fix");
  L.ok(lodash.package === "lodash" && lodash.recommended === "4.17.21" && zlib.package === "zlib" && zlib.recommended === "" &&
    zlib.fixed_versions.join("|") === "1.3.1|1.2.13", "worst severity first, then name; zlib (unknown package type) gets no single version");
  L.ok(plan.no_fix_groups.length === 1 && plan.no_fix_groups[0].package === "left-pad" && plan.no_fix_groups[0].resolves.open === 0, "left-pad has no fixed version: second list");
  const worker = (await kim.api.get(`/projects/${key}/targets`)).find((x) => x.name === "e2e-fix-worker");
  const one = await kim.api.get(`/projects/${key}/fixes?target_id=${worker.id}`);
  L.ok(one.totals.open_vulns === 1 && one.groups.length === 1 && one.groups[0].recommended === "2.15.0", "target_id narrows the plan to that target's findings");
  L.ok((await kim.api.raw.get(`/projects/${key}/fixes?target_id=x`)).status === 400, "a bad target_id is refused (400)");

  // screen: the tab, the one-sentence summary and the two remainders
  await page.goto(`${L.BASE}/projects/${key}`);
  await page.getByRole("tab", { name: "조치 계획" }).click();
  await page.getByRole("heading", { name: "올릴 패키지" }).waitFor();
  L.ok(new URL(page.url()).pathname === `/projects/${key}/fixes`, "the 조치 계획 tab has its own address");
  L.ok((await page.locator(".fix-lead").innerText()).replace(/\s+/g, " ") === "패키지 3개를 올리면 열린 취약점 7건 중 5건이 해결됩니다.", "summary: 패키지 3개를 올리면 열린 취약점 7건 중 5건이 해결됩니다.");
  const rest = await page.locator(".fix-rest").innerText();
  L.ok(/아직 조치 버전 없음 2건/.test(rest) && /코드 분석 \d+건/.test(rest), "the summary names what stays: findings without a fix and the other kinds");
  const rows = page.locator("#h-fix").locator("xpath=ancestor::section").locator(".fix-row");
  const first = (await rows.first().innerText()).replace(/\s+/g, " ");
  L.ok(await rows.count() === 3 && ["log4j-core", "maven", "2.14.1", "2.17.1 이상", "CRITICAL 2", "MEDIUM 1", "3건 해결", "대상 2개"].every((s) => first.includes(s)),
    `the first row reads as an instruction (${first})`);
  const zrow = (await rows.nth(2).innerText()).replace(/\s+/g, " ");
  L.ok(zrow.includes("1.3.1, 1.2.13") && zrow.includes("비교 못 함") && !zrow.includes("이상"), "zlib shows its fixed versions as written, marked 비교 못 함");
  await L.shot(page, "fixes-plan");

  // an opened group: targets, findings, the note about what stays, the drawer
  await rows.first().click();
  const body = page.locator(".fix-body");
  const table = body.getByRole("table", { name: "log4j-core 2.14.1 취약점" });
  await table.waitFor();
  const bodyText = await body.innerText();
  L.ok(bodyText.includes("이 중 1건은 아직 조치 버전이 없어") && bodyText.includes("e2e-fix-api") && bodyText.includes("e2e-fix-worker") && bodyText.includes("app/jar.lock"),
    "the opened group lists both targets with the file and says 1 finding stays");
  L.ok(await table.getByRole("row").count() === 5 && (await table.getByRole("row").nth(1).innerText()).includes("CRITICAL"), "4 findings, most severe first");
  await table.getByRole("row", { name: /CVE-2021-44832/ }).locator("td").first().click();
  const drawer = page.getByRole("dialog");
  await drawer.getByRole("link", { name: /취약점 상세/ }).waitFor();
  L.ok(/[?&]finding=\d+/.test(page.url()) && (await drawer.innerText()).includes("CVE-2021-44832"), "a finding row opens the finding drawer (address carries ?finding=)");
  await page.keyboard.press("Escape");
  await drawer.waitFor({ state: "hidden" });
  await L.shot(page, "fixes-group-open");

  // copy: one group, then the whole plan
  const clip = () => page.evaluate(() => navigator.clipboard.readText());
  await body.getByRole("button", { name: "복사", exact: true }).click();
  await page.getByText("log4j-core 조치 내용을 복사했습니다").waitFor();
  const g = await clip();
  L.ok(g.includes("log4j-core (maven) 2.14.1 → 2.17.1 이상") && g.includes("해결 3건 (CRITICAL 2, MEDIUM 1), 아직 조치 버전 없음 1건") &&
    g.includes("대상: e2e-fix-api, e2e-fix-worker") && g.includes("CVE-2021-44228") && !g.includes("lodash"), "복사 on a group copies that upgrade as plain text");
  await page.getByRole("button", { name: "계획 전체 복사" }).click();
  await page.getByText("조치 계획을 복사했습니다").waitFor();
  const all = await clip();
  L.ok(all.startsWith("[E2E Fixes] 조치 계획") && all.includes("패키지 3개를 올리면 열린 취약점 7건 중 5건이 해결됩니다.") && all.includes("1. log4j-core") &&
    all.includes("3. zlib (conan) 1.2.11 → 1.3.1, 1.2.13 중 설치 계열에 맞는 버전") && all.includes("- left-pad (npm) 1.3.0") && /이 계획에 없는 열린 결과: 코드 분석 \d+건/.test(all),
    "계획 전체 복사 copies every upgrade, the packages without a fix and what the plan leaves out");

  // packages without a fix say that upgrading does not help
  const nofix = page.locator("#h-nofix").locator("xpath=ancestor::section");
  L.ok((await nofix.innerText()).includes("버전을 올려도 해결되지 않습니다") && (await nofix.locator(".fix-row").innerText()).includes("조치 버전 없음"), "조치 버전이 아직 없는 패키지: left-pad, with what to do instead");

  // target filter
  await page.getByLabel("대상", { exact: true }).selectOption(String(worker.id));
  await L.until(async () => (await page.locator(".fix-lead").innerText()).replace(/\s+/g, " ") === "패키지 1개를 올리면 열린 취약점 1건 중 1건이 해결됩니다.", "the target filter narrows the plan to the worker image");
  L.ok(await page.locator(".fix-rest").count() === 0 && await page.locator("#h-nofix").count() === 0 && new URL(page.url()).searchParams.get("target_id") === String(worker.id),
    "nothing stays on that target, and the filter is in the address");
  await page.getByLabel("대상", { exact: true }).selectOption("");
  await page.locator("#h-nofix").waitFor();

  // a 1024px window keeps the row and the copy button inside
  await page.setViewportSize({ width: 1024, height: 800 });
  const inside = async (loc) => { const b = await loc.boundingBox(); return !!b && b.x >= 0 && b.x + b.width <= 1024; };
  L.ok(await inside(rows.first()) && await inside(rows.first().locator(".fix-gain")) && await inside(page.getByRole("button", { name: "계획 전체 복사" })), "at 1024px the rows and 계획 전체 복사 are inside the window");
  await L.shot(page, "fixes-1024");
  await page.setViewportSize({ width: 1440, height: 900 });

  // the numbers link to the results list with the matching filter
  await page.getByRole("link", { name: "아직 조치 버전 없음 2건" }).click();
  const results = page.getByRole("table", { name: "결과 목록" });
  await results.getByRole("row", { name: /CVE-2030-0002/ }).waitFor();
  const sp = new URL(page.url()).searchParams;
  L.ok(sp.get("kind") === "vuln" && sp.get("fixable") === "false" && await results.getByRole("row").count() === 3, "아직 조치 버전 없음 2건 opens the results tab with those 2 findings");
  L.ok(await page.locator(".filter-chip", { hasText: "조치 버전 없음" }).count() === 1, "the results filter bar shows the 조치 버전 없음 filter");

  // the printable report carries the top of the plan
  await page.goto(`${L.BASE}/reports/${key}`);
  const top = page.getByRole("table", { name: "먼저 올릴 패키지" });
  await top.waitFor();
  L.ok(await top.getByRole("row").count() === 4 && (await top.getByRole("row").nth(1).innerText()).replace(/\s+/g, " ").includes("2.14.1 → 2.17.1 이상"), "the report lists 먼저 올릴 패키지 in the plan's order");

  // a viewer reads the same plan
  const park = await L.sso(browser, "park");
  await kim.api.put(`/projects/${key}/members`, [...await kim.api.get(`/projects/${key}/members`), { principal_kind: "user", principal: String((await park.api.get("/me")).id), role: "viewer" }]);
  await park.page.goto(`${L.BASE}/projects/${key}/fixes`);
  await park.page.locator(".fix-row").first().click();
  await park.page.locator(".fix-body").getByRole("table").waitFor();
  L.ok((await park.page.locator(".fix-lead").innerText()).includes("5건") && await park.page.locator(".page-actions").getByRole("link", { name: "스캔하기" }).count() === 0, "a viewer sees the plan (and still no 스캔하기)");

  // without a plan: no scan yet, then only a scan that never looked at packages
  const none = await L.project(kim.api, "e2e-fix-none", "E2E Fixes None");
  await page.goto(`${L.BASE}/projects/${none.key}/fixes`);
  await page.getByRole("heading", { name: "첫 스캔을 보내세요" }).waitFor();
  L.ok(true, "a project without scans is pointed to its first scan");
  L.ok((await L.ingest(none.key, none.token, L.fixture("sarif/semgrep.sarif"), "?target=code&kind=repo")).status < 300, "SARIF uploaded to the empty project");
  await page.reload();
  await page.getByText("패키지를 살펴본 스캔이 없습니다").waitFor();
  L.ok(await page.getByText("열린 취약점이 없습니다").count() === 0 && /코드 분석 \d+건/.test(await page.locator(".fix-rest").innerText()),
    "after a SARIF-only scan the tab does not claim there are no vulnerabilities: no scan looked at packages, and the SAST results are linked");
  await L.shot(page, "fixes-no-inventory");
  await browser.close();
});
