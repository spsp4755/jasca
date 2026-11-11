// 패키지 찾기: kim (security) finds log4j across two projects by name and version condition, sees what could not be
// compared and what was not searched, follows the open findings, downloads the CSV and opens a prefilled advisory.
// park sees only the project he is a viewer of, lee (no access to either) sees nothing of them.
const L = require("./lib.cjs");

// A Trivy image report with one lang-pkgs result: pkgs are [name, version, file path], vulns [id, package, version, path, severity].
let seq = 0;
const doc = (type, pkgs, vulns = []) => Buffer.from(JSON.stringify({
  SchemaVersion: 2, ArtifactName: "e2e", ArtifactType: "container_image", Created: `pkg-${++seq}`,
  Results: [{
    Target: "app", Class: "lang-pkgs", Type: type,
    Packages: pkgs.map(([Name, Version, FilePath = ""]) => ({ Name, Version, FilePath })),
    Vulnerabilities: vulns.map(([VulnerabilityID, PkgName, InstalledVersion, PkgPath, Severity]) => ({ VulnerabilityID, PkgName, InstalledVersion, PkgPath, Severity, Title: "e2e" })),
  }],
}));
const CORE = "org.apache.logging.log4j:log4j-core", API = "org.apache.logging.log4j:log4j-api";

L.run(async () => {
  const browser = await L.launch();
  const kim = await L.sso(browser, "kim");
  const page = kim.page;
  const a = await L.project(kim.api, "e2e-pkg", "E2E Packages");
  const b = await L.project(kim.api, "e2e-pkg2", "E2E Packages 2");
  const up = async (p, buf, query) => L.ok((await L.ingest(p.key, p.token, buf, query)).status < 300, `uploaded ${p.key} ${query}`);
  await up(a, doc("jar", [[CORE, "2.10.0", "app/old.jar"]]), "?target=pay-api&kind=image&ref=1.0"); // replaced by the next scan's inventory
  await up(a, doc("jar", [[CORE, "2.14.1", "app/lib/a.jar"], [CORE, "2.14.1", "app/lib/b.jar"], [API, "2.14.1", "app/lib/api.jar"]],
    [["CVE-2021-44228", CORE, "2.14.1", "app/lib/a.jar", "CRITICAL"]]), "?target=pay-api&kind=image&ref=1.1");
  await up(a, doc("npm", [["log4js", "6.9.1"], ["log4js-next", "1.x"]]), "?target=front&kind=repo");
  await up(a, L.fixture("sarif/semgrep.sarif"), "?target=src&kind=repo"); // no package list: cannot be searched
  await up(b, doc("jar", [[CORE, "2.17.1", "worker.jar"]]), "?target=worker&kind=image&ref=3.0");

  // the API: latest inventory only, the caller's projects only, a bad condition is a 400 that shows an example
  const all = await kim.api.get("/packages?q=LOG4J&project=e2e-pkg");
  L.ok(all.items.map((r) => `${r.target_name} ${r.name} ${r.version}`).join(" | ") ===
    `front log4js 6.9.1 | front log4js-next 1.x | pay-api ${API} 2.14.1 | pay-api ${CORE} 2.14.1`, "API: one row per target and package version, from the latest inventory, any letter case");
  const core = all.items.find((r) => r.name === CORE);
  L.ok(core.path_count === 2 && core.open_findings === 1 && core.worst_severity === "CRITICAL" && all.items[0].open_findings === 0,
    "API: paths are counted and the open findings of the package come with their worst severity");
  L.ok(all.totals.matched === 4 && all.totals.projects === 1 && all.totals.targets === 2 && all.totals.targets_searched === 2 &&
    all.totals.targets_without_inventory === 1 && !all.truncated, "API: totals count the matches and the target that has no package list");
  const bad = await kim.api.raw.get("/packages?q=log4j&version=%3C");
  L.ok(bad.status === 400 && bad.body.message.includes("<2.17.1"), "API: an unreadable version condition is refused with an example");
  L.ok((await kim.api.raw.get("/packages?q=l")).status === 400, "API: a one-letter search is refused");

  // the screen: reached from the sidebar, the search box has the focus, examples explain what it is for
  await page.goto(L.BASE + "/");
  await page.getByRole("navigation", { name: "주 메뉴" }).getByRole("link", { name: "패키지 찾기" }).click();
  await page.getByRole("heading", { name: "패키지 찾기", level: 1 }).waitFor();
  const box = page.getByRole("searchbox", { name: "패키지 이름" });
  const version = page.getByRole("textbox", { name: "버전 조건" });
  await L.until(() => box.evaluate((el) => el === document.activeElement), "the search box has the focus after opening the page from the menu");
  await page.getByText("찾을 패키지 이름을 입력하세요").waitFor();
  L.ok(await page.getByRole("button", { name: "openssl" }).count() === 1, "before a search the page explains itself and offers example searches");
  await box.fill("l");
  await box.press("Enter");
  await page.getByRole("alert").filter({ hasText: "2자 이상" }).waitFor();
  L.ok(!new URL(page.url()).search, "a one-letter search is stopped on the page with a message, without a request");

  // a search by name, narrowed to the project so the numbers are this suite's own
  await box.fill("log4j-core");
  await box.press("Enter");
  await page.waitForURL(/\/packages\?q=log4j-core$/);
  const found = page.getByRole("table", { name: "찾은 패키지" });
  await found.getByRole("row", { name: /e2e-pkg2.*worker/ }).waitFor();
  L.ok(true, "Enter searches every visible project and keeps the search in the address");
  await page.getByRole("combobox", { name: "프로젝트" }).selectOption("e2e-pkg");
  await page.getByText("프로젝트 1개 · 대상 1개에서 1건").waitFor();
  const row = found.getByRole("row", { name: /log4j-core/ });
  L.ok(await found.locator("tbody tr").count() === 1 && /2\.14\.1/.test(await row.innerText()) && !/2\.10\.0/.test(await row.innerText()),
    "the project filter leaves the project's one row: the version of the latest scan, not of the older one");
  L.ok(/app\/lib\/a\.jar/.test(await row.innerText()) && /외 1곳/.test(await row.innerText()), "the row shows where the package is and how many more places");
  await page.getByText("대상 1개는 패키지 목록이 없어 찾지 못합니다").waitFor();
  L.ok(true, "the summary says one target has no package list and was not searched");
  await L.shot(page, "packages-result");

  // a version condition: matches, and below them what could not be compared
  await box.fill("log4j");
  await version.fill("<2.17.1");
  await version.press("Enter");
  await page.waitForURL((u) => u.searchParams.get("version") === "<2.17.1" && u.searchParams.get("q") === "log4j" && u.searchParams.get("project") === "e2e-pkg");
  await page.getByText("프로젝트 1개 · 대상 1개에서 2건 · 버전을 비교하지 못함 1건").waitFor();
  L.ok(await found.locator("tbody tr").count() === 2 && await found.getByText("log4js").count() === 0, "<2.17.1 keeps log4j-core and log4j-api 2.14.1 and drops log4js 6.9.1");
  const unknown = page.getByRole("table", { name: "버전을 비교하지 못한 패키지" });
  await unknown.getByRole("row", { name: /log4js-next.*1\.x/ }).waitFor();
  L.ok(await unknown.locator("tbody tr").count() === 1, "the version that cannot be compared is listed apart, not dropped");
  await L.shot(page, "packages-version");
  const eco = page.getByRole("combobox", { name: "패키지 종류" });
  L.ok((await eco.locator("option").allInnerTexts()).join(",") === "모든 종류,maven,npm", "the package type choices come from the result");
  await eco.selectOption("npm");
  await page.getByText("조건에 맞는다고 확인된 패키지는 없습니다").waitFor();
  L.ok(await found.count() === 0 && await unknown.locator("tbody tr").count() === 1, "npm only: nothing confirmed, the uncomparable row stays with a note");
  await eco.selectOption("");

  // the CSV is the same rows; the open findings link leads to the project's findings for that package
  const href = await page.getByRole("link", { name: "CSV 내려받기" }).getAttribute("href");
  const csv = await kim.api.raw.get(href.replace("/api/v1", ""));
  L.ok(csv.status === 200 && csv.body.charCodeAt(0) === 0xfeff && csv.body.includes('"프로젝트"') && csv.body.includes(`"${CORE}","2.14.1","maven"`) &&
    csv.body.includes("비교하지 못함") && csv.body.trimEnd().split("\r\n").length === 4, "CSV: BOM, Korean header and the 3 rows on the screen");
  await found.getByRole("link", { name: /열린 취약점 1건/ }).click();
  await page.waitForURL(/\/projects\/e2e-pkg\/findings\?/);
  await page.getByRole("table", { name: "결과 목록" }).getByRole("row", { name: /CVE-2021-44228/ }).waitFor();
  L.ok(await page.getByRole("table", { name: "결과 목록" }).locator("tbody tr").count() === 1, "열린 취약점 opens the project's findings for that package and target");
  await page.goBack();
  await page.getByText("프로젝트 1개 · 대상 1개에서 2건").waitFor();
  L.ok(await box.inputValue() === "log4j" && await version.inputValue() === "<2.17.1", "Back returns to the search with its conditions");

  // security: the found packages and the condition go into a new advisory form (nothing is saved here)
  await eco.selectOption("maven");
  await page.getByText("프로젝트 1개 · 대상 1개에서 2건").waitFor();
  await page.getByRole("button", { name: "사내 Advisory로 등록" }).click();
  await page.waitForURL(/\/advisories\/new\?/);
  await page.getByRole("heading", { name: "새 Advisory", level: 1 }).waitFor();
  const names = await page.getByLabel(/^패키지( \(행 \d+\))?$/).evaluateAll((els) => els.map((el) => el.value));
  const ranges = await page.getByLabel(/^영향 범위/).evaluateAll((els) => els.map((el) => el.value));
  L.ok(names.join(",") === `${API},${CORE}` && ranges.join(",") === "<2.17.1,<2.17.1" && await page.getByLabel(/^패키지 종류/).first().inputValue() === "maven",
    "사내 Advisory로 등록 opens the new advisory form with the packages, their type and the version condition filled in");
  await page.goBack();

  // nothing found: says what was searched and what could not be
  await box.fill("e2e-no-such-package");
  await box.press("Enter");
  await page.getByText('"e2e-no-such-package"에 맞는 패키지를 찾지 못했습니다').waitFor();
  const none = await page.locator(".empty").innerText();
  L.ok(/패키지 목록이 있는 대상 2개/.test(none) && /대상 1개는 패키지 목록이 없어 찾지 못합니다/.test(none), "no match: the page says how many targets were searched and how many could not be");
  await page.getByRole("button", { name: "이름만으로 다시 찾기" }).click();
  await page.waitForURL(/\/packages\?q=e2e-no-such-package$/);
  L.ok(true, "이름만으로 다시 찾기 drops the other conditions");

  // 1024px: the page does not scroll sideways and the table fits
  await page.setViewportSize({ width: 1024, height: 800 });
  await page.goto(`${L.BASE}/packages?q=log4j&project=e2e-pkg`);
  await found.getByRole("row", { name: /log4j-core/ }).waitFor();
  await L.sleep(200);
  L.ok(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth) && await page.locator(".table-wide").count() === 0,
    "at 1024px neither the page nor the table scrolls sideways");
  await L.shot(page, "packages-1024");
  await page.setViewportSize({ width: 1440, height: 900 });

  // park is a viewer of e2e-pkg only: the shared link shows that project's rows, no advisory button, nothing of e2e-pkg2
  const park = await L.sso(browser, "park");
  await kim.api.put("/projects/e2e-pkg/members", [...await kim.api.get("/projects/e2e-pkg/members"),
    { principal_kind: "user", principal: String((await park.api.get("/me")).id), role: "viewer" }]);
  await park.page.goto(`${L.BASE}/packages?q=log4j-core`);
  const mine = park.page.getByRole("table", { name: "찾은 패키지" });
  await mine.getByRole("row", { name: /e2e-pkg.*pay-api/ }).waitFor();
  // by project key: the fixes suite leaves park another project whose target name also has "worker" in it
  L.ok(await mine.getByText("e2e-pkg2").count() === 0, "a viewer sees his project's packages, not the other project's");
  L.ok(await park.page.getByRole("button", { name: "사내 Advisory로 등록" }).count() === 0, "a viewer has no advisory button");
  L.ok(await park.page.getByRole("link", { name: "CSV 내려받기" }).count() === 1, "a viewer can download the CSV");
  const theirs = await park.api.get("/packages?q=log4j-core&project=e2e-pkg2");
  L.ok(theirs.items.length === 0 && theirs.totals.targets_searched === 0 && theirs.totals.targets_without_inventory === 0, "asking for a project he cannot see gives nothing, not even counts");
  // lee is in neither project
  const lee = await L.sso(browser, "lee");
  const hers = await lee.api.get("/packages?q=log4j-core");
  L.ok(!hers.items.some((r) => r.project_key.startsWith("e2e-pkg")), "someone outside both projects finds none of their packages");
  await browser.close();
});
