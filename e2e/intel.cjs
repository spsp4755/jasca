// 악용 정보 (KEV · EPSS): the two files are uploaded on 관리 → Trivy DB (a bad file is refused, a file under the wrong
// block is applied as what it is), then the badge, the score, the filter and the sort on the results list, the result
// drawer, the vulnerability page, 조치 계획, the report, the home count, the CSV, and the notification for newly
// listed CVEs. Own project (e2e-intel) and the small files in testdata/intel.
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");
const L = require("./lib.cjs");
const DATA = path.join(__dirname, "..", "testdata", "intel");
const tmp = (name, buf) => { const f = path.join(L.OUT, name); fs.writeFileSync(f, buf); return f; };

L.run(async () => {
  const browser = await L.launch();
  const admin = await L.local(browser);
  const kim = await L.sso(browser, "kim");
  const { key, token } = await L.project(kim.api, "e2e-intel", "E2E Intel");
  const report = Buffer.from(JSON.stringify({
    SchemaVersion: 2, ArtifactName: "intel-app", ArtifactType: "container_image", CreatedAt: "2026-01-01T00:00:00Z",
    Results: [{ Target: "app/npm.lock", Class: "lang-pkgs", Type: "npm", Vulnerabilities: [
      ["CVE-2099-10001", "listed-and-scored", "1.0.0", "1.0.1", "HIGH"], ["CVE-2099-10004", "scored-only", "1.0.0", "1.0.1", "HIGH"],
      ["CVE-2099-10009", "no-data", "1.0.0", "1.0.1", "CRITICAL"], ["CVE-2099-10002", "listed-no-fix", "1.0.0", "", "LOW"],
    ].map(([VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Severity]) => ({ VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Severity, Title: `${PkgName}: ${VulnerabilityID}` })) }],
  }));
  L.ok((await L.ingest(key, token, report, "?target=intel-app&kind=image&ref=1.0")).status < 300, "a report with four vulnerabilities uploaded");
  const ch = await admin.api.post("/admin/channels", { kind: "mattermost", name: "e2e-intel", enabled: true, config: { webhook_url: "http://127.0.0.1:9/hooks/e2e-intel" } });
  await kim.api.put(`/projects/${key}/notify`, [{ channel_id: ch.id, events: ["kev_listed"] }]);
  const list = async (q = "") => (await kim.api.get(`/findings?project=${key}${q}`));
  const ids = (p) => p.items.map((i) => i.rule_id.replace("CVE-2099-", "")).join(" ");

  // before any upload: nothing is marked, and only the admin is told what is missing
  let l = await list();
  L.ok(l.items.every((i) => i.kev === false && i.epss === null) && (await list("&kev=true")).total === 0, "without the files no result has a badge or a score");
  L.ok((await kim.api("POST", "/admin/intel")).status === 403 && (await kim.api("GET", "/admin/intel")).status === 403, "the upload is the admin's (403 for kim)");

  // 관리 → Trivy DB → 악용 정보
  const page = admin.page;
  await page.goto(L.BASE + "/admin/trivy");
  const kevBlock = page.getByRole("region", { name: "KEV 목록", exact: true }), epssBlock = page.getByRole("region", { name: "EPSS 점수", exact: true });
  await kevBlock.getByText("올리지 않음", { exact: true }).waitFor();
  await epssBlock.getByText("올리지 않음", { exact: true }).waitFor();
  L.ok(true, "both blocks start as 올리지 않음");
  const kev = fs.readFileSync(path.join(DATA, "kev.json")), epss = fs.readFileSync(path.join(DATA, "epss.csv"));
  await kevBlock.locator('input[type="file"]').setInputFiles(tmp("kev-cut.json", kev.subarray(0, 300)));
  await page.getByText(/KEV 목록\(known_exploited_vulnerabilities\.json\)이나 EPSS 점수 파일.+기존 정보를 그대로 사용합니다/).waitFor();
  L.ok((await admin.api.get("/admin/intel")).kev.loaded_at === null, "a cut-off catalog is refused with the Korean message; nothing is stored");
  // the KEV file under the EPSS block: applied as what it is, and said so
  await epssBlock.locator('input[type="file"]').setInputFiles(path.join(DATA, "kev.json"));
  await page.getByText(/올린 파일이 KEV 목록이어서 KEV 목록을 적용했습니다 \(.+ 기준, CVE 3개\)\. 새로 등재된 CVE는 3개입니다\./).waitFor({ timeout: 30000 });
  await kevBlock.getByText("적용됨", { exact: true }).waitFor();
  await kevBlock.getByText("방금 적용됨").waitFor();
  L.ok((await epssBlock.getByText("방금 적용됨").count()) === 0 && /3개/.test(await kevBlock.locator(".kv").innerText()), "KEV picked under EPSS: applied as KEV, with its date and 3 CVEs");
  await epssBlock.locator('input[type="file"]').setInputFiles(tmp("epss_scores.csv.gz", zlib.gzipSync(epss)));
  await page.getByText(/^EPSS 점수를 적용했습니다 \(.+ 기준, CVE 6개\)\./).waitFor({ timeout: 30000 });
  await epssBlock.getByText("적용됨", { exact: true }).waitFor();
  const st = await admin.api.get("/admin/intel");
  L.ok(st.kev.count === 3 && st.kev.date.startsWith("2026-11-13") && st.epss.count === 6 && st.epss.date.startsWith("2026-11-16"), "API: both sources loaded with their data dates");
  await page.locator(".intel-help > summary").click();
  await page.getByText("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json").waitFor();
  L.ok(true, "the fold-out names the two download addresses");
  await L.shot(page, "intel-admin");

  // the list: inside a severity the exploited one first; filter and sort
  l = await list();
  L.ok(ids(l) === "10009 10001 10004 10002", `default order: CRITICAL, then HIGH with the exploited one first (${ids(l)})`);
  const row = l.items.find((i) => i.rule_id === "CVE-2099-10001");
  L.ok(row.kev === true && row.epss === 0.50312 && row.epss_percentile === 0.97511, "a listed and scored CVE carries kev, epss and epss_percentile");
  L.ok(ids(await list("&kev=true")) === "10001 10002" && ids(await list("&sort=epss")).startsWith("10001 10004"), "kev=true keeps the two listed CVEs; sort=epss puts the highest score first");
  const kp = kim.page;
  await kp.goto(`${L.BASE}/projects/${key}`);
  const rows = kp.getByRole("table", { name: "결과 목록" }).locator("tbody tr");
  await rows.first().waitFor();
  L.ok(await rows.nth(1).getByText("악용 확인", { exact: true }).count() === 1 && /50\.3%/.test(await rows.nth(1).innerText()) && await rows.nth(0).getByText("악용 확인", { exact: true }).count() === 0,
    "screen: the exploited HIGH row has the badge and 50.3%; the CRITICAL row above has neither");
  await kp.getByLabel("악용 확인만").click(); // the box follows the address, so it changes a moment after the click
  await kp.waitForURL(/kev=true/);
  await kp.locator(".result-count").getByText("2").waitFor();
  L.ok(await rows.count() === 2, "악용 확인만: two rows, and the filter is in the address");
  await kp.getByLabel("악용 확인만").click();
  await kp.waitForURL((u) => !u.searchParams.has("kev"));
  await kp.getByRole("button", { name: "악용 가능성 순" }).click();
  await kp.waitForURL(/sort=epss/);
  await L.until(async () => /CVE-2099-10001/.test(await rows.first().innerText()), "악용 가능성 순: the 50.3% row is first");
  await L.shot(kp, "intel-list");
  await rows.first().click();
  const drawer = kp.getByRole("dialog");
  await drawer.getByText("실제 공격에 쓰이는 취약점입니다. 먼저 조치하세요.").waitFor();
  L.ok(/CISA KEV 목록에 있습니다/.test(await drawer.innerText()) && /30일 안에 악용될 확률\s*50\.3%/.test(await drawer.innerText()), "the result drawer says it is exploited and gives the probability");
  await kp.keyboard.press("Escape");

  // vulnerability page: listed with details, scored only, and neither
  await kp.goto(`${L.BASE}/vulns/CVE-2099-10001`);
  const intel = kp.getByRole("region", { name: "악용 정보" });
  await intel.getByText("실제 공격에 쓰이고 있습니다").waitFor();
  const text = await intel.innerText();
  L.ok(/2026\. 11\. 12\./.test(text) && /확인된 바 없음/.test(text) && /Apply updates per vendor instructions\./.test(text) && /50\.3%/.test(text) && /상위 2\.5%/.test(text),
    "vulnerability page: listed on 2026-11-12, no ransomware use known, the required action, 50.3% and its rank");
  await L.shot(kp, "intel-vuln");
  await kp.goto(`${L.BASE}/vulns/CVE-2099-10009`);
  await intel.getByText("목록에 없습니다").waitFor();
  await intel.getByText("점수가 없습니다").waitFor();
  L.ok(true, "a CVE neither file names: 목록에 없습니다 / 점수가 없습니다, not a blank");

  // 조치 계획 and the report
  const plan = await kim.api.get(`/projects/${key}/fixes`);
  L.ok(plan.groups[0].package === "listed-and-scored" && plan.groups[0].kev === 1 && plan.groups[1].package === "no-data" && plan.no_fix_groups[0].kev === 1,
    "plan: the HIGH upgrade that fixes an exploited vulnerability comes before the CRITICAL one that does not");
  await kp.goto(`${L.BASE}/projects/${key}/fixes`);
  await kp.getByRole("heading", { name: "올릴 패키지" }).waitFor();
  L.ok(/악용 확인 1건/.test(await kp.locator(".fix-row").first().innerText()) && /실제 공격에 쓰이는 취약점이 2건 있습니다/.test(await kp.locator(".fix-rest").innerText()),
    "조치 계획: the first row is marked 악용 확인 1건 and the summary counts 2");
  await kp.goto(`${L.BASE}/reports/${key}`);
  await kp.getByText(/실제 공격에 쓰이는 것이 확인된\(CISA KEV\) 열린 취약점/).waitFor();
  L.ok(/열린 취약점\s*2건/.test(await kp.locator(".report-doc").innerText()), "report: the summary counts the 2 exploited vulnerabilities");

  // home and CSV
  await kp.goto(L.BASE + "/");
  await kp.locator(".risk-kev a").click();
  await kp.waitForURL(/\/findings\?kev=true/);
  L.ok(true, "home: the 악용 확인 count links to the filtered list");
  const csv = await (await kim.ctx.request.get(`${L.BASE}/api/v1/findings.csv?project=${key}&kev=true`)).text();
  const lines = csv.trim().split("\r\n");
  L.ok(lines.length === 3 && lines[0].endsWith('"악용 확인(KEV)","EPSS","EPSS 백분위"') && lines[1].endsWith('"Y","0.50312","0.97511"'), "CSV: three more columns at the end");

  // notifications: the first catalog told the project about its 2 open ones; a new catalog only about what it adds
  const sent = () => Number(L.psql(`select count(*) from deliveries where event = 'kev_listed' and channel_id = ${ch.id}`));
  L.ok(sent() === 1, "the first catalog queued one 악용이 확인된 취약점 notification for the project");
  const more = JSON.parse(kev);
  more.vulnerabilities.push({ ...more.vulnerabilities[1], cveID: "CVE-2099-10009", dateAdded: "2026-11-14" });
  more.count = 4;
  await kevBlock.locator('input[type="file"]').setInputFiles(tmp("kev-more.json", JSON.stringify(more)));
  await page.getByText(/새로 등재된 CVE는 1개입니다\./).waitFor({ timeout: 30000 });
  const last = L.psql(`select payload::text from deliveries where event = 'kev_listed' and channel_id = ${ch.id} order by id desc limit 1`);
  L.ok(sent() === 2 && last.includes("CVE-2099-10009") && !last.includes("CVE-2099-10001"), "a new catalog notifies only about the newly listed CVE");
  await kevBlock.locator('input[type="file"]').setInputFiles(path.join(DATA, "kev.json")); // back to the three, for the suites after this one
  await page.getByText(/새로 등재된 CVE는 없습니다\./).waitFor({ timeout: 30000 });
  L.ok(sent() === 2, "an older catalog lists nothing new: nobody is told");
  await kp.goto(`${L.BASE}/projects/${key}/settings?tab=notify`);
  await kp.getByText("악용이 확인된 취약점").first().waitFor();
  await page.goto(L.BASE + "/admin/audit");
  await page.getByText("악용 정보 올리기", { exact: true }).first().waitFor();
  await page.getByText("악용 정보 올리기 실패", { exact: true }).first().waitFor();
  L.ok(true, "project settings offer the event; the audit log names the uploads and the refused file");
  await admin.api.del(`/admin/channels/${ch.id}`);
  await browser.close();
});
