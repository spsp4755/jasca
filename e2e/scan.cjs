// Server-side scan of a small tar.gz with the real Trivy binary and DB (run.sh skips this suite without them). Then what
// a scan must never do: look clean when it examined nothing, skipped Java archives, or was given an image as source.
// This suite runs before trivydb.cjs, so no Java DB is installed here.
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
  L.ok(/패키지 1개를 검사했습니다/.test(await run.innerText()), "the result says how many packages were examined");
  L.ok(await page.evaluate(() => document.activeElement?.id === "h-run"), "keyboard focus moved to the result heading");
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
  const raw = await (await kim.ctx.request.get(`${L.BASE}/api/v1/scans/${id}/raw`)).json();
  L.ok(raw.ArtifactName === "lodash-app" && raw.SchemaVersion === 2 && raw.Results.length > 0, `the downloaded report names the target, not the server's work directory (${raw.ArtifactName})`);

  // files in tar order -> .out/<name>.tar.gz
  const lock = fs.readFileSync(path.join(dir, "package-lock.json"));
  const pack = (name, files) => {
    const d = fs.mkdtempSync(path.join(L.OUT, name + "-"));
    for (const [p, c] of files) { fs.mkdirSync(path.dirname(path.join(d, p)), { recursive: true }); fs.writeFileSync(path.join(d, p), c); }
    const out = path.join(L.OUT, name + ".tar.gz");
    execFileSync("tar", ["-czf", out, "-C", d, ...files.map(([p]) => p)]);
    fs.rmSync(d, { recursive: true, force: true });
    return out;
  };
  const scanFile = async (target, file) => {
    const r = await kim.ctx.request.post(`${L.BASE}/api/v1/projects/e2e-scan/scan-jobs`, { headers: { Origin: L.BASE },
      multipart: { target, kind: "fs", file: { name: path.basename(file), mimeType: "application/gzip", buffer: fs.readFileSync(file) } } });
    L.ok(r.status() === 201, `${target}: upload accepted`);
    const { scan_id } = await r.json();
    return L.until(async () => { const s = await kim.api.get(`/scans/${scan_id}`); return ["done", "failed"].includes(s.status) && s; }, `${target}: scan finished`, 120000);
  };
  const notes = await scanFile("notes", pack("notes", [["notes.txt", "nothing to examine here"]]));
  L.ok(notes.status === "done" && notes.summary.packages === 0 && /찾지 못했습니다/.test(notes.summary.warnings?.[0]), "an archive with nothing to examine: done, 0 packages, a warning that says so");
  L.ok(notes.policy.passed === false && notes.policy.reasons.length === 1, "and its policy does not pass: " + notes.policy.reasons[0]);
  await page.goto(`${L.BASE}/scans/${notes.id}`);
  await page.getByText(/검사할 수 있는 패키지나 설정 파일을 찾지 못했습니다/).waitFor();
  L.ok(await page.getByText("정책 통과").count() === 0 && (await page.getByText("정책 실패").count()) > 0, "the scan page shows the warning and no green 정책 통과");
  await L.shot(page, "scan-nothing-examined");
  const jar = await scanFile("with-jar", pack("with-jar", [["package-lock.json", lock], ["lib/app.jar", "PK"], ["build/app.war", "PK"]]));
  L.ok(jar.status === "done" && jar.summary.packages === 1 && jar.summary.warnings?.length === 1 && /JAR\/WAR\/EAR 파일 2개는 검사하지 않았습니다/.test(jar.summary.warnings[0]),
    "Java archives without a Java DB: the rest is scanned and the result says 2 files were not examined");
  const img = await scanFile("image-as-source", pack("image-as-source", [["blobs/sha256/aa", "layer"], ["index.json", "{}"], ["oci-layout", "{}"]]));
  L.ok(img.status === "failed" && /파일 종류를 '컨테이너 이미지'로 골라/.test(img.error), "an image layout uploaded as source fails with what to do: " + img.error);

  // the form: a source archive that starts with index.json is still source; an empty file is refused when chosen
  await page.goto(L.BASE + "/scan");
  await page.locator('input[type="file"]').setInputFiles(pack("pwa-src", [["index.json", '{"name":"pwa"}'], ["manifest.json", '{"name":"pwa"}'], ["package-lock.json", lock]]));
  await page.getByRole("radio", { name: "소스 코드·패키지" }).waitFor();
  L.ok(await page.getByRole("radio", { name: "소스 코드·패키지" }).isChecked(), "a source tar.gz whose first entry is index.json is not guessed as an image");
  const empty = path.join(L.OUT, "empty.zip");
  fs.writeFileSync(empty, "");
  await page.locator('input[type="file"]').setInputFiles(empty);
  await page.getByText("빈 파일입니다").waitFor();
  L.ok(await page.locator(".dropzone.has-file").count() === 0, "a 0-byte file is refused when chosen");
  // beside the form: the latest uploads can be scanned again without retyping, and the commands that make the file
  const aside = page.getByRole("complementary", { name: "스캔 도움말과 최근 스캔" });
  const againBtn = aside.getByRole("button", { name: / 다시 스캔$/ }).first();
  const againTarget = (await againBtn.getAttribute("aria-label")).replace(/ 다시 스캔$/, "");
  await againBtn.click();
  L.ok(await page.getByLabel(/^대상 이름/).inputValue() === againTarget && await page.getByRole("combobox", { name: /^프로젝트/ }).inputValue() === "e2e-scan",
    "다시 on a recent scan fills in its project and target: " + againTarget);
  L.ok(await aside.getByText("docker save -o app.tar 이미지:태그").count() === 1 && await aside.getByRole("button", { name: /명령 복사$/ }).count() === 2, "the side shows how to make each kind of file, with copy buttons");
  // A release per file name (relapp-1.0, relapp-1.1) must stay one target: the version goes to its own field, and the
  // second scan closes what the upgrade fixed. A version typed into the name is caught before it makes a second target.
  const release = async (ver, lodash, typed) => {
    await page.goto(L.BASE + "/scan");
    await page.locator('input[type="file"]').setInputFiles(pack("relapp-" + ver, [["package-lock.json", lock.toString().replaceAll("4.17.15", lodash)]]));
    await page.getByRole("radio", { name: "소스 코드·패키지" }).waitFor();
    const name = page.getByLabel(/^대상 이름/), version = page.getByLabel("버전");
    await page.waitForFunction(() => document.querySelector(".scan-form select").value === "e2e-scan"); // the last project used, once the list is in
    L.ok(await name.inputValue() === "relapp" && await version.inputValue() === ver, `relapp-${ver}.tar.gz fills in target relapp and version ${ver}`);
    if (typed) {
      await page.getByText("이미 있는 대상입니다").waitFor();
      await name.fill(typed);
      await version.fill("");
      await page.locator(".scan-similar").getByText("relapp", { exact: true }).waitFor();
      await page.getByRole("button", { name: "이 대상으로 스캔" }).click();
      L.ok(await name.inputValue() === "relapp" && await version.inputValue() === ver && await page.locator(".scan-similar").count() === 0,
        `typing ${typed} as the target is caught: one click goes back to relapp and keeps the version`);
    }
    await page.getByRole("button", { name: "스캔 시작" }).click();
    await page.locator(".scan-run").getByText(/검사를 마쳤습니다|스캔하지 못했습니다/).waitFor({ timeout: 120000 });
    const t = (await kim.api.get("/projects/e2e-scan/targets")).find((x) => x.name === "relapp");
    return { t, scans: (await kim.api.get(`/projects/e2e-scan/scans?target_id=${t.id}`)).items };
  };
  const projOpen = async () => (await kim.api.get("/projects/e2e-scan")).counts.open;
  const open0 = await projOpen();
  const r1 = await release("1.0", "4.17.15");
  L.ok(r1.t.counts.open > 0 && r1.scans[0].ref === "1.0", `release 1.0 has ${r1.t.counts.open} open findings and the scan carries its version`);
  const r2 = await release("1.1", "4.17.21", "relapp-1.1");
  const fixed = (await kim.api.get(`/findings?project=e2e-scan&target_id=${r2.t.id}&status=fixed&limit=100`)).total;
  L.ok(r2.t.id === r1.t.id && r2.scans.length === 2 && r2.t.counts.open < r1.t.counts.open && fixed > 0 && await projOpen() === open0 + r2.t.counts.open,
    `release 1.1 landed on the same target: ${fixed} findings became 조치됨, open ${r1.t.counts.open} → ${r2.t.counts.open}`);
  // the way out for targets that did get a version in their name: an owner renames (findings follow) or deletes them
  await page.goto(L.BASE + "/projects/e2e-scan/targets");
  await page.getByRole("button", { name: "relapp 이름 변경" }).click();
  const dlg = page.getByRole("dialog");
  await dlg.getByLabel("대상 이름").fill("lodash-app");
  await dlg.getByRole("button", { name: "변경" }).click();
  await dlg.getByText("같은 종류와 이름의 대상이 이미 있습니다").waitFor();
  await dlg.getByLabel("대상 이름").fill("relapp-web");
  await dlg.getByRole("button", { name: "변경" }).click();
  await page.getByRole("button", { name: "relapp-web 삭제" }).waitFor();
  const renamed = (await kim.api.get("/projects/e2e-scan/targets")).find((x) => x.id === r1.t.id);
  L.ok(renamed.name === "relapp-web" && renamed.counts.open === r2.t.counts.open, "a target can be renamed; a taken name is refused, and its findings follow");
  await page.getByRole("button", { name: "relapp-web 삭제" }).click();
  await dlg.getByText(/되돌릴 수 없습니다/).waitFor();
  await dlg.getByRole("button", { name: "삭제" }).click();
  await page.getByText('대상 "relapp-web"을(를) 삭제했습니다.').waitFor();
  L.ok(!(await kim.api.get("/projects/e2e-scan/targets")).some((x) => x.id === r1.t.id) && await projOpen() === open0, "a target can be deleted, and the project's open count drops with it");
  // several files at once: a row per file and a scan each; two files for one target are refused before anything goes up
  await page.goto(L.BASE + "/scan");
  await page.waitForFunction(() => document.querySelector(".scan-form select").value === "e2e-scan");
  await page.locator('input[type="file"]').setInputFiles([pack("multi-a-2.0", [["package-lock.json", lock]]), pack("multi-b", [["package-lock.json", lock]])]);
  const rows = page.getByRole("list", { name: "검사할 파일 목록" });
  const rowB = rows.getByLabel("multi-b.tar.gz 대상 이름");
  await rowB.waitFor();
  L.ok(await rows.getByLabel("multi-a-2.0.tar.gz 대상 이름").inputValue() === "multi-a" && await rows.getByLabel("multi-a-2.0.tar.gz 버전").inputValue() === "2.0"
    && await rows.getByLabel("multi-b.tar.gz 파일 종류").inputValue() === "fs" && await page.getByLabel(/^대상 이름/).count() === 0,
    "two files picked at once get a row each, with kind, target and version filled in from the file");
  await rowB.fill("multi-a");
  await page.getByRole("button", { name: "2개 스캔 시작" }).click();
  await page.getByText("같은 대상 이름이 두 번 있습니다").waitFor();
  L.ok(await page.locator(".scan-run").count() === 0 && await rowB.getAttribute("aria-invalid") === "true", "two files for one target are refused before anything is uploaded");
  await rowB.fill("multi-b");
  await page.getByRole("button", { name: "2개 스캔 시작" }).click();
  const many = page.locator(".scan-run");
  for (const n of ["multi-a", "multi-b"]) await many.getByRole("link", { name: n + " 결과 보기" }).waitFor({ timeout: 120000 });
  const mt = (await kim.api.get("/projects/e2e-scan/targets")).filter((x) => /^multi-[ab]$/.test(x.name));
  const ma = mt.length === 2 ? (await kim.api.get(`/projects/e2e-scan/scans?target_id=${mt.find((x) => x.name === "multi-a").id}`)).items : [];
  L.ok(mt.length === 2 && mt.every((x) => x.counts.open > 0) && ma.length === 1 && ma[0].status === "done" && ma[0].ref === "2.0"
    && await many.getByText("2개 중 2개를 올렸습니다").count() === 1, "both files were uploaded one after another and scanned as two targets");
  await L.shot(page, "scan-batch");
  for (const x of mt) await kim.api.del(`/projects/e2e-scan/targets/${x.id}`); // the suites after this one count this project's findings
  await page.goto(L.BASE + "/scan");
  // the sidebar folds to icons (button and [ key), keeps link names for screen readers, and remembers it
  await page.getByRole("button", { name: "사이드바 접기" }).click();
  await page.waitForFunction(() => document.querySelector(".sidebar").getBoundingClientRect().width <= 64); // the fold is animated
  L.ok(await page.getByRole("link", { name: "취약점", exact: true }).getAttribute("title") === "취약점", "the sidebar folds to an icon rail; links keep their names and get a tooltip");
  await page.reload();
  await page.getByRole("button", { name: "사이드바 펴기" }).waitFor();
  L.ok(true, "the folded sidebar is remembered after a reload");
  await page.locator("main h1").click();
  await page.keyboard.press("[");
  await page.getByRole("button", { name: "사이드바 접기" }).waitFor();
  const edge = page.getByRole("separator", { name: "사이드바 너비 조절" });
  await edge.focus();
  for (let i = 0; i < 3; i++) await page.keyboard.press("ArrowRight");
  L.ok(await edge.getAttribute("aria-valuenow") === "276", "the sidebar edge resizes with the arrow keys (228 → 276)");
  await edge.dblclick();
  L.ok(await edge.getAttribute("aria-valuenow") === "228", "double-clicking the edge restores the default width");
  // no vulnerability DB (what /auth/config would say on a new server): the page says so before a file is picked
  await page.route("**/api/v1/auth/config", async (route) => {
    const r = await route.fetch();
    await route.fulfill({ response: r, json: { ...(await r.json()), trivy_db_ready: false } });
  });
  await page.reload();
  await page.getByText("취약점 DB가 아직 설치되지 않아 스캔할 수 없습니다.").waitFor();
  L.ok(await page.getByText("관리자에게 요청하세요.").count() === 1 && await page.getByRole("button", { name: "스캔 시작" }).isDisabled(),
    "without a vulnerability DB a member is told to ask the admin and 스캔 시작 is disabled");
  await page.unroute("**/api/v1/auth/config");
  fs.rmSync(dir, { recursive: true, force: true });
  await browser.close();
});
