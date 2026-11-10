// 관리 → Trivy DB. Uploads: a bad bundle is refused with a Korean message and the old DB stays; a Java DB picked under
// the 취약점 DB block is still installed and the page says which DB it was; a good DB is installed and its recheck run
// completes. Scan options: saved with one button, refused by the server with the reason shown next to the form.
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");
const { execFileSync } = require("child_process");
const L = require("./lib.cjs");
L.run(async () => {
  const bundle = process.env.JASCA_E2E_TRIVY_BUNDLE;
  L.ok(!!bundle && fs.existsSync(bundle), "good DB bundle prepared by run.sh");
  const bad = path.join(L.OUT, "bad-db.tar.gz");
  fs.writeFileSync(bad, zlib.gzipSync(Buffer.from("this is not a trivy db bundle")));
  // A stand-in javadb.tar.gz: the server checks the file names, the size and metadata.json, not the DB content. No
  // suite after this one scans a JAR, and run.sh starts every run with an empty data directory.
  const jdir = fs.mkdtempSync(path.join(L.OUT, "javadb-"));
  fs.writeFileSync(path.join(jdir, "trivy-java.db"), Buffer.alloc(2 << 20, 7));
  fs.writeFileSync(path.join(jdir, "metadata.json"), JSON.stringify({ Version: 1, NextUpdate: "2026-11-12T00:00:00Z", UpdatedAt: "2026-11-09T00:00:00Z" }));
  const javadb = path.join(L.OUT, "javadb.tar.gz");
  execFileSync("tar", ["-czf", javadb, "-C", jdir, "trivy-java.db", "metadata.json"]);

  const browser = await L.launch();
  const admin = await L.local(browser, { next: "/admin/trivy" });
  const page = admin.page;
  const dbBlock = page.getByRole("region", { name: "취약점 DB", exact: true });
  const javaBlock = page.getByRole("region", { name: "Java DB", exact: true });
  const before = await admin.api.get("/admin/trivy");
  L.ok(before.db_version > 0, "the server starts with the copied DB (v" + before.db_version + ")");
  L.ok(before.java_db === null, "and without a Java DB");
  await dbBlock.getByText("설치됨", { exact: true }).waitFor();
  await javaBlock.getByText("설치 안 됨", { exact: true }).waitFor();
  L.ok(true, "the two blocks show 설치됨 / 설치 안 됨");
  L.ok((await admin.api.get("/auth/config")).trivy_db_ready === true, "/auth/config tells signed-in users the vulnerability DB is ready");
  await javaBlock.getByText(/없으면 그 파일만 건너뛰고 나머지를 검사하며, 스캔 결과에 검사하지 못한 Java 파일이 있다고 표시합니다/).waitFor();
  await page.getByText(/스캐너를 끈 경우는 다릅니다/).waitFor();
  L.ok(true, "the page says what happens without a Java DB and what a switched-off scanner does to open results");
  const runsBefore = (await admin.api.get("/admin/recheck")).length;

  await dbBlock.locator('input[type="file"]').setInputFiles(bad);
  await page.getByText(/올바른 Trivy DB 번들/).waitFor();
  L.ok(true, "bad bundle rejected with the Korean message, old DB kept");
  const same = await admin.api.get("/admin/trivy");
  L.ok(same.db_version === before.db_version && same.updated_at === before.updated_at, "DB status unchanged after the bad bundle");
  L.ok((await admin.api.get("/admin/recheck")).length === runsBefore, "no recheck run started for the bad bundle");

  // the Java file under the wrong block: applied as what it is, and said so
  await dbBlock.locator('input[type="file"]').setInputFiles(javadb);
  await page.getByText(/올린 파일이 Java DB여서 Java DB를 적용했습니다 \(.+ 생성\)\. 다음 서버 스캔부터 JAR\/WAR\/EAR 파일을 검사합니다\./).waitFor({ timeout: 30000 });
  L.ok(true, "Java DB picked under 취약점 DB: the message says a Java DB was applied");
  await javaBlock.getByText("설치됨", { exact: true }).waitFor();
  await javaBlock.getByText("방금 적용됨").waitFor();
  L.ok((await dbBlock.getByText("방금 적용됨").count()) === 0, "only the Java DB block is marked 방금 적용됨, with its 생성 시각");
  const withJava = await admin.api.get("/admin/trivy");
  L.ok(withJava.java_db && withJava.java_db.updated_at === "2026-11-09T00:00:00Z" && withJava.updated_at === before.updated_at, "API: java_db installed, the vulnerability DB untouched");
  L.ok((await admin.api.get("/admin/recheck")).length === runsBefore, "a Java DB starts no recheck (stored package lists do not change)");

  await dbBlock.locator('input[type="file"]').setInputFiles(bundle);
  await page.getByText(/^취약점 DB를 적용했습니다 \(.+ 생성\)\. 저장된 결과의 재평가를 시작했습니다\./).waitFor({ timeout: 120000 });
  await dbBlock.getByText("방금 적용됨").waitFor();
  L.ok(true, "good bundle installed, the message says the recheck started");
  const run = await L.until(async () => {
    const runs = await admin.api.get("/admin/recheck");
    const r = runs.find((x) => x.reason === "trivydb");
    return r && r.state !== "running" && r;
  }, "recheck run of the new DB finishes", 180000);
  L.ok(run.state === "done" && run.total > 0 && run.done === run.total, `recheck run done (${run.done}/${run.total} targets, ${run.new_findings} new findings)`);
  await page.reload();
  await page.getByRole("table", { name: "재평가 실행 기록" }).getByText("Trivy DB 갱신").first().waitFor();
  L.ok(true, "run listed on the Trivy DB screen");
  await javaBlock.getByText("설치됨", { exact: true }).waitFor();
  L.ok(true, "Java DB still shown as installed after a reload");

  // scan options
  const saveBtn = page.getByRole("button", { name: "저장" });
  L.ok(await saveBtn.isDisabled(), "저장 is disabled until something changes");
  await page.getByLabel(/^조치 버전이 없는 취약점 제외/).check();
  await page.getByRole("group", { name: "결과에 넣을 심각도" }).getByLabel("LOW", { exact: true }).uncheck();
  await page.getByLabel("건너뛸 디렉터리").fill("node_modules\n\n  **/testdata  \n");
  await saveBtn.click();
  await page.getByText("스캔 옵션을 저장했습니다. 다음 스캔과 재평가부터 적용됩니다.").waitFor();
  const opt = await admin.api.get("/admin/trivy");
  L.ok(opt.ignore_unfixed === true && opt.severities.join() === "CRITICAL,HIGH,MEDIUM,UNKNOWN" && opt.skip_dirs.join() === "node_modules,**/testdata",
    "options saved: ignore_unfixed, severities without LOW, two trimmed patterns");
  await L.until(() => saveBtn.isDisabled(), "저장 is disabled again after saving");
  await page.getByLabel("건너뛸 파일").fill("x".repeat(201));
  await saveBtn.click();
  await page.getByRole("alert").filter({ hasText: /1~200자/ }).waitFor();
  L.ok((await admin.api.get("/admin/trivy")).skip_files.length === 0, "a 201-character pattern is refused by the server, the reason is shown by the form, nothing is saved");
  // back to the defaults, whatever runs next
  await admin.api.put("/admin/trivy", { scanners: ["vuln", "secret"], ignore_unfixed: false, severities: [], pkg_types: [], include_dev_deps: false,
    detection_priority: "precise", skip_dirs: [], skip_files: [], timeout_min: 0 });
  await browser.close();
});
