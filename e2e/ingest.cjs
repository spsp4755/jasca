// CI-style uploads of the format fixtures with the token the projects suite made (curl --data-binary equivalent).
const zlib = require("zlib");
const L = require("./lib.cjs");
L.run(async () => {
  const browser = await L.launch();
  const kim = await L.sso(browser, "kim");
  const { token } = L.state();
  L.ok(!!token, "token from the projects suite");
  const key = "e2e-proj";

  // an upload without or with a wrong token is refused
  L.ok((await L.ingest(key, "jasca_wrong", L.fixture("trivy/image-debian.json"))).status === 401, "wrong token refused (401)");

  // no CRITICAL: the default policy passes
  const deb = await L.ingest(key, token, L.fixture("trivy/image-debian.json"), "?target=debian-app&kind=image&ref=1.0");
  L.ok(deb.status === 200 || deb.status === 201, `debian image report accepted (${deb.status})`);
  L.ok(deb.body.policy.passed === true && !deb.body.duplicate, "no CRITICAL open: policy passed:true");

  // same report again: duplicate, no new scan
  const again = await L.ingest(key, token, L.fixture("trivy/image-debian.json"), "?target=debian-app&kind=image&ref=1.0");
  L.ok(again.body.duplicate === true && again.body.scan_id === deb.body.scan_id, "same report again answers duplicate:true with the same scan");

  // a CRITICAL finding fails the gate; gzip body like `gzip -c | curl -H Content-Encoding: gzip`
  const alp = await fetch(`${L.BASE}/api/v1/projects/${key}/scans?target=alpine-app&kind=image&ref=1.0`, {
    method: "POST", headers: { Authorization: "Bearer " + token, "Content-Encoding": "gzip" }, body: zlib.gzipSync(L.fixture("trivy/image-alpine.json")) });
  const alpBody = await alp.json();
  L.ok(alp.ok && alpBody.policy.passed === false, "CRITICAL in the report: policy passed:false (gzip upload)");
  L.ok(alpBody.policy.reasons.length > 0, "the failure carries a reason");

  // the other formats
  for (const [file, query] of [
    ["trivy/fs-mixed.json", "?target=mixed&kind=fs"], ["harbor/report.json", "?target=harbor-img&kind=image"],
    ["sarif/semgrep.sarif", "?target=semgrep&kind=repo"], ["sarif/checkov.sarif", "?target=checkov&kind=repo"], ["cyclonedx/image.json", "?target=sbom&kind=sbom"]]) {
    const r = await L.ingest(key, token, L.fixture(file), query);
    L.ok(r.status === 200 || r.status === 201, `${file} accepted (${r.status})`);
  }
  L.ok((await L.ingest(key, token, Buffer.from("not a report"), "?target=x&kind=fs")).status === 400, "garbage body refused with 400");

  // findings visible through the API and on the project's results screen
  const f = await kim.api.get(`/findings?project=${key}&status=open&limit=200`);
  const ids = new Set(f.items.map((i) => i.rule_id));
  L.ok(ids.has("CVE-2022-37434") && ids.has("CVE-2026-84782"), "API lists the findings of both image reports");
  await kim.page.goto(`${L.BASE}/projects/${key}`);
  await kim.page.getByRole("table", { name: "결과 목록" }).getByText("CVE-2022-37434").first().waitFor();
  L.ok(true, "project results screen shows CVE-2022-37434");
  const scans = await kim.api.get(`/projects/${key}/scans`);
  L.ok((scans.items ?? scans).length >= 7, "scan history has the uploads");
  await L.shot(kim.page, "ingest-results");
  // a scan that checks fewer kinds: what it could not see is neither "gone" nor, next time, "new"
  const d = await L.project(kim.api, "e2e-diff", "E2E Diff");
  const full = JSON.parse(L.fixture("trivy/fs-mixed.json")); // 4 vulnerabilities, 2 misconfigurations, 2 secrets
  const doc = (keep, n) => Buffer.from(JSON.stringify({ ...full, CreatedAt: `2026-01-0${n}T00:00:00Z`, Results: full.Results.filter((r) => keep.includes(r.Class)) }));
  const up = async (keep, scanners, n, target = "mixed") => (await L.ingest(d.key, d.token, doc(keep, n), `?target=${target}&kind=fs&scanners=${scanners}`)).body;
  await up(["lang-pkgs", "config", "secret"], "vuln,misconfig,secret", 1);
  const narrow = await up(["lang-pkgs", "config"], "vuln,misconfig", 2); // the secret scanner switched off
  let diff = (await kim.api.get(`/scans/${narrow.scan_id}`)).diff;
  L.ok(diff.new === 0 && diff.fixed === 0 && diff.unchanged === 6 && diff.not_covered === 2 && narrow.summary.open === 8,
    `the narrower scan resolves nothing: 2 secrets it did not check stay open and are not counted as gone (${JSON.stringify(diff)})`);
  await kim.page.goto(`${L.BASE}/scans/${narrow.scan_id}`);
  await kim.page.getByText("이전 스캔에 있던 2건은 이번 스캔이 검사하지 않은 종류라 그대로 열려 있습니다.").waitFor();
  await kim.page.getByRole("tab", { name: /^사라짐/ }).click();
  await kim.page.getByText("사라진 결과가 없습니다").waitFor();
  await kim.page.getByRole("tab", { name: /이 스캔의 전체 결과/ }).click();
  await L.until(async () => await kim.page.getByRole("table", { name: "결과" }).getByRole("row").count() === 7, "the page says so in one line, and its lists match the numbers (사라짐 0, 전체 6)");
  await L.shot(kim.page, "ingest-scan-diff");
  const back = await up(["lang-pkgs", "config", "secret"], "vuln,misconfig,secret", 3);
  diff = (await kim.api.get(`/scans/${back.scan_id}`)).diff;
  L.ok(diff.new === 0 && diff.unchanged === 8 && diff.not_covered === 0, `the next full scan does not call the never-closed secrets new (${JSON.stringify(diff)})`);

  // policy switched off: CI still reads passed:true, the screens say the scan was not judged
  await kim.api.put(`/projects/${d.key}/policy`, { enabled: false });
  const off = await up(["lang-pkgs", "config", "secret"], "vuln,misconfig,secret", 4);
  L.ok(off.policy.passed === true && off.policy.disabled === true, "with the policy off the upload answers passed:true and disabled:true");
  await kim.page.goto(`${L.BASE}/scans/${off.scan_id}`);
  await kim.page.getByText("정책 사용 안 함").first().waitFor();
  L.ok(await kim.page.getByText("정책 통과").count() === 0, "the scan page shows 정책 사용 안 함, not a green 정책 통과 over CRITICAL findings");
  await kim.page.goto(`${L.BASE}/projects/${d.key}/scans`);
  const hist = kim.page.getByRole("table", { name: "스캔 기록" });
  await hist.getByRole("row").nth(1).getByText("사용 안 함").waitFor();
  L.ok(/소스·패키지/.test(await hist.innerText()) && !/파일시스템/.test(await hist.innerText()), "the scan history's 정책 column says 사용 안 함; the kind reads 소스·패키지 like the scan form");

  // the printed report fits A4: no 1024px minimum, a long unbroken target name wraps, secrets show where they are
  await up(["lang-pkgs", "secret"], "vuln,secret", 5, "x".repeat(160));
  await kim.page.goto(`${L.BASE}/reports/${d.key}`);
  await kim.page.getByRole("table", { name: "주요 취약점" }).getByText("creds.sh:1").first().waitFor();
  await kim.page.emulateMedia({ media: "print" });
  await kim.page.setViewportSize({ width: 690, height: 1000 }); // A4 less the page margins, in CSS px
  const wide = await kim.page.evaluate(() => [document.documentElement.scrollWidth, ...[...document.querySelectorAll(".report-doc table")].map((t) => Math.ceil(t.getBoundingClientRect().right))]);
  L.ok(wide.every((w) => w <= 690), `in print the page and every report table fit the paper width (${wide.join(", ")} of 690px)`);
  await kim.page.pdf({ path: L.OUT + "/shots/report-a4.pdf", format: "A4" });
  await kim.page.emulateMedia({ media: null });
  await kim.page.setViewportSize({ width: 1440, height: 900 });

  // home: the oldest-CRITICAL panel is about every kind of result
  await kim.page.goto(L.BASE + "/");
  await kim.page.getByRole("heading", { name: "오래 열린 CRITICAL 결과" }).waitFor();
  L.ok(true, "home titles the panel 오래 열린 CRITICAL 결과");
  await L.shot(kim.page, "ingest-home");

  // AI is off on a fresh install: the vulnerability page says so once instead of offering a button that fails
  await kim.page.goto(`${L.BASE}/vulns/CVE-2022-37434`);
  await kim.page.getByText("AI 안내는 관리자가 켜면 쓸 수 있습니다.").waitFor();
  L.ok(await kim.page.getByRole("button", { name: /안내 받기/ }).count() === 0, "with AI off the vulnerability page offers no AI button");
  await browser.close();
});
