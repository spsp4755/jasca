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
  // AI is off on a fresh install: the vulnerability page says so once instead of offering a button that fails
  await kim.page.goto(`${L.BASE}/vulns/CVE-2022-37434`);
  await kim.page.getByText("AI 안내는 관리자가 켜면 쓸 수 있습니다.").waitFor();
  L.ok(await kim.page.getByRole("button", { name: /안내 받기/ }).count() === 0, "with AI off the vulnerability page offers no AI button");
  await browser.close();
});
