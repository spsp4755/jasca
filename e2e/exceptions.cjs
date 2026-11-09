// lee (member through the department) requests an exception in the UI, kim (security) approves it; nobody approves their own.
const L = require("./lib.cjs");
L.run(async () => {
  const browser = await L.launch();
  const kim = await L.sso(browser, "kim");
  const lee = await L.sso(browser, "lee");
  const { key, token } = await L.project(kim.api, "e2e-exc", "E2E Exceptions");
  await kim.api.put(`/projects/${key}/members`, [{ principal_kind: "group", principal: (await kim.api.get("/principals?q=" + encodeURIComponent("개발본부/플랫폼팀"))).find((p) => p.kind === "group").principal, role: "member" },
    { principal_kind: "user", principal: String((await kim.api.get("/me")).id), role: "owner" }]);
  const up = await L.ingest(key, token, L.fixture("trivy/image-alpine.json"), "?target=alpine-app&kind=image&ref=1.0");
  L.ok(up.status < 300, "report uploaded");

  // lee requests through the finding drawer
  await lee.page.goto(`${L.BASE}/projects/${key}`);
  await lee.page.getByRole("table", { name: "결과 목록" }).getByRole("row", { name: /CVE-2022-37434/ }).locator(".pkg-name").click();
  await lee.page.getByRole("button", { name: "예외 요청" }).click();
  const dlg = lee.page.getByRole("dialog", { name: "예외 요청" });
  await dlg.getByLabel("사유").fill("내부망 전용 서비스로 해당 기능을 쓰지 않음");
  await dlg.getByRole("button", { name: "요청 보내기" }).click();
  await lee.page.getByText("예외를 요청했습니다").waitFor();
  L.ok(true, "lee's request sent from the finding drawer");

  const pend = (await lee.api.get("/exceptions")).filter((e) => e.status === "pending");
  L.ok(pend.length === 1 && pend[0].project_key === key, "request is pending and visible to lee");
  const id = pend[0].id;

  // lee cannot approve (not security): no button, API refuses
  await lee.page.goto(`${L.BASE}/exceptions`);
  await lee.page.getByRole("table", { name: "예외 목록" }).getByText("내부망 전용").waitFor();
  L.ok(await lee.page.getByRole("button", { name: "승인", exact: true }).count() === 0, "lee has no approve button");
  L.ok((await lee.api.raw.post(`/exceptions/${id}/approve`, { note: "" })).status === 403, "lee's API approve is refused (403)");

  // kim approves in the approvals queue
  await kim.page.goto(`${L.BASE}/exceptions/approvals`);
  const row = kim.page.getByRole("table", { name: "예외 목록" }).getByRole("row", { name: /내부망 전용/ });
  await row.getByRole("button", { name: "승인", exact: true }).click();
  await kim.page.getByRole("dialog", { name: "예외 승인" }).getByLabel("메모").fill("확인함");
  await kim.page.getByRole("dialog", { name: "예외 승인" }).getByRole("button", { name: "승인", exact: true }).click();
  await kim.page.getByText("승인했습니다.").waitFor();
  const after = (await kim.api.get("/exceptions")).find((e) => e.id === id);
  L.ok(after.status === "approved", "kim approved the request");
  const fnd = await kim.api.get(`/findings?project=${key}&limit=50&status=open,excepted,accepted,false_positive,fixed`);
  L.ok(fnd.items.find((i) => i.rule_id === "CVE-2022-37434")?.status !== "open", "the approved finding is no longer open");

  // kim cannot approve a request of their own
  const mine = await kim.api.post("/exceptions", { scope: "project_vuln", project_key: key, vuln_id: "CVE-2022-37434", resolution: "accepted", reason: "own request",
    expires_at: new Date(Date.now() + 30 * 864e5).toISOString() });
  const own = Array.isArray(mine) ? mine[0] : mine;
  await kim.page.goto(`${L.BASE}/exceptions/approvals`);
  const mrow = kim.page.getByRole("table", { name: "예외 목록" }).getByRole("row", { name: /own request/ });
  await mrow.waitFor();
  L.ok(await mrow.getByRole("button", { name: "승인", exact: true }).isDisabled(), "approve is disabled on kim's own request");
  const r = await kim.api.raw.post(`/exceptions/${own.id ?? (own.ids ?? [])[0]}/approve`, { note: "" });
  L.ok(r.status >= 400 && r.status < 500, `API refuses self-approval (${r.status})`);
  await browser.close();
});
