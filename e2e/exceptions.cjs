// lee (member through the department) requests an exception in the UI, kim (security) approves it; nobody approves their own.
// Around that: what park sees without access and as a viewer, what a security user may ask for outside their projects,
// and the approvals table at a 1024px window.
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
  const fid = (await kim.api.get(`/findings?project=${key}&limit=50`)).items.find((i) => i.rule_id === "CVE-2022-37434").id;

  // park has no access: the report and a finding link say so and offer nothing else
  const park = await L.sso(browser, "park");
  await park.page.goto(`${L.BASE}/reports/${key}`);
  await park.page.getByText("프로젝트를 찾을 수 없습니다").waitFor();
  L.ok(await park.page.getByRole("button", { name: /인쇄/ }).count() === 0, "a report without access shows only the not-found state, no print button");
  await park.page.goto(`${L.BASE}/findings?finding=${fid}`);
  await park.page.getByRole("alert").filter({ hasText: "찾을 수 없습니다" }).waitFor();
  L.ok(true, "a finding link without access says the result was not found or is not accessible");

  // park as a viewer: no scan button, no silent other project on the scan page, nothing to tick, no exception request
  await kim.api.put(`/projects/${key}/members`, [...await kim.api.get(`/projects/${key}/members`), { principal_kind: "user", principal: String((await park.api.get("/me")).id), role: "viewer" }]);
  await park.page.goto(`${L.BASE}/projects/${key}`);
  const results = park.page.getByRole("table", { name: "결과 목록" });
  await results.getByRole("row", { name: /CVE-2022-37434/ }).waitFor();
  L.ok(await park.page.locator(".page-actions").getByRole("link", { name: "스캔하기" }).count() === 0, "a viewer has no 스캔하기 button on the project");
  L.ok(await results.getByRole("checkbox").count() === 0, "a viewer has no row checkboxes");
  await results.getByRole("row", { name: /CVE-2022-37434/ }).locator(".pkg-name").click();
  await park.page.getByRole("link", { name: /취약점 상세/ }).waitFor();
  L.ok(await park.page.getByRole("button", { name: "예외 요청" }).count() === 0, "a viewer is not offered 예외 요청 in the drawer");
  await park.api.post("/projects", { key: "e2e-park", name: "E2E Park", description: "" }); // park's own project, the one used last
  await park.page.evaluate(() => localStorage.setItem("jasca.scan.project", "e2e-park"));
  await park.page.goto(`${L.BASE}/scan?project=${key}`);
  await park.page.getByText("E2E Exceptions 프로젝트는 보기 전용이라 스캔을 올릴 수 없습니다. 다른 프로젝트를 고르거나 소유자에게 멤버 권한을 요청하세요.").waitFor();
  L.ok(await park.page.getByRole("combobox", { name: "프로젝트", exact: true }).inputValue() === "", "the scan page leaves the project unselected for a view-only ?project=, not the one used last");

  // lee requests through the finding drawer
  await lee.page.goto(`${L.BASE}/projects/${key}`);
  await lee.page.getByRole("table", { name: "결과 목록" }).getByRole("row", { name: /CVE-2022-37434/ }).locator(".pkg-name").click();
  L.ok(/패키지를 .+ 버전 이상으로 올리세요\.|아직 조치 버전이 없습니다/.test(await lee.page.locator(".drawer-todo").innerText()), "the drawer starts with what to do");
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
  await kim.page.getByRole("heading", { name: "예외 승인", level: 1 }).waitFor();
  const row = kim.page.getByRole("table", { name: "예외 목록" }).getByRole("row", { name: /내부망 전용/ });
  const who = (await lee.api.get("/me")).name;
  L.ok(pend[0].requested_by_name === who && (await row.innerText()).includes(who), "the approver sees who asked (" + who + ")");
  L.ok(await row.getByRole("link", { name: /CVE-2022-37434/ }).count() === 1, "the vulnerability is a link");
  L.ok((await row.innerText()).includes("대상 alpine-app"), "a finding-scope row names the target the finding is on");
  L.ok(await kim.page.getByRole("columnheader", { name: "결정 메모" }).count() === 0, "no always-empty 결정 메모 column");
  // a 1024px window: the buttons are on screen and the reason has room
  await kim.page.setViewportSize({ width: 1024, height: 800 });
  const fits = async (name) => { const b = await row.getByRole("button", { name, exact: true }).boundingBox(); return !!b && b.x >= 0 && b.x + b.width <= 1024; };
  L.ok(await fits("승인") && await fits("반려") && await fits("철회"), "at 1024px 승인, 반려 and 철회 are inside the window");
  const reasonW = (await row.getByText("내부망 전용").boundingBox()).width;
  L.ok(reasonW >= 140, `at 1024px the reason column is readable (${Math.round(reasonW)}px)`);
  await L.shot(kim.page, "exceptions-approvals-1024");
  await kim.page.setViewportSize({ width: 1440, height: 900 });
  await row.getByRole("button", { name: "승인", exact: true }).click();
  await kim.page.getByRole("dialog", { name: "예외 승인" }).getByLabel("메모").fill("확인함");
  await kim.page.getByRole("dialog", { name: "예외 승인" }).getByRole("button", { name: "승인", exact: true }).click();
  await kim.page.getByText("승인했습니다.").waitFor();
  const after = (await kim.api.get("/exceptions")).find((e) => e.id === id);
  L.ok(after.status === "approved", "kim approved the request");
  const fnd = await kim.api.get(`/findings?project=${key}&limit=50&status=open,excepted,accepted,false_positive,fixed`);
  L.ok(fnd.items.find((i) => i.rule_id === "CVE-2022-37434")?.status !== "open", "the approved finding is no longer open");
  // the report names a finding-scope exception like the exceptions page does
  await kim.page.goto(`${L.BASE}/reports/${key}`);
  const exc = kim.page.getByRole("table", { name: "예외", exact: true });
  await exc.getByText(/CVE-2022-37434 · zlib · /).waitFor();
  L.ok(!/결과 #/.test(await exc.innerText()), "the report shows CVE · package · severity for a finding-scope exception, not a number");
  // tabs keep the project filter
  await kim.page.goto(`${L.BASE}/exceptions?project=${key}`);
  await kim.page.getByRole("tab", { name: /내 요청/ }).click();
  await kim.page.getByRole("tab", { name: /내 요청/, selected: true }).waitFor();
  L.ok(new URL(kim.page.url()).searchParams.get("project") === key, "switching tabs keeps ?project=");

  // kim cannot approve a request of their own
  const mine = await kim.api.post("/exceptions", { scope: "project_vuln", project_key: key, vuln_id: "CVE-2022-37434", resolution: "accepted", reason: "own request",
    expires_at: new Date(Date.now() + 30 * 864e5).toISOString() });
  const own = Array.isArray(mine) ? mine[0] : mine;
  await kim.page.goto(`${L.BASE}/exceptions/approvals`);
  const mrow = kim.page.getByRole("table", { name: "예외 목록" }).getByRole("row", { name: /own request/ });
  await mrow.waitFor();
  L.ok(await mrow.getByRole("button", { name: "승인", exact: true }).isDisabled() && await mrow.getByRole("button", { name: "반려", exact: true }).isDisabled()
    && (await mrow.innerText()).includes("본인 요청은 승인 불가"), "approve and reject are both disabled on kim's own request, with the reason");
  const r = await kim.api.raw.post(`/exceptions/${own.id ?? (own.ids ?? [])[0]}/approve`, { note: "" });
  L.ok(r.status >= 400 && r.status < 500, `API refuses self-approval (${r.status})`);

  // cancelling an approved exception says so (the button and the message use the same word)
  await kim.page.goto(`${L.BASE}/exceptions?id=${id}`);
  kim.page.once("dialog", (d) => d.accept());
  await kim.page.getByRole("table", { name: "예외 목록" }).getByRole("row", { name: /내부망 전용/ }).getByRole("button", { name: "취소", exact: true }).click();
  await kim.page.getByText("예외를 취소했습니다.").waitFor();
  L.ok(true, "cancelling an approved exception toasts 예외를 취소했습니다");

  // a security user outside the project is offered only the scope the API takes from them: company-wide
  const admin = await L.local(browser);
  const other = await L.project(admin.api, "e2e-exc-sec", "E2E Exceptions Sec");
  L.ok((await L.ingest(other.key, other.token, L.fixture("trivy/image-alpine.json"), "?target=alpine-app&kind=image&ref=1.0")).status < 300, "report uploaded to a project kim is not a member of");
  await kim.page.goto(`${L.BASE}/projects/${other.key}`);
  await kim.page.getByRole("table", { name: "결과 목록" }).getByRole("row", { name: /CVE-2022-37434/ }).locator(".pkg-name").click();
  await kim.page.getByRole("button", { name: "예외 요청" }).click();
  const sdlg = kim.page.getByRole("dialog", { name: "예외 요청" });
  await sdlg.getByText("이 프로젝트의 멤버가 아니어서 전사 범위로만 요청할 수 있습니다.").waitFor();
  L.ok(await sdlg.getByRole("radio", { name: /모든 프로젝트의 같은 취약점/ }).isChecked() && await sdlg.getByRole("radio", { name: /고른 결과만/ }).count() === 0,
    "outside their projects a security user gets the company-wide scope preselected and no other");
  await sdlg.getByLabel("사유").fill("전사 공통으로 영향 없음 확인");
  await sdlg.getByRole("button", { name: "요청 보내기" }).click();
  await kim.page.getByText("예외를 요청했습니다").waitFor();
  L.ok(true, "the offered scope is accepted by the API");
  await browser.close();
});
