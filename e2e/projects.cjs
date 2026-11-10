// Project creation, member by department, API token shown once (all through the screens).
const L = require("./lib.cjs");
L.run(async () => {
  const browser = await L.launch();
  const kim = await L.sso(browser, "kim");
  const page = kim.page;

  await page.goto(L.BASE + "/projects");
  await page.getByRole("button", { name: "새 프로젝트" }).first().click();
  const dlg = page.getByRole("dialog");
  await dlg.getByLabel("이름").fill("E2E Projects");
  await dlg.getByLabel("키").fill("e2e-proj");
  await dlg.getByRole("button", { name: "만들기" }).click();
  await page.waitForURL(/\/projects\/e2e-proj$/);
  await page.getByRole("heading", { name: "E2E Projects" }).waitFor();
  L.ok(true, "project created, its page opens");

  await page.getByRole("tab", { name: "설정" }).click();
  await page.getByLabel("사용자나 그룹 추가").fill("/개발본부");
  await page.getByRole("option", { name: /개발본부\/플랫폼팀/ }).click();
  await page.getByRole("button", { name: "변경 저장" }).click();
  await page.getByText("멤버를 저장했습니다.").waitFor();
  const members = page.getByRole("table", { name: "멤버" });
  await members.getByRole("row", { name: /그룹.*개발본부\/플랫폼팀/ }).waitFor();
  L.ok(true, "department 개발본부/플랫폼팀 added as a member group");

  // the policy count refuses what cannot be saved, in words
  await page.getByLabel("허용 개수").fill("1.5");
  await page.getByRole("alert").filter({ hasText: "허용 개수는 0부터 1,000,000까지의 정수로 입력하세요." }).waitFor();
  L.ok(await page.locator("#policy").getByRole("button", { name: "저장" }).isDisabled(), "a non-integer policy count shows a message and cannot be saved");
  await page.getByLabel("허용 개수").fill("0");

  // lee belongs to that department and can now open the project, but is not an owner
  const lee = await L.sso(browser, "lee");
  const mine = await lee.api.get("/projects/e2e-proj");
  L.ok(mine.my_role === "member", "lee sees the project as member through the department");
  L.ok((await (await L.sso(browser, "park")).api.raw.get("/projects/e2e-proj")).status === 404, "park (other department) does not see it");
  L.ok((await lee.api.raw.get("/projects/e2e-proj/tokens")).status === 403, "lee cannot list tokens (owner only)");

  // token: shown once
  await page.getByRole("button", { name: "토큰 만들기" }).click();
  await page.getByRole("dialog").getByLabel("이름").fill("ci-e2e");
  await page.getByRole("dialog").getByRole("button", { name: "만들기" }).click();
  const shown = page.getByRole("dialog", { name: "토큰을 만들었습니다" });
  await shown.waitFor();
  const token = (await shown.locator("code").innerText()).trim();
  L.ok(token.length >= 24 && !/\s/.test(token), "token value shown in the dialog");
  await shown.getByRole("button", { name: "복사했습니다, 닫기" }).click();
  await page.getByRole("table", { name: "API 토큰" }).getByText("ci-e2e").waitFor();
  L.ok(!(await page.content()).includes(token), "after closing, the token value is nowhere on the page");
  await page.reload();
  await page.getByRole("table", { name: "API 토큰" }).getByText("ci-e2e").waitFor();
  L.ok(!(await page.content()).includes(token), "after reload the token value is still not shown");
  const list = await kim.api.get("/projects/e2e-proj/tokens");
  L.ok(!JSON.stringify(list).includes(token), "token list API carries no token value");
  L.state({ token });
  await L.shot(page, "projects-settings");
  await browser.close();
});
