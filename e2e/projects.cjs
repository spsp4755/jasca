// Project creation, member by department, API token shown once (all through the screens).
const L = require("./lib.cjs");
L.run(async () => {
  const browser = await L.launch();
  const kim = await L.sso(browser, "kim");
  const page = kim.page;

  await page.goto(L.BASE + "/projects");
  await page.getByRole("button", { name: "새 프로젝트" }).first().click();
  const dlg = page.getByRole("dialog");
  const focused = (loc) => loc.evaluate((el) => el === document.activeElement);
  L.ok(await focused(dlg.getByLabel("이름")) && await dlg.getByLabel("이름").getAttribute("maxlength") === "100",
    "the dialog opens with focus in its first field (not on X); the name field stops at the real limit of 100");
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

  // a double click on 저장 sends one request and writes one audit row
  let patches = 0;
  page.on("request", (r) => { if (r.method() === "PATCH" && r.url().endsWith("/projects/e2e-proj")) patches++; });
  await page.locator("#general").getByLabel("설명").fill("브라우저 테스트용");
  await page.locator("#general").getByRole("button", { name: "저장" }).dblclick();
  await page.getByText("저장했습니다.", { exact: true }).waitFor();
  await L.sleep(400);
  const updates = (await kim.api.get("/audit?project=e2e-proj&action=project.update")).items.length;
  L.ok(patches === 1 && updates === 1, `double-clicking 저장 saves once (${patches} request, ${updates} audit row)`);

  // lee belongs to that department and can now open the project, but is not an owner
  const lee = await L.sso(browser, "lee");
  const mine = await lee.api.get("/projects/e2e-proj");
  L.ok(mine.my_role === "member", "lee sees the project as member through the department");
  L.ok((await (await L.sso(browser, "park")).api.raw.get("/projects/e2e-proj")).status === 404, "park (other department) does not see it");
  L.ok((await lee.api.raw.get("/projects/e2e-proj/tokens")).status === 403, "lee cannot list tokens (owner only)");

  // token dialog: Enter right after opening does not close it, Esc does and focus goes back to the button
  const open = page.getByRole("button", { name: "토큰 만들기" });
  await open.click();
  const tdlg = page.getByRole("dialog", { name: "API 토큰 만들기" });
  L.ok(await focused(tdlg.getByLabel("이름")), "the token dialog opens with focus in 이름");
  await page.keyboard.press("Enter"); // the empty required field stops the submit
  await L.sleep(300);
  L.ok(await tdlg.isVisible(), "Enter right after opening does not close the dialog");
  await page.keyboard.press("Escape");
  await tdlg.waitFor({ state: "hidden" });
  L.ok(await focused(open), "Esc closes the dialog and focus returns to 토큰 만들기");

  // token: shown once. The expiry day is the picked calendar day in the server's display zone (the browser is in another one)
  const day = new Intl.DateTimeFormat("en-CA", { timeZone: "Asia/Seoul" }).format(Date.now() + 40 * 864e5); // YYYY-MM-DD
  await open.click();
  await page.getByRole("dialog").getByLabel("이름").fill("ci-e2e");
  await page.getByRole("dialog").getByLabel("만료일").fill(day);
  await page.getByRole("dialog").getByRole("button", { name: "만들기" }).click();
  const shown = page.getByRole("dialog", { name: "토큰을 만들었습니다" });
  await shown.waitFor();
  await shown.getByText(`${day.replaceAll("-", ". ")}.까지 쓸 수 있습니다.`).waitFor();
  const exp = (await kim.api.get("/projects/e2e-proj/tokens")).find((t) => t.name === "ci-e2e").expires_at;
  L.ok(new Date(exp).getTime() === Date.parse(`${day}T23:59:59+09:00`), `picking ${day} expires the token at the end of that day in Asia/Seoul (${exp})`);
  L.ok(await focused(shown.getByRole("button", { name: "복사", exact: true })), "the one-time token dialog opens on 복사, not on the button that closes it");
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
