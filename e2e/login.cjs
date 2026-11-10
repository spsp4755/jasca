// Local admin sign-in, SSO + sync configured through the admin screens, SSO sign-in of kim/lee/park, department shown in 관리 → 사용자.
const L = require("./lib.cjs");
L.run(async () => {
  const browser = await L.launch();
  const ctx = await L.context(browser, "admin");
  const page = await ctx.newPage();

  // wrong password, then the right one, on the local form
  await page.goto(L.BASE + "/login?local=1");
  await page.getByLabel("아이디").fill("admin");
  await page.getByLabel("비밀번호").fill("not-the-password");
  await page.getByRole("button", { name: "로그인" }).click();
  await page.getByRole("alert").filter({ hasText: "올바르지 않습니다" }).waitFor();
  L.ok(true, "wrong password shows the Korean error");
  await page.getByLabel("비밀번호").fill(L.ADMIN);
  await page.getByRole("button", { name: "로그인" }).click();
  await page.locator(".sidebar").waitFor();
  L.ok(await page.getByRole("link", { name: "관리" }).isVisible(), "local admin signed in, 관리 in the sidebar");

  // SSO settings through the UI
  await page.goto(L.BASE + "/admin/sso");
  await page.getByLabel("Issuer URL").fill(L.KC_ISSUER);
  await page.getByLabel("Client ID").fill("jasca");
  await page.getByLabel("Client Secret").fill(L.KC_CLIENT_SECRET);
  await page.getByLabel("관리자 역할").fill("jasca-admin");
  await page.getByLabel("보안 담당 역할").fill("jasca-security");
  await page.getByLabel("SSO 로그인 사용").check();
  await page.getByRole("button", { name: "저장" }).click();
  await page.getByText("SSO 설정을 저장했습니다.").waitFor();
  L.ok(true, "SSO settings saved");

  // sync settings + run
  await page.goto(L.BASE + "/admin/sync");
  await page.getByLabel("서비스 계정 Client ID").fill("jasca-sync");
  await page.getByLabel("서비스 계정 Secret").fill(L.KC_SYNC_SECRET);
  await page.getByLabel("부서 속성 이름").fill("department");
  await page.getByRole("button", { name: "저장" }).click();
  await page.getByText("동기화 설정을 저장했습니다.").waitFor();
  await page.getByRole("button", { name: "지금 동기화" }).click();
  await page.getByText(/동기화했습니다\. 그룹 \d+개, 사용자 \d+명/).waitFor({ timeout: 15000 });
  L.ok(true, "Keycloak sync ran from the admin screen");

  // SSO sign-in as kim: the login page now offers Keycloak
  const kim = await L.sso(browser, "kim");
  L.ok(await kim.page.getByRole("link", { name: "관리" }).isVisible(), "kim (jasca-security) signed in through Keycloak and sees 관리");
  const kimMe = await kim.api.get("/me");
  L.ok(kimMe.system_role === "security", "kim's system role comes from the jasca-security client role");
  const lee = await L.sso(browser, "lee");
  L.ok(!(await lee.page.getByRole("link", { name: "관리" }).count()), "lee (no role) does not see 관리");
  L.ok((await lee.api.get("/me")).system_role === "", "lee is a plain user");
  const park = await L.sso(browser, "park");
  L.ok((await park.api.get("/me")).system_role === "", "park is a plain user");

  // recent SSO logins on the sync page show where each department came from
  await page.goto(L.BASE + "/admin/sync");
  const logins = page.getByRole("table", { name: "최근 SSO 로그인의 부서" });
  await logins.getByRole("row", { name: /kim.*보안실\/취약점팀.*토큰 클레임/ }).waitFor();
  L.ok(true, "sync page lists kim's department from the token claim");

  // departments in 관리 → 사용자
  await page.goto(L.BASE + "/admin/users");
  const users = page.getByRole("table", { name: "사용자 목록" });
  await users.getByRole("row", { name: /kim.*보안실\/취약점팀/ }).waitFor();
  L.ok(true, "관리 → 사용자 shows kim's department 보안실/취약점팀");
  L.ok(await users.getByRole("row", { name: /lee.*개발본부\/플랫폼팀/ }).count() === 1, "lee's department 개발본부/플랫폼팀 shown");
  const parkRow = users.getByRole("row", { name: /park/ });
  L.ok(!/\//.test(await parkRow.locator("td").nth(2).innerText()), "park has no department");
  L.ok((await users.getByRole("row", { name: /kim.*보안실/ }).locator("td").nth(2).innerText()).trim() === "보안실/취약점팀", "department shown without the stored leading slash");
  await L.shot(page, "login-users");

  // an admin can change a role that came from Keycloak, after confirming who gets which role; the change is JASCA-only
  // and survives the next Keycloak login, until the role is handed back to Keycloak
  const role = page.getByLabel("park 역할");
  const asked = [];
  const setRole = (v, answer = "accept") => {
    page.once("dialog", (d) => { asked.push(d.message()); d[answer](); });
    return Promise.all([
      answer === "accept" && page.waitForResponse((r) => r.request().method() === "PATCH" && r.url().includes("/admin/users/") && r.ok()),
      role.selectOption(v),
    ]);
  };
  L.ok(await role.isEnabled() && await role.inputValue() === "sso", "a Keycloak-mapped user's role reads \"Keycloak 역할 따름\" and can be changed");
  await setRole("security", "dismiss");
  L.ok(/park/.test(asked[0]) && /보안 담당/.test(asked[0]) && await role.inputValue() === "sso", "a role change asks first, naming the user and the role; cancelling changes nothing");
  await setRole("admin");
  const park2 = await L.sso(browser, "park");
  L.ok((await park2.api.get("/me")).system_role === "admin", "park keeps the role set in JASCA after a Keycloak login");
  // the local admin is the emergency way in: another admin can neither switch it off nor demote it
  await park2.page.goto(L.BASE + "/admin/users");
  const localRow = park2.page.getByRole("table", { name: "사용자 목록" }).getByRole("row", { name: /로컬/ });
  await localRow.getByText("비상용 계정이라 바꿀 수 없습니다").waitFor();
  L.ok(await park2.page.getByLabel("admin 역할").isDisabled() && await park2.page.getByLabel("admin 활성").isDisabled(), "the local admin's role and state are locked for another admin");
  const localId = (await park2.api.get("/admin/users")).find((u) => u.source === "local").id;
  const off = await park2.api("PATCH", `/admin/users/${localId}`, { active: false });
  L.ok(off.status === 400 && /비상용/.test(off.body.message), "the API refuses to deactivate the local admin (400)");
  await setRole("sso"); // back to Keycloak: decided again at park's next Keycloak login
  L.ok(/Keycloak 역할 따름/.test(asked[2]), "handing the role back is confirmed too");
  await page.getByRole("table", { name: "사용자 목록" }).getByRole("row", { name: /park/ }).getByText("다음 Keycloak 로그인 때 다시 정해집니다").waitFor();
  L.ok((await (await L.sso(browser, "park")).api.get("/me")).system_role === "", "park follows Keycloak again: a plain user after the next login");

  // a signed-in user can sign out
  await kim.page.locator(".usermenu-btn").click();
  L.ok((await kim.page.locator(".menu-role .tag-quiet").allInnerTexts()).join("|") === "보안실/취약점팀", "the user menu shows the department as one chip with its full path");
  await kim.page.getByRole("group", { name: "사용자 메뉴" }).getByText("로그아웃").click();
  await kim.page.waitForURL(/\/login/);
  L.ok(true, "kim signed out");
  await browser.close();
});
