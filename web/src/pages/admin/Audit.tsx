import { useState } from "react";
import { useInfiniteQuery } from "@tanstack/react-query";
import PageHeader from "../../components/PageHeader";
import Button from "../../components/Button";
import Table from "../../components/Table";
import { useApi } from "../../api/hooks";
import { ApiError, api, qs } from "../../api/client";
import { statusLabel } from "../../components/StatusBadge";
import { KIND_LABEL, RESOLUTION_LABEL, ROLE_LABEL, SCOPE_LABEL, SYSTEM_ROLE_LABEL, fmtDateTime } from "../../lib/format";
import type { AuditEntry, AuditPage, Project } from "../../api/types";
import { NOTIFY_EVENTS } from "../ProjectSettings";
import { Loading } from "./parts";

const LIMIT = 50;

// Every action code the server writes (the s.audit calls in the Go files). A code missing here is shown as it is.
const ACTION: Record<string, string> = {
  "auth.login": "로그인", "auth.login_failed": "로그인 실패", "auth.logout": "로그아웃",
  "auth.password_change": "비밀번호 변경", "auth.password_change_failed": "비밀번호 변경 실패",
  "user.update": "사용자 역할·상태 변경", "settings.update": "연동 설정 변경", "smtp.update": "메일(SMTP) 설정 변경",
  "retention.update": "보존 기간 변경", "default_policy.update": "기본 정책 변경",
  "project.create": "프로젝트 생성", "project.update": "프로젝트 수정", "project.delete": "프로젝트 삭제", "project.members": "프로젝트 멤버 변경",
  "policy.update": "프로젝트 정책 변경", "notify.update": "알림 구독 변경", "token.create": "API 토큰 생성", "token.revoke": "API 토큰 폐기",
  "scan.upload": "CI 업로드", "scan.job": "파일 업로드 스캔", "scan.cancel": "스캔 취소", "recheck.start": "재평가 시작",
  "exception.request": "예외 요청", "exception.approve": "예외 승인", "exception.reject": "예외 반려", "exception.revoke": "예외 철회·취소", "exception.expire": "예외 만료",
  "advisory.create": "Advisory 등록", "advisory.update": "Advisory 수정", "advisory.delete": "Advisory 삭제", "advisory.import": "Advisory 가져오기",
  "ai.guide": "AI 조치 안내 요청", "ai.report": "AI 보고서 요청",
  "harbor.link_create": "Harbor 연결 추가", "harbor.link_update": "Harbor 연결 수정", "harbor.link_delete": "Harbor 연결 삭제",
  "harbor.mappings_put": "Harbor 매핑 변경", "harbor.assign": "Harbor 이미지 프로젝트 지정", "harbor.fetch": "Harbor 보고서 가져오기",
  "channel.create": "알림 채널 추가", "channel.update": "알림 채널 수정", "channel.delete": "알림 채널 삭제", "channel.test": "알림 채널 시험 발송",
  "trivy.settings": "스캐너 설정 변경", "trivy.db_upload": "Trivy DB 올리기", "trivy.db_upload_failed": "Trivy DB 올리기 실패", "sync.run": "Keycloak 동기화",
};
const ACTIONS = Object.entries(ACTION).sort((a, b) => a[1].localeCompare(b[1], "ko"));
const DETAIL: Record<string, string> = {
  method: "방식", reason: "사유", step: "단계", op: "작업", before: "이전", after: "이후", was: "이전 상태", name: "이름", description: "설명",
  credential_changed: "비밀값 변경", secret_changed: "비밀값 변경", password_changed: "비밀번호 변경",
  members: "멤버", policy: "정책", subs: "구독", matched: "걸린 결과", severity: "심각도", active: "사용", enabled: "사용", system_role: "역할",
  raw_per_target: "대상별 보관 수", raw_days: "보관 일수", min_severity: "최소 심각도", max_count: "허용 개수", new_only: "새 결과만", fixable_only: "조치 버전 있는 것만",
  vuln_guide_custom: "조치 안내 프롬프트 수정", project_report_custom: "보고서 프롬프트 수정", run_id: "실행 번호", exception_id: "예외 번호",
  scope: "범위", scopes: "권한", resolution: "처리", expires_at: "만료", note: "메모", id: "번호", project_id: "프로젝트 번호", link_id: "연결 번호", scan_id: "스캔 번호",
  base_url: "주소", rows: "행 수", digest: "다이제스트", duplicate: "중복", bytes: "크기(바이트)", kind: "종류", ok: "성공", host: "호스트", port: "포트",
  format: "형식", ref: "태그·커밋(ref)", tls: "TLS", findings: "결과 수", policy_passed: "정책 통과", total: "대상 수", scanners: "스캐너", error: "오류",
  version: "버전", updated_at: "갱신 시각", groups: "그룹 수", users: "사용자 수", principal_kind: "구분", principal: "대상", role: "역할", channel_id: "채널 번호", events: "이벤트",
  role_from_sso: "Keycloak 역할 따름", added: "추가", removed: "제거", changed: "역할 변경", member_count: "멤버 수",
};
// Stored codes by detail key, in the words the other screens use. A code missing here is shown as it is.
const CODE: Record<string, Record<string, string>> = {
  system_role: SYSTEM_ROLE_LABEL, before: SYSTEM_ROLE_LABEL, after: SYSTEM_ROLE_LABEL, role: ROLE_LABEL, from: ROLE_LABEL,
  resolution: RESOLUTION_LABEL, scope: SCOPE_LABEL, scanners: KIND_LABEL, events: Object.fromEntries(NOTIFY_EVENTS),
  scopes: { upload: "업로드", read: "읽기" }, kind: { mattermost: "Mattermost", email: "이메일" },
  method: { local: "로컬 계정", sso: "Keycloak" }, op: { sso_role: "Keycloak 역할 반영" },
};
const code = (k: string, v: unknown) => (typeof v !== "string" ? String(v) : k === "was" ? statusLabel(v) : CODE[k]?.[v] ?? v);
const MEMBER_LISTS = new Set(["added", "removed", "changed"]); // project.members: [{name, role, from?}]
const HIDDEN = new Set(["project_key", "added_more", "removed_more", "changed_more"]); // its own column; folded into the lists
// The server logs that a secret changed, never its value. Should a value ever arrive under such a key, it is not shown.
const SECRET_KEY = /(secret|password|token|api_?key|credential)$/i;

function value(k: string, v: unknown, d: Record<string, unknown>): string {
  if (typeof v === "boolean") return v ? "예" : "아니오";
  if (SECRET_KEY.test(k)) return "(숨김)";
  if (Array.isArray(v) && MEMBER_LISTS.has(k)) {
    return (v as { name: string; role: string; from?: string }[]).map((m) => `${m.name}(${m.from ? `${code("role", m.from)} → ` : ""}${code("role", m.role)})`).join(", ")
      + (d[`${k}_more`] ? ` 외 ${d[`${k}_more`]}` : "");
  }
  if (Array.isArray(v)) return v.every((x) => typeof x !== "object") ? v.map((x) => code(k, x)).join(", ") || "없음" : `${v.length}개`;
  if (v && typeof v === "object") return `(${detailText(v as Record<string, unknown>)})`;
  return typeof v === "string" && /_at$/.test(k) ? fmtDateTime(v) : code(k, v);
}
/** "키: 값 · 키: 값" with Korean key names and values. Empty values are left out, unless empty is itself a value (the role "일반 사용자"). */
function detailText(d: Record<string, unknown>): string {
  return Object.entries(d).filter(([k, v]) => v !== null && !HIDDEN.has(k) && (v !== "" || CODE[k]?.[""] !== undefined) && !(k === "after" && "before" in d))
    .map(([k, v]) => (k === "before" && "after" in d ? `역할: ${code(k, v)} → ${code("after", d.after)}` : `${DETAIL[k] ?? k}: ${value(k, v, d)}`)).join(" · ");
}

export default function Audit() {
  const projects = useApi<Project[]>("/projects");
  const [project, setProject] = useState("");
  const [action, setAction] = useState("");
  const [applied, setApplied] = useState({ project: "", action: "" });
  const q = useInfiniteQuery<AuditPage, ApiError, { pages: AuditPage[] }, unknown[], string>({
    queryKey: ["/audit", applied], initialPageParam: "",
    queryFn: ({ pageParam, signal }) => api.get<AuditPage>(`/audit${qs({ ...applied, limit: LIMIT, cursor: pageParam })}`, { signal }),
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });
  const rows: AuditEntry[] = q.data?.pages.flatMap((p) => p.items ?? []) ?? [];
  const who = (e: AuditEntry) => e.actor || (e.actor_user ? `사용자 #${e.actor_user}` : e.actor_token ? `API 토큰 #${e.actor_token}` : "시스템");
  return (
    <>
      <PageHeader title="감사 로그" description="누가 언제 무엇을 바꿨는지 기록입니다. 최신순이며, 지울 수 없습니다." />
      <form className="panel" style={{ padding: 12, display: "flex", gap: 10, alignItems: "flex-end", flexWrap: "wrap" }}
        onSubmit={(e) => { e.preventDefault(); setApplied({ project, action }); }}>
        <label className="field"><span className="field-label">프로젝트</span>
          <select className="input" value={project} onChange={(e) => setProject(e.target.value)}>
            <option value="">전체</option>{(projects.data ?? []).map((p) => <option key={p.id} value={p.key}>{p.name} ({p.key})</option>)}
          </select></label>
        <label className="field"><span className="field-label">동작</span>
          <select className="input" value={action} onChange={(e) => setAction(e.target.value)}>
            <option value="">전체</option>{ACTIONS.map(([code, label]) => <option key={code} value={code}>{label} ({code})</option>)}
          </select></label>
        <Button type="submit" variant="primary" icon="search">조회</Button>
      </form>
      <Loading q={q} />
      <div className="panel">
        <Table<AuditEntry> dense rowKey={(e) => e.id} rows={rows} loading={q.isLoading} caption="감사 로그" empty={<span className="muted">조건에 맞는 기록이 없습니다.</span>}
          columns={[
            { key: "at", header: "시각", nowrap: true, render: (e) => fmtDateTime(e.at) },
            { key: "who", header: "행위자", nowrap: true, render: who },
            { key: "action", header: "동작", nowrap: true, render: (e) => <span title={e.action}>{ACTION[e.action] ?? e.action}</span> },
            { key: "project", header: "프로젝트", nowrap: true, render: (e) => e.project_key || "-" },
            { key: "target", header: "대상", render: (e) => e.target || "-" },
            { key: "ip", header: "IP", mono: true, nowrap: true, render: (e) => e.ip || "-" },
            { key: "d", header: "상세", render: (e) => { const s = detailText(e.details ?? {}); return s ? <span className="clamp muted" title={s}>{s}</span> : "-"; } },
          ]} />
        {q.hasNextPage && <div style={{ padding: 12, textAlign: "center" }}><Button loading={q.isFetchingNextPage} onClick={() => q.fetchNextPage()}>더 보기</Button></div>}
      </div>
    </>
  );
}
