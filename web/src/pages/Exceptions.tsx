import { useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import PageHeader from "../components/PageHeader";
import Tabs from "../components/Tabs";
import Table, { type Column } from "../components/Table";
import Dialog from "../components/Dialog";
import Field from "../components/Field";
import Button from "../components/Button";
import StatusBadge from "../components/StatusBadge";
import Empty from "../components/Empty";
import { useToast } from "../components/Toast";
import { ApiError, api } from "../api/client";
import { isSecurity, useApi, useMe } from "../api/hooks";
import { RESOLUTION_LABEL, SCOPE_LABEL, fmtDate } from "../lib/format";
import type { ExceptionItem } from "../api/types";

type Act = { item: ExceptionItem; kind: "approve" | "reject" };

export default function Exceptions() {
  const { pathname } = useLocation();
  const nav = useNavigate();
  const { data: me } = useMe();
  const sec = isSecurity(me);
  const q = useApi<ExceptionItem[]>("/exceptions");
  const qc = useQueryClient();
  const toast = useToast();
  const [act, setAct] = useState<Act | null>(null);
  const [note, setNote] = useState("");
  const tab = pathname.endsWith("/approvals") && sec ? "pending" : (new URLSearchParams(useLocation().search).get("tab") ?? "mine");
  const all = q.data ?? [];
  const mine = all.filter((e) => e.requested_by === me?.id);
  const pending = all.filter((e) => e.status === "pending");
  const rows = tab === "pending" ? pending : tab === "all" ? all : mine;

  const done = () => { void qc.invalidateQueries({ queryKey: ["/exceptions"] }); setAct(null); setNote(""); };
  const decide = useMutation<unknown, ApiError, Act>({
    mutationFn: ({ item, kind }) => api.post(`/exceptions/${item.id}/${kind}`, { note: note.trim() }),
    onSuccess: (_r, v) => { toast(v.kind === "approve" ? "승인했습니다." : "반려했습니다.", "ok"); done(); },
    onError: (e) => toast(e.message, "error"),
  });
  const revoke = useMutation<unknown, ApiError, number>({
    mutationFn: (id) => api.post(`/exceptions/${id}/revoke`),
    onSuccess: () => { toast("요청을 철회했습니다.", "ok"); done(); },
    onError: (e) => toast(e.message, "error"),
  });

  const cols: Column<ExceptionItem>[] = [
    { key: "scope", header: "범위", render: (e) => SCOPE_LABEL[e.scope] ?? e.scope, nowrap: true },
    { key: "target", header: "대상", render: (e) => <span className="mono">{e.vuln_id ?? (e.finding_id ? `결과 #${e.finding_id}` : "—")}</span> },
    { key: "project", header: "프로젝트", render: (e) => e.project_key ?? (e.scope === "global_vuln" ? "전사" : "—") },
    { key: "res", header: "처리", render: (e) => RESOLUTION_LABEL[e.resolution] ?? e.resolution, nowrap: true },
    { key: "reason", header: "사유", render: (e) => <span title={e.reason}>{e.reason}</span> },
    { key: "status", header: "상태", render: (e) => <StatusBadge status={e.status} /> },
    { key: "exp", header: "만료", render: (e) => fmtDate(e.expires_at), nowrap: true },
    { key: "note", header: "결정 메모", render: (e) => e.decision_note || "—" },
    {
      key: "act", header: "", nowrap: true, render: (e) => {
        const own = e.requested_by === me?.id;
        const canRevoke = e.status === "pending" ? own || sec : e.status === "approved" && sec;
        return (
          <div className="row-gap">
            {sec && e.status === "pending" && (
              <>
                <Button size="sm" variant="primary" disabled={own} title={own ? "본인이 요청한 예외는 승인할 수 없습니다." : undefined}
                  onClick={() => setAct({ item: e, kind: "approve" })}>승인</Button>
                <Button size="sm" onClick={() => setAct({ item: e, kind: "reject" })}>반려</Button>
                {own && <span className="muted" style={{ fontSize: 12 }}>본인 요청은 승인 불가</span>}
              </>
            )}
            {canRevoke && <Button size="sm" variant="ghost" loading={revoke.isPending && revoke.variables === e.id}
              onClick={() => { if (confirm(e.status === "pending" ? "이 요청을 철회할까요?" : "이 예외를 취소하고 결과를 다시 열까요?")) revoke.mutate(e.id); }}>
              {e.status === "pending" ? "철회" : "취소"}</Button>}
          </div>
        );
      },
    },
  ];

  return (
    <>
      <PageHeader title="예외" description="위험 수용·오탐 처리 요청입니다. 만료일이 지나면 결과가 자동으로 다시 열립니다." />
      <Tabs label="예외 구분" value={tab} onChange={(t) => nav(t === "mine" ? "/exceptions" : `/exceptions?tab=${t}`)}
        tabs={[{ id: "mine", label: "내 요청", count: mine.length }, { id: "pending", label: "승인 대기", count: pending.length, hidden: !sec }, { id: "all", label: "전체", count: all.length }]} />
      {q.error && <div className="alert alert-danger" role="alert">{q.error.message}</div>}
      <div role="tabpanel" id={`tabpanel-${tab}`} aria-labelledby={`tab-${tab}`}>
        <Table columns={cols} rows={rows} rowKey={(e) => e.id} loading={q.isLoading} caption="예외 목록"
          empty={<Empty title={tab === "pending" ? "승인 대기 중인 요청이 없습니다" : "예외가 없습니다"}
            description="취약점 결과 화면에서 &quot;예외 요청&quot;을 눌러 만들 수 있습니다." />} />
      </div>
      <Dialog open={!!act} onClose={() => setAct(null)} title={act?.kind === "approve" ? "예외 승인" : "예외 반려"}
        description={act ? `${act.item.vuln_id ?? `결과 #${act.item.finding_id}`} · ${act.item.reason}` : undefined}
        footer={<><Button onClick={() => setAct(null)}>취소</Button>
          <Button variant={act?.kind === "approve" ? "primary" : "danger"} loading={decide.isPending} disabled={act?.kind === "reject" && !note.trim()}
            onClick={() => act && decide.mutate(act)}>{act?.kind === "approve" ? "승인" : "반려"}</Button></>}>
        <Field label="메모" required={act?.kind === "reject"} hint="요청자에게 보입니다. 반려할 때는 이유를 적어 주세요.">
          <textarea className="input" value={note} onChange={(e) => setNote(e.target.value)} maxLength={1000} />
        </Field>
      </Dialog>
    </>
  );
}
