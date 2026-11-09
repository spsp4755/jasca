import { useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import PageHeader from "../components/PageHeader";
import Table, { type Column } from "../components/Table";
import Dialog from "../components/Dialog";
import Button from "../components/Button";
import Empty from "../components/Empty";
import SeverityBadge from "../components/SeverityBadge";
import { useToast } from "../components/Toast";
import { ApiError, api } from "../api/client";
import { isSecurity, useApi, useMe } from "../api/hooks";
import { fmtDate } from "../lib/format";
import type { Advisory } from "../api/types";

const SAMPLE = `id,title,severity,ecosystem,package,range,fixed,description,refs
JASCA-2026-001,내부 라이브러리 인증 우회,HIGH,npm,@example/auth,<1.4.2,1.4.2,토큰 검증 누락,https://wiki.example.internal/advisory/1
JASCA-2026-002,사내 공용 모듈 취약점,CRITICAL,gomod,example.internal/lib/core,>=1.0.0 <1.2.5,1.2.5,입력 검증 부재,
`;

function ImportDialog({ onClose }: { onClose: () => void }) {
  const toast = useToast();
  const qc = useQueryClient();
  const [text, setText] = useState("");
  const [name, setName] = useState("");
  const input = useRef<HTMLInputElement>(null);
  const imp = useMutation<unknown, ApiError>({
    mutationFn: () => api.post("/advisories/import", text),
    onSuccess: (r) => {
      const n = r as { created?: number; updated?: number; matched?: number } | undefined;
      toast(n ? `가져왔습니다. 새로 ${n.created ?? 0}건, 수정 ${n.updated ?? 0}건, 일치한 결과 ${n.matched ?? 0}건.` : "가져왔습니다.", "ok");
      void qc.invalidateQueries({ queryKey: ["/advisories"] });
      onClose();
    },
    onError: (e) => toast(e.message, "error"),
  });
  const sample = () => {
    const url = URL.createObjectURL(new Blob(["﻿" + SAMPLE], { type: "text/csv" }));
    const a = Object.assign(document.createElement("a"), { href: url, download: "advisories-sample.csv" });
    a.click(); URL.revokeObjectURL(url);
  };
  return (
    <Dialog open onClose={onClose} title="CSV 가져오기" description="헤더: id,title,severity,ecosystem,package,range,fixed,description,refs. 같은 id가 있으면 덮어씁니다. refs는 공백으로 구분합니다."
      footer={<><Button onClick={onClose}>취소</Button><Button variant="primary" disabled={!text} loading={imp.isPending} onClick={() => imp.mutate()}>가져오기</Button></>}>
      <div className="row-gap">
        <Button onClick={() => input.current?.click()}>CSV 파일 선택</Button>
        <Button variant="ghost" icon="table" onClick={sample}>샘플 내려받기</Button>
        <span className="muted">{name || "선택한 파일 없음"}</span>
        <input ref={input} type="file" accept=".csv,text/csv" hidden onChange={async (e) => {
          const f = e.target.files?.[0]; if (!f) return; setName(f.name); setText(await f.text());
        }} />
      </div>
      {text && <pre className="code-block" style={{ maxHeight: 180 }}>{text.slice(0, 2000)}</pre>}
    </Dialog>
  );
}

export default function Advisories() {
  const { data: me } = useMe();
  const sec = isSecurity(me);
  const q = useApi<Advisory[]>("/advisories");
  const nav = useNavigate();
  const [imp, setImp] = useState(false);
  const cols: Column<Advisory>[] = [
    { key: "id", header: "ID", mono: true, nowrap: true, render: (a) => <Link to={`/advisories/${encodeURIComponent(a.id)}`}>{a.id}</Link> },
    { key: "title", header: "제목", render: (a) => a.title },
    { key: "sev", header: "심각도", render: (a) => <SeverityBadge severity={a.severity} /> },
    { key: "aff", header: "영향 패키지", align: "right", render: (a) => (a.affected ?? []).length },
    { key: "active", header: "상태", render: (a) => (a.active ? "사용 중" : "중지") },
    { key: "upd", header: "수정", nowrap: true, render: (a) => fmtDate(a.updated_at) },
  ];
  return (
    <>
      <PageHeader title="사내 Advisory" description="공개 DB에 없는 사내 취약점 정보를 등록하면, 저장하는 즉시 기존 스캔 결과에도 적용됩니다."
        actions={sec ? <><Button onClick={() => setImp(true)}>CSV 가져오기</Button><Link className="btn btn-primary" to="/advisories/new">새 Advisory</Link></> : undefined} />
      {q.error && <div className="alert alert-danger" role="alert">{q.error.message}</div>}
      <div className="panel"><Table columns={cols} rows={q.data ?? []} rowKey={(a) => a.id} loading={q.isLoading} caption="사내 Advisory 목록"
        onRowClick={(a) => nav(`/advisories/${encodeURIComponent(a.id)}`)}
        empty={<Empty title="등록된 Advisory가 없습니다" description={sec ? "새 Advisory를 만들거나 CSV로 한꺼번에 가져오세요." : "보안 담당자가 등록하면 여기에 나타납니다."} />} /></div>
      {imp && <ImportDialog onClose={() => setImp(false)} />}
    </>
  );
}
