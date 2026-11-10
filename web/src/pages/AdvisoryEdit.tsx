import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import PageHeader from "../components/PageHeader";
import Field from "../components/Field";
import Button from "../components/Button";
import Dialog from "../components/Dialog";
import Table from "../components/Table";
import Empty from "../components/Empty";
import { useToast } from "../components/Toast";
import { ApiError, api } from "../api/client";
import { isSecurity, useApi, useMe } from "../api/hooks";
import { SEVERITY_LABEL } from "../lib/format";
import { SEVERITIES, type Advisory, type AdvisoryAffected, type AdvisoryPreviewRow, type Severity } from "../api/types";
import { Check, Loading, Panel } from "./admin/parts";
import "../styles/t17.css";

const ECOS = ["debian", "ubuntu", "alpine", "redhat", "rocky", "alma", "amazon", "suse", "npm", "pip", "gomod", "maven", "cargo", "nuget", "gem", "composer"];
const OTHER = "__other";
const BLANK: AdvisoryAffected = { ecosystem: "npm", name: "", range: "", fixed: "" };
type Form = { id: string; title: string; description: string; severity: Severity; refs: string; active: boolean; affected: AdvisoryAffected[] };
const NEW: Form = { id: "", title: "", description: "", severity: "HIGH", refs: "", active: true, affected: [{ ...BLANK }] };

function AffectedEditor({ rows, onChange, disabled }: { rows: AdvisoryAffected[]; onChange: (r: AdvisoryAffected[]) => void; disabled: boolean }) {
  // rows whose ecosystem is not in the list keep showing the free-text input, even while empty
  const [free, setFree] = useState<Set<number>>(new Set());
  const upd = (i: number, p: Partial<AdvisoryAffected>) => onChange(rows.map((r, j) => (j === i ? { ...r, ...p } : r)));
  return (
    <div className="stack">
      {rows.map((r, i) => {
        const isFree = free.has(i) || !ECOS.includes(r.ecosystem);
        const row = i ? <span className="sr-only"> (행 {i + 1})</span> : null; // screen readers tell the rows apart
        return (
          <div className="aff-row" key={i}>
            <Field label={<>패키지 종류{row}</>}>
              {isFree ? <input className="input" placeholder="직접 입력" value={r.ecosystem} disabled={disabled} onChange={(e) => upd(i, { ecosystem: e.target.value })} />
                : <select className="input" value={r.ecosystem} disabled={disabled}
                  onChange={(e) => e.target.value === OTHER ? (setFree(new Set(free).add(i)), upd(i, { ecosystem: "" })) : upd(i, { ecosystem: e.target.value })}>
                  {ECOS.map((e) => <option key={e}>{e}</option>)}<option value={OTHER}>기타(직접 입력)</option>
                </select>}
            </Field>
            <Field label={<>패키지{row}</>}><input className="input mono" value={r.name} disabled={disabled} onChange={(e) => upd(i, { name: e.target.value })} /></Field>
            <Field label={<>영향 범위{row}</>}><input className="input mono" placeholder={i ? undefined : "<1.4.2"} value={r.range} disabled={disabled} onChange={(e) => upd(i, { range: e.target.value })} /></Field>
            <Field label={<>조치 버전{row}</>}><input className="input mono" value={r.fixed} disabled={disabled} onChange={(e) => upd(i, { fixed: e.target.value })} /></Field>
            <Button variant="ghost" aria-label={`행 ${i + 1} 삭제`} icon="x" disabled={disabled || rows.length < 2} onClick={() => onChange(rows.filter((_, j) => j !== i))} />
            {isFree && r.ecosystem && !ECOS.includes(r.ecosystem) && (
              <p className="field-hint" style={{ gridColumn: "1 / -1" }}>알 수 없는 패키지 종류 &quot;{r.ecosystem}&quot;는 일반 비교(숫자·문자 순)로 판단하므로 정확하지 않을 수 있습니다.</p>
            )}
          </div>
        );
      })}
      {/* one hint under the rows: a hint inside a single field would push that field out of line with its neighbours */}
      <p className="field-hint" style={{ margin: 0 }}>패키지 종류는 패키지를 설치한 방식입니다(예: npm, pip, maven, 또는 debian·alpine 같은 OS). 영향 범위는 <span className="mono">&lt;1.4.2</span> 또는 <span className="mono">&gt;=1.0 &lt;1.2.5</span>처럼 씁니다.</p>
      {!disabled && <div><Button size="sm" onClick={() => onChange([...rows, { ...BLANK }])}>행 추가</Button></div>}
    </div>
  );
}

export default function AdvisoryEdit() {
  const { id } = useParams();
  const isNew = !id;
  const { data: me } = useMe();
  const sec = isSecurity(me);
  const nav = useNavigate();
  const qc = useQueryClient();
  const toast = useToast();
  const q = useApi<Advisory & { warnings?: string[] }>(id ? `/advisories/${encodeURIComponent(id)}` : null);
  const [f, setF] = useState<Form>(NEW);
  const [preview, setPreview] = useState<AdvisoryPreviewRow[] | null>(null);
  useEffect(() => {
    const a = q.data;
    if (a) setF({ id: a.id, title: a.title, description: a.description, severity: a.severity, refs: (a.refs ?? []).join("\n"), active: a.active, affected: a.affected?.length ? a.affected : [{ ...BLANK }] });
  }, [q.data]);
  const set = (p: Partial<Form>) => { setF({ ...f, ...p }); setPreview(null); };
  const affected = f.affected.map((a) => ({ ...a, name: a.name.trim(), range: a.range.trim(), fixed: a.fixed.trim(), ecosystem: a.ecosystem.trim() }));
  const body = { id: f.id.trim(), title: f.title.trim(), description: f.description.trim(), severity: f.severity, affected, active: f.active,
    refs: f.refs.split(/\s+/).map((s) => s.trim()).filter(Boolean) };
  const idOK = /^[A-Z][A-Z0-9-]{2,40}$/.test(body.id);
  const valid = idOK && body.title && affected.length > 0 && affected.every((a) => a.ecosystem && a.name && a.range);

  const prev = useMutation<AdvisoryPreviewRow[], ApiError>({
    mutationFn: () => api.post<AdvisoryPreviewRow[]>("/advisories/preview", body),
    onSuccess: (r) => setPreview(r ?? []),
    onError: (e) => toast(e.message, "error"),
  });
  const save = useMutation<unknown, ApiError>({
    mutationFn: () => (isNew ? api.post("/advisories", body) : api.put(`/advisories/${encodeURIComponent(id!)}`, body)),
    onSuccess: () => { toast("저장했습니다. 기존 스캔 결과에 적용됩니다.", "ok"); void qc.invalidateQueries({ queryKey: ["/advisories"] }); void qc.invalidateQueries({ queryKey: [`/advisories/${id}`] }); nav("/advisories"); },
    onError: (e) => toast(e.message, "error"),
  });
  const del = useMutation<void, ApiError>({
    mutationFn: () => api.del(`/advisories/${encodeURIComponent(id!)}`),
    onSuccess: () => { toast("삭제했습니다.", "ok"); void qc.invalidateQueries({ queryKey: ["/advisories"] }); nav("/advisories"); },
    onError: (e) => toast(e.message, "error"),
  });
  const dis = !sec;
  if (!isNew && q.isError) { // nothing to edit or delete: only say so
    return (
      <>
        <PageHeader title={id!} crumbs={[{ label: "사내 Advisory", to: "/advisories" }, { label: id! }]} />
        <div className="panel"><Empty icon="alert" title={q.error.status === 404 ? "Advisory를 찾을 수 없습니다" : "Advisory를 불러오지 못했습니다"}
          description={q.error.status === 404 ? "없는 ID이거나 삭제된 Advisory입니다." : q.error.message}
          action={<Link className="btn btn-secondary btn-sm" to="/advisories">Advisory 목록으로</Link>} /></div>
      </>
    );
  }
  if (isNew && me && !sec) {
    return (
      <>
        <PageHeader title="새 Advisory" crumbs={[{ label: "사내 Advisory", to: "/advisories" }, { label: "새로 만들기" }]} />
        <div className="panel"><Empty icon="alert" title="권한이 없습니다" description="사내 Advisory는 보안 담당자만 만들 수 있습니다."
          action={<Link className="btn btn-secondary btn-sm" to="/advisories">Advisory 목록으로</Link>} /></div>
      </>
    );
  }
  return (
    <>
      <PageHeader title={isNew ? "새 Advisory" : f.id || "Advisory"} crumbs={[{ label: "사내 Advisory", to: "/advisories" }, { label: isNew ? "새로 만들기" : id! }]}
        actions={sec && q.data ? <Button variant="danger" loading={del.isPending} onClick={() => confirm("이 Advisory를 삭제할까요? 이로 인해 생긴 결과가 정리됩니다.") && del.mutate()}>삭제</Button> : undefined} />
      {!isNew && <Loading q={q} />}
      {!sec && <div className="alert alert-info">읽기 전용입니다. 수정은 보안 담당자만 할 수 있습니다.</div>}
      {(q.data?.warnings ?? []).map((w, i) => <div key={i} className="alert alert-warn" role="alert">{w}</div>)}
      {(isNew || q.data) && (
        <form className="stack" style={{ maxWidth: 980 }} onSubmit={(e) => { e.preventDefault(); if (valid) prev.mutate(); }}>
          <Panel title="기본 정보">
            <div className="stack">
              <div className="admin-form" style={{ maxWidth: "none" }}>
                <div className="two">
                  <Field label="ID" required error={isNew && body.id && !idOK ? "대문자로 시작하고 대문자·숫자·하이픈만 써서 3~41자로 입력하세요. 예: JASCA-2026-001" : undefined}
                    hint={isNew && body.id && !idOK ? undefined : "대문자·숫자·하이픈, 3~41자. 예: JASCA-2026-001"}><input className="input mono" value={f.id} disabled={dis || !isNew} onChange={(e) => set({ id: e.target.value.toUpperCase() })} /></Field>
                  <Field label="심각도" required><select className="input" value={f.severity} disabled={dis} onChange={(e) => set({ severity: e.target.value as Severity })}>
                    {SEVERITIES.map((s) => <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>)}</select></Field>
                </div>
                <Field label="제목" required><input className="input" value={f.title} disabled={dis} onChange={(e) => set({ title: e.target.value })} /></Field>
                <Field label="설명"><textarea className="input" value={f.description} disabled={dis} onChange={(e) => set({ description: e.target.value })} /></Field>
                <Field label="참고 링크" hint="공백 또는 줄바꿈으로 구분"><textarea className="input mono" value={f.refs} disabled={dis} onChange={(e) => set({ refs: e.target.value })} /></Field>
                <Check checked={f.active} onChange={(v) => !dis && set({ active: v })}>사용 중 <span className="muted">· 끄면 이후 스캔과 재평가에 적용하지 않습니다</span></Check>
              </div>
            </div>
          </Panel>
          <Panel title="영향 받는 패키지"><AffectedEditor rows={f.affected} onChange={(r) => set({ affected: r })} disabled={dis} /></Panel>
          {sec && <div className="row-gap">
            <Button type="submit" loading={prev.isPending} disabled={!valid}>영향 미리보기</Button>
            <span className="muted">저장 전에 어떤 프로젝트가 영향을 받는지 확인한 뒤 저장합니다.</span>
          </div>}
        </form>
      )}
      <Dialog open={preview !== null} onClose={() => setPreview(null)} size="lg" title="영향 미리보기"
        description={!preview ? undefined : f.active ? `${preview.length.toLocaleString("ko-KR")}건의 기존 스캔 결과가 이 Advisory에 걸립니다.`
          : `"사용 중"이 꺼져 있습니다. 저장하면 이 Advisory로 생긴 결과 ${preview.length.toLocaleString("ko-KR")}건이 해결됨으로 바뀌고, 새 결과는 생기지 않습니다.`}
        footer={<><Button onClick={() => setPreview(null)}>계속 수정</Button><Button variant="primary" loading={save.isPending} onClick={() => save.mutate()}>저장</Button></>}>
        <Table dense maxHeight={320} caption="영향 미리보기" rows={preview ?? []} rowKey={(r) => `${r.project_key}|${r.target}|${r.pkg}|${r.version}`}
          columns={[{ key: "p", header: "프로젝트", render: (r) => r.project_key }, { key: "t", header: "대상", render: (r) => r.target },
            { key: "k", header: "패키지", mono: true, render: (r) => r.pkg }, { key: "v", header: "버전", mono: true, render: (r) => r.version }]}
          empty={<Empty compact title={f.active ? "영향 받는 결과가 없습니다" : "해결됨으로 바뀔 결과가 없습니다"} description="저장해도 지금 있는 스캔 결과는 바뀌지 않습니다." />} />
      </Dialog>
    </>
  );
}
