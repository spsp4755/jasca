import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { api, type ApiError } from "../api/client";
import { useApi } from "../api/hooks";
import type { Project, Target } from "../api/types";
import Button from "../components/Button";
import Dialog from "../components/Dialog";
import Field from "../components/Field";
import Icon from "../components/Icon";
import { useToast } from "../components/Toast";
import Table from "../components/Table";
import { TARGET_KIND_LABEL, fmtDateTime, fmtNumber, fmtRelative } from "../lib/format";
import { SummaryCell } from "./Home";
import { FirstScan } from "./ProjectFindings";

export default function ProjectTargets({ project }: { project: Project }) {
  const q = useApi<Target[] | null>(`/projects/${project.key}/targets`);
  const navigate = useNavigate();
  const rows = q.data ?? [];
  const owner = project.my_role === "owner";
  const [edit, setEdit] = useState<{ t: Target; del: boolean } | null>(null);
  if (q.isSuccess && !rows.length) return <FirstScan project={project} />;
  return (
    <div className="panel">
      {q.isError && <div className="alert alert-danger" role="alert" style={{ margin: 12 }}><Icon name="alert" />{q.error.message}</div>}
      <Table<Target> caption="대상 목록" rows={rows} rowKey={(t) => t.id} loading={q.isPending}
        onRowClick={(t) => navigate(`/projects/${project.key}?target_id=${t.id}`)}
        columns={[
          { key: "kind", header: "종류", width: 100, render: (t) => <span className="tag tag-quiet">{TARGET_KIND_LABEL[t.kind] ?? t.kind}</span> },
          { key: "name", header: "이름", render: (t) => (
            <span className="target-name">
              <span className="mono">{t.name}</span>
              {t.recheck_excluded && <span className="tag tag-quiet" title="Harbor 대상은 재평가와 사내 Advisory 매칭에서 제외됩니다.">재평가 제외</span>}
            </span>) },
          { key: "open", header: "열린 결과", width: 90, align: "right", render: (t) => <b className={`num${t.counts.open ? "" : " muted"}`}>{fmtNumber(t.counts.open)}</b> },
          { key: "sev", header: "심각도별", width: 260, render: (t) => <SummaryCell s={t.counts} /> },
          { key: "scan", header: "마지막 스캔", width: 120, align: "right", render: (t) => <span className="muted" title={fmtDateTime(t.last_scan_at)}>{t.last_scan_at ? fmtRelative(t.last_scan_at) : "없음"}</span> },
          { key: "go", header: <span className="sr-only">스캔 기록</span>, width: 96, align: "right", render: (t) => <Link to={`/projects/${project.key}/scans?target_id=${t.id}`} className="nw">스캔 기록</Link> },
          ...(owner ? [{ key: "edit", header: <span className="sr-only">관리</span>, width: 150, align: "right" as const, render: (t: Target) => (
            <span className="row-actions">
              {!t.recheck_excluded && <Button size="sm" variant="ghost" aria-label={`${t.name} 이름 변경`} onClick={() => setEdit({ t, del: false })}>이름 변경</Button>}
              <Button size="sm" variant="ghost" aria-label={`${t.name} 삭제`} onClick={() => setEdit({ t, del: true })}>삭제</Button>
            </span>) }] : []),
        ]} />
      {edit && <TargetDialog project={project} target={edit.t} del={edit.del} onClose={() => setEdit(null)} />}
    </div>
  );
}

/** Rename or delete one target (owners). The way out when a version went into the name and every release became its own target. */
function TargetDialog({ project, target, del, onClose }: { project: Project; target: Target; del: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [name, setName] = useState(target.name);
  const path = `/projects/${project.key}/targets/${target.id}`;
  const m = useMutation<unknown, ApiError>({
    mutationFn: () => (del ? api.del(path) : api.patch(path, { name: name.trim() })),
    onSuccess: () => {
      // counts on the home screen, the project and the lists all include this target
      void qc.invalidateQueries();
      toast(del ? `대상 "${target.name}"을(를) 삭제했습니다.` : `대상 이름을 "${name.trim()}"(으)로 바꿨습니다.`, "ok");
      onClose();
    },
  });
  const err = m.isError && <div className="alert alert-danger" role="alert" style={{ margin: 0 }}><Icon name="alert" />{m.error.message}</div>;
  if (del) return (
    <Dialog open onClose={onClose} size="sm" title="대상을 삭제할까요?"
      description={<><span className="mono">{target.name}</span>의 스캔 기록과 결과{target.counts.open ? `(열린 결과 ${fmtNumber(target.counts.open)}건 포함)` : ""}가 모두 지워지며 되돌릴 수 없습니다.</>}
      footer={<><Button onClick={onClose}>취소</Button><Button variant="danger" loading={m.isPending} onClick={() => m.mutate()}>삭제</Button></>}>
      <p className="muted" style={{ margin: 0 }}>같은 서비스의 새 버전을 다른 이름으로 올려 생긴 대상이라면, 지우는 대신 이름을 바꾸고 그 이름으로 다시 스캔하면 고친 취약점이 조치됨으로 남습니다.</p>
      {err}
    </Dialog>
  );
  return (
    <Dialog open onClose={onClose} size="sm" title="대상 이름 변경" description="스캔 기록과 결과는 그대로 따라갑니다."
      footer={<><Button onClick={onClose}>취소</Button><Button variant="primary" loading={m.isPending} disabled={!name.trim() || name.trim() === target.name} onClick={() => m.mutate()}>변경</Button></>}>
      <form onSubmit={(e) => { e.preventDefault(); if (name.trim() && name.trim() !== target.name) m.mutate(); }}>
        <Field label="대상 이름" hint="버전은 빼고 서비스 이름만 쓰세요(예: web-app). CI나 스크립트가 예전 이름으로 올리고 있다면 그쪽 이름도 바꿔야 같은 대상으로 쌓입니다.">
          <input className="input mono" value={name} maxLength={200} spellCheck={false} autoComplete="off" onChange={(e) => setName(e.target.value)} />
        </Field>
      </form>
      {err}
    </Dialog>
  );
}
