import { useState } from "react";
import type { TargetKind } from "../api/types";
import { copyText } from "../lib/clipboard";
import { TARGET_KIND_LABEL } from "../lib/format";
import Button from "./Button";
import { useToast } from "./Toast";

const SCANNERS = [["vuln", "취약점"], ["misconfig", "설정 오류"], ["secret", "비밀값"]] as const;
type Scanner = (typeof SCANNERS)[number][0];

// encodeURIComponent leaves ! ' ( ) * alone; ! can trigger bash history expansion inside double quotes
const enc = (s: string) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

/** Two shell lines for CI: run Trivy, then upload; the job fails (exit 1) when the policy gate fails. */
export function ciCommand(o: { origin: string; projectKey: string; target: string; kind: TargetKind; scanners: Scanner[]; gzip: boolean }) {
  const sc = o.scanners.join(",");
  const trivy = {
    image: `trivy image --format json --scanners ${sc} -o trivy.json "$IMAGE:$TAG"`,
    repo: `trivy fs --format json --scanners ${sc} -o trivy.json .`,
    fs: `trivy fs --format json --scanners ${sc} -o trivy.json .`,
    sbom: `trivy sbom --format json -o trivy.json sbom.cdx.json`,
  }[o.kind];
  const url = `${o.origin}/api/v1/projects/${o.projectKey}/scans?target=${enc(o.target)}&kind=${o.kind}&ref=$TAG` +
    (o.kind === "sbom" ? "" : `&scanners=${sc}`);
  const auth = `-H "Authorization: Bearer $JASCA_TOKEN"`;
  const upload = o.gzip
    ? `gzip -c trivy.json | curl -fsS -X POST ${auth} -H "Content-Encoding: gzip" --data-binary @- "${url}" | tee jasca.json; grep -q '"passed":true' jasca.json`
    : `curl -fsS -X POST ${auth} --data-binary @trivy.json "${url}" | tee jasca.json; grep -q '"passed":true' jasca.json`;
  return `${trivy}\n${upload}`;
}

export default function CiSnippet({ projectKey, defaultTarget = "", defaultKind = "image" }: {
  projectKey: string; defaultTarget?: string; defaultKind?: TargetKind;
}) {
  const toast = useToast();
  const [target, setTarget] = useState(defaultTarget);
  const [kind, setKind] = useState<TargetKind>(defaultKind);
  const [scanners, setScanners] = useState<Scanner[]>(["vuln"]);
  const [gzip, setGzip] = useState(false);
  const name = target.trim() || (kind === "image" ? "registry.example.internal/team/app" : "team/app");
  const cmd = ciCommand({ origin: location.origin, projectKey, target: name, kind, scanners, gzip });
  const toggle = (s: Scanner) => setScanners((cur) => {
    const next = cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s];
    return next.length ? SCANNERS.map(([k]) => k).filter((k) => next.includes(k)) : cur; // keep at least one
  });
  return (
    <div className="ci">
      <div className="ci-controls">
        <label className="field ci-target">
          <span className="field-label">대상 이름</span>
          <input className="input" value={target} placeholder={name} onChange={(e) => setTarget(e.target.value)} />
        </label>
        <label className="field">
          <span className="field-label">종류</span>
          <select className="input" value={kind} onChange={(e) => setKind(e.target.value as TargetKind)}>
            {(Object.keys(TARGET_KIND_LABEL) as TargetKind[]).map((k) => <option key={k} value={k}>{TARGET_KIND_LABEL[k]}</option>)}
          </select>
        </label>
        {kind !== "sbom" && (
          <fieldset className="field ci-scanners">
            <legend className="field-label">스캐너</legend>
            <div className="ci-checks">
              {SCANNERS.map(([k, label]) => (
                <label key={k} className="check-row"><input type="checkbox" checked={scanners.includes(k)} onChange={() => toggle(k)} />{label}</label>
              ))}
            </div>
          </fieldset>
        )}
        <label className="check-row ci-gzip"><input type="checkbox" checked={gzip} onChange={(e) => setGzip(e.target.checked)} />gzip 압축 업로드</label>
      </div>
      <div className="ci-code">
        <pre aria-label="CI 명령"><code>{cmd}</code></pre>
        <Button size="sm" icon="copy" className="ci-copy"
          onClick={async () => toast((await copyText(cmd)) ? "명령을 복사했습니다." : "복사하지 못했습니다. 직접 선택해 복사하세요.", "info")}>복사</Button>
      </div>
      <ul className="ci-notes">
        <li><code>JASCA_TOKEN</code>은 이 프로젝트의 <b>업로드</b> 권한 API 토큰입니다. CI 비밀 변수로 넣으세요.</li>
        <li><code>TAG</code>는 이미지 태그나 커밋 해시처럼 이번 빌드를 구분하는 값입니다{kind === "image" && <>, <code>IMAGE</code>는 이미지 주소입니다</>}.</li>
        <li>정책을 통과하지 못하거나 업로드가 실패하면 마지막 명령이 종료 코드 1로 끝나 CI 작업이 실패합니다.</li>
      </ul>
    </div>
  );
}
