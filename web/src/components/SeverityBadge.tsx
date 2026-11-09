import type { Severity } from "../api/types";
import { SEVERITY_LABEL } from "../lib/format";

/** Tinted pill with a swatch. `count` renders "치명 12" (counts in tables and summaries). */
export default function SeverityBadge({ severity, count, compact }: { severity: Severity; count?: number; compact?: boolean }) {
  const s = severity.toLowerCase();
  return (
    <span className={`sev sev-${s}${compact ? " sev-compact" : ""}`} title={severity}>
      <span className="sev-dot" aria-hidden="true" />
      {compact ? <span className="sr-only">{SEVERITY_LABEL[severity]}</span> : SEVERITY_LABEL[severity]}
      {count !== undefined && <span className="sev-count">{count.toLocaleString("ko-KR")}</span>}
    </span>
  );
}
