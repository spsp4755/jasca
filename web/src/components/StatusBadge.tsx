type Tone = "neutral" | "ok" | "warn" | "danger" | "accent" | "muted";

// Finding, scan/job and exception statuses share one badge. Unknown values render as-is in neutral.
const STATUS: Record<string, [string, Tone]> = {
  open: ["열림", "neutral"],
  fixed: ["해결됨", "ok"],
  accepted: ["위험 수용", "accent"],
  false_positive: ["오탐", "muted"],
  queued: ["대기 중", "accent"],
  running: ["진행 중", "accent"],
  done: ["완료", "ok"],
  failed: ["실패", "danger"],
  canceled: ["취소됨", "muted"],
  pending: ["승인 대기", "warn"],
  approved: ["승인됨", "ok"],
  rejected: ["반려됨", "danger"],
  expired: ["만료됨", "muted"],
  revoked: ["철회됨", "muted"],
};

export const statusLabel = (status: string) => STATUS[status]?.[0] ?? status;

export default function StatusBadge({ status }: { status: string }) {
  const [label, tone] = STATUS[status] ?? [status, "neutral"];
  return (
    <span className={`status status-${tone}${status === "running" ? " status-live" : ""}`}>
      <span className="status-dot" aria-hidden="true" />
      {label}
    </span>
  );
}
