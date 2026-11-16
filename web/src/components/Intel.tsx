// Exploitation data of a vulnerability (관리 → Trivy DB → 악용 정보): the KEV badge and the EPSS probability.

/** 0.94358 → "94.4%", 0.00042 → "0.04%". A probability is never certain: 0.99997 stays "99.9%". */
export const fmtPct = (v: number) => `${Math.min(v * 100, 99.9).toFixed(v < 0.01 ? 2 : 1)}%`;
/** Where a percentile puts the vulnerability among all scored CVEs: 0.99957 → "상위 0.1% 이내", 0.92 → "상위 8%". */
export const fmtTop = (pct: number) => { const top = (1 - pct) * 100; return top < 0.1 ? "상위 0.1% 이내" : `상위 ${top.toFixed(top < 10 ? 1 : 0)}%`; };

/** The vulnerability is in CISA's KEV catalog: attacks using it have been seen. With `count`, "악용 확인 3건". */
export function KevBadge({ count }: { count?: number }) {
  return <span className="tag tag-kev" title="실제 공격에 쓰이는 것이 확인된 취약점입니다 (CISA KEV 목록).">악용 확인{count !== undefined && ` ${count.toLocaleString("ko-KR")}건`}</span>;
}

/** EPSS as a percentage; 10% and above (roughly the top few percent of all CVEs) stands out. */
export function EpssText({ value }: { value?: number | null }) {
  if (value == null) return <span className="muted">—</span>;
  return <span className={`num epss${value >= 0.1 ? " epss-high" : ""}`} title={`EPSS: 앞으로 30일 안에 악용될 확률 ${fmtPct(value)}`}>{fmtPct(value)}</span>;
}
