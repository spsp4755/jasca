import type { ExceptionResolution, ExceptionScope, FindingKind, FindingOrigin, ProjectRole, ScanSource, Severity, TargetKind } from "../api/types";

export const DEFAULT_TZ = "Asia/Seoul";
/** Zone every time is shown in (JASCA_TZ, from GET /auth/config). Set by useAuthConfig before signed-in pages render. */
export let TZ = DEFAULT_TZ;

let dateFmt: Intl.DateTimeFormat, dtFmt: Intl.DateTimeFormat, mdFmt: Intl.DateTimeFormat;
const build = (timeZone: string) => {
  dateFmt = new Intl.DateTimeFormat("ko-KR", { timeZone, year: "numeric", month: "2-digit", day: "2-digit" });
  dtFmt = new Intl.DateTimeFormat("ko-KR", {
    timeZone, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hourCycle: "h23",
  });
  mdFmt = new Intl.DateTimeFormat("ko-KR", { timeZone, month: "numeric", day: "numeric" });
};
build(TZ);

/** Switches the display zone; an empty or unknown name (Intl throws RangeError) keeps Asia/Seoul. */
export function setTimeZone(tz?: string) {
  const next = tz || DEFAULT_TZ;
  if (next === TZ) return;
  try { build(next); TZ = next; } catch { build(DEFAULT_TZ); TZ = DEFAULT_TZ; }
}
const numFmt = new Intl.NumberFormat("ko-KR");

const valid = (iso?: string | null) => (iso ? new Date(iso) : null);
const ok = (d: Date | null): d is Date => !!d && !Number.isNaN(d.getTime());

/** 2026. 11. 09. */
export const fmtDate = (iso?: string | null) => { const d = valid(iso); return ok(d) ? dateFmt.format(d) : "—"; };
/** 2026. 11. 09. 14:05 */
export const fmtDateTime = (iso?: string | null) => { const d = valid(iso); return ok(d) ? dtFmt.format(d) : "—"; };
/** 11. 9. — chart axes. A bare YYYY-MM-DD is a calendar day, not an instant, so it is not shifted. */
export const fmtMonthDay = (date: string) => {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(date);
  if (m) return `${Number(m[2])}. ${Number(m[3])}.`;
  const d = valid(date);
  return ok(d) ? mdFmt.format(d) : date;
};
export const fmtNumber = (n?: number | null) => (n == null ? "—" : numFmt.format(n));

/** "방금", "5분 전", "3일 전", "2일 후" … falls back to the date after 30 days. */
export function fmtRelative(iso?: string | null, now = Date.now()): string {
  const d = valid(iso);
  if (!ok(d)) return "—";
  const diff = d.getTime() - now;
  const abs = Math.abs(diff);
  const suffix = diff < 0 ? "전" : "후";
  const min = 60_000, hour = 60 * min, day = 24 * hour;
  if (abs < min) return "방금";
  if (abs < hour) return `${Math.floor(abs / min)}분 ${suffix}`;
  if (abs < day) return `${Math.floor(abs / hour)}시간 ${suffix}`;
  if (abs < 30 * day) return `${Math.floor(abs / day)}일 ${suffix}`;
  return fmtDate(iso);
}

/** Whole days from iso to now (age of an open finding). */
export const daysSince = (iso: string, now = Date.now()) => Math.max(0, Math.floor((now - new Date(iso).getTime()) / 86_400_000));

/** Whole days from now until iso, rounded up: 0 = within the next day, negative = that many days past. */
export const daysUntil = (iso: string, now = Date.now()) => Math.ceil((new Date(iso).getTime() - now) / 86_400_000);

// Korean labels; the API enum stays visible as a tooltip where it matters (SeverityBadge title).
export const SEVERITY_LABEL: Record<Severity, string> = { CRITICAL: "치명", HIGH: "높음", MEDIUM: "중간", LOW: "낮음", UNKNOWN: "알 수 없음" };
export const SOURCE_LABEL: Record<ScanSource, string> = { upload: "CI 업로드", server: "서버 스캔", harbor: "Harbor", recheck: "재평가" };
export const ORIGIN_LABEL: Record<FindingOrigin, string> = { scan: "스캔", recheck: "재평가", advisory: "사내 Advisory" };
export const SCOPE_LABEL: Record<ExceptionScope, string> = { finding: "결과", project_vuln: "프로젝트 전체", global_vuln: "전사" };
export const RESOLUTION_LABEL: Record<ExceptionResolution, string> = { accepted: "위험 수용", false_positive: "오탐" };

// --- Task 16: finding/target labels and date-input helpers ---
export const KIND_LABEL: Record<FindingKind, string> = { vuln: "취약점", misconfig: "설정 오류", secret: "비밀값", sast: "코드 분석" };
export const TARGET_KIND_LABEL: Record<TargetKind, string> = { image: "이미지", repo: "저장소", fs: "파일시스템", sbom: "SBOM" };
export const ROLE_LABEL: Record<ProjectRole, string> = { owner: "소유자", member: "멤버", viewer: "보기 전용" };
/** Local YYYY-MM-DD `days` from today, for <input type="date"> values and min/max. */
export const dateInput = (days = 0) => {
  const d = new Date(Date.now() + days * 86_400_000);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
};
/** End of that local day as RFC3339; the API caps expiry at 365 days, so date pickers stop at dateInput(364). */
export const endOfDayISO = (date: string) => new Date(`${date}T23:59:59`).toISOString();
