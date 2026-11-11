import type { ExceptionResolution, ExceptionScope, FindingKind, FindingOrigin, ProjectRole, ScanSource, Severity, SystemRole, TargetKind } from "../api/types";

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
/** A stored department path ("/AI실/보안팀") as people write it: no leading slash. */
export const fmtDept = (path: string) => path.replace(/^\//, "");
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

/** "오늘", "3일 전": how long ago a finding was first seen. */
export const fmtDaysAgo = (iso: string) => { const d = daysSince(iso); return d === 0 ? "오늘" : `${d}일 전`; };

/** Whole days from now until iso, rounded up: 0 = within the next day, negative = that many days past. */
export const daysUntil = (iso: string, now = Date.now()) => Math.ceil((new Date(iso).getTime() - now) / 86_400_000);

// Severities keep the names scanners, CVE feeds and CI logs use; the other labels are Korean.
export const SEVERITY_LABEL: Record<Severity, string> = { CRITICAL: "CRITICAL", HIGH: "HIGH", MEDIUM: "MEDIUM", LOW: "LOW", UNKNOWN: "UNKNOWN" };
export const SOURCE_LABEL: Record<ScanSource, string> = { upload: "CI 업로드", server: "파일 업로드", harbor: "Harbor", recheck: "재평가" };
export const ORIGIN_LABEL: Record<FindingOrigin, string> = { scan: "스캔", recheck: "재평가", advisory: "사내 Advisory" };
export const SCOPE_LABEL: Record<ExceptionScope, string> = { finding: "결과", project_vuln: "프로젝트 전체", global_vuln: "전사" };
export const RESOLUTION_LABEL: Record<ExceptionResolution, string> = { accepted: "위험 수용", false_positive: "오탐" };

// --- Task 16: finding/target labels and date-input helpers ---
export const KIND_LABEL: Record<FindingKind, string> = { vuln: "취약점", misconfig: "설정 오류", secret: "비밀값", sast: "코드 분석" };
// short forms of the scan form's "소스 코드·패키지" and "컨테이너 이미지", to fit table tags
export const TARGET_KIND_LABEL: Record<TargetKind, string> = { image: "이미지", repo: "저장소", fs: "소스·패키지", sbom: "SBOM" };
export const ROLE_LABEL: Record<ProjectRole, string> = { owner: "소유자", member: "멤버", viewer: "보기 전용" };
export const SYSTEM_ROLE_LABEL: Record<SystemRole, string> = { "": "일반 사용자", security: "보안 담당", admin: "관리자" };
// Date pickers work in calendar days of the display zone (TZ), like every date shown; the browser's own zone never counts.
/** The display zone's wall clock at instant t, read as if it were UTC. */
const wallClock = (t: number) => {
  const p: Record<string, number> = {};
  for (const x of new Intl.DateTimeFormat("en-US", { timeZone: TZ, hourCycle: "h23", year: "numeric", month: "numeric", day: "numeric", hour: "numeric", minute: "numeric", second: "numeric" }).formatToParts(t)) p[x.type] = Number(x.value);
  return Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute, p.second);
};
/** YYYY-MM-DD `days` from today in the display zone, for <input type="date"> values and min/max. */
export const dateInput = (days = 0) => {
  const d = new Date(wallClock(Date.now()));
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0, 10);
};
/** The YYYY-MM-DD of an instant in the display zone, for a date input that shows a stored time. */
export const dateOf = (iso: string) => new Date(wallClock(new Date(iso).getTime())).toISOString().slice(0, 10);
/**
 * A deadline as people say it: "3일 남음", "오늘까지", "5일 지남", counted in calendar days of the display zone.
 * over: the deadline has passed (what the API counts as overdue). days: calendar days left, negative when past.
 */
export function fmtDue(iso: string, now = Date.now()) {
  const day = (t: number) => Math.floor(wallClock(t) / 86_400_000);
  const days = day(new Date(iso).getTime()) - day(now);
  const over = new Date(iso).getTime() < now;
  return { over, days, text: over ? (days < 0 ? `${-days}일 지남` : "오늘 지남") : days === 0 ? "오늘까지" : `${days}일 남음` };
}
/** 23:59:59 of that day in the display zone as RFC3339; the API caps expiry at 365 days, so date pickers stop at dateInput(364). */
export const endOfDayISO = (date: string) => {
  const t = Date.parse(`${date}T23:59:59Z`);
  return new Date(2 * t - wallClock(t)).toISOString(); // t minus the zone's offset at about that time
};
