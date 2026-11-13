// Mirrors the API contract in .superpowers/sdd/2026-11-09-jasca-v1/common.md (snake_case, times are RFC3339 strings).
// Where the contract only names a field (e.g. dashboard lists, scan rows) the shape follows the DB schema columns.

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
export const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
export type FindingStatus = "open" | "fixed" | "accepted" | "false_positive";
export type FindingKind = "vuln" | "misconfig" | "secret" | "sast";
export type FindingOrigin = "scan" | "recheck" | "advisory";
export type SystemRole = "" | "admin" | "security";
export type ProjectRole = "owner" | "member" | "viewer";
export type TargetKind = "image" | "repo" | "fs" | "sbom";
export type ScanSource = "upload" | "server" | "harbor" | "recheck";
export type JobState = "queued" | "running" | "done" | "failed" | "canceled";
export type ExceptionScope = "finding" | "project_vuln" | "global_vuln";
export type ExceptionResolution = "accepted" | "false_positive";
export type ExceptionStatus = "pending" | "approved" | "rejected" | "expired" | "revoked";
export type TokenScope = "upload" | "read";
export type ChannelKind = "mattermost" | "email";

/** Error body: `{"error":"<code>","message":"<Korean text>"}`. */
export interface ApiErrorBody { error: string; message: string }

/** Severity counts used by projects, targets, scan summaries and dashboard totals. */
export interface Counts { critical: number; high: number; medium: number; low: number; unknown: number; open: number }

// --- auth / me ---
/** tz: IANA zone from JASCA_TZ; the UI shows times in it. */
/** ai_enabled, max_scan_upload_mb and trivy_db_ready (false: no vulnerability DB yet, scans are refused) come only when signed in. */
/** session_ended: why this browser's session stopped working ("replaced" = the account signed in somewhere else). */
export interface AuthConfig { sso_enabled: boolean; local_login?: boolean; session_ended?: string; tz?: string; version?: string; signed_in?: boolean; ai_enabled?: boolean; max_scan_upload_mb?: number; trivy_db_ready?: boolean }
export interface LocalLoginRequest { username: string; password: string }
export interface LocalLoginResponse { user: Me }
export interface Me {
  id: number; username: string; name: string; email: string; system_role: SystemRole; source: "local" | "sso"; depts: string[]; groups: string[];
  /** Only in the first /me after a login that found the account open elsewhere: sessions it ended, sessions still open. */
  session_notice?: { ended: number; active: number };
}
export interface Principal { kind: "user" | "group"; principal: string; display: string }

// --- projects ---
/** my_role is "" for API-token callers. */
export interface Project {
  id: number; key: string; name: string; description: string; created_by: number | null; created_at: string;
  my_role: ProjectRole | ""; counts: Counts; last_scan_at: string | null;
  /** open findings past their deadline */
  overdue: number;
}
export interface ProjectCreate { key: string; name: string; description: string }
export interface Member { principal_kind: "user" | "group"; principal: string; role: ProjectRole; display: string }
export interface ApiToken {
  id: number; project_id: number; created_by: number | null; name: string; prefix: string; scopes: TokenScope[]; expires_at: string; last_used_at: string | null;
  created_at: string; revoked_at: string | null;
}
export interface TokenCreate { name: string; scopes: TokenScope[]; expires_at: string }
/** `token` is plaintext and only ever returned here. */
export interface TokenCreated { id: number; token: string }
/** A personal MCP key: the agent that presents it acts as its user. */
export interface McpKey {
  id: number; user_id: number; name: string; prefix: string; read_only: boolean; expires_at: string; last_used_at: string | null;
  created_at: string; revoked_at: string | null;
}
/** The administrator's view of everyone's keys. */
export interface AdminMcpKey extends McpKey { username: string; user_name: string; user_active: boolean }
/** `key` is plaintext and only ever returned here. */
export interface McpKeyCreated { id: number; key: string }
/** One MCP tool as the key page lists it; disabled = not for the signed-in person's role. */
export interface McpToolInfo { name: string; title: string; group: "user" | "security" | "admin"; write: boolean; disabled: boolean }
export interface Policy { enabled: boolean; min_severity: Severity; max_count: number; new_only: boolean; fixable_only: boolean }
export interface NotifySub { channel_id: number; events: string[] }
export interface Target {
  id: number; kind: TargetKind; name: string; last_scan_at: string | null; counts: Counts; recheck_excluded: boolean;
}

// --- scans ---
/** error is set when the gate failed closed (evaluation error). */
/** disabled: the project's policy was off, so nothing was judged (passed is still true, for CI). */
export interface PolicyResult { passed: boolean; reasons: string[]; error?: string; disabled?: boolean }
export interface Scan {
  id: number; project_id: number; target_id: number; target_kind: TargetKind; target_name: string; source: ScanSource;
  format: string; ref: string; status: JobState; error: string; created_by_user: number | null; created_by_token: number | null; created_by: string;
  /** packages: how many the scan examined. warnings: what it could not examine (Java archives without a Java DB, nothing recognisable). */
  summary: Partial<Counts> & { os?: { family: string; name: string }; packages?: number; warnings?: string[] }; policy: PolicyResult | null; has_raw: boolean;
  created_at: string; finished_at: string | null;
}
export interface ScanPage { items: Scan[]; next_before: number | null }
/** diff compares with the previous done scan of the same target and format (set difference of linked findings). */
export interface ScanDetail extends Scan { diff: { new: number; fixed: number; unchanged: number; not_covered: number; previous_scan_id: number | null } }
export interface ScanJobCreated { scan_id: number }

// --- findings / vulns ---
/** Who fixes a finding. name is the person's name, else the username; active false = the account was deactivated since. */
export interface Assignee { id: number; name: string; username: string; active: boolean }
export interface Finding {
  id: number; project_id: number; project_key: string; target_id: number; target_kind: TargetKind; target_name: string; kind: FindingKind; tool: string; rule_id: string; title: string;
  severity: Severity; pkg_name: string; pkg_version: string; fixed_version: string; pkg_path: string; location: string;
  status: FindingStatus; origin: FindingOrigin; first_seen_at: string; last_seen_at: string; fixed_at: string | null;
  reopened_count: number; exception_id: number | null; details: Record<string, unknown>;
  /** due_at: the deadline, only while open (overdue = it is in the past). due_manual: a person set it, not the deadline setting. */
  assignee: Assignee | null; due_at: string | null; due_manual: boolean;
  pending_exception_id?: number | null; // GET /findings/{id} only: a request waiting for a decision that covers it
  sla_days?: number | null; // GET /findings/{id} only: the days the deadline setting gives this severity
}
/** Query of GET /findings and /findings.csv. severity, status, kind and origin take comma lists. */
export interface FindingFilters {
  project?: string; target_id?: string; severity?: string; status?: string; kind?: string; origin?: string;
  fixable?: "true" | "false" | ""; q?: string; limit?: number; cursor?: string;
  /** assignee: "me", "none" or a user id. due: overdue, or soon = within 7 days. sort=due: earliest deadline first. */
  assignee?: string; due?: string; sort?: string;
}
export interface FindingPage { items: Finding[]; next_cursor: string | null; total: number }
export interface VulnAffected {
  project_key: string; target: string; finding_id: number; severity: Severity; status: FindingStatus;
  pkg_name: string; pkg_version: string; fixed_version: string;
}
export interface Vuln {
  id: string; title: string; description: string; cvss_score: number | null; cvss_vector: string; refs: string[];
  cwe_ids: string[]; published_at: string | null; last_modified_at: string | null; ai_guide: string; ai_guide_at: string | null;
  /** the id is an internal advisory (/advisories/{id}) */
  advisory?: boolean;
  affected: VulnAffected[];
}

// --- packages ---
/** One package of a target's current inventory. open_findings 0 = no known vulnerability yet. */
export interface PackageHit {
  project_key: string; project_name: string; target_id: number; target_kind: TargetKind; target_name: string;
  ecosystem: string; name: string; version: string; paths: string[]; path_count: number; scan_id: number; scan_at: string;
  open_findings: number; worst_severity: Severity | ""; version_unknown: boolean;
}
export interface PackageSearch {
  items: PackageHit[]; truncated: boolean; ecosystems: string[];
  totals: { matched: number; version_unknown: number; projects: number; targets: number; targets_searched: number; targets_without_inventory: number };
}

// --- AI ---
export interface RunRef { run_id: number }
export interface AiRun {
  id: number; kind: "vuln_guide" | "project_report"; project_id: number | null; vuln_id: string | null;
  state: "queued" | "running" | "done" | "failed"; output: string; error: string; created_at: string; finished_at: string | null;
}

// --- exceptions / advisories ---
export interface ExceptionItem {
  id: number; scope: ExceptionScope; project_id: number | null; finding_id: number | null; vuln_id: string | null;
  resolution: ExceptionResolution; reason: string; status: ExceptionStatus; requested_by: number | null;
  decided_by: number | null; decided_at: string | null; decision_note: string; expires_at: string; created_at: string;
  project_key?: string;
  finding_rule?: string | null; finding_pkg?: string | null; finding_severity?: Severity | null;
  /** name (else username) of requested_by and decided_by; "" when the account is gone */
  requested_by_name?: string; decided_by_name?: string;
  /** finding scope: the target the finding is on */
  finding_target?: string | null;
}
export interface ExceptionCreate {
  scope: ExceptionScope; project_key?: string; finding_ids?: number[]; vuln_id?: string;
  resolution: ExceptionResolution; reason: string; expires_at: string;
}
export interface AdvisoryAffected { ecosystem: string; name: string; range: string; fixed: string }
export interface Advisory {
  id: string; title: string; description: string; severity: Severity; affected: AdvisoryAffected[]; refs: string[];
  active: boolean; created_at: string; updated_at: string;
}
export interface AdvisoryPreviewRow { project_key: string; target: string; pkg: string; version: string }

// --- dashboard ---
export interface TrendPoint { date: string; critical: number; high: number; medium: number; low: number }
export interface DashboardFinding {
  id: number; project_key: string; target: string; rule_id: string; title: string; severity: Severity;
  pkg_name: string; pkg_version: string; fixed_version: string; location: string; origin: FindingOrigin; first_seen_at: string;
}
export interface DashboardScan {
  id: number; project_key: string; target: string; source: ScanSource; status: JobState; summary: Partial<Counts>;
  policy: PolicyResult | null; created_at: string;
}
export interface Dashboard {
  totals: Counts; trend: TrendPoint[]; oldest_critical: DashboardFinding[]; expiring_exceptions: ExceptionItem[];
  recent_scans: DashboardScan[]; newly_known: DashboardFinding[];
  /** overdue: open findings past their deadline by severity (open = all). mine: open findings assigned to me. */
  overdue: Counts; mine: { open: number; overdue: number };
}

// --- audit / channels ---
export interface AuditEntry {
  id: number; at: string; actor_user: number | null; actor_token: number | null; ip: string; action: string;
  project_id: number | null; target: string; details: Record<string, unknown>; actor?: string;
  /** "" without a project; kept after the project is deleted */
  project_key?: string;
}
export interface AuditPage { items: AuditEntry[]; next_cursor: string | null }
export interface Channel { id: number; name: string; kind: ChannelKind }

// --- admin ---
export interface AdminUser {
  id: number; username: string; name: string; email: string; source: "local" | "sso"; system_role: SystemRole;
  role_from_sso: boolean; active: boolean; last_login_at: string | null; created_at: string; depts: string[]; groups: string[];
}
/** role_from_sso: true hands the role back to Keycloak (decided again at the user's next Keycloak login). */
export interface AdminUserPatch { system_role?: SystemRole; role_from_sso?: true; active?: boolean }
export interface SSOSettings {
  issuer: string; client_id: string; client_secret_set: boolean; admin_role: string; security_role: string;
  public_url: string; enabled: boolean;
}
/** PUT body: an empty or omitted client_secret keeps the stored one. */
export type SSOSettingsPut = Omit<SSOSettings, "client_secret_set"> & { client_secret?: string };
export interface SyncSettings {
  client_id: string; client_secret_set: boolean; interval_min: number; dept_attribute: string; dept_off: boolean;
  last_run: string | null; last_error: string;
}
export type TrivyScanner = "vuln" | "secret" | "misconfig";
export type TrivyPkgType = "os" | "library";
/** What the admin chose for every server-side Trivy run (PUT /admin/trivy; a field left out keeps its stored value). */
export interface TrivyOptions {
  scanners: TrivyScanner[]; ignore_unfixed: boolean;
  /** all five = no filter */
  severities: Severity[]; pkg_types: TrivyPkgType[]; include_dev_deps: boolean; detection_priority: "precise" | "comprehensive";
  /** glob patterns, at most 50 of 1-200 characters each */
  skip_dirs: string[]; skip_files: string[];
  /** minutes, 1-240; 0 = default_timeout_min */
  timeout_min: number;
}
export interface TrivyStatus extends TrivyOptions {
  /** schema version of the installed DB; 0 = none installed. java_db is {updated_at} or null, also without a DB. */
  db_version: number; updated_at: string | null; next_update: string | null; java_db: { updated_at: string } | null;
  trivy_version: string; default_timeout_min: number;
}
/** POST /admin/trivy/db: kind is what the file turned out to be; recheck_run_id is 0 when no recheck started (Java DB). */
export interface TrivyUpload extends TrivyStatus { kind: "db" | "java-db"; recheck_run_id: number }
export interface RecheckRun {
  id: number; reason: "trivydb" | "manual"; state: "running" | "done" | "failed" | "canceled"; total: number; done: number;
  new_findings: number; started_at: string; finished_at: string | null; error: string;
}
export interface HarborLink { id: number; name: string; base_url: string; robot_user: string; robot_secret_set: boolean; created_at: string }
/** webhook_secret is shown once, right after creation. */
export interface HarborLinkCreated { id: number; webhook_url: string; webhook_secret: string }
export interface HarborMapping { harbor_project: string; repo_pattern: string; project_id: number }
export interface HarborUnmapped {
  id: number; link_id: number; harbor_project: string; repository: string; digest: string; tag: string; received_at: string;
}
export interface AISettings {
  base_url: string; model: string; api_key_set: boolean; timeout_sec: number; max_input_tokens: number; enabled: boolean;
}
export type AISettingsPut = Omit<AISettings, "api_key_set"> & { api_key?: string };
export interface NotifyChannel { id: number; kind: ChannelKind; name: string; config: Record<string, unknown>; enabled: boolean; created_at: string }
export interface Retention { raw_per_target: number; raw_days: number }

// --- admin (t18) ---
export interface DeptLogin { user: string; at: string; source: "claim" | "claim_empty" | "admin_api" | "missing" | "error" | string; depts: string[] }
export interface SyncStatus extends SyncSettings { groups: number; users: number }
export interface SyncRunResult { groups: number; users: number; error: string }
/** Assumed shape of GET/PUT /admin/ai/prompts (contract does not spell it out). */
export interface AIPrompts { vuln_guide: string; project_report: string }
/** GET adds the built-in prompts an empty field falls back to. */
export interface AIPromptsView extends AIPrompts { defaults: AIPrompts }
export type DefaultPolicy = Policy;
/** GET/PUT /admin/sla: days a finding of each severity may stay open; null or left out = no deadline (UNKNOWN never has one). */
export interface SLA { enabled: boolean; days: Partial<Record<Severity, number | null>> }
export interface SMTPSettings { host: string; port: number; username: string; password_set: boolean; from: string; tls: "starttls" | "tls" | "none" }
/** PUT body: an empty or omitted password keeps the stored one. */
export type SMTPSettingsPut = Omit<SMTPSettings, "password_set"> & { password?: string };

// --- reports (t17) ---
/** GET /projects/{key}/report (reports.go): open findings summary, targets, top 100 open findings, active exceptions,
 * the project's policy settings and the latest finished AI report. */
export interface ReportFinding {
  id: number; target: string; kind: FindingKind; rule_id: string; title: string; severity: Severity;
  pkg_name: string; pkg_version: string; fixed_version: string; first_seen_at: string;
  location: string; details: { start_line?: number; end_line?: number };
}
// --- 조치 계획: GET /projects/{key}/fixes ---
export interface FixFinding { id: number; rule_id: string; severity: Severity; title: string; target_id: number; target: string; pkg_path: string; fixed_version: string }
export interface FixTarget { id: number; kind: TargetKind; name: string; paths: string[] }
/**
 * One package at one installed version. recommended: that version or a higher one resolves every finding counted in
 * resolves (resolves.open = all of them); "" when the fixed versions could not be compared, then fixed_versions is shown as written.
 */
export interface FixGroup {
  package: string; ecosystem: string; installed: string; recommended: string; fixed_versions: string[];
  resolves: Counts; no_fix: number; targets: FixTarget[]; findings: FixFinding[];
}
/** inventory_targets: targets whose scans listed packages (0: nothing looked at packages). truncated: only the `limit` most severe findings were grouped. */
export interface FixPlan {
  groups: FixGroup[]; no_fix_groups: FixGroup[];
  totals: { open_vulns: number; fixable: number; no_fix: number; other_kinds: Record<"misconfig" | "secret" | "sast", number>; inventory_targets: number };
  limit: number; truncated: boolean;
}
export interface ProjectReportData {
  project: { key: string; name: string; description: string };
  generated_at: string;
  summary: { by_severity: Counts; by_kind: Record<FindingKind, number>; overdue?: Counts };
  targets: Target[];
  findings: ReportFinding[];
  exceptions: ExceptionItem[];
  policy: Policy;
  ai_report: { id: number; output: string; created_at: string } | null;
}
