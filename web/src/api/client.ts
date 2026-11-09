import type { ApiErrorBody } from "./types";

export const API_BASE = "/api/v1";

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

const FALLBACK: Record<number, string> = {
  0: "서버에 연결하지 못했습니다. 네트워크를 확인하세요.",
  401: "로그인이 필요합니다.",
  403: "권한이 없습니다.",
  404: "찾을 수 없습니다.",
  413: "파일이 너무 큽니다.",
  429: "요청이 너무 많습니다. 잠시 후 다시 시도하세요.",
};

/**
 * A relative path inside this app; anything else becomes "/": //host, https:, any backslash, and control
 * characters (URL parsers drop tabs/newlines, so "/\t/host" would turn into "//host").
 */
export function safeNext(next: string | null | undefined): string {
  return next && next.startsWith("/") && !next.startsWith("//") && !/[\\\u0000-\u001f\u007f]/.test(next) ? next : "/";
}

export function loginUrl(): string {
  return `/login?next=${encodeURIComponent(location.pathname + location.search)}`;
}

type Body = BodyInit | object | undefined;

/**
 * fetch wrapper for /api/v1. Plain objects are sent as JSON; FormData, Blob, strings etc. go as-is.
 * 204 resolves to undefined. Failures throw ApiError. A 401 (outside /auth/*) sends the browser to /login?next=.
 */
export async function request<T>(method: string, path: string, body?: Body, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  let payload: BodyInit | undefined;
  if (body !== undefined) {
    const raw = body instanceof FormData || body instanceof Blob || body instanceof ArrayBuffer ||
      body instanceof URLSearchParams || typeof body === "string" || body instanceof ReadableStream;
    if (raw) payload = body as BodyInit;
    else { payload = JSON.stringify(body); headers.set("Content-Type", "application/json"); }
  }
  let res: Response;
  try {
    res = await fetch(API_BASE + path, { ...init, method, headers, body: payload, credentials: "same-origin" });
  } catch (e) {
    if ((e as Error).name === "AbortError") throw e;
    throw new ApiError(0, "network", FALLBACK[0]);
  }
  if (res.ok) {
    if (res.status === 204) return undefined as T;
    const type = res.headers.get("Content-Type") || "";
    return (type.includes("json") ? res.json() : res.text()) as Promise<T>;
  }
  let err: Partial<ApiErrorBody> = {};
  try { err = await res.json(); } catch { /* non-JSON error page (proxy, gateway) */ }
  if (res.status === 401 && !path.startsWith("/auth/") && location.pathname !== "/login") location.assign(loginUrl());
  throw new ApiError(res.status, err.error || `http_${res.status}`, err.message || FALLBACK[res.status] || `요청을 처리하지 못했습니다. (${res.status})`);
}

export const api = {
  get: <T>(path: string, init?: RequestInit) => request<T>("GET", path, undefined, init),
  post: <T>(path: string, body?: Body, init?: RequestInit) => request<T>("POST", path, body, init),
  put: <T>(path: string, body?: Body, init?: RequestInit) => request<T>("PUT", path, body, init),
  patch: <T>(path: string, body?: Body, init?: RequestInit) => request<T>("PATCH", path, body, init),
  del: <T = void>(path: string, init?: RequestInit) => request<T>("DELETE", path, undefined, init),
};

/** "?a=1&b=x" from an object, skipping undefined, null and "" values. */
export function qs(params: object): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  const s = p.toString();
  return s ? `?${s}` : "";
}
