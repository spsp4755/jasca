import { QueryClient, useMutation, useQuery, useQueryClient, type UseQueryOptions } from "@tanstack/react-query";
import { setTimeZone } from "../lib/format";
import { ApiError, api } from "./client";
import type { AuthConfig, Dashboard, LocalLoginRequest, LocalLoginResponse, Me } from "./types";

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      // one retry for network/5xx; a 4xx will not change on retry
      retry: (count, err) => !(err instanceof ApiError && err.status >= 400 && err.status < 500) && count < 1,
      refetchOnWindowFocus: false,
    },
    mutations: { retry: false },
  },
});

/** GET `path` (relative to /api/v1) cached under the key [path]. Pages add their own typed hooks on top of this. */
export function useApi<T>(path: string | null, opts: Omit<UseQueryOptions<T, ApiError>, "queryKey" | "queryFn"> = {}) {
  return useQuery<T, ApiError>({ queryKey: [path], queryFn: ({ signal }) => api.get<T>(path!, { signal }), enabled: path !== null, ...opts });
}

export const useMe = (enabled = true) => useApi<Me>(enabled ? "/me" : null, { staleTime: 5 * 60_000 });
/** Also applies the server's display time zone (cfg.tz) before anything reads the formatters. */
export const useAuthConfig = () => useQuery<AuthConfig, ApiError>({
  queryKey: ["/auth/config"], staleTime: Infinity,
  queryFn: ({ signal }) => api.get<AuthConfig>("/auth/config", { signal }).then((c) => { setTimeZone(c.tz); return c; }),
});
// Go marshals nil slices as null; the page always gets arrays.
export const useDashboard = () => useApi<Dashboard>("/dashboard", {
  refetchInterval: 60_000,
  select: (d) => ({
    ...d, trend: d.trend ?? [], oldest_critical: d.oldest_critical ?? [], expiring_exceptions: d.expiring_exceptions ?? [],
    recent_scans: d.recent_scans ?? [], newly_known: d.newly_known ?? [],
  }),
});

export const isAdmin = (me?: Me) => me?.system_role === "admin";
/** security perm = security or admin. */
export const isSecurity = (me?: Me) => me?.system_role === "security" || me?.system_role === "admin";

export function useLocalLogin() {
  const qc = useQueryClient();
  return useMutation<LocalLoginResponse, ApiError, LocalLoginRequest>({
    mutationFn: (body) => api.post<LocalLoginResponse>("/auth/local", body),
    onSuccess: () => qc.removeQueries(),
  });
}

export function useLogout() {
  const qc = useQueryClient();
  return useMutation<void, ApiError>({
    mutationFn: () => api.post<void>("/auth/logout"),
    // leave even if the session was already gone
    onSettled: () => { qc.clear(); location.assign("/login"); },
  });
}
