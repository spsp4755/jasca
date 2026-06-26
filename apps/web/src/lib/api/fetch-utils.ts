/**
 * Fetch utilities with authentication support
 */
import { useAuthStore } from '@/stores/auth-store';

/**
 * Fetch with authentication token automatically added
 */
export async function fetchWithAuth(
    url: string,
    options: RequestInit = {}
): Promise<Response> {
    const token = useAuthStore.getState().accessToken;
    
    const headers = new Headers(options.headers);
    
    if (token) {
        headers.set('Authorization', `Bearer ${token}`);
    }
    
    if (!headers.has('Content-Type') && options.method && ['POST', 'PUT', 'PATCH'].includes(options.method)) {
        headers.set('Content-Type', 'application/json');
    }
    
    return fetch(url, {
        ...options,
        headers,
    });
}

/**
 * Fetch with auth and automatic JSON parsing
 */
export async function fetchJsonWithAuth<T>(
    url: string,
    options: RequestInit = {}
): Promise<T> {
    const res = await fetchWithAuth(url, options);

    if (!res.ok) {
        const error = await res.text();
        throw new Error(error || `HTTP ${res.status}: ${res.statusText}`);
    }

    return res.json();
}

/**
 * Download a file from an authenticated endpoint. Fetches the response as a blob
 * (so the Bearer token is sent) and triggers a browser download. The filename is
 * taken from the Content-Disposition header when available, else fallbackName.
 */
export async function downloadWithAuth(url: string, fallbackName: string): Promise<void> {
    const res = await fetchWithAuth(url);
    if (!res.ok) {
        const error = await res.text();
        throw new Error(error || `HTTP ${res.status}: ${res.statusText}`);
    }

    let fileName = fallbackName;
    const disposition = res.headers.get('Content-Disposition');
    if (disposition) {
        const match = /filename="?([^"]+)"?/.exec(disposition);
        if (match?.[1]) fileName = match[1];
    }

    triggerBlobDownload(await res.blob(), fileName);
}

/**
 * Download a file from an authenticated POST endpoint (e.g. bulk export where
 * the list of ids is sent in the request body). Same download behavior as
 * downloadWithAuth.
 */
export async function downloadPostWithAuth(
    url: string,
    body: unknown,
    fallbackName: string,
): Promise<void> {
    const res = await fetchWithAuth(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
    if (!res.ok) {
        const error = await res.text();
        throw new Error(error || `HTTP ${res.status}: ${res.statusText}`);
    }

    let fileName = fallbackName;
    const disposition = res.headers.get('Content-Disposition');
    if (disposition) {
        const match = /filename="?([^"]+)"?/.exec(disposition);
        if (match?.[1]) fileName = match[1];
    }

    triggerBlobDownload(await res.blob(), fileName);
}

function triggerBlobDownload(blob: Blob, fileName: string): void {
    const objectUrl = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = objectUrl;
    link.download = fileName;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(objectUrl);
}
