const rawBackendUrl = process.env.REACT_APP_BACKEND_URL?.trim();

const resolvedBackendUrl = (() => {
  if (!rawBackendUrl || rawBackendUrl === 'undefined' || rawBackendUrl === 'null') {
    return '';
  }

  try {
    const parsed = new URL(rawBackendUrl);
    const isLocalhostTarget = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
    const isBrowserLocalhost = typeof window !== 'undefined' && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1');

    if (isLocalhostTarget && !isBrowserLocalhost) {
      return '';
    }

    return rawBackendUrl.replace(/\/+$/, '');
  } catch {
    return '';
  }
})();

export const BACKEND_BASE_URL = resolvedBackendUrl;
export const API_ROOT = resolvedBackendUrl ? `${resolvedBackendUrl}/api` : '/api';
