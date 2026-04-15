const INTERNAL_HOSTS = new Set(["backend", "soc-api", "db", "redis", "nginx", "frontend"]);

function stripTrailingSlash(value) {
  return value.replace(/\/+$/, "");
}

function isInternalHost(hostname) {
  return INTERNAL_HOSTS.has(String(hostname || "").toLowerCase());
}

function normalizeConfiguredUrl(raw, allowedProtocols) {
  if (!raw) return null;

  const trimmed = String(raw).trim();
  if (!trimmed) return null;
  if (trimmed.startsWith("/")) return stripTrailingSlash(trimmed);

  try {
    const parsed = new URL(trimmed);
    if (!allowedProtocols.includes(parsed.protocol)) return null;
    if (isInternalHost(parsed.hostname)) return null;
    return stripTrailingSlash(parsed.toString());
  } catch {
    return null;
  }
}

export function getApiBaseUrl() {
  const configured =
    normalizeConfiguredUrl(process.env.NEXT_PUBLIC_SOC_CORE_API_URL, ["http:", "https:"]) ||
    normalizeConfiguredUrl(process.env.NEXT_PUBLIC_API_URL, ["http:", "https:"]);

  if (configured) return configured;
  return "/api";
}

export function getWebSocketUrl(path = "/ws") {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  const configured =
    normalizeConfiguredUrl(process.env.NEXT_PUBLIC_SOC_CORE_WS_URL, ["ws:", "wss:"]) ||
    normalizeConfiguredUrl(process.env.NEXT_PUBLIC_WS_URL, ["ws:", "wss:"]);

  if (configured) {
    return configured.endsWith(normalizedPath) ? configured : `${configured}${normalizedPath}`;
  }

  if (typeof window !== "undefined") {
    const scheme = window.location.protocol === "https:" ? "wss" : "ws";
    if (window.location.port === "3000") {
      return `${scheme}://${window.location.hostname}:8000${normalizedPath}`;
    }
    return `${scheme}://${window.location.host}${normalizedPath}`;
  }

  return `ws://127.0.0.1:8000${normalizedPath}`;
}