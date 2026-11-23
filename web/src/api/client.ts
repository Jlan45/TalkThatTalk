import type {
  AuthUser,
  ClientKeysResponse,
  GatewayStatsSnapshot,
  OAuthAuthorizeResponse,
  ProxyImportResult,
  ProxyView,
  UpsertClientKeyPayload,
  UpstreamView,
  UserItem,
  UserRole,
} from "../types/gateway";

const API_BASE = "/api/v1";

async function requestRaw(path: string, init?: RequestInit): Promise<Response> {
  const adminToken = localStorage.getItem("ttt_admin_token");
  const adminKey = localStorage.getItem("ttt_admin_key");
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string> | undefined),
  };
  if (adminToken) {
    headers["X-Admin-Token"] = adminToken;
  } else if (adminKey) {
    headers["X-Admin-Key"] = adminKey;
  }

  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers,
  });

  if (!res.ok) {
    if (
      res.status === 401 &&
      path !== "/auth/login" &&
      path !== "/auth/password" &&
      path !== "/auth/status"
    ) {
      localStorage.removeItem("ttt_admin_token");
      window.dispatchEvent(new Event("ttt:unauthorized"));
    }
    const errBody = await res.json().catch(() => null);
    const msg = errBody?.error?.message ?? `HTTP ${res.status}`;
    throw new Error(msg);
  }
  return res;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  return (await requestRaw(path, init)).json() as Promise<T>;
}

export interface AuthStatusResponse {
  initialized: boolean;
  authenticated: boolean;
  allow_registration: boolean;
  user?: AuthUser | null;
}

export const gatewayApi = {
  getAuthStatus: () => request<AuthStatusResponse>("/auth/status"),

  setupAdmin: (username: string, password: string) =>
    request<{ token: string; user: AuthUser }>("/auth/setup", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),

  registerUser: (username: string, password: string) =>
    request<{ token: string; user: AuthUser }>("/auth/register", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),

  loginAdmin: (username: string, password: string) =>
    request<{ token: string; user: AuthUser }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),

  getSettings: () =>
    request<{
      admin_auth_enabled: boolean;
      allow_registration: boolean;
      default_user_restrict_upstreams: boolean;
      default_user_allowed_upstreams: string[];
    }>("/settings"),

  updateSettings: (payload: {
    allow_registration?: boolean;
    default_user_restrict_upstreams?: boolean;
    default_user_allowed_upstreams?: string[];
  }) =>
    request<{
      status: string;
      allow_registration: boolean;
      default_user_restrict_upstreams: boolean;
      default_user_allowed_upstreams: string[];
    }>("/settings", {
      method: "PUT",
      body: JSON.stringify(payload),
    }),

  logoutAdmin: () =>
    request<{ status: string }>("/auth/logout", {
      method: "POST",
    }),

  changeAdminPassword: (current_password: string, new_password: string) =>
    request<{ status: string; token: string; user: AuthUser }>("/auth/password", {
      method: "PUT",
      body: JSON.stringify({ current_password, new_password }),
    }),

  listUsers: () => request<{ users: UserItem[] }>("/users"),

  createUser: (payload: {
    username: string;
    password: string;
    role: UserRole;
    enabled: boolean;
    allow_private_upstreams: boolean;
    restrict_upstreams: boolean;
    allowed_upstreams: string[];
    restrict_models: boolean;
    allowed_models: string[];
  }) =>
    request<{ status: string; user: UserItem }>("/users", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  updateUser: (
    id: number,
    payload: {
      role: UserRole;
      enabled: boolean;
      allow_private_upstreams: boolean;
      restrict_upstreams: boolean;
      allowed_upstreams: string[];
      restrict_models: boolean;
      allowed_models: string[];
      password?: string | null;
    }
  ) =>
    request<{ status: string }>(`/users/${id}`, {
      method: "PUT",
      body: JSON.stringify(payload),
    }),

  deleteUser: (id: number) =>
    request<{ status: string }>(`/users/${id}`, {
      method: "DELETE",
    }),

  listProxies: () => request<{ proxies: ProxyView[] }>("/proxies"),

  importProxySubscription: (url: string) =>
    request<ProxyImportResult>("/proxies/import", {
      method: "POST",
      body: JSON.stringify({ url }),
    }),

  createProxy: (payload: Record<string, unknown>) =>
    request<{ status: string; name: string }>("/proxies", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  updateProxy: (name: string, payload: Record<string, unknown>) =>
    request<{ status: string; name: string }>(`/proxies/${encodeURIComponent(name)}`, {
      method: "PUT",
      body: JSON.stringify(payload),
    }),

  deleteProxy: (name: string) =>
    request<{ status: string; name: string }>(`/proxies/${encodeURIComponent(name)}`, {
      method: "DELETE",
    }),

  testProxy: (name: string, targetUrl?: string) =>
    request<{ ok: boolean; status?: number; latency_ms: number; error?: string }>(
      `/proxies/${encodeURIComponent(name)}/test`,
      {
        method: "POST",
        body: JSON.stringify({ target_url: targetUrl }),
      }
    ),

  getStats: () => request<GatewayStatsSnapshot>("/stats"),

  listUpstreams: () => request<{ upstreams: UpstreamView[] }>("/upstreams"),

  createUpstream: (payload: Record<string, unknown>) =>
    request<{ status: string; name: string }>("/upstreams", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  updateUpstream: (name: string, payload: Record<string, unknown>) =>
    request<{ status: string; name: string }>(`/upstreams/${encodeURIComponent(name)}`, {
      method: "PUT",
      body: JSON.stringify(payload),
    }),

  deleteUpstream: (name: string) =>
    request<{ status: string; name: string }>(`/upstreams/${encodeURIComponent(name)}`, {
      method: "DELETE",
    }),

  refreshUpstreamQuota: (name: string) =>
    request<{ quota: import("../types/gateway").QuotaSnapshot }>(
      `/upstreams/${encodeURIComponent(name)}/quota/refresh`,
      { method: "POST" },
    ),

  fetchModelsAdhoc: (payload: {
    base_url: string;
    models_path?: string;
    api_key?: string;
    header_name?: string;
    prefix?: string | null;
    extra_headers?: Record<string, string>;
  }) =>
    request<{ url: string; models: string[] }>("/upstreams/fetch-models", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  fetchUpstreamModels: (name: string, modelsPath = "/models") =>
    request<{ url: string; models: string[] }>(
      `/upstreams/${encodeURIComponent(name)}/models?models_path=${encodeURIComponent(modelsPath)}`
    ),

  startPresetOAuthAuthorize: (preset: "codex" | "claude_code") =>
    request<OAuthAuthorizeResponse>(`/oauth/preset/${preset}/authorize`, {
      method: "POST",
    }),

  startOAuthAuthorize: (upstream: string) =>
    request<OAuthAuthorizeResponse>(`/oauth/${encodeURIComponent(upstream)}/authorize`, {
      method: "POST",
    }),

  submitOAuthCallback: (upstream: string, input: string, state: string) =>
    request<{ status: string; expires_at?: number }>(
      `/oauth/${encodeURIComponent(upstream)}/callback`,
      {
        method: "POST",
        body: JSON.stringify({ input, state }),
      }
    ),

  refreshOAuth: (upstream: string) =>
    request<{ status: string; expires_at?: number }>(
      `/oauth/${encodeURIComponent(upstream)}/refresh`,
      {
        method: "POST",
      }
    ),

  listPlaygroundModels: (signal?: AbortSignal) =>
    request<{ data: { id: string }[] }>("/playground/models", { signal }),

  streamPlaygroundChat: (
    model: string,
    messages: { role: "user" | "assistant"; content: string }[]
  ) =>
    requestRaw("/playground/chat/completions", {
      method: "POST",
      body: JSON.stringify({ model, messages, stream: true }),
    }),

  listKeys: () => request<ClientKeysResponse>("/keys"),

  addKey: (payload: UpsertClientKeyPayload) =>
    request<{ status: string; masked: string }>("/keys", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  updateKey: (payload: UpsertClientKeyPayload) =>
    request<{ status: string; masked: string }>("/keys", {
      method: "PUT",
      body: JSON.stringify(payload),
    }),

  deleteKey: (key: string) =>
    request<{ status: string }>("/keys", {
      method: "DELETE",
      body: JSON.stringify({ key }),
    }),
};
