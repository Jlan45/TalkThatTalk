export type ProtocolFamily = "openai" | "openai_responses" | "anthropic" | "gemini" | "antigravity";
export type OAuthPreset = "codex" | "claude_code" | "antigravity" | "custom";
export type PromptCacheMode =
  | "auto"
  | "open_ai"
  | "strip_open_ai_cache_fields"
  | "xai_grok"
  | "open_router"
  | "opencode"
  | "passthrough";
export type UserRole = "admin" | "user";
export type ProxyProtocol =
  | "http"
  | "socks5"
  | "shadowsocks"
  | "trojan"
  | "vmess"
  | "vless"
  | "anytls"
  | "hysteria2";

export interface ProxyImportResult {
  imported: number;
  duplicates: number;
  skipped: number;
}

export interface ProxyView {
  name: string;
  protocol: ProxyProtocol;
  server: string;
  port: number;
  username?: string | null;
  has_password: boolean;
  cipher?: string | null;
  tls: boolean;
  sni?: string | null;
  ws_path?: string | null;
  ws_host?: string | null;
  reality_public_key?: string | null;
  reality_short_id?: string | null;
  enabled: boolean;
  active: boolean;
}

export interface AuthUser {
  id: number;
  username: string;
  role: UserRole;
  allow_private_upstreams?: boolean;
}

export interface UserItem {
  id: number;
  username: string;
  role: UserRole;
  enabled: boolean;
  allow_private_upstreams: boolean;
  restrict_upstreams: boolean;
  allowed_upstreams: string[];
  restrict_models: boolean;
  allowed_models: string[];
  created_at: number;
  key_count: number;
}

export interface OAuthStatusView {
  preset?: OAuthPreset;
  account_id: string;
  token_present: boolean;
  refresh_token_present: boolean;
  expires_at?: number;
  expires_in_secs?: number;
  can_login_pkce: boolean;
  can_refresh: boolean;
  client_id?: string | null;
  redirect_uri?: string | null;
  has_client_secret?: boolean;
  project_id_pending?: boolean;
}

export interface UpstreamView {
  name: string;
  base_url: string;
  protocol: ProtocolFamily;
  protocol_endpoints: Partial<Record<ProtocolFamily, string>>;
  auth_mode: "api_key" | "oauth";
  models: string[];
  model_mapping: Record<string, string>;
  extra_headers: Record<string, string>;
  protocol_headers: Partial<Record<ProtocolFamily, Record<string, string>>>;
  weight: number;
  default_cooldown_secs: number;
  max_retries: number;
  cooling_down: boolean;
  api_key_count?: number;
  auth_header_name?: string;
  auth_header_prefix?: string | null;
  oauth?: OAuthStatusView;
  owner_user_id?: number | null;
  owner_username?: string | null;
  scope: "global" | "private";
  can_manage: boolean;
  proxy?: string | null;
  quota_config?: QuotaMonitorConfig | null;
  can_probe_quota: boolean;
  quota?: QuotaSnapshot | null;
  session_header_out?: string | null;
  strip_other_session_headers?: boolean;
  prompt_cache_mode?: PromptCacheMode;
}

export type QuotaProbeKind = "auto" | "claude_code" | "codex" | "antigravity" | "opencode_go" | "custom_http";
export type QuotaStatus = "healthy" | "low" | "exhausted" | "error";

export interface QuotaMonitorConfig {
  enabled: boolean;
  probe: QuotaProbeKind;
  poll_interval_secs: number;
  chatgpt_account_id?: string | null;
  custom_url?: string | null;
  custom_headers?: Record<string, string>;
  remaining_path?: string | null;
  used_path?: string | null;
  total_path?: string | null;
  scale?: number | null;
  currency?: string | null;
}

export type QuotaDimension =
  | {
      kind: "window_utilization";
      window: string;
      used_percent: number;
      resets_at?: number | null;
    }
  | {
      kind: "monetary";
      currency: string;
      remaining?: number | null;
      used?: number | null;
      total?: number | null;
    };

export interface QuotaSnapshot {
  upstream: string;
  probe: QuotaProbeKind;
  status: QuotaStatus;
  dimensions: QuotaDimension[];
  available_models?: string[];
  plan_type?: string | null;
  error?: string | null;
  fetched_at: number;
}

export interface UpstreamStats {
  requests: number;
  errors: number;
  input_tokens: number;
  total_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
  cache_hit_rate: number;
}

export interface ActiveRequest {
  req_id: string;
  user_id?: number;
  username?: string;
  upstream: string;
  model?: string | null;
  path: string;
  elapsed_ms: number;
  is_stream: boolean | null;
}

export interface ActiveRequestsSnapshot {
  total: number;
  requests: ActiveRequest[];
}

export interface RequestLogEntry {
  req_id: string;
  user_id?: number;
  username?: string;
  timestamp_secs: number;
  upstream: string;
  model?: string;
  path: string;
  status: number;
  is_stream?: boolean | null;
  ttft_ms: number;
  duration_ms: number;
  total_bytes: number;
  input_tokens: number;
  output_tokens: number;
  total_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

export interface GatewayStatsSnapshot {
  uptime_secs: number;
  total_requests: number;
  success_requests: number;
  error_requests: number;
  avg_ttft_ms: number;
  total_input_tokens: number;
  total_output_tokens: number;
  total_tokens: number;
  total_cache_read_tokens: number;
  total_cache_write_tokens: number;
  cache_hit_rate: number;
  cache_hit_requests: number;
  cache_request_hit_rate: number;
  by_upstream: Record<string, UpstreamStats>;
  by_model: Record<string, number>;
  recent_requests: RequestLogEntry[];
}

export interface ClientKeyItem {
  masked: string;
  key: string;
  name: string;
  enabled: boolean;
  restrict_upstreams: boolean;
  allowed_upstreams: string[];
  restrict_models: boolean;
  allowed_models: string[];
  owner_username?: string | null;
}

export interface UpsertClientKeyPayload {
  key: string;
  name: string;
  enabled: boolean;
}

export interface ClientKeysResponse {
  auth_enabled: boolean;
  keys: ClientKeyItem[];
}

export interface OAuthAuthorizeResponse {
  authorize_url: string;
  state: string;
}
