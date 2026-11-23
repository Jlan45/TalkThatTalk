import { useEffect, useMemo, useState } from "react";
import { gatewayApi } from "../api/client";
import type {
  OAuthPreset,
  ProtocolFamily,
  ProxyView,
  QuotaMonitorConfig,
  QuotaProbeKind,
  UpstreamView,
} from "../types/gateway";
import { IconCopy, IconExternal, IconRefresh } from "./Icons";
import { ProviderLogo, type ProviderLogoId } from "./ProviderLogos";

interface Props {
  initial?: UpstreamView | null;
  onClose: () => void;
  onSaved: (authorizeUpstream?: string) => void;
}

type AuthMode = "api_key" | "oauth";

interface EndpointRow {
  protocol: ProtocolFamily;
  endpoint: string;
}

interface ProviderCatalogItem {
  id: string;
  title: string;
  badge: string;
  logo: ProviderLogoId;
  desc: string;
  authMode: AuthMode;
  defaultName: string;
  baseUrl: string;
  modelsPath: string;
  protocolEndpoints: EndpointRow[];
  headerName: string;
  headerPrefix: string;
  suggestedModels: string[];
  protocolHeaders?: Partial<Record<ProtocolFamily, Record<string, string>>>;
  oauth?: {
    preset: OAuthPreset;
    accountId: string;
    authorizeUrl: string;
    tokenUrl: string;
    redirectUri: string;
    scopes: string[];
  };
}

const ALL_PROTOCOLS: { value: ProtocolFamily; label: string; defaultEndpoint: string }[] = [
  { value: "openai", label: "OpenAI Chat", defaultEndpoint: "/v1/chat/completions" },
  { value: "openai_responses", label: "OpenAI Responses", defaultEndpoint: "/v1/responses" },
  { value: "anthropic", label: "Anthropic Messages", defaultEndpoint: "/v1/messages" },
  { value: "gemini", label: "Google Gemini", defaultEndpoint: "/v1beta" },
  { value: "antigravity", label: "Google Antigravity", defaultEndpoint: "/v1internal:generateContent" },
];

const PROVIDER_CATALOG: ProviderCatalogItem[] = [
  {
    id: "codex-oauth",
    title: "OpenAI Codex",
    badge: "OAuth 2.0",
    logo: "codex",
    desc: "官方 OAuth 账号授权登录，支持自动续期",
    authMode: "oauth",
    defaultName: "codex-oauth",
    baseUrl: "https://chatgpt.com/backend-api/codex",
    modelsPath: "/models?client_version=1.0.0",
    protocolEndpoints: [{ protocol: "openai_responses", endpoint: "/responses" }],
    headerName: "authorization",
    headerPrefix: "Bearer ",
    suggestedModels: ["gpt-5-codex", "codex-mini-latest", "gpt-5"],
    oauth: {
      preset: "codex",
      accountId: "codex-main",
      authorizeUrl: "https://auth.openai.com/oauth/authorize",
      tokenUrl: "https://auth.openai.com/oauth/token",
      redirectUri: "http://localhost:1455/auth/callback",
      scopes: ["openid", "profile", "email", "offline_access"],
    },
  },
  {
    id: "claude-code-oauth",
    title: "Claude Code",
    badge: "OAuth 2.0",
    logo: "claudecode",
    desc: "Anthropic OAuth JSON 令牌端点，支持 code#state 与自动刷新",
    authMode: "oauth",
    defaultName: "claude-code-oauth",
    baseUrl: "https://api.anthropic.com",
    modelsPath: "/v1/models",
    protocolEndpoints: [{ protocol: "anthropic", endpoint: "/v1/messages" }],
    headerName: "authorization",
    headerPrefix: "Bearer ",
    suggestedModels: ["claude-sonnet-4-20250514", "claude-opus-4-20250514", "claude-3-7-sonnet-20250219"],
    protocolHeaders: {
      anthropic: {
        "anthropic-version": "2023-06-01",
        "anthropic-beta": "claude-code-20250219,oauth-2025-04-20",
      },
    },
    oauth: {
      preset: "claude_code",
      accountId: "claude-main",
      authorizeUrl: "https://claude.ai/oauth/authorize",
      tokenUrl: "https://console.anthropic.com/v1/oauth/token",
      redirectUri: "https://console.anthropic.com/oauth/code/callback",
      scopes: ["org:create_api_key", "user:profile", "user:inference"],
    },
  },
  {
    id: "antigravity-oauth",
    title: "Antigravity",
    badge: "OAuth 2.0",
    logo: "gemini",
    desc: "Google Cloud Code Assist OAuth，支持 Gemini / Claude 模型与额度监控",
    authMode: "oauth",
    defaultName: "antigravity-oauth",
    baseUrl: "https://daily-cloudcode-pa.googleapis.com",
    modelsPath: "/v1internal:fetchAvailableModels",
    protocolEndpoints: [{ protocol: "antigravity", endpoint: "/v1internal:generateContent" }],
    headerName: "authorization",
    headerPrefix: "Bearer ",
    suggestedModels: [],
    oauth: {
      preset: "antigravity",
      accountId: "antigravity-main",
      authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth",
      tokenUrl: "https://oauth2.googleapis.com/token",
      redirectUri: "http://localhost:51121/oauth-callback",
      scopes: [
        "https://www.googleapis.com/auth/cloud-platform",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/cclog",
        "https://www.googleapis.com/auth/experimentsandconfigs",
      ],
    },
  },
  {
    id: "openai-api",
    title: "OpenAI 官方 / 中转",
    badge: "API Base",
    logo: "openai",
    desc: "标准 OpenAI Chat & Responses 协议，支持多 Key 无锁轮询",
    authMode: "api_key",
    defaultName: "openai-api",
    baseUrl: "https://api.openai.com",
    modelsPath: "/v1/models",
    protocolEndpoints: [
      { protocol: "openai", endpoint: "/v1/chat/completions" },
      { protocol: "openai_responses", endpoint: "/v1/responses" },
    ],
    headerName: "authorization",
    headerPrefix: "Bearer ",
    suggestedModels: ["gpt-4o", "gpt-4o-mini", "o3-mini", "gpt-5"],
  },
  {
    id: "anthropic-api",
    title: "Anthropic Claude",
    badge: "API Base",
    logo: "claude",
    desc: "使用 x-api-key 连接官方 Anthropic Messages 端点，支持跨协议互转",
    authMode: "api_key",
    defaultName: "anthropic-api",
    baseUrl: "https://api.anthropic.com",
    modelsPath: "/v1/models",
    protocolEndpoints: [{ protocol: "anthropic", endpoint: "/v1/messages" }],
    headerName: "x-api-key",
    headerPrefix: "",
    suggestedModels: ["claude-sonnet-4-20250514", "claude-opus-4-20250514", "claude-3-5-haiku-20241022"],
    protocolHeaders: {
      anthropic: {
        "anthropic-version": "2023-06-01",
      },
    },
  },
  {
    id: "gemini-api",
    title: "Google Gemini",
    badge: "API Base",
    logo: "gemini",
    desc: "原生 Gemini 协议，自动支持 OpenAI 客户端流式无感转换",
    authMode: "api_key",
    defaultName: "gemini-api",
    baseUrl: "https://generativelanguage.googleapis.com",
    modelsPath: "/v1beta/models",
    protocolEndpoints: [{ protocol: "gemini", endpoint: "/v1beta" }],
    headerName: "x-goog-api-key",
    headerPrefix: "",
    suggestedModels: ["gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.0-flash"],
  },
  {
    id: "volcengine-agent-plan",
    title: "火山方舟 Agent Plan",
    badge: "多协议直通",
    logo: "volcengine",
    desc: "Base URL + /v1/messages (Anthropic) 与 /v3/chat/completions (OpenAI) 双协议直通",
    authMode: "api_key",
    defaultName: "volcengine-agent-plan",
    baseUrl: "https://ark.cn-beijing.volces.com/api/plan",
    modelsPath: "/v3/models",
    protocolEndpoints: [
      { protocol: "anthropic", endpoint: "/v1/messages" },
      { protocol: "openai", endpoint: "/v3/chat/completions" },
    ],
    headerName: "authorization",
    headerPrefix: "Bearer ",
    suggestedModels: [
      "ark-code-latest",
      "doubao-seed-evolving",
      "doubao-seed-2.0-code",
      "doubao-seed-2.0-pro",
      "doubao-seed-2.0-lite",
      "doubao-seed-code",
      "deepseek-v4.1-flash",
      "deepseek-v4",
      "deepseek-v3.2",
      "glm-5.3",
      "glm-5.2",
      "glm-4.7",
      "kimi-k3",
      "kimi-k2.6",
      "kimi-k2.5",
    ],
    protocolHeaders: {
      anthropic: {
        "anthropic-version": "2023-06-01",
      },
    },
  },
  {
    id: "minimax-api",
    title: "MiniMax M Plan",
    badge: "多协议直通",
    logo: "minimax",
    desc: "MiniMax 中国站订阅，支持 OpenAI Chat、Responses 与 Anthropic Messages",
    authMode: "api_key",
    defaultName: "minimax-api",
    baseUrl: "https://api.minimax.cn",
    modelsPath: "/v1/models",
    protocolEndpoints: [
      { protocol: "openai", endpoint: "/v1/chat/completions" },
      { protocol: "openai_responses", endpoint: "/v1/responses" },
      { protocol: "anthropic", endpoint: "/anthropic/v1/messages" },
    ],
    headerName: "authorization",
    headerPrefix: "Bearer ",
    suggestedModels: ["MiniMax-M3.1-Flash"],
    protocolHeaders: {
      anthropic: {
        "anthropic-version": "2023-06-01",
      },
    },
  },
  {
    id: "opencode-go",
    title: "OpenCode Go",
    badge: "多协议直通",
    logo: "opencode",
    desc: "opencode.ai/zen/go 订阅套餐，支持 OpenAI / Responses / Anthropic 协议",
    authMode: "api_key",
    defaultName: "opencode-go",
    baseUrl: "https://opencode.ai/zen/go",
    modelsPath: "/v1/models",
    protocolEndpoints: [
      { protocol: "openai", endpoint: "/v1/chat/completions" },
      { protocol: "openai_responses", endpoint: "/v1/responses" },
      { protocol: "anthropic", endpoint: "/v1/messages" },
    ],
    headerName: "authorization",
    headerPrefix: "Bearer ",
    suggestedModels: [
      "deepseek-v4-pro",
      "deepseek-v4.1-flash",
      "kimi-k3",
      "kimi-k2.7-code",
      "kimi-k2.6",
      "glm-5.3-flash",
      "glm-5.2",
    ],
    protocolHeaders: {
      anthropic: {
        "anthropic-version": "2023-06-01",
      },
    },
  },
  {
    id: "deepseek-api",
    title: "DeepSeek",
    badge: "API Base",
    logo: "deepseek",
    desc: "DeepSeek 官方接口，支持 OpenAI 与 Anthropic 双协议",
    authMode: "api_key",
    defaultName: "deepseek-api",
    baseUrl: "https://api.deepseek.com",
    modelsPath: "/v1/models",
    protocolEndpoints: [
      { protocol: "openai", endpoint: "/v1/chat/completions" },
      { protocol: "anthropic", endpoint: "/anthropic/v1/messages" },
    ],
    headerName: "authorization",
    headerPrefix: "Bearer ",
    suggestedModels: ["deepseek-chat", "deepseek-reasoner"],
  },
  {
    id: "openrouter-api",
    title: "OpenRouter",
    badge: "API Base",
    logo: "openrouter",
    desc: "聚合多厂商模型路由，OpenAI 兼容接口",
    authMode: "api_key",
    defaultName: "openrouter-api",
    baseUrl: "https://openrouter.ai/api",
    modelsPath: "/v1/models",
    protocolEndpoints: [{ protocol: "openai", endpoint: "/v1/chat/completions" }],
    headerName: "authorization",
    headerPrefix: "Bearer ",
    suggestedModels: ["anthropic/claude-sonnet-4", "openai/gpt-4o", "google/gemini-2.5-pro"],
  },
  {
    id: "qwen-api",
    title: "通义千问 Qwen",
    badge: "API Base",
    logo: "qwen",
    desc: "阿里云 DashScope OpenAI 兼容模式",
    authMode: "api_key",
    defaultName: "qwen-dashscope",
    baseUrl: "https://dashscope.aliyuncs.com/compatible-mode",
    modelsPath: "/v1/models",
    protocolEndpoints: [{ protocol: "openai", endpoint: "/v1/chat/completions" }],
    headerName: "authorization",
    headerPrefix: "Bearer ",
    suggestedModels: ["qwen-max", "qwen-plus", "qwen-coder-plus"],
  },
  {
    id: "local-ollama",
    title: "Ollama / vLLM 本地",
    badge: "API Base",
    logo: "ollama",
    desc: "本地部署推理引擎（Ollama / vLLM / SGLang）",
    authMode: "api_key",
    defaultName: "local-llm",
    baseUrl: "http://127.0.0.1:11434",
    modelsPath: "/v1/models",
    protocolEndpoints: [{ protocol: "openai", endpoint: "/v1/chat/completions" }],
    headerName: "authorization",
    headerPrefix: "Bearer ",
    suggestedModels: ["qwen2.5-coder:32b", "llama3.3:70b", "deepseek-r1:32b"],
  },
  {
    id: "custom-api-base",
    title: "自定义 API Base",
    badge: "API Base",
    logo: "custom_api",
    desc: "完全自定义 Base URL、多协议 Endpoint、鉴权头与模型列表",
    authMode: "api_key",
    defaultName: "",
    baseUrl: "",
    modelsPath: "/v1/models",
    protocolEndpoints: [{ protocol: "openai", endpoint: "/v1/chat/completions" }],
    headerName: "authorization",
    headerPrefix: "Bearer ",
    suggestedModels: [],
  },
  {
    id: "custom-oauth",
    title: "自定义 OAuth 2.0",
    badge: "OAuth 2.0",
    logo: "oauth",
    desc: "任意标准 RFC 6749 / 7636 / 8628 企业或第三方 OAuth 上游",
    authMode: "oauth",
    defaultName: "custom-oauth",
    baseUrl: "https://api.example.com",
    modelsPath: "/v1/models",
    protocolEndpoints: [{ protocol: "openai", endpoint: "/v1/chat/completions" }],
    headerName: "authorization",
    headerPrefix: "Bearer ",
    suggestedModels: ["*"],
    oauth: {
      preset: "custom",
      accountId: "custom-acct",
      authorizeUrl: "",
      tokenUrl: "",
      redirectUri: "http://127.0.0.1:1455/auth/callback",
      scopes: [],
    },
  },
];

function initialEndpoints(initial?: UpstreamView | null): EndpointRow[] {
  if (!initial) return [{ protocol: "openai", endpoint: "/v1/chat/completions" }];
  const entries = Object.entries(initial.protocol_endpoints ?? {});
  if (entries.length > 0) {
    return entries.map(([protocol, endpoint]) => ({
      protocol: protocol as ProtocolFamily,
      endpoint: endpoint ?? "",
    }));
  }
  return [{ protocol: initial.protocol, endpoint: "/v1/chat/completions" }];
}

function inferDefaultModelsPath(initial?: UpstreamView | null): string {
  if (!initial) return "/v1/models";
  if (initial.oauth?.preset === "antigravity") return "/v1internal:fetchAvailableModels";
  if (initial.oauth?.preset === "codex" || initial.base_url.includes("backend-api/codex")) {
    return "/models?client_version=1.0.0";
  }
  if (initial.base_url.includes("volces.com")) {
    return "/v3/models";
  }
  if (initial.protocol === "gemini") {
    return "/v1beta/models";
  }
  return "/v1/models";
}

function initialProtocolHeadersText(
  initial?: UpstreamView | null
): Partial<Record<ProtocolFamily, string>> {
  const out: Partial<Record<ProtocolFamily, string>> = {};
  if (!initial) return out;
  const protoHdrs = initial.protocol_headers ?? {};
  for (const [proto, hdrs] of Object.entries(protoHdrs)) {
    if (hdrs && Object.keys(hdrs).length > 0) {
      out[proto as ProtocolFamily] = JSON.stringify(hdrs, null, 2);
    }
  }
  if (Object.keys(out).length === 0 && Object.keys(initial.extra_headers ?? {}).length > 0) {
    out[initial.protocol] = JSON.stringify(initial.extra_headers, null, 2);
  }
  return out;
}

export function UpstreamModal({ initial, onClose, onSaved }: Props) {
  const isEdit = Boolean(initial);

  // Two-step state: Step 1 = pick provider catalog, Step 2 = configure details.
  const [step, setStep] = useState<1 | 2>(isEdit ? 2 : 1);
  const [catalogFilter, setCatalogFilter] = useState<"all" | "oauth" | "api_key">("all");
  const [catalogQuery, setCatalogQuery] = useState("");
  const [catalogPage, setCatalogPage] = useState(1);
  const [selectedProvider, setSelectedProvider] = useState<ProviderCatalogItem | null>(null);

  // Step 2 form state: Base URL + relative protocol_endpoints (`final = base_url + endpoint`)
  const [name, setName] = useState(initial?.name ?? "");
  const [baseUrl, setBaseUrl] = useState(initial?.base_url ?? "https://api.openai.com");
  const [proxyName, setProxyName] = useState(initial?.proxy ?? "");
  const [quotaEnabled, setQuotaEnabled] = useState(initial?.quota_config?.enabled ?? true);
  const [quotaProbe, setQuotaProbe] = useState<QuotaProbeKind>(
    initial?.quota_config?.probe ?? "auto",
  );
  const [quotaPollSecs, setQuotaPollSecs] = useState(
    String(initial?.quota_config?.poll_interval_secs ?? 300),
  );
  const [quotaAccountId, setQuotaAccountId] = useState(
    initial?.quota_config?.chatgpt_account_id ?? "",
  );
  const [quotaCustomUrl, setQuotaCustomUrl] = useState(initial?.quota_config?.custom_url ?? "");
  const [quotaRemainingPath, setQuotaRemainingPath] = useState(
    initial?.quota_config?.remaining_path ?? "",
  );
  const [quotaUsedPath, setQuotaUsedPath] = useState(initial?.quota_config?.used_path ?? "");
  const [quotaTotalPath, setQuotaTotalPath] = useState(initial?.quota_config?.total_path ?? "");
  const [quotaScale, setQuotaScale] = useState(
    initial?.quota_config?.scale != null ? String(initial.quota_config.scale) : "",
  );
  const [quotaCurrency, setQuotaCurrency] = useState(initial?.quota_config?.currency ?? "USD");
  const [availableProxies, setAvailableProxies] = useState<ProxyView[]>([]);
  const [endpoints, setEndpoints] = useState<EndpointRow[]>(() => initialEndpoints(initial));
  const [authMode, setAuthMode] = useState<AuthMode>(initial?.auth_mode ?? "api_key");
  const [selectedModels, setSelectedModels] = useState<string[]>(initial?.models ?? ["gpt-4o"]);
  const [fetchedModels, setFetchedModels] = useState<string[]>([]);
  const [modelsPath, setModelsPath] = useState(() => inferDefaultModelsPath(initial));
  const [fetchingModels, setFetchingModels] = useState(false);
  const [fetchInfo, setFetchInfo] = useState<string | null>(null);
  const [customModel, setCustomModel] = useState("");
  const [weight, setWeight] = useState(String(initial?.weight ?? 1));
  const [maxRetries, setMaxRetries] = useState(String(initial?.max_retries ?? 1));
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [mappingText, setMappingText] = useState(
    initial && Object.keys(initial.model_mapping).length > 0
      ? JSON.stringify(initial.model_mapping, null, 2)
      : ""
  );
  const [protocolHeadersText, setProtocolHeadersText] = useState<
    Partial<Record<ProtocolFamily, string>>
  >(() => initialProtocolHeadersText(initial));

  // API Key fields
  const [apiKeys, setApiKeys] = useState<string[]>([""]);
  const [headerName, setHeaderName] = useState(initial?.auth_header_name ?? "authorization");
  const [headerPrefix, setHeaderPrefix] = useState(
    initial ? (initial.auth_header_prefix ?? "") : "Bearer "
  );

  // OAuth fields
  const [preset, setPreset] = useState<OAuthPreset>(initial?.oauth?.preset ?? "codex");
  const [accountId, setAccountId] = useState(initial?.oauth?.account_id ?? "");
  const [authorizeUrl, setAuthorizeUrl] = useState("");
  const [tokenUrl, setTokenUrl] = useState("");
  const [clientId, setClientId] = useState(initial?.oauth?.client_id ?? "");
  const [clientSecret, setClientSecret] = useState("");
  const [redirectUri, setRedirectUri] = useState(initial?.oauth?.redirect_uri ?? "");
  const [scopesText, setScopesText] = useState("");
  const [accessToken, setAccessToken] = useState("");
  const [refreshToken, setRefreshToken] = useState("");

  // Official OAuth direct login state (Codex / Claude Code)
  const [officialAuthUrl, setOfficialAuthUrl] = useState("");
  const [officialAuthState, setOfficialAuthState] = useState("");
  const [officialCallbackInput, setOfficialCallbackInput] = useState("");
  const [loadingAuthUrl, setLoadingAuthUrl] = useState(false);
  const [copiedAuthUrl, setCopiedAuthUrl] = useState(false);

  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isAntigravity = authMode === "oauth" && preset === "antigravity";
  const authorizeAntigravity = isAntigravity && (
    !initial?.oauth?.token_present ||
    Boolean(clientSecret.trim()) ||
    clientId.trim() !== (initial.oauth.client_id ?? "") ||
    redirectUri.trim() !== (initial.oauth.redirect_uri ?? "")
  );
  const isOfficialOAuth = authMode === "oauth" && (preset === "codex" || preset === "claude_code");

  const fetchOfficialAuthUrl = async (targetPreset: "codex" | "claude_code") => {
    setLoadingAuthUrl(true);
    setError(null);
    try {
      const res = await gatewayApi.startPresetOAuthAuthorize(targetPreset);
      setOfficialAuthUrl(res.authorize_url);
      setOfficialAuthState(res.state);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoadingAuthUrl(false);
    }
  };

  useEffect(() => {
    gatewayApi
      .listProxies()
      .then((res) => setAvailableProxies(res.proxies.filter((p) => p.enabled)))
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (
      step === 2 &&
      isOfficialOAuth &&
      (preset === "codex" || preset === "claude_code")
    ) {
      setOfficialCallbackInput("");
      void fetchOfficialAuthUrl(preset);
    }
  }, [step, isOfficialOAuth, preset]);

  const CATALOG_PAGE_SIZE = 8;

  const filteredCatalog = useMemo(() => {
    const q = catalogQuery.trim().toLowerCase();
    return PROVIDER_CATALOG.filter((item) => {
      if (catalogFilter !== "all" && item.authMode !== catalogFilter) return false;
      if (!q) return true;
      return (
        item.title.toLowerCase().includes(q) ||
        item.desc.toLowerCase().includes(q) ||
        item.protocolEndpoints.some((e) => e.protocol.toLowerCase().includes(q))
      );
    });
  }, [catalogFilter, catalogQuery]);

  const catalogTotalPages = Math.max(1, Math.ceil(filteredCatalog.length / CATALOG_PAGE_SIZE));
  const safeCatalogPage = Math.min(catalogPage, catalogTotalPages);
  const pagedCatalog = useMemo(() => {
    const start = (safeCatalogPage - 1) * CATALOG_PAGE_SIZE;
    return filteredCatalog.slice(start, start + CATALOG_PAGE_SIZE);
  }, [filteredCatalog, safeCatalogPage]);

  const selectCatalogProvider = (item: ProviderCatalogItem) => {
    setSelectedProvider(item);
    setError(null);
    setFetchInfo(null);
    setName(item.defaultName);
    setBaseUrl(item.baseUrl);
    setModelsPath(item.modelsPath);
    setEndpoints(item.protocolEndpoints.map((e) => ({ ...e })));
    setAuthMode(item.authMode);
    setHeaderName(item.headerName);
    setHeaderPrefix(item.headerPrefix);
    setApiKeys([""]);
    setSelectedModels([...item.suggestedModels]);
    const nextProtoHeaders: Partial<Record<ProtocolFamily, string>> = {};
    if (item.protocolHeaders) {
      for (const [proto, hdrs] of Object.entries(item.protocolHeaders)) {
        if (hdrs && Object.keys(hdrs).length > 0) {
          nextProtoHeaders[proto as ProtocolFamily] = JSON.stringify(hdrs, null, 2);
        }
      }
    }
    setProtocolHeadersText(nextProtoHeaders);

    if (item.id === "custom-api-base") {
      setShowAdvanced(true);
    } else {
      setShowAdvanced(false);
    }

    if (item.oauth) {
      setPreset(item.oauth.preset);
      setAccountId(item.oauth.accountId);
      setClientId("");
      setClientSecret("");
      setAuthorizeUrl(item.oauth.authorizeUrl);
      setTokenUrl(item.oauth.tokenUrl);
      setRedirectUri(item.oauth.redirectUri);
      setScopesText(item.oauth.scopes.join(", "));
    }
    setStep(2);
  };

  const suggestedModelPool = useMemo(() => {
    const set = new Set<string>(selectedModels);
    for (const m of selectedProvider?.suggestedModels ?? []) {
      set.add(m);
    }
    for (const m of fetchedModels) {
      set.add(m);
    }
    return Array.from(set);
  }, [selectedModels, selectedProvider, fetchedModels]);

  const handleFetchModels = async () => {
    setError(null);
    setFetchInfo(null);
    if (isAntigravity && !initial?.oauth?.token_present) {
      setError("请先保存并授权 Antigravity 渠道，再获取模型");
      return;
    }
    setFetchingModels(true);
    try {
      const firstKey = apiKeys.map((k) => k.trim()).find(Boolean);

      let res: { url: string; models: string[] };
      if (isEdit && initial && !firstKey) {
        res = await gatewayApi.fetchUpstreamModels(initial.name, modelsPath);
      } else {
        const targetBase = baseUrl.trim();
        if (!targetBase) {
          setError("请先填写 Base URL");
          return;
        }
        let extra_headers: Record<string, string> = {};
        const fetchProto = endpoints.some((e) => e.protocol === "openai")
          ? "openai"
          : endpoints[0]?.protocol;
        const rawHdr = fetchProto ? protocolHeadersText[fetchProto] : undefined;
        if (rawHdr?.trim()) {
          try {
            extra_headers = JSON.parse(rawHdr);
          } catch {
            // ignore invalid JSON during fetch
          }
        }
        res = await gatewayApi.fetchModelsAdhoc({
          base_url: targetBase,
          models_path: modelsPath.trim() || "/v1/models",
          api_key: firstKey || accessToken.trim() || undefined,
          header_name: headerName.trim() || "authorization",
          prefix: headerPrefix ? headerPrefix : null,
          extra_headers,
        });
      }

      setFetchedModels(res.models);
      if (res.models.length > 0) {
        setSelectedModels((prev) => isAntigravity
          ? res.models
          : Array.from(new Set([...prev.filter((m) => m !== "*"), ...res.models])));
        setFetchInfo(`已从 ${res.url} 获取到 ${res.models.length} 个模型`);
      } else {
        setFetchInfo(`请求 ${res.url} 成功，但未返回模型条目`);
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setFetchingModels(false);
    }
  };

  const toggleModel = (model: string) => {
    if (selectedModels.includes(model)) {
      setSelectedModels(selectedModels.filter((m) => m !== model));
    } else {
      setSelectedModels([...selectedModels, model]);
    }
  };

  const addCustomModel = () => {
    const m = customModel.trim();
    if (!m) return;
    if (!selectedModels.includes(m)) {
      setSelectedModels([...selectedModels, m]);
    }
    setCustomModel("");
  };

  const handleSubmit = async () => {
    setError(null);
    if (!name.trim()) {
      setError("渠道名称不能为空");
      return;
    }
    let model_mapping: Record<string, string> = {};
    if (mappingText.trim()) {
      try {
        model_mapping = JSON.parse(mappingText);
      } catch {
        setError("模型映射必须是合法 JSON 对象");
        return;
      }
    }

    const protocol_headers: Partial<Record<ProtocolFamily, Record<string, string>>> = {};
    const activeProtocols = Array.from(new Set(endpoints.map((e) => e.protocol)));
    for (const proto of activeProtocols) {
      const raw = protocolHeadersText[proto]?.trim();
      if (!raw) continue;
      try {
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
          if (Object.keys(parsed).length > 0) {
            protocol_headers[proto] = parsed as Record<string, string>;
          }
        } else {
          const label = ALL_PROTOCOLS.find((p) => p.value === proto)?.label ?? proto;
          setError(`${label} 请求头必须是合法 JSON 对象`);
          return;
        }
      } catch {
        const label = ALL_PROTOCOLS.find((p) => p.value === proto)?.label ?? proto;
        setError(`${label} 请求头必须是合法 JSON 对象`);
        return;
      }
    }

    const auth =
      authMode === "api_key"
        ? {
            type: "api_key",
            keys: apiKeys.map((k) => k.trim()).filter(Boolean),
            header_name: headerName.trim() || "authorization",
            prefix: headerPrefix ? headerPrefix : null,
          }
        : isOfficialOAuth || isAntigravity
          ? {
              type: "oauth",
              preset,
              account_id: accountId.trim() || name.trim(),
              header_name: "authorization",
              prefix: "Bearer ",
              ...(isAntigravity && {
                client_id: clientId.trim() || null,
                client_secret: clientSecret.trim() || null,
                redirect_uri: redirectUri.trim() || null,
              }),
            }
          : {
              type: "oauth",
              preset,
              account_id: accountId.trim() || name.trim(),
              access_token: accessToken.trim() || null,
              refresh_token: refreshToken.trim() || null,
              authorize_url: authorizeUrl.trim() || null,
              token_url: tokenUrl.trim() || null,
              client_id: clientId.trim() || null,
              redirect_uri: redirectUri.trim() || null,
              scopes: scopesText
                .split(",")
                .map((s) => s.trim())
                .filter(Boolean),
              header_name: headerName.trim() || "authorization",
              prefix: headerPrefix ? headerPrefix : null,
            };

    if (!baseUrl.trim()) {
      setError("Base URL 不能为空");
      return;
    }

    const protocol_endpoints: Partial<Record<ProtocolFamily, string>> = {};
    for (const row of endpoints) {
      const ep = row.endpoint.trim();
      if (ep) {
        protocol_endpoints[row.protocol] = ep;
      }
    }
    const endpointPairs = Object.entries(protocol_endpoints);
    if (endpointPairs.length === 0) {
      setError("请至少填写一个协议端点（Endpoint）");
      return;
    }

    const [primaryProtocol] = endpointPairs[0] as [ProtocolFamily, string];

    const quota: QuotaMonitorConfig | null =
      !quotaEnabled || quotaProbe !== "auto" || quotaAccountId.trim() || quotaCustomUrl.trim()
        ? {
            enabled: quotaEnabled,
            probe: quotaProbe,
            poll_interval_secs: Math.max(60, Number(quotaPollSecs) || 300),
            chatgpt_account_id: quotaAccountId.trim() || null,
            custom_url: quotaCustomUrl.trim() || null,
            custom_headers: initial?.quota_config?.custom_headers ?? {},
            remaining_path: quotaRemainingPath.trim() || null,
            used_path: quotaUsedPath.trim() || null,
            total_path: quotaTotalPath.trim() || null,
            scale: quotaScale.trim() ? Number(quotaScale) || 1 : null,
            currency: quotaCurrency.trim() || null,
          }
        : null;

    const payload = {
      name: name.trim(),
      base_url: baseUrl.trim(),
      protocol: primaryProtocol,
      protocol_endpoints,
      auth,
      models: selectedModels.length > 0 ? selectedModels : ["*"],
      model_mapping,
      extra_headers: {},
      protocol_headers,
      weight: Math.max(1, Number(weight) || 1),
      default_cooldown_secs: 30,
      max_retries: Math.max(0, Number(maxRetries) || 0),
      proxy: proxyName.trim() || null,
      quota,
    };

    setSaving(true);
    try {
      if (isEdit && initial) {
        await gatewayApi.updateUpstream(initial.name, payload);
      } else {
        await gatewayApi.createUpstream(payload);
      }
      // If user pasted the official OAuth callback code/URL in Step 2, complete token exchange immediately.
      if (isOfficialOAuth && officialCallbackInput.trim() && officialAuthState) {
        await gatewayApi.submitOAuthCallback(
          name.trim(),
          officialCallbackInput.trim(),
          officialAuthState
        );
      }
      onSaved(authorizeAntigravity ? initial?.name ?? name.trim() : undefined);
      onClose();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" style={{ maxWidth: 740 }} onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div style={{ display: "flex", alignItems: "center", gap: 14, flexWrap: "wrap" }}>
            <div className="modal-title">
              {isEdit ? `编辑渠道 · ${initial?.name}` : "添加上游渠道"}
            </div>
            {!isEdit && (
              <div className="step-bar">
                <span className={`step-pill ${step === 1 ? "active" : ""}`}>1. 选择渠道</span>
                <span>→</span>
                <span className={`step-pill ${step === 2 ? "active" : ""}`}>2. 配置连接信息</span>
              </div>
            )}
          </div>
          <button className="btn btn-ghost btn-sm" onClick={onClose}>
            关闭
          </button>
        </div>

        {/* STEP 1: Provider Selection Grid */}
        {step === 1 && (
          <>
            <div className="modal-body">
              <div className="toolbar" style={{ marginBottom: 4 }}>
                <input
                  className="input"
                  style={{ flex: 1, minWidth: 200 }}
                  placeholder="搜索渠道名称（如 Codex、Claude、Gemini、DeepSeek）..."
                  value={catalogQuery}
                  onChange={(e) => {
                    setCatalogQuery(e.target.value);
                    setCatalogPage(1);
                  }}
                  autoFocus
                />
                <div className="actions-row">
                  <button
                    className={`btn btn-sm ${catalogFilter === "all" ? "" : "btn-ghost"}`}
                    onClick={() => {
                      setCatalogFilter("all");
                      setCatalogPage(1);
                    }}
                  >
                    全部
                  </button>
                  <button
                    className={`btn btn-sm ${catalogFilter === "oauth" ? "" : "btn-ghost"}`}
                    onClick={() => {
                      setCatalogFilter("oauth");
                      setCatalogPage(1);
                    }}
                  >
                    OAuth 2.0
                  </button>
                  <button
                    className={`btn btn-sm ${catalogFilter === "api_key" ? "" : "btn-ghost"}`}
                    onClick={() => {
                      setCatalogFilter("api_key");
                      setCatalogPage(1);
                    }}
                  >
                    API Base
                  </button>
                </div>
              </div>

              <div className="provider-grid">
                {pagedCatalog.map((item) => (
                  <button
                    type="button"
                    key={item.id}
                    className="provider-card"
                    onClick={() => selectCatalogProvider(item)}
                  >
                    <div className="provider-icon">
                      <ProviderLogo id={item.logo} size={20} />
                    </div>
                    <div className="provider-card-body">
                      <div className="provider-card-head">
                        <span className="provider-card-title">{item.title}</span>
                        <span
                          className={`chip ${
                            item.authMode === "oauth" ? "chip-purple" : "chip-blue"
                          }`}
                        >
                          {item.badge}
                        </span>
                      </div>
                      <div className="provider-card-desc">{item.desc}</div>
                    </div>
                  </button>
                ))}
              </div>
            </div>

            <div className="modal-footer" style={{ justifyContent: "space-between", alignItems: "center" }}>
              <div className="actions-row">
                <button
                  type="button"
                  className="btn btn-ghost btn-sm"
                  disabled={safeCatalogPage <= 1}
                  onClick={() => setCatalogPage((p) => Math.max(1, p - 1))}
                >
                  上一页
                </button>
                <span className="muted tabular">
                  第 {safeCatalogPage} / {catalogTotalPages} 页（共 {filteredCatalog.length} 个）
                </span>
                <button
                  type="button"
                  className="btn btn-ghost btn-sm"
                  disabled={safeCatalogPage >= catalogTotalPages}
                  onClick={() => setCatalogPage((p) => Math.min(catalogTotalPages, p + 1))}
                >
                  下一页
                </button>
              </div>
              <button className="btn btn-ghost" onClick={onClose}>
                取消
              </button>
            </div>
          </>
        )}

        {/* STEP 2: Channel Configuration Form */}
        {step === 2 && (
          <>
            <div className="modal-body">
              {error && <div className="error-banner">{error}</div>}

              {!isEdit && selectedProvider && (
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 10,
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <div className="provider-icon" style={{ width: 32, height: 32 }}>
                      <ProviderLogo id={selectedProvider.logo} size={18} />
                    </div>
                    <div>
                      <div style={{ fontWeight: 600, fontSize: 13.5 }}>{selectedProvider.title}</div>
                      <div className="muted">{selectedProvider.desc}</div>
                    </div>
                  </div>
                  <button className="btn btn-ghost btn-sm" onClick={() => setStep(1)}>
                    ← 重选渠道
                  </button>
                </div>
              )}

              {/* Section 1: Base URL & Multi-Protocol Endpoints */}
              <div className="section-box">
                <div className="section-box-title">
                  <span>{isOfficialOAuth ? "渠道名称" : "基础连接"}</span>
                  {!isOfficialOAuth && endpoints.length < ALL_PROTOCOLS.length && (
                    <button
                      type="button"
                      className="btn btn-ghost btn-sm"
                      onClick={() => {
                        const used = new Set(endpoints.map((e) => e.protocol));
                        const next =
                          ALL_PROTOCOLS.find((p) => !used.has(p.value)) ?? ALL_PROTOCOLS[0];
                        setEndpoints([
                          ...endpoints,
                          { protocol: next.value, endpoint: next.defaultEndpoint },
                        ]);
                      }}
                    >
                      + 添加协议端点
                    </button>
                  )}
                </div>
                <div className="form-grid">
                  <div className={`form-field ${isOfficialOAuth ? "full" : ""}`}>
                    <label className="form-label">渠道名称</label>
                    <input
                      className="input"
                      disabled={isEdit}
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder="e.g. volcengine-agent-plan"
                    />
                  </div>
                  {!isOfficialOAuth && (
                    <div className="form-field">
                      <label className="form-label">Base URL</label>
                      <input
                        className="input mono"
                        value={baseUrl}
                        onChange={(e) => setBaseUrl(e.target.value)}
                        placeholder="https://ark.cn-beijing.volces.com/api/plan"
                      />
                    </div>
                  )}
                  <div className={`form-field ${isOfficialOAuth ? "full" : "full"}`}>
                    <label className="form-label">出站代理</label>
                    <select
                      className="select"
                      value={proxyName}
                      onChange={(e) => setProxyName(e.target.value)}
                    >
                      <option value="">直连（不使用代理）</option>
                      {availableProxies.map((p) => (
                        <option key={p.name} value={p.name}>
                          {p.name} ({p.protocol.toUpperCase()} · {p.server}:{p.port})
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                <div
                  style={{
                    border: "1px solid var(--border)",
                    borderRadius: 10,
                    padding: 12,
                    display: "flex",
                    flexDirection: "column",
                    gap: 10,
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span className="form-label" style={{ margin: 0 }}>
                      额度监控（Claude / Codex / 自定义）
                    </span>
                    <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12 }}>
                      <input
                        type="checkbox"
                        checked={quotaEnabled}
                        onChange={(e) => setQuotaEnabled(e.target.checked)}
                      />
                      启用轮询
                    </label>
                  </div>
                  {quotaEnabled && (
                    <div className="form-grid">
                      <div className="form-field">
                        <label className="form-label">探测模式</label>
                        <select
                          className="select"
                          value={quotaProbe}
                          onChange={(e) => setQuotaProbe(e.target.value as QuotaProbeKind)}
                        >
                          <option value="auto">自动识别</option>
                          <option value="claude_code">Claude Code（/api/oauth/usage）</option>
                          <option value="codex">Codex（/backend-api/wham/usage）</option>
                          <option value="antigravity">Antigravity（fetchAvailableModels）</option>
                          <option value="opencode_go">OpenCode Go</option>
                          <option value="custom_http">自定义 HTTP JSON</option>
                        </select>
                      </div>
                      <div className="form-field">
                        <label className="form-label">轮询周期（秒，最低 60）</label>
                        <input
                          className="input"
                          type="number"
                          min={60}
                          value={quotaPollSecs}
                          onChange={(e) => setQuotaPollSecs(e.target.value)}
                        />
                      </div>
                      {(quotaProbe === "codex" || (quotaProbe === "auto" && authMode === "oauth" && preset === "codex")) && (
                        <div className="form-field full">
                          <label className="form-label">ChatGPT-Account-Id（可选，默认自动从 JWT 解析）</label>
                          <input
                            className="input"
                            placeholder="留空自动提取"
                            value={quotaAccountId}
                            onChange={(e) => setQuotaAccountId(e.target.value)}
                          />
                        </div>
                      )}
                      {quotaProbe === "custom_http" && (
                        <>
                          <div className="form-field full">
                            <label className="form-label">查询 URL（支持 {"{{api_key}}"}）</label>
                            <input
                              className="input"
                              placeholder="https://api.example.com/v1/usage"
                              value={quotaCustomUrl}
                              onChange={(e) => setQuotaCustomUrl(e.target.value)}
                            />
                          </div>
                          <div className="form-field">
                            <label className="form-label">剩余额度 JSON 路径</label>
                            <input
                              className="input"
                              placeholder="data.remain_quota"
                              value={quotaRemainingPath}
                              onChange={(e) => setQuotaRemainingPath(e.target.value)}
                            />
                          </div>
                          <div className="form-field">
                            <label className="form-label">已用额度 JSON 路径</label>
                            <input
                              className="input"
                              placeholder="data.used_quota"
                              value={quotaUsedPath}
                              onChange={(e) => setQuotaUsedPath(e.target.value)}
                            />
                          </div>
                          <div className="form-field">
                            <label className="form-label">总额度 JSON 路径</label>
                            <input
                              className="input"
                              placeholder="data.total_quota"
                              value={quotaTotalPath}
                              onChange={(e) => setQuotaTotalPath(e.target.value)}
                            />
                          </div>
                          <div className="form-field">
                            <label className="form-label">换算系数 / 币种</label>
                            <div style={{ display: "flex", gap: 6 }}>
                              <input
                                className="input"
                                placeholder="1"
                                value={quotaScale}
                                onChange={(e) => setQuotaScale(e.target.value)}
                              />
                              <input
                                className="input"
                                style={{ width: 80 }}
                                placeholder="USD"
                                value={quotaCurrency}
                                onChange={(e) => setQuotaCurrency(e.target.value)}
                              />
                            </div>
                          </div>
                        </>
                      )}
                    </div>
                  )}
                </div>

                {!isOfficialOAuth && (
                  <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                    <label className="form-label">协议端点（Endpoints）</label>
                    {endpoints.map((row, idx) => (
                      <div
                        key={`${row.protocol}-${idx}`}
                        style={{ display: "flex", gap: 8, alignItems: "center" }}
                      >
                        <select
                          className="select"
                          style={{ width: 190, flexShrink: 0 }}
                          value={row.protocol}
                          onChange={(e) => {
                            const p = e.target.value as ProtocolFamily;
                            const defEp =
                              ALL_PROTOCOLS.find((x) => x.value === p)?.defaultEndpoint ??
                              row.endpoint;
                            const next = [...endpoints];
                            next[idx] = { protocol: p, endpoint: row.endpoint || defEp };
                            setEndpoints(next);
                          }}
                        >
                          {ALL_PROTOCOLS.map((p) => (
                            <option key={p.value} value={p.value}>
                              {p.label}
                            </option>
                          ))}
                        </select>
                        <input
                          className="input mono"
                          style={{ flex: 1 }}
                          value={row.endpoint}
                          onChange={(e) => {
                            const next = [...endpoints];
                            next[idx] = { ...row, endpoint: e.target.value };
                            setEndpoints(next);
                          }}
                          placeholder="/v1/chat/completions"
                        />
                        {endpoints.length > 1 && (
                          <button
                            type="button"
                            className="btn btn-danger btn-sm"
                            onClick={() =>
                              setEndpoints(endpoints.filter((_, i) => i !== idx))
                            }
                          >
                            移除
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Section 2: Authentication Credentials */}
              <div className="section-box">
                <div className="section-box-title">
                  <span>
                    {authMode === "api_key"
                      ? "API Key 凭据池"
                      : isOfficialOAuth
                        ? `${preset === "codex" ? "OpenAI Codex" : "Claude Code"} 官方账号授权`
                        : "自定义 OAuth 2.0 配置"}
                  </span>
                  {!isOfficialOAuth && (
                    <select
                      className="select"
                      style={{ padding: "3px 8px", fontSize: 12 }}
                      value={authMode}
                      onChange={(e) => setAuthMode(e.target.value as AuthMode)}
                    >
                      <option value="api_key">API Base 模式</option>
                      <option value="oauth">OAuth 2.0 模式</option>
                    </select>
                  )}
                </div>

                {authMode === "api_key" ? (
                  <div className="form-grid">
                    <div className="form-field full">
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "space-between",
                        }}
                      >
                        <label className="form-label">API Keys</label>
                        <button
                          type="button"
                          className="btn btn-ghost btn-sm"
                          onClick={() => setApiKeys([...apiKeys, ""])}
                        >
                          + 添加 Key
                        </button>
                      </div>
                      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                        {apiKeys.map((keyVal, idx) => (
                          <div
                            key={idx}
                            style={{ display: "flex", gap: 8, alignItems: "center" }}
                          >
                            <input
                              className="input mono"
                              style={{ flex: 1 }}
                              value={keyVal}
                              onChange={(e) => {
                                const val = e.target.value;
                                if (val.includes("\n")) {
                                  const parts = val
                                    .split(/\r?\n/)
                                    .map((s) => s.trim())
                                    .filter(Boolean);
                                  if (parts.length > 1) {
                                    const next = [...apiKeys];
                                    next.splice(idx, 1, ...parts);
                                    setApiKeys(next);
                                    return;
                                  }
                                }
                                const next = [...apiKeys];
                                next[idx] = val;
                                setApiKeys(next);
                              }}
                              placeholder={
                                idx === 0 && isEdit && initial?.api_key_count
                                  ? `已保存 ${initial.api_key_count} 个 Key，留空保持不变`
                                  : `sk-... (#${idx + 1})`
                              }
                            />
                            {apiKeys.length > 1 && (
                              <button
                                type="button"
                                className="btn btn-danger btn-sm"
                                onClick={() =>
                                  setApiKeys(apiKeys.filter((_, i) => i !== idx))
                                }
                              >
                                移除
                              </button>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                    <div className="form-field">
                      <label className="form-label">鉴权 Header 名称</label>
                      <input
                        className="input mono"
                        value={headerName}
                        onChange={(e) => setHeaderName(e.target.value)}
                      />
                    </div>
                    <div className="form-field">
                      <label className="form-label">Header 前缀（可选）</label>
                      <input
                        className="input mono"
                        value={headerPrefix}
                        onChange={(e) => setHeaderPrefix(e.target.value)}
                        placeholder="Bearer "
                      />
                    </div>
                  </div>
                ) : isAntigravity ? (
                  <div className="form-grid">
                    <div className="form-field">
                      <label className="form-label" htmlFor="antigravity-client-id">Google OAuth Client ID</label>
                      <input
                        id="antigravity-client-id"
                        className="input mono"
                        value={clientId}
                        onChange={(e) => setClientId(e.target.value)}
                        placeholder="留空使用服务端配置"
                      />
                    </div>
                    <div className="form-field">
                      <label className="form-label" htmlFor="antigravity-client-secret">Google OAuth Client Secret</label>
                      <input
                        id="antigravity-client-secret"
                        className="input mono"
                        type="password"
                        autoComplete="off"
                        value={clientSecret}
                        onChange={(e) => setClientSecret(e.target.value)}
                        placeholder={initial?.oauth?.has_client_secret ? "已保存，留空保留" : "留空使用服务端配置"}
                      />
                    </div>
                    <div className="form-field full">
                      <label className="form-label" htmlFor="antigravity-redirect-uri">Redirect URI（可选）</label>
                      <input
                        id="antigravity-redirect-uri"
                        className="input mono"
                        value={redirectUri}
                        onChange={(e) => setRedirectUri(e.target.value)}
                        placeholder="http://localhost:51121/oauth-callback"
                      />
                    </div>
                  </div>
                ) : isOfficialOAuth ? (
                  <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                    <div className="form-field">
                      <label className="form-label">1. 点击前往官方页面登录授权</label>
                      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                        <a
                          className="btn"
                          href={officialAuthUrl || "#"}
                          target="_blank"
                          rel="noreferrer"
                          style={{
                            textDecoration: "none",
                            pointerEvents: officialAuthUrl ? "auto" : "none",
                            opacity: officialAuthUrl ? 1 : 0.5,
                          }}
                        >
                          {loadingAuthUrl ? "生成登录链接中..." : "打开官方登录链接"}
                          <IconExternal width={14} height={14} />
                        </a>
                        <button
                          type="button"
                          className="btn btn-ghost btn-sm"
                          disabled={!officialAuthUrl}
                          onClick={async () => {
                            if (!officialAuthUrl) return;
                            await navigator.clipboard.writeText(officialAuthUrl);
                            setCopiedAuthUrl(true);
                            setTimeout(() => setCopiedAuthUrl(false), 1600);
                          }}
                        >
                          <IconCopy width={13} height={13} />
                          {copiedAuthUrl ? "已复制链接" : "复制登录链接"}
                        </button>
                        <button
                          type="button"
                          className="btn btn-ghost btn-sm"
                          disabled={loadingAuthUrl}
                          onClick={() => {
                            if (preset === "codex" || preset === "claude_code") {
                              void fetchOfficialAuthUrl(preset);
                            }
                          }}
                        >
                          <IconRefresh width={13} height={13} />
                          刷新链接
                        </button>
                      </div>
                    </div>

                    <div className="form-field">
                      <label className="form-label">2. 粘贴回调链接或 code#state</label>
                      <textarea
                        className="textarea"
                        rows={2}
                        value={officialCallbackInput}
                        onChange={(e) => setOfficialCallbackInput(e.target.value)}
                        placeholder={
                          preset === "claude_code"
                            ? "粘贴 code#state"
                            : "粘贴回调 URL"
                        }
                      />
                    </div>
                  </div>
                ) : (
                  <div className="form-grid">
                    <div className="form-field">
                      <label className="form-label">OAuth 协议预设</label>
                      <select
                        className="select"
                        value={preset}
                        onChange={(e) => setPreset(e.target.value as OAuthPreset)}
                      >
                        <option value="codex">Codex (Form Token Endpoint)</option>
                        <option value="claude_code">Claude Code (JSON Token Endpoint)</option>
                        <option value="antigravity">Antigravity (Google OAuth)</option>
                        <option value="custom">Custom RFC 6749</option>
                      </select>
                    </div>
                    <div className="form-field">
                      <label className="form-label">加密库 Account ID</label>
                      <input
                        className="input mono"
                        value={accountId}
                        onChange={(e) => setAccountId(e.target.value)}
                      />
                    </div>
                    <div className="form-field">
                      <label className="form-label">Client ID</label>
                      <input
                        className="input mono"
                        value={clientId}
                        onChange={(e) => setClientId(e.target.value)}
                        placeholder="OAuth client_id"
                      />
                    </div>
                    <div className="form-field">
                      <label className="form-label">Redirect URI</label>
                      <input
                        className="input mono"
                        value={redirectUri}
                        onChange={(e) => setRedirectUri(e.target.value)}
                      />
                    </div>
                    <div className="form-field full">
                      <label className="form-label">Authorize URL</label>
                      <input
                        className="input mono"
                        value={authorizeUrl}
                        onChange={(e) => setAuthorizeUrl(e.target.value)}
                      />
                    </div>
                    <div className="form-field full">
                      <label className="form-label">Token URL</label>
                      <input
                        className="input mono"
                        value={tokenUrl}
                        onChange={(e) => setTokenUrl(e.target.value)}
                      />
                    </div>
                    <div className="form-field full">
                      <label className="form-label">Scopes（逗号分隔）</label>
                      <input
                        className="input mono"
                        value={scopesText}
                        onChange={(e) => setScopesText(e.target.value)}
                      />
                    </div>
                    <div className="form-field">
                      <label className="form-label">初始 Access Token（可选）</label>
                      <input
                        className="input mono"
                        value={accessToken}
                        onChange={(e) => setAccessToken(e.target.value)}
                        placeholder="留空可在保存后点击 OAuth 登录"
                      />
                    </div>
                    <div className="form-field">
                      <label className="form-label">初始 Refresh Token（可选）</label>
                      <input
                        className="input mono"
                        value={refreshToken}
                        onChange={(e) => setRefreshToken(e.target.value)}
                      />
                    </div>
                  </div>
                )}
              </div>

              {/* Section 3: Models */}
              <div className="section-box">
                <div className="section-box-title">
                  <span>路由模型（已选 {selectedModels.length} 个）</span>
                  <div className="actions-row">
                    <button
                      type="button"
                      className="btn btn-ghost btn-sm"
                      onClick={() => toggleModel("*")}
                    >
                      {selectedModels.includes("*") ? "取消通配符 *" : "添加通配符 *"}
                    </button>
                    {selectedModels.length > 0 && (
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        onClick={() => setSelectedModels([])}
                      >
                        清空
                      </button>
                    )}
                  </div>
                </div>

                {/* Auto-fetch models via customizable path */}
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <input
                    className="input mono"
                    style={{ width: 170 }}
                    value={modelsPath}
                    onChange={(e) => setModelsPath(e.target.value)}
                    placeholder="/v1/models"
                    title="上游获取模型列表的相对路径（最终调用 Base URL + 此路径）"
                  />
                  <button
                    type="button"
                    className="btn btn-ghost btn-sm"
                    disabled={fetchingModels}
                    onClick={() => void handleFetchModels()}
                  >
                    <IconRefresh width={13} height={13} />
                    {fetchingModels ? "获取中..." : "自动获取模型"}
                  </button>
                  {fetchInfo && <span className="muted">{fetchInfo}</span>}
                </div>

                <div className="chip-picker">
                  {suggestedModelPool.map((m) => {
                    const active = selectedModels.includes(m);
                    return (
                      <button
                        type="button"
                        key={m}
                        className={`pick-chip ${active ? "selected" : ""}`}
                        onClick={() => toggleModel(m)}
                      >
                        {active ? "✓ " : ""}
                        {m}
                      </button>
                    );
                  })}
                </div>

                <div style={{ display: "flex", gap: 8 }}>
                  <input
                    className="input mono"
                    style={{ flex: 1 }}
                    placeholder="输入自定义模型名后按回车添加..."
                    value={customModel}
                    onChange={(e) => setCustomModel(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        e.preventDefault();
                        addCustomModel();
                      }
                    }}
                  />
                  <button type="button" className="btn btn-ghost btn-sm" onClick={addCustomModel}>
                    添加模型
                  </button>
                </div>
              </div>

              {/* Section 4: Collapsible Advanced Settings */}
              <div>
                <button
                  type="button"
                  className="btn btn-ghost btn-sm"
                  onClick={() => setShowAdvanced((v) => !v)}
                >
                  {showAdvanced ? "收起高级选项" : "展开高级选项（权重 / 模型映射 / 扩展 Header）"}
                </button>

                {showAdvanced && (
                  <div className="section-box" style={{ marginTop: 10 }}>
                    <div className="form-grid">
                      <div className="form-field">
                        <label className="form-label">路由权重</label>
                        <input
                          className="input"
                          type="number"
                          min={1}
                          value={weight}
                          onChange={(e) => setWeight(e.target.value)}
                        />
                      </div>
                      <div className="form-field">
                        <label className="form-label">首字节前最大重试次数</label>
                        <input
                          className="input"
                          type="number"
                          min={0}
                          value={maxRetries}
                          onChange={(e) => setMaxRetries(e.target.value)}
                        />
                      </div>
                      <div className="form-field full">
                        <label className="form-label">模型重定向映射 JSON</label>
                        <textarea
                          className="textarea"
                          rows={2}
                          value={mappingText}
                          onChange={(e) => setMappingText(e.target.value)}
                          placeholder={'{"gpt-4-alias": "gpt-4o"}'}
                        />
                      </div>
                      {Array.from(new Set(endpoints.map((e) => e.protocol))).map((proto) => {
                        const label =
                          ALL_PROTOCOLS.find((p) => p.value === proto)?.label ?? proto;
                        return (
                          <div className="form-field" key={`hdr-${proto}`}>
                            <label className="form-label">{label} 请求头 JSON</label>
                            <textarea
                              className="textarea"
                              rows={3}
                              value={protocolHeadersText[proto] ?? ""}
                              onChange={(e) =>
                                setProtocolHeadersText((prev) => ({
                                  ...prev,
                                  [proto]: e.target.value,
                                }))
                              }
                              placeholder={
                                proto === "anthropic"
                                  ? '{"anthropic-version": "2023-06-01"}'
                                  : '{"x-custom-header": "value"}'
                              }
                            />
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div className="modal-footer">
              {!isEdit && (
                <button
                  className="btn btn-ghost"
                  style={{ marginRight: "auto" }}
                  onClick={() => setStep(1)}
                >
                  ← 上一步
                </button>
              )}
              <button className="btn btn-ghost" onClick={onClose}>
                取消
              </button>
              <button className="btn" disabled={saving} onClick={() => void handleSubmit()}>
                {saving ? "保存中..." : authorizeAntigravity ? "保存并授权" : "保存"}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
