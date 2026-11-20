import { useEffect, useMemo, useState } from "react";
import { gatewayApi } from "../api/client";
import { IconPlus, IconRefresh } from "../components/Icons";
import { OAuthLoginModal } from "../components/OAuthLoginModal";
import { detectProviderLogo, ProviderLogo } from "../components/ProviderLogos";
import { UpstreamModal } from "../components/UpstreamModal";
import type { AuthUser, UpstreamView } from "../types/gateway";

interface Props {
  currentUser: AuthUser;
}

function formatTtl(secs?: number): string {
  if (secs === undefined || secs === null) return "";
  if (secs <= 0) return "已过期";
  if (secs > 3600) return `剩余 ${Math.floor(secs / 3600)}h`;
  return `剩余 ${Math.floor(secs / 60)}m`;
}

export function UpstreamsPage({ currentUser }: Props) {
  const canCreate =
    currentUser.role === "admin" || currentUser.allow_private_upstreams !== false;
  const [upstreams, setUpstreams] = useState<UpstreamView[]>([]);
  const [query, setQuery] = useState("");
  const [protoFilter, setProtoFilter] = useState("all");
  const [authFilter, setAuthFilter] = useState("all");
  const [page, setPage] = useState(1);
  const [error, setError] = useState<string | null>(null);
  const PAGE_SIZE = 8;

  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<UpstreamView | null>(null);
  const [oauthTarget, setOauthTarget] = useState<string | null>(null);
  const [expandedModels, setExpandedModels] = useState<Record<string, boolean>>({});

  const load = async () => {
    try {
      const res = await gatewayApi.listUpstreams();
      setUpstreams(res.upstreams);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return upstreams.filter((u) => {
      const supportedProtos = Object.keys(u.protocol_endpoints ?? {});
      if (
        protoFilter !== "all" &&
        u.protocol !== protoFilter &&
        !supportedProtos.includes(protoFilter)
      ) {
        return false;
      }
      if (authFilter !== "all" && u.auth_mode !== authFilter) return false;
      if (!q) return true;
      return (
        u.name.toLowerCase().includes(q) ||
        u.base_url.toLowerCase().includes(q) ||
        Object.values(u.protocol_endpoints ?? {}).some((url) =>
          (url ?? "").toLowerCase().includes(q)
        ) ||
        u.models.some((m) => m.toLowerCase().includes(q))
      );
    });
  }, [upstreams, query, protoFilter, authFilter]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages);
  const paged = useMemo(() => {
    const start = (safePage - 1) * PAGE_SIZE;
    return filtered.slice(start, start + PAGE_SIZE);
  }, [filtered, safePage]);

  const handleRefreshOAuth = async (name: string) => {
    try {
      await gatewayApi.refreshOAuth(name);
      await load();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const handleDelete = async (name: string) => {
    if (!window.confirm(`确认删除上游渠道 "${name}"？`)) return;
    try {
      await gatewayApi.deleteUpstream(name);
      await load();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">渠道管理</h1>
        <div className="actions-row">
          <button className="btn btn-ghost" onClick={() => void load()}>
            <IconRefresh width={14} height={14} />
            刷新
          </button>
          {canCreate && (
            <button
              className="btn"
              onClick={() => {
                setEditing(null);
                setModalOpen(true);
              }}
            >
              <IconPlus width={14} height={14} />
              {currentUser.role === "admin" ? "添加渠道" : "挂载我的渠道"}
            </button>
          )}
        </div>
      </div>

      {error && <div className="error-banner">{error}</div>}

      <div className="toolbar">
        <input
          className="input"
          style={{ width: 260 }}
          placeholder="搜索渠道名、Base URL 或模型..."
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setPage(1);
          }}
        />
        <select
          className="select"
          value={protoFilter}
          onChange={(e) => {
            setProtoFilter(e.target.value);
            setPage(1);
          }}
        >
          <option value="all">全部协议</option>
          <option value="openai">OpenAI Chat</option>
          <option value="openai_responses">Codex / Responses</option>
          <option value="anthropic">Anthropic / Claude</option>
          <option value="gemini">Google Gemini</option>
        </select>
        <select
          className="select"
          value={authFilter}
          onChange={(e) => {
            setAuthFilter(e.target.value);
            setPage(1);
          }}
        >
          <option value="all">全部鉴权</option>
          <option value="api_key">API Base</option>
          <option value="oauth">OAuth 2.0</option>
        </select>
        <span className="muted" style={{ marginLeft: "auto" }}>
          共 {filtered.length} 个渠道
        </span>
      </div>

      <div className="card card-flush">
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>渠道</th>
                <th>协议</th>
                <th>鉴权</th>
                <th>模型</th>
                <th>权重 / 重试</th>
                <th>状态</th>
                <th style={{ textAlign: "right" }}>操作</th>
              </tr>
            </thead>
            <tbody>
              {paged.map((up) => {
                const isExpanded = Boolean(expandedModels[up.name]);
                const MAX_VISIBLE_MODELS = 2;
                const visibleModels = isExpanded
                  ? up.models
                  : up.models.slice(0, MAX_VISIBLE_MODELS);
                const hiddenCount = Math.max(0, up.models.length - MAX_VISIBLE_MODELS);

                return (
                <tr key={up.name}>
                  <td>
                    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                      <div className="provider-icon" style={{ width: 32, height: 32, flexShrink: 0 }}>
                        <ProviderLogo
                          id={detectProviderLogo({
                            name: up.name,
                            baseUrl: up.base_url,
                            protocol: up.protocol,
                            preset: up.oauth?.preset,
                          })}
                          size={18}
                        />
                      </div>
                      <div style={{ minWidth: 0 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                          <span style={{ fontWeight: 600, whiteSpace: "nowrap" }}>{up.name}</span>
                          {up.scope === "private" ? (
                            <span className="chip chip-purple">
                              {up.owner_username && up.owner_username !== currentUser.username
                                ? `私有 · ${up.owner_username}`
                                : "私有"}
                            </span>
                          ) : (
                            <span className="chip">全局</span>
                          )}
                          {up.proxy && (
                            <span className="chip chip-blue" title={`出站代理: ${up.proxy}`}>
                              代理 · {up.proxy}
                            </span>
                          )}
                        </div>
                        <div
                          className="muted mono"
                          title={up.base_url}
                          style={{
                            fontSize: 11.5,
                            maxWidth: 230,
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                          }}
                        >
                          {up.base_url}
                        </div>
                      </div>
                    </div>
                  </td>
                  <td>
                    <div className="tag-list" style={{ maxWidth: 180 }}>
                      {Object.entries(up.protocol_endpoints ?? {}).length > 0 ? (
                        Object.entries(up.protocol_endpoints).map(([proto, url]) => (
                          <span className="chip" key={proto} title={url}>
                            {proto}
                          </span>
                        ))
                      ) : (
                        <span className="chip">{up.protocol}</span>
                      )}
                    </div>
                  </td>
                  <td>
                    {up.auth_mode === "oauth" ? (
                      <span className="chip chip-purple">
                        OAuth · {up.oauth?.preset ?? "custom"}
                      </span>
                    ) : (
                      <span className="chip chip-blue">API Base · {up.api_key_count ?? 0} keys</span>
                    )}
                  </td>
                  <td>
                    <div
                      className="tag-list"
                      style={{ maxWidth: isExpanded ? 320 : 240 }}
                      title={up.models.join(", ")}
                    >
                      {visibleModels.map((m) => (
                        <span className="tag" key={m}>
                          {m}
                        </span>
                      ))}
                      {hiddenCount > 0 && (
                        <button
                          type="button"
                          className="tag tag-more"
                          onClick={() =>
                            setExpandedModels((prev) => ({
                              ...prev,
                              [up.name]: !prev[up.name],
                            }))
                          }
                        >
                          {isExpanded ? "收起" : `+${hiddenCount}`}
                        </button>
                      )}
                    </div>
                  </td>
                  <td className="tabular muted" style={{ whiteSpace: "nowrap" }}>
                    w={up.weight} / r={up.max_retries}
                  </td>
                  <td>
                    {up.cooling_down ? (
                      <span className="chip chip-warn">429 冷却中</span>
                    ) : up.auth_mode === "oauth" ? (
                      up.oauth?.token_present ? (
                        <span className="chip chip-ok">
                          已授权 {formatTtl(up.oauth.expires_in_secs)}
                        </span>
                      ) : (
                        <span className="chip chip-warn">未授权</span>
                      )
                    ) : (
                      <span className="chip chip-ok">运行中</span>
                    )}
                  </td>
                  <td style={{ textAlign: "right" }}>
                    {up.can_manage ? (
                      <div className="table-actions">
                        {up.auth_mode === "oauth" && up.oauth?.can_login_pkce && (
                          <button
                            className={up.oauth.token_present ? "btn btn-ghost btn-sm" : "btn btn-sm"}
                            onClick={() => setOauthTarget(up.name)}
                          >
                            {up.oauth.token_present ? "重授" : "登录"}
                          </button>
                        )}
                        {up.auth_mode === "oauth" && up.oauth?.can_refresh && (
                          <button
                            className="btn btn-ghost btn-sm"
                            onClick={() => void handleRefreshOAuth(up.name)}
                          >
                            刷新
                          </button>
                        )}
                        <button
                          className="btn btn-ghost btn-sm"
                          onClick={() => {
                            setEditing(up);
                            setModalOpen(true);
                          }}
                        >
                          编辑
                        </button>
                        <button
                          className="btn btn-danger btn-sm"
                          onClick={() => void handleDelete(up.name)}
                        >
                          删除
                        </button>
                      </div>
                    ) : (
                      <span className="muted">共享只读</span>
                    )}
                  </td>
                </tr>
                );
              })}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={7} className="muted" style={{ textAlign: "center", padding: 32 }}>
                    没有匹配的渠道
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {totalPages > 1 && (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: "12px 16px",
              borderTop: "1px solid var(--border)",
            }}
          >
            <span className="muted tabular">
              第 {safePage} / {totalPages} 页 · 每页 {PAGE_SIZE} 个 · 共 {filtered.length} 个渠道
            </span>
            <div className="actions-row">
              <button
                className="btn btn-ghost btn-sm"
                disabled={safePage <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                上一页
              </button>
              <button
                className="btn btn-ghost btn-sm"
                disabled={safePage >= totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              >
                下一页
              </button>
            </div>
          </div>
        )}
      </div>

      {modalOpen && (
        <UpstreamModal
          initial={editing}
          onClose={() => setModalOpen(false)}
          onSaved={() => void load()}
        />
      )}

      {oauthTarget && (
        <OAuthLoginModal
          upstreamName={oauthTarget}
          onClose={() => setOauthTarget(null)}
          onSuccess={() => void load()}
        />
      )}
    </div>
  );
}
