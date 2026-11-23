import { useEffect, useState } from "react";
import { gatewayApi } from "../api/client";
import { IconCopy, IconPlus } from "../components/Icons";
import type { ClientKeyItem, UpsertClientKeyPayload } from "../types/gateway";

function generateRandomKey(): string {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return `sk-ttt-${hex}`;
}

export function KeysPage() {
  const [keys, setKeys] = useState<ClientKeyItem[]>([]);
  const [authEnabled, setAuthEnabled] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Create / Edit modal state
  const [modalOpen, setModalOpen] = useState(false);
  const [isEdit, setIsEdit] = useState(false);
  const [formKey, setFormKey] = useState("");
  const [formName, setFormName] = useState("");
  const [formEnabled, setFormEnabled] = useState(true);
  const [saving, setSaving] = useState(false);

  const load = async () => {
    try {
      const keysRes = await gatewayApi.listKeys();
      setKeys(keysRes.keys);
      setAuthEnabled(keysRes.auth_enabled);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const openCreateModal = () => {
    setIsEdit(false);
    setFormKey(generateRandomKey());
    setFormName("");
    setFormEnabled(true);
    setModalOpen(true);
  };

  const openEditModal = (item: ClientKeyItem) => {
    setIsEdit(true);
    setFormKey(item.key);
    setFormName(item.name);
    setFormEnabled(item.enabled);
    setModalOpen(true);
  };

  const handleSave = async () => {
    const trimmed = formKey.trim();
    if (!trimmed) {
      setError("API Key 不能为空");
      return;
    }
    setSaving(true);
    setError(null);
    const payload: UpsertClientKeyPayload = {
      key: trimmed,
      name: formName.trim(),
      enabled: formEnabled,
    };
    try {
      if (isEdit) {
        await gatewayApi.updateKey(payload);
      } else {
        await gatewayApi.addKey(payload);
      }
      setModalOpen(false);
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  const handleQuickToggleEnabled = async (item: ClientKeyItem) => {
    try {
      await gatewayApi.updateKey({
        key: item.key,
        name: item.name,
        enabled: !item.enabled,
      });
      await load();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const handleDelete = async (key: string) => {
    if (!window.confirm("确认撤销此网关 API Key？")) return;
    try {
      await gatewayApi.deleteKey(key);
      await load();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const copyText = async (text: string) => {
    await navigator.clipboard.writeText(text);
    setCopiedKey(text);
    setTimeout(() => setCopiedKey(null), 1500);
  };

  const gatewayOrigin = window.location.origin;
  const sampleKey = keys.find((k) => k.enabled)?.key ?? keys[0]?.key ?? "sk-ttt-your-key";
  const agentPrompt = `请帮我配置当前 AI 工具接入本地统一模型网关（TalkThatTalk）：

1. 网关地址：${gatewayOrigin}
2. API Key：${sampleKey}
3. 可用协议端点：
   - OpenAI Chat Completions：${gatewayOrigin}/v1/chat/completions（OPENAI_BASE_URL=${gatewayOrigin}/v1）
   - OpenAI Responses（Codex）：${gatewayOrigin}/v1/responses（OPENAI_BASE_URL=${gatewayOrigin}/v1）
   - Anthropic Messages（Claude Code）：${gatewayOrigin}/v1/messages（ANTHROPIC_BASE_URL=${gatewayOrigin}）
   - 模型列表接口：GET ${gatewayOrigin}/v1/models
4. 鉴权方式：
   - OpenAI 协议：Authorization: Bearer ${sampleKey}
   - Anthropic 协议：x-api-key: ${sampleKey} 或 Authorization: Bearer ${sampleKey}
5. 获取可用模型：请先请求 GET ${gatewayOrigin}/v1/models（携带 Authorization: Bearer ${sampleKey}）获取当前令牌可用的模型列表，再按需选择模型写入配置。
6. 会话亲和与 Prompt 缓存优化（可选，不强制）：
   - 网关会自动识别主流 Agent 自带的会话标识（如 Codex 的 session_id、Claude Code 的 metadata.user_id、OpenCode 的 x-opencode-session、以及 x-session-id、prompt_cache_key 等），未携带时也会自动按上下文前缀指纹做亲和路由，普通工具无需额外配置。
   - 若自研客户端或脚本支持按每次对话动态传递请求头，可优先传入稳定的会话 ID：x-ttt-session-id: <per-conversation-uuid>（或 x-session-id），同一会话多轮复用同一上游与 Key，网关转发前会自动剥离 x-ttt-session-id 并按目标渠道转换为对应的会话头（切勿使用每次请求变化的 request-id，也不要在全局静态配置里写死固定值）。

请根据当前工具的配置文件格式（如 Claude Code ~/.claude/settings.json、Codex ~/.codex/config.toml、OpenCode / Cursor / Cline 等）自动完成配置，并优先使用与当前工具匹配的原生协议端点；配置完成后发一条简短测试请求验证连通性。`;

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">客户端 API 令牌</h1>
        <div className="actions-row">
          <span className={`chip ${authEnabled ? "chip-ok" : "chip-warn"}`}>
            {authEnabled ? "鉴权已开启" : "未开启客户端鉴权"}
          </span>
          <button className="btn" onClick={openCreateModal}>
            <IconPlus width={14} height={14} />
            新建令牌
          </button>
        </div>
      </div>

      {error && <div className="error-banner">{error}</div>}

      <div className="card card-flush" style={{ marginBottom: 14 }}>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>名称</th>
                <th>密钥</th>
                <th>归属</th>
                <th>状态</th>
                <th style={{ textAlign: "right" }}>操作</th>
              </tr>
            </thead>
            <tbody>
              {keys.map((item) => (
                <tr key={item.key}>
                  <td style={{ fontWeight: 600 }}>{item.name || "未命名令牌"}</td>
                  <td className="mono">{item.masked}</td>
                  <td>
                    {item.owner_username ? (
                      <span className="chip">{item.owner_username}</span>
                    ) : (
                      <span className="muted">-</span>
                    )}
                  </td>
                  <td>
                    <span className={`chip ${item.enabled ? "chip-ok" : "chip-err"}`}>
                      {item.enabled ? "已启用" : "已禁用"}
                    </span>
                  </td>
                  <td style={{ textAlign: "right" }}>
                    <div className="table-actions">
                      <button
                        className="btn btn-ghost btn-sm"
                        onClick={() => openEditModal(item)}
                      >
                        编辑
                      </button>
                      <button
                        className="btn btn-ghost btn-sm"
                        onClick={() => void handleQuickToggleEnabled(item)}
                      >
                        {item.enabled ? "禁用" : "启用"}
                      </button>
                      <button
                        className="btn btn-ghost btn-sm"
                        onClick={() => void copyText(item.key)}
                      >
                        <IconCopy width={13} height={13} />
                        {copiedKey === item.key ? "已复制" : "复制"}
                      </button>
                      <button
                        className="btn btn-danger btn-sm"
                        onClick={() => void handleDelete(item.key)}
                      >
                        撤销
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {keys.length === 0 && (
                <tr>
                  <td colSpan={5} className="muted" style={{ textAlign: "center", padding: 32 }}>
                    暂无令牌，点击右上角「新建令牌」创建。
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 14 }}>
        <div className="card-header">
          <div className="card-title">Agent 接入提示词</div>
          <button
            className="btn btn-ghost btn-sm"
            onClick={() => void copyText(agentPrompt)}
          >
            <IconCopy width={13} height={13} />
            {copiedKey === agentPrompt ? "已复制" : "复制提示词"}
          </button>
        </div>
        <pre className="code-block">{agentPrompt}</pre>
      </div>

      <div className="two-col">
        <div className="card">
          <div className="card-header">
            <div className="card-title">OpenAI SDK / Codex 接入示例</div>
          </div>
          <pre className="code-block">{`export OPENAI_BASE_URL="${gatewayOrigin}/v1"
export OPENAI_API_KEY="${sampleKey}"

# 可选：携带稳定的会话头 x-ttt-session-id（每轮对话保持一致）以提升 Prompt 缓存命中率
curl ${gatewayOrigin}/v1/chat/completions \\
  -H "Authorization: Bearer ${sampleKey}" \\
  -H "Content-Type: application/json" \\
  -H "x-ttt-session-id: conv-demo-001" \\
  -d '{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"Hello"}]}'`}</pre>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">Claude Code / Anthropic SDK 接入示例</div>
          </div>
          <pre className="code-block">{`export ANTHROPIC_BASE_URL="${gatewayOrigin}"
export ANTHROPIC_API_KEY="${sampleKey}"

# 可选：Claude Code 会自动带 metadata.user_id；自定义脚本也可传 x-ttt-session-id
curl ${gatewayOrigin}/v1/messages \\
  -H "x-api-key: ${sampleKey}" \\
  -H "anthropic-version: 2023-06-01" \\
  -H "Content-Type: application/json" \\
  -H "x-ttt-session-id: conv-demo-001" \\
  -d '{"model":"claude-sonnet-4-20250514","max_tokens":256,"messages":[{"role":"user","content":"Hello"}]}'`}</pre>
        </div>
      </div>

      {modalOpen && (
        <div className="modal-backdrop" onClick={() => setModalOpen(false)}>
          <div className="modal" style={{ maxWidth: 460 }} onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title">{isEdit ? "编辑令牌" : "新建网关令牌"}</div>
              <button className="btn btn-ghost btn-sm" onClick={() => setModalOpen(false)}>
                关闭
              </button>
            </div>

            <div className="modal-body">
              <div className="form-grid">
                <div className="form-field">
                  <label className="form-label">令牌名称</label>
                  <input
                    className="input"
                    value={formName}
                    onChange={(e) => setFormName(e.target.value)}
                    placeholder="e.g. Claude Code 专用"
                  />
                </div>

                <div className="form-field">
                  <label className="form-label">启用状态</label>
                  <div className="switch-row" style={{ padding: "6px 10px" }}>
                    <span className="muted">{formEnabled ? "启用" : "禁用"}</span>
                    <label className="switch">
                      <input
                        type="checkbox"
                        checked={formEnabled}
                        onChange={(e) => setFormEnabled(e.target.checked)}
                      />
                      <span className="switch-slider" />
                    </label>
                  </div>
                </div>

                <div className="form-field full">
                  <label className="form-label">API Key</label>
                  <div style={{ display: "flex", gap: 8 }}>
                    <input
                      className="input mono"
                      style={{ flex: 1 }}
                      disabled={isEdit}
                      value={formKey}
                      onChange={(e) => setFormKey(e.target.value)}
                    />
                    {!isEdit && (
                      <button
                        className="btn btn-ghost"
                        onClick={() => setFormKey(generateRandomKey())}
                      >
                        重新生成
                      </button>
                    )}
                  </div>
                </div>
              </div>
            </div>

            <div className="modal-footer">
              <button className="btn btn-ghost" onClick={() => setModalOpen(false)}>
                取消
              </button>
              <button className="btn" disabled={saving} onClick={() => void handleSave()}>
                {saving ? "保存中..." : "保存"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
