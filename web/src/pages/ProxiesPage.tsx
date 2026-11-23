import { useEffect, useState } from "react";
import { gatewayApi } from "../api/client";
import { IconPlus, IconRefresh } from "../components/Icons";
import { ProxySubscriptionModal } from "../components/ProxySubscriptionModal";
import type { ProxyProtocol, ProxyView } from "../types/gateway";

const PROTOCOLS: { value: ProxyProtocol; label: string }[] = [
  { value: "socks5", label: "SOCKS5" },
  { value: "http", label: "HTTP" },
  { value: "shadowsocks", label: "Shadowsocks" },
  { value: "trojan", label: "Trojan" },
  { value: "vmess", label: "VMess" },
  { value: "vless", label: "VLESS" },
  { value: "anytls", label: "AnyTLS" },
  { value: "hysteria2", label: "Hysteria2" },
];

const SS_CIPHERS = [
  "aes-256-gcm",
  "aes-128-gcm",
  "chacha20-ietf-poly1305",
  "2022-blake3-aes-256-gcm",
  "2022-blake3-aes-128-gcm",
];

interface TestResult {
  testing: boolean;
  ok?: boolean;
  latencyMs?: number;
  error?: string;
}

function parseProxyUri(raw: string): Partial<{
  name: string;
  protocol: ProxyProtocol;
  server: string;
  port: string;
  username: string;
  password: string;
  cipher: string;
  tls: boolean;
  sni: string;
  wsPath: string;
  wsHost: string;
  realityPbk: string;
  realitySid: string;
}> | null {
  const s = raw.trim();
  if (!s) return null;

  try {
    if (s.startsWith("vmess://")) {
      const b64 = s.slice("vmess://".length);
      const json = JSON.parse(atob(b64));
      return {
        name: json.ps || "",
        protocol: "vmess",
        server: json.add || "",
        port: String(json.port || 443),
        password: json.id || "",
        cipher: json.scy || "auto",
        tls: json.tls === "tls",
        sni: json.sni || json.host || "",
        wsPath: json.net === "ws" ? json.path || "/" : "",
        wsHost: json.net === "ws" ? json.host || "" : "",
      };
    }

    if (s.startsWith("ss://")) {
      const hashIdx = s.indexOf("#");
      const name = hashIdx >= 0 ? decodeURIComponent(s.slice(hashIdx + 1)) : "";
      const main = hashIdx >= 0 ? s.slice(5, hashIdx) : s.slice(5);
      if (main.includes("@")) {
        const [credPart, hostPart] = main.split("@");
        const decodedCred = credPart.includes(":") ? decodeURIComponent(credPart) : atob(credPart);
        const [cipher, ...pwParts] = decodedCred.split(":");
        const [server, port] = hostPart.split(":");
        return {
          name,
          protocol: "shadowsocks",
          server,
          port: (port || "8388").split("?")[0],
          cipher,
          password: pwParts.join(":"),
        };
      } else {
        const decoded = atob(main);
        const at = decoded.lastIndexOf("@");
        const cred = decoded.slice(0, at);
        const hostPart = decoded.slice(at + 1);
        const [cipher, ...pwParts] = cred.split(":");
        const [server, port] = hostPart.split(":");
        return {
          name,
          protocol: "shadowsocks",
          server,
          port: port || "8388",
          cipher,
          password: pwParts.join(":"),
        };
      }
    }

    const u = new URL(s);
    const scheme = u.protocol.replace(":", "").toLowerCase();
    const name = u.hash ? decodeURIComponent(u.hash.slice(1)) : "";
    const q = u.searchParams;

    if (scheme === "vless") {
      const security = q.get("security") || "";
      return {
        name,
        protocol: "vless",
        server: u.hostname,
        port: u.port || "443",
        password: decodeURIComponent(u.username),
        tls: security === "tls" || security === "reality",
        sni: q.get("sni") || "",
        wsPath: q.get("type") === "ws" ? q.get("path") || "/" : "",
        wsHost: q.get("type") === "ws" ? q.get("host") || "" : "",
        realityPbk: q.get("pbk") || "",
        realitySid: q.get("sid") || "",
      };
    }

    if (scheme === "trojan") {
      return {
        name,
        protocol: "trojan",
        server: u.hostname,
        port: u.port || "443",
        password: decodeURIComponent(u.username),
        tls: true,
        sni: q.get("sni") || "",
        wsPath: q.get("type") === "ws" ? q.get("path") || "/" : "",
        wsHost: q.get("type") === "ws" ? q.get("host") || "" : "",
      };
    }

    if (scheme === "socks5" || scheme === "socks5h" || scheme === "socks") {
      return {
        name,
        protocol: "socks5",
        server: u.hostname,
        port: u.port || "1080",
        username: decodeURIComponent(u.username),
        password: decodeURIComponent(u.password),
      };
    }

    if (scheme === "http" || scheme === "https") {
      return {
        name,
        protocol: "http",
        server: u.hostname,
        port: u.port || (scheme === "https" ? "443" : "8080"),
        username: decodeURIComponent(u.username),
        password: decodeURIComponent(u.password),
      };
    }
  } catch {
    return null;
  }
  return null;
}

export function ProxiesPage() {
  const [proxies, setProxies] = useState<ProxyView[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [testMap, setTestMap] = useState<Record<string, TestResult>>({});
  const [subscriptionOpen, setSubscriptionOpen] = useState(false);

  // Modal state
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<ProxyView | null>(null);
  const [importUri, setImportUri] = useState("");
  const [name, setName] = useState("");
  const [protocol, setProtocol] = useState<ProxyProtocol>("socks5");
  const [server, setServer] = useState("");
  const [port, setPort] = useState("1080");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [cipher, setCipher] = useState("aes-256-gcm");
  const [tls, setTls] = useState(false);
  const [sni, setSni] = useState("");
  const [wsPath, setWsPath] = useState("");
  const [wsHost, setWsHost] = useState("");
  const [realityPbk, setRealityPbk] = useState("");
  const [realitySid, setRealitySid] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const requiresTls = protocol === "trojan" || protocol === "anytls" || protocol === "hysteria2";

  const load = async () => {
    try {
      const res = await gatewayApi.listProxies();
      setProxies(res.proxies);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const openCreate = () => {
    setEditing(null);
    setImportUri("");
    setName("");
    setProtocol("socks5");
    setServer("");
    setPort("1080");
    setUsername("");
    setPassword("");
    setCipher("aes-256-gcm");
    setTls(false);
    setSni("");
    setWsPath("");
    setWsHost("");
    setRealityPbk("");
    setRealitySid("");
    setEnabled(true);
    setFormError(null);
    setModalOpen(true);
  };

  const openEdit = (p: ProxyView) => {
    setEditing(p);
    setImportUri("");
    setName(p.name);
    setProtocol(p.protocol);
    setServer(p.server);
    setPort(String(p.port));
    setUsername(p.username ?? "");
    setPassword("");
    setCipher(p.cipher ?? (p.protocol === "vmess" ? "auto" : "aes-256-gcm"));
    setTls(p.tls);
    setSni(p.sni ?? "");
    setWsPath(p.ws_path ?? "");
    setWsHost(p.ws_host ?? "");
    setRealityPbk(p.reality_public_key ?? "");
    setRealitySid(p.reality_short_id ?? "");
    setEnabled(p.enabled);
    setFormError(null);
    setModalOpen(true);
  };

  const handleImportUri = () => {
    setFormError(null);
    const parsed = parseProxyUri(importUri);
    if (!parsed) {
      setFormError("无法识别节点链接格式（支持 ss://、trojan://、vless://、vmess://、socks5://、http://）");
      return;
    }
    if (!editing && parsed.name) setName(parsed.name);
    if (parsed.protocol) setProtocol(parsed.protocol);
    if (parsed.server) setServer(parsed.server);
    if (parsed.port) setPort(parsed.port);
    if (parsed.username !== undefined) setUsername(parsed.username);
    if (parsed.password !== undefined) setPassword(parsed.password);
    if (parsed.cipher !== undefined) setCipher(parsed.cipher);
    if (parsed.tls !== undefined) setTls(parsed.tls);
    if (parsed.sni !== undefined) setSni(parsed.sni);
    if (parsed.wsPath !== undefined) setWsPath(parsed.wsPath);
    if (parsed.wsHost !== undefined) setWsHost(parsed.wsHost);
    if (parsed.realityPbk !== undefined) setRealityPbk(parsed.realityPbk);
    if (parsed.realitySid !== undefined) setRealitySid(parsed.realitySid);
  };

  const handleSave = async () => {
    setFormError(null);
    if (!name.trim()) {
      setFormError("代理名称不能为空");
      return;
    }
    if (!server.trim()) {
      setFormError("服务器地址不能为空");
      return;
    }
    const portNum = Number(port);
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
      setFormError("端口必须是 1-65535 之间的整数");
      return;
    }

    const payload = {
      name: name.trim(),
      protocol,
      server: server.trim(),
      port: portNum,
      username: username.trim() || null,
      password: password.trim() || null,
      cipher:
        protocol === "shadowsocks" || protocol === "vmess" ? cipher.trim() || null : null,
      tls: requiresTls || tls,
      sni: sni.trim() || null,
      ws_path: wsPath.trim() || null,
      ws_host: wsHost.trim() || null,
      reality_public_key: protocol === "vless" ? realityPbk.trim() || null : null,
      reality_short_id: protocol === "vless" ? realitySid.trim() || null : null,
      enabled,
    };

    setSaving(true);
    try {
      if (editing) {
        await gatewayApi.updateProxy(editing.name, payload);
      } else {
        await gatewayApi.createProxy(payload);
      }
      setModalOpen(false);
      await load();
    } catch (e) {
      setFormError((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  const handleTest = async (proxyName: string) => {
    setTestMap((prev) => ({ ...prev, [proxyName]: { testing: true } }));
    try {
      const res = await gatewayApi.testProxy(proxyName);
      setTestMap((prev) => ({
        ...prev,
        [proxyName]: {
          testing: false,
          ok: res.ok,
          latencyMs: res.latency_ms,
          error: res.error,
        },
      }));
    } catch (e) {
      setTestMap((prev) => ({
        ...prev,
        [proxyName]: {
          testing: false,
          ok: false,
          error: (e as Error).message,
        },
      }));
    }
  };

  const handleDelete = async (proxyName: string) => {
    if (!window.confirm(`确认删除代理 "${proxyName}"？`)) return;
    try {
      await gatewayApi.deleteProxy(proxyName);
      await load();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const showTransport = protocol === "trojan" || protocol === "vmess" || protocol === "vless";

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">代理管理</h1>
        <div className="actions-row">
          <button className="btn btn-ghost" onClick={() => void load()}>
            <IconRefresh width={14} height={14} />
            刷新
          </button>
          <button className="btn btn-ghost" onClick={() => setSubscriptionOpen(true)}>
            导入订阅
          </button>
          <button className="btn" onClick={openCreate}>
            <IconPlus width={14} height={14} />
            添加代理
          </button>
        </div>
      </div>

      {error && <div className="error-banner">{error}</div>}

      <div className="card card-flush">
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>名称</th>
                <th>协议</th>
                <th>服务器</th>
                <th>传输层</th>
                <th>状态</th>
                <th>延迟</th>
                <th style={{ textAlign: "right" }}>操作</th>
              </tr>
            </thead>
            <tbody>
              {proxies.map((p) => {
                const tr = testMap[p.name];
                return (
                  <tr key={p.name}>
                    <td style={{ fontWeight: 600, whiteSpace: "nowrap" }}>{p.name}</td>
                    <td>
                      <span className="chip">{p.protocol.toUpperCase()}</span>
                    </td>
                    <td className="mono muted" style={{ whiteSpace: "nowrap" }}>
                      {p.server}:{p.port}
                    </td>
                    <td>
                      <div className="tag-list">
                        {p.reality_public_key && <span className="chip chip-purple">REALITY</span>}
                        {!p.reality_public_key && p.tls && <span className="chip">TLS</span>}
                        {p.ws_path && <span className="chip">WS</span>}
                        {!p.tls && !p.ws_path && !p.reality_public_key && (
                          <span className="muted">-</span>
                        )}
                      </div>
                    </td>
                    <td>
                      {!p.enabled ? (
                        <span className="chip">已禁用</span>
                      ) : p.active ? (
                        <span className="chip chip-ok">运行中</span>
                      ) : (
                        <span className="chip chip-warn">未激活</span>
                      )}
                    </td>
                    <td className="tabular" style={{ whiteSpace: "nowrap" }}>
                      {tr?.testing ? (
                        <span className="muted">测速中...</span>
                      ) : tr?.ok ? (
                        <span className="chip chip-ok">{tr.latencyMs} ms</span>
                      ) : tr && !tr.ok ? (
                        <span className="chip chip-err" title={tr.error}>
                          失败
                        </span>
                      ) : (
                        <span className="muted">-</span>
                      )}
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <div className="table-actions">
                        <button
                          className="btn btn-ghost btn-sm"
                          disabled={!p.active || tr?.testing}
                          onClick={() => void handleTest(p.name)}
                        >
                          测速
                        </button>
                        <button className="btn btn-ghost btn-sm" onClick={() => openEdit(p)}>
                          编辑
                        </button>
                        <button
                          className="btn btn-danger btn-sm"
                          onClick={() => void handleDelete(p.name)}
                        >
                          删除
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
              {proxies.length === 0 && (
                <tr>
                  <td colSpan={7} className="muted" style={{ textAlign: "center", padding: 32 }}>
                    暂无代理节点，可添加代理或导入 Clash 订阅。
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {subscriptionOpen && (
        <ProxySubscriptionModal
          onClose={() => setSubscriptionOpen(false)}
          onImported={load}
        />
      )}

      {modalOpen && (
        <div className="modal-backdrop" onClick={() => setModalOpen(false)}>
          <div className="modal" style={{ maxWidth: 600 }} onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title">{editing ? `编辑代理 · ${editing.name}` : "添加代理"}</div>
              <button className="btn btn-ghost btn-sm" onClick={() => setModalOpen(false)}>
                关闭
              </button>
            </div>
            <div className="modal-body">
              {formError && <div className="error-banner">{formError}</div>}

              {!editing && (
                <div className="form-field">
                  <label className="form-label">导入节点链接（可选）</label>
                  <div style={{ display: "flex", gap: 8 }}>
                    <input
                      className="input mono"
                      style={{ flex: 1 }}
                      value={importUri}
                      onChange={(e) => setImportUri(e.target.value)}
                      placeholder="ss:// / trojan:// / vless:// / vmess:// / socks5:// / http://"
                    />
                    <button type="button" className="btn btn-ghost btn-sm" onClick={handleImportUri}>
                      解析填入
                    </button>
                  </div>
                </div>
              )}

              <div className="form-grid">
                <div className="form-field">
                  <label className="form-label">代理名称</label>
                  <input
                    className="input"
                    disabled={Boolean(editing)}
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="e.g. us-node-1"
                  />
                </div>
                <div className="form-field">
                  <label className="form-label">协议</label>
                  <select
                    className="select"
                    value={protocol}
                    onChange={(e) => {
                      const next = e.target.value as ProxyProtocol;
                      setProtocol(next);
                      if (next === "trojan") setTls(true);
                      if (next === "vmess" && !cipher) setCipher("auto");
                    }}
                  >
                    {PROTOCOLS.map((p) => (
                      <option key={p.value} value={p.value}>
                        {p.label}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="form-field">
                  <label className="form-label">服务器地址</label>
                  <input
                    className="input mono"
                    value={server}
                    onChange={(e) => setServer(e.target.value)}
                    placeholder="1.2.3.4 或 example.com"
                  />
                </div>
                <div className="form-field">
                  <label className="form-label">端口</label>
                  <input
                    className="input mono"
                    type="number"
                    min={1}
                    max={65535}
                    value={port}
                    onChange={(e) => setPort(e.target.value)}
                  />
                </div>

                {(protocol === "socks5" || protocol === "http") && (
                  <div className="form-field">
                    <label className="form-label">用户名（可选）</label>
                    <input
                      className="input mono"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                    />
                  </div>
                )}

                <div className="form-field">
                  <label className="form-label">
                    {protocol === "vmess" || protocol === "vless" ? "UUID" : "密码"}
                  </label>
                  <input
                    className="input mono"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder={
                      editing?.has_password
                        ? "已保存，留空保持不变"
                        : protocol === "vmess" || protocol === "vless"
                          ? "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                          : "可选或节点密码"
                    }
                  />
                </div>

                {protocol === "shadowsocks" && (
                  <div className="form-field">
                    <label className="form-label">加密方式</label>
                    <select
                      className="select mono"
                      value={cipher}
                      onChange={(e) => setCipher(e.target.value)}
                    >
                      {SS_CIPHERS.map((c) => (
                        <option key={c} value={c}>
                          {c}
                        </option>
                      ))}
                    </select>
                  </div>
                )}

                {protocol === "vmess" && (
                  <div className="form-field">
                    <label className="form-label">加密方式</label>
                    <input
                      className="input mono"
                      value={cipher}
                      onChange={(e) => setCipher(e.target.value)}
                      placeholder="auto"
                    />
                  </div>
                )}

                <div className="form-field">
                  <label className="form-label">启用状态</label>
                  <div className="switch-row" style={{ padding: "6px 10px" }}>
                    <span className="muted">{enabled ? "启用" : "禁用"}</span>
                    <label className="switch">
                      <input
                        type="checkbox"
                        checked={enabled}
                        onChange={(e) => setEnabled(e.target.checked)}
                      />
                      <span className="switch-slider" />
                    </label>
                  </div>
                </div>
              </div>

              {(showTransport || requiresTls) && (
                <div className="section-box">
                  <div className="section-box-title">
                    <span>传输与 TLS</span>
                  </div>
                  <div className="form-grid">
                    <div className="form-field">
                      <div className="switch-row" style={{ padding: "6px 10px" }}>
                        <span className="form-label">TLS</span>
                        <label className="switch">
                          <input
                            type="checkbox"
                            checked={requiresTls || tls}
                            disabled={requiresTls}
                            onChange={(e) => setTls(e.target.checked)}
                          />
                          <span className="switch-slider" />
                        </label>
                      </div>
                    </div>
                    <div className="form-field">
                      <label className="form-label">SNI</label>
                      <input
                        className="input mono"
                        value={sni}
                        onChange={(e) => setSni(e.target.value)}
                        placeholder="example.com"
                      />
                    </div>
                    {showTransport && (
                      <>
                        <div className="form-field">
                          <label className="form-label">WebSocket Path（可选）</label>
                          <input
                            className="input mono"
                            value={wsPath}
                            onChange={(e) => setWsPath(e.target.value)}
                            placeholder="/ws"
                          />
                        </div>
                        <div className="form-field">
                          <label className="form-label">WebSocket Host（可选）</label>
                          <input
                            className="input mono"
                            value={wsHost}
                            onChange={(e) => setWsHost(e.target.value)}
                            placeholder="cdn.example.com"
                          />
                        </div>
                      </>
                    )}
                    {protocol === "vless" && (
                      <>
                        <div className="form-field">
                          <label className="form-label">REALITY Public Key（可选）</label>
                          <input
                            className="input mono"
                            value={realityPbk}
                            onChange={(e) => setRealityPbk(e.target.value)}
                          />
                        </div>
                        <div className="form-field">
                          <label className="form-label">REALITY Short ID（可选）</label>
                          <input
                            className="input mono"
                            value={realitySid}
                            onChange={(e) => setRealitySid(e.target.value)}
                          />
                        </div>
                      </>
                    )}
                  </div>
                </div>
              )}
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
