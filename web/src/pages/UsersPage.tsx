import { useEffect, useMemo, useState } from "react";
import { gatewayApi } from "../api/client";
import { IconPlus, IconRefresh } from "../components/Icons";
import type { AuthUser, UpstreamView, UserItem, UserRole } from "../types/gateway";

interface Props {
  currentUser: AuthUser;
}

function formatDate(secs: number): string {
  if (!secs) return "-";
  return new Date(secs * 1000).toLocaleString();
}

export function UsersPage({ currentUser }: Props) {
  const [users, setUsers] = useState<UserItem[]>([]);
  const [upstreams, setUpstreams] = useState<UpstreamView[]>([]);
  const [allowRegistration, setAllowRegistration] = useState(true);
  const [defaultRestrict, setDefaultRestrict] = useState(false);
  const [defaultAllowed, setDefaultAllowed] = useState<string[]>([]);
  const [savingDefaults, setSavingDefaults] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<UserItem | null>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<UserRole>("user");
  const [enabled, setEnabled] = useState(true);
  const [allowPrivate, setAllowPrivate] = useState(true);
  const [restrictUpstreams, setRestrictUpstreams] = useState(false);
  const [allowedUpstreams, setAllowedUpstreams] = useState<string[]>([]);
  const [restrictModels, setRestrictModels] = useState(false);
  const [allowedModels, setAllowedModels] = useState<string[]>([]);
  const [customModelInput, setCustomModelInput] = useState("");
  const [saving, setSaving] = useState(false);

  const load = async () => {
    try {
      const [res, settings, upRes] = await Promise.all([
        gatewayApi.listUsers(),
        gatewayApi.getSettings(),
        gatewayApi.listUpstreams(),
      ]);
      setUsers(res.users);
      setAllowRegistration(settings.allow_registration);
      setDefaultRestrict(settings.default_user_restrict_upstreams);
      setDefaultAllowed(settings.default_user_allowed_upstreams ?? []);
      setUpstreams(upRes.upstreams);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const globalUpstreams = useMemo(
    () => upstreams.filter((u) => u.scope === "global"),
    [upstreams]
  );

  const allAvailableModels = useMemo(() => {
    const set = new Set<string>();
    for (const up of upstreams) {
      for (const m of up.models) {
        if (m !== "*") set.add(m);
      }
      for (const alias of Object.keys(up.model_mapping)) {
        set.add(alias);
      }
    }
    for (const m of allowedModels) set.add(m);
    return Array.from(set).sort();
  }, [upstreams, allowedModels]);

  const toggleRegistration = async (next: boolean) => {
    try {
      const res = await gatewayApi.updateSettings({ allow_registration: next });
      setAllowRegistration(res.allow_registration);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const saveDefaultChannels = async (nextRestrict: boolean, nextAllowed: string[]) => {
    setSavingDefaults(true);
    try {
      const res = await gatewayApi.updateSettings({
        default_user_restrict_upstreams: nextRestrict,
        default_user_allowed_upstreams: nextAllowed,
      });
      setDefaultRestrict(res.default_user_restrict_upstreams);
      setDefaultAllowed(res.default_user_allowed_upstreams);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSavingDefaults(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const toggleItem = (list: string[], value: string, setter: (v: string[]) => void) => {
    if (list.includes(value)) {
      setter(list.filter((x) => x !== value));
    } else {
      setter([...list, value]);
    }
  };

  const addCustomModel = () => {
    const m = customModelInput.trim();
    if (!m) return;
    if (!allowedModels.includes(m)) {
      setAllowedModels([...allowedModels, m]);
    }
    setCustomModelInput("");
  };

  const openCreate = () => {
    setEditing(null);
    setUsername("");
    setPassword("");
    setRole("user");
    setEnabled(true);
    setAllowPrivate(true);
    setRestrictUpstreams(defaultRestrict);
    setAllowedUpstreams([...defaultAllowed]);
    setRestrictModels(false);
    setAllowedModels([]);
    setCustomModelInput("");
    setError(null);
    setModalOpen(true);
  };

  const openEdit = (u: UserItem) => {
    setEditing(u);
    setUsername(u.username);
    setPassword("");
    setRole(u.role);
    setEnabled(u.enabled);
    setAllowPrivate(u.allow_private_upstreams);
    setRestrictUpstreams(u.restrict_upstreams);
    setAllowedUpstreams(u.allowed_upstreams ?? []);
    setRestrictModels(u.restrict_models);
    setAllowedModels(u.allowed_models ?? []);
    setCustomModelInput("");
    setError(null);
    setModalOpen(true);
  };

  const handleSave = async () => {
    setError(null);
    if (!editing && !username.trim()) {
      setError("用户名不能为空");
      return;
    }
    if (!editing && password.trim().length < 6) {
      setError("密码长度至少 6 位");
      return;
    }
    if (editing && password.trim() && password.trim().length < 6) {
      setError("新密码长度至少 6 位");
      return;
    }

    setSaving(true);
    try {
      if (editing) {
        await gatewayApi.updateUser(editing.id, {
          role,
          enabled,
          allow_private_upstreams: allowPrivate,
          restrict_upstreams: role === "admin" ? false : restrictUpstreams,
          allowed_upstreams: role === "admin" ? [] : allowedUpstreams,
          restrict_models: role === "admin" ? false : restrictModels,
          allowed_models: role === "admin" ? [] : allowedModels,
          password: password.trim() ? password.trim() : null,
        });
      } else {
        await gatewayApi.createUser({
          username: username.trim(),
          password: password.trim(),
          role,
          enabled,
          allow_private_upstreams: allowPrivate,
          restrict_upstreams: role === "admin" ? false : restrictUpstreams,
          allowed_upstreams: role === "admin" ? [] : allowedUpstreams,
          restrict_models: role === "admin" ? false : restrictModels,
          allowed_models: role === "admin" ? [] : allowedModels,
        });
      }
      setModalOpen(false);
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  const handleQuickToggle = async (u: UserItem) => {
    try {
      await gatewayApi.updateUser(u.id, {
        role: u.role,
        enabled: !u.enabled,
        allow_private_upstreams: u.allow_private_upstreams,
        restrict_upstreams: u.restrict_upstreams,
        allowed_upstreams: u.allowed_upstreams,
        restrict_models: u.restrict_models,
        allowed_models: u.allowed_models,
      });
      await load();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const handleDelete = async (u: UserItem) => {
    if (!window.confirm(`确认删除用户 "${u.username}" 及其名下令牌？`)) return;
    try {
      await gatewayApi.deleteUser(u.id);
      await load();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">用户管理</h1>
        <div className="actions-row">
          <div className="switch-row" style={{ padding: "5px 10px", gap: 8 }}>
            <span className="muted" style={{ fontSize: 12.5 }}>开放注册</span>
            <label className="switch">
              <input
                type="checkbox"
                checked={allowRegistration}
                onChange={(e) => void toggleRegistration(e.target.checked)}
              />
              <span className="switch-slider" />
            </label>
          </div>
          <button className="btn btn-ghost" onClick={() => void load()}>
            <IconRefresh width={14} height={14} />
            刷新
          </button>
          <button className="btn" onClick={openCreate}>
            <IconPlus width={14} height={14} />
            新建用户
          </button>
        </div>
      </div>

      {error && <div className="error-banner">{error}</div>}

      <div className="card" style={{ marginBottom: 14, padding: "14px 18px" }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 12,
            flexWrap: "wrap",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span className="card-title">普通用户默认授权渠道</span>
            <label className="switch">
              <input
                type="checkbox"
                checked={defaultRestrict}
                disabled={savingDefaults}
                onChange={(e) => void saveDefaultChannels(e.target.checked, defaultAllowed)}
              />
              <span className="switch-slider" />
            </label>
            <span className="muted" style={{ fontSize: 12.5 }}>
              {defaultRestrict ? `仅授权已选 ${defaultAllowed.length} 个全局渠道` : "默认全部全局渠道可用"}
            </span>
          </div>
          {defaultRestrict && (
            <div className="chip-picker" style={{ marginTop: 0 }}>
              {globalUpstreams.map((up) => {
                const selected = defaultAllowed.includes(up.name);
                return (
                  <button
                    type="button"
                    key={up.name}
                    disabled={savingDefaults}
                    className={`pick-chip ${selected ? "selected" : ""}`}
                    onClick={() => {
                      const next = selected
                        ? defaultAllowed.filter((x) => x !== up.name)
                        : [...defaultAllowed, up.name];
                      void saveDefaultChannels(true, next);
                    }}
                  >
                    {selected ? "✓ " : ""}
                    {up.name}
                  </button>
                );
              })}
              {globalUpstreams.length === 0 && <span className="muted">暂无全局渠道</span>}
            </div>
          )}
        </div>
      </div>

      <div className="card card-flush">
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>用户名</th>
                <th>角色</th>
                <th>权限范围</th>
                <th>自建渠道</th>
                <th>令牌数</th>
                <th>状态</th>
                <th>创建时间</th>
                <th style={{ textAlign: "right" }}>操作</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => {
                const isSelf = u.id === currentUser.id;
                return (
                  <tr key={u.id}>
                    <td>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <span style={{ fontWeight: 600 }}>{u.username}</span>
                        {isSelf && <span className="chip">当前</span>}
                      </div>
                    </td>
                    <td>
                      {u.role === "admin" ? (
                        <span className="chip chip-purple">管理员</span>
                      ) : (
                        <span className="chip">普通用户</span>
                      )}
                    </td>
                    <td>
                      {u.role === "admin" ? (
                        <span className="chip chip-ok">全部权限</span>
                      ) : (
                        <div className="tag-list">
                          {u.restrict_upstreams ? (
                            <span className="chip chip-blue">
                              Provider: {u.allowed_upstreams.length}
                            </span>
                          ) : (
                            <span className="chip">全局 Provider 不限</span>
                          )}
                          {u.restrict_models ? (
                            <span className="chip chip-purple">
                              Model: {u.allowed_models.length}
                            </span>
                          ) : (
                            <span className="chip">Model 不限</span>
                          )}
                        </div>
                      )}
                    </td>
                    <td>
                      {u.role === "admin" || u.allow_private_upstreams ? (
                        <span className="chip chip-ok">允许</span>
                      ) : (
                        <span className="chip">禁止</span>
                      )}
                    </td>
                    <td className="tabular">{u.key_count}</td>
                    <td>
                      {u.enabled ? (
                        <span className="chip chip-ok">启用</span>
                      ) : (
                        <span className="chip chip-err">禁用</span>
                      )}
                    </td>
                    <td className="muted tabular" style={{ whiteSpace: "nowrap" }}>
                      {formatDate(u.created_at)}
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <div className="table-actions">
                        <button className="btn btn-ghost btn-sm" onClick={() => openEdit(u)}>
                          权限 / 编辑
                        </button>
                        {!isSelf && (
                          <>
                            <button
                              className="btn btn-ghost btn-sm"
                              onClick={() => void handleQuickToggle(u)}
                            >
                              {u.enabled ? "禁用" : "启用"}
                            </button>
                            <button
                              className="btn btn-danger btn-sm"
                              onClick={() => void handleDelete(u)}
                            >
                              删除
                            </button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {modalOpen && (
        <div className="modal-backdrop" onClick={() => setModalOpen(false)}>
          <div className="modal" style={{ maxWidth: 560 }} onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title">
                {editing ? `编辑用户 · ${editing.username}` : "新建用户"}
              </div>
              <button className="btn btn-ghost btn-sm" onClick={() => setModalOpen(false)}>
                关闭
              </button>
            </div>
            <div className="modal-body">
              {error && <div className="error-banner">{error}</div>}
              <div className="form-grid">
                <div className="form-field">
                  <label className="form-label">用户名</label>
                  <input
                    className="input"
                    disabled={Boolean(editing)}
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="e.g. alice"
                  />
                </div>
                <div className="form-field">
                  <label className="form-label">{editing ? "重置密码（留空不变）" : "密码"}</label>
                  <input
                    className="input"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder={editing ? "留空保持原密码" : "至少 6 位"}
                  />
                </div>
                <div className="form-field">
                  <label className="form-label">角色</label>
                  <select
                    className="select"
                    value={role}
                    onChange={(e) => setRole(e.target.value as UserRole)}
                  >
                    <option value="user">普通用户</option>
                    <option value="admin">管理员</option>
                  </select>
                </div>
                <div className="form-field">
                  <label className="form-label">状态</label>
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

              {role !== "admin" && (
                <>
                  <div className="form-field">
                    <div className="switch-row">
                      <span className="form-label">允许挂载个人私有渠道</span>
                      <label className="switch">
                        <input
                          type="checkbox"
                          checked={allowPrivate}
                          onChange={(e) => setAllowPrivate(e.target.checked)}
                        />
                        <span className="switch-slider" />
                      </label>
                    </div>
                  </div>

                  <div className="form-field">
                    <div className="switch-row">
                      <span className="form-label">全局 Provider 限制</span>
                      <label className="switch">
                        <input
                          type="checkbox"
                          checked={restrictUpstreams}
                          onChange={(e) => setRestrictUpstreams(e.target.checked)}
                        />
                        <span className="switch-slider" />
                      </label>
                    </div>
                    {restrictUpstreams && (
                      <div className="chip-picker">
                        {globalUpstreams.map((up) => {
                          const selected = allowedUpstreams.includes(up.name);
                          return (
                            <button
                              type="button"
                              key={up.name}
                              className={`pick-chip ${selected ? "selected" : ""}`}
                              onClick={() =>
                                toggleItem(allowedUpstreams, up.name, setAllowedUpstreams)
                              }
                            >
                              {selected ? "✓ " : ""}
                              {up.name}
                            </button>
                          );
                        })}
                        {globalUpstreams.length === 0 && (
                          <span className="muted">暂无全局渠道</span>
                        )}
                      </div>
                    )}
                  </div>

                  <div className="form-field">
                    <div className="switch-row">
                      <span className="form-label">Model 限制</span>
                      <label className="switch">
                        <input
                          type="checkbox"
                          checked={restrictModels}
                          onChange={(e) => setRestrictModels(e.target.checked)}
                        />
                        <span className="switch-slider" />
                      </label>
                    </div>
                    {restrictModels && (
                      <>
                        <div className="chip-picker">
                          {allAvailableModels.map((m) => {
                            const selected = allowedModels.includes(m);
                            return (
                              <button
                                type="button"
                                key={m}
                                className={`pick-chip ${selected ? "selected" : ""}`}
                                onClick={() => toggleItem(allowedModels, m, setAllowedModels)}
                              >
                                {selected ? "✓ " : ""}
                                {m}
                              </button>
                            );
                          })}
                        </div>
                        <div style={{ display: "flex", gap: 8 }}>
                          <input
                            className="input mono"
                            style={{ flex: 1 }}
                            value={customModelInput}
                            onChange={(e) => setCustomModelInput(e.target.value)}
                            onKeyDown={(e) => {
                              if (e.key === "Enter") {
                                e.preventDefault();
                                addCustomModel();
                              }
                            }}
                            placeholder="输入自定义模型名后回车添加..."
                          />
                          <button
                            type="button"
                            className="btn btn-ghost btn-sm"
                            onClick={addCustomModel}
                          >
                            添加
                          </button>
                        </div>
                      </>
                    )}
                  </div>
                </>
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
