import { useState, type FormEvent } from "react";
import { gatewayApi } from "../api/client";
import { IconMoon, IconSun } from "../components/Icons";
import type { AuthUser } from "../types/gateway";

interface Props {
  initialized: boolean;
  allowRegistration: boolean;
  theme: "light" | "dark";
  onToggleTheme: () => void;
  onAuthenticated: (token: string, user: AuthUser) => void;
}

export function LoginPage({
  initialized,
  allowRegistration,
  theme,
  onToggleTheme,
  onAuthenticated,
}: Props) {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState(initialized ? "" : "admin");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isSetup = !initialized;
  const isRegister = initialized && allowRegistration && mode === "register";
  const needsConfirm = isSetup || isRegister;

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!username.trim()) {
      setError("请输入用户名");
      return;
    }
    if (!password) {
      setError("请输入密码");
      return;
    }

    if (needsConfirm) {
      if (isRegister && (username.trim().length < 2 || username.trim().length > 32)) {
        setError("用户名长度需为 2-32 个字符");
        return;
      }
      if (password.length < 6) {
        setError("密码长度至少 6 位");
        return;
      }
      if (password !== confirmPassword) {
        setError("两次输入的密码不一致");
        return;
      }
    }

    setSubmitting(true);
    try {
      const res = isSetup
        ? await gatewayApi.setupAdmin(username.trim(), password)
        : isRegister
          ? await gatewayApi.registerUser(username.trim(), password)
          : await gatewayApi.loginAdmin(username.trim(), password);
      onAuthenticated(res.token, res.user);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 20,
        position: "relative",
      }}
    >
      <div style={{ position: "fixed", top: 16, right: 20 }}>
        <button
          type="button"
          className="btn btn-ghost btn-icon"
          title={theme === "light" ? "切换到深色主题" : "切换到浅色主题"}
          aria-label="切换主题"
          onClick={onToggleTheme}
        >
          {theme === "light" ? <IconMoon /> : <IconSun />}
        </button>
      </div>

      <div className="card" style={{ width: "100%", maxWidth: 380, padding: 28 }}>
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            gap: 10,
            marginBottom: 20,
          }}
        >
          <span
            className="brand-logo"
            style={{ width: 38, height: 38, fontSize: 15, borderRadius: 10 }}
          >
            TT
          </span>
          <div style={{ fontSize: 18, fontWeight: 650, letterSpacing: "-0.02em" }}>
            TalkThatTalk
          </div>
          {isSetup && (
            <div className="muted" style={{ fontSize: 13 }}>
              初始化管理员账号
            </div>
          )}
        </div>

        {initialized && allowRegistration && (
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: 4,
              padding: 4,
              borderRadius: 9,
              background: "var(--surface-subtle)",
              border: "1px solid var(--border)",
              marginBottom: 18,
            }}
          >
            <button
              type="button"
              className={`btn btn-sm ${mode === "login" ? "" : "btn-ghost"}`}
              style={{
                border: "none",
                background: mode === "login" ? "var(--primary)" : "transparent",
                color: mode === "login" ? "var(--primary-fg)" : "var(--muted)",
              }}
              onClick={() => {
                setMode("login");
                setError(null);
              }}
            >
              登录
            </button>
            <button
              type="button"
              className={`btn btn-sm ${mode === "register" ? "" : "btn-ghost"}`}
              style={{
                border: "none",
                background: mode === "register" ? "var(--primary)" : "transparent",
                color: mode === "register" ? "var(--primary-fg)" : "var(--muted)",
              }}
              onClick={() => {
                setMode("register");
                setError(null);
              }}
            >
              注册
            </button>
          </div>
        )}

        {error && (
          <div className="error-banner" style={{ marginBottom: 14 }}>
            {error}
          </div>
        )}

        <form
          onSubmit={(e) => void handleSubmit(e)}
          style={{ display: "flex", flexDirection: "column", gap: 14 }}
        >
          <div className="form-field">
            <label className="form-label">用户名</label>
            <input
              className="input"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder={isRegister ? "2-32 位用户名" : "admin"}
              autoFocus
            />
          </div>

          <div className="form-field">
            <label className="form-label">密码</label>
            <input
              className="input"
              type="password"
              autoComplete={needsConfirm ? "new-password" : "current-password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={needsConfirm ? "至少 6 位密码" : "输入密码"}
            />
          </div>

          {needsConfirm && (
            <div className="form-field">
              <label className="form-label">确认密码</label>
              <input
                className="input"
                type="password"
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="再次输入密码"
              />
            </div>
          )}

          <button
            type="submit"
            className="btn"
            disabled={submitting}
            style={{ width: "100%", marginTop: 4, padding: "9px 14px" }}
          >
            {submitting
              ? isSetup
                ? "创建中..."
                : isRegister
                  ? "注册中..."
                  : "登录中..."
              : isSetup
                ? "创建管理员并登录"
                : isRegister
                  ? "注册并登录"
                  : "登录"}
          </button>
        </form>
      </div>
    </div>
  );
}
