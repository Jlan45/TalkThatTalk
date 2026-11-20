import { useEffect, useState } from "react";
import { BrowserRouter, Link, NavLink, Navigate, Route, Routes } from "react-router-dom";
import { gatewayApi } from "./api/client";
import {
  IconChannels,
  IconDashboard,
  IconGlobe,
  IconKey,
  IconLogs,
  IconMoon,
  IconPlay,
  IconShield,
  IconSun,
  IconUsers,
} from "./components/Icons";
import { DashboardPage } from "./pages/DashboardPage";
import { KeysPage } from "./pages/KeysPage";
import { LoginPage } from "./pages/LoginPage";
import { LogsPage } from "./pages/LogsPage";
import { PlaygroundPage } from "./pages/PlaygroundPage";
import { ProxiesPage } from "./pages/ProxiesPage";
import { UpstreamsPage } from "./pages/UpstreamsPage";
import { UsersPage } from "./pages/UsersPage";
import type { AuthUser } from "./types/gateway";

const ALL_NAV_ITEMS = [
  { path: "/", label: "概览", end: true, adminOnly: false, icon: <IconDashboard width={15} height={15} /> },
  { path: "/upstreams", label: "渠道", end: false, adminOnly: false, icon: <IconChannels width={15} height={15} /> },
  { path: "/proxies", label: "代理", end: false, adminOnly: true, icon: <IconGlobe width={15} height={15} /> },
  { path: "/keys", label: "令牌", end: false, adminOnly: false, icon: <IconKey width={15} height={15} /> },
  { path: "/users", label: "用户", end: false, adminOnly: true, icon: <IconUsers width={15} height={15} /> },
  { path: "/logs", label: "日志", end: false, adminOnly: false, icon: <IconLogs width={15} height={15} /> },
  { path: "/playground", label: "Playground", end: false, adminOnly: false, icon: <IconPlay width={14} height={14} /> },
] as const;

export function App() {
  const [theme, setTheme] = useState<"light" | "dark">(() => {
    const saved = localStorage.getItem("ttt_theme");
    return saved === "dark" ? "dark" : "light";
  });
  const [healthy, setHealthy] = useState<boolean | null>(null);

  // Multi-user auth state
  const [authChecked, setAuthChecked] = useState(false);
  const [authInitialized, setAuthInitialized] = useState(false);
  const [allowRegistration, setAllowRegistration] = useState(true);
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(null);

  // Change password modal state
  const [pwModal, setPwModal] = useState(false);
  const [curPw, setCurPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [confirmNewPw, setConfirmNewPw] = useState("");
  const [pwSaving, setPwSaving] = useState(false);
  const [pwError, setPwError] = useState<string | null>(null);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("ttt_theme", theme);
  }, [theme]);

  const checkAuth = async () => {
    try {
      const st = await gatewayApi.getAuthStatus();
      setAuthInitialized(st.initialized);
      setAllowRegistration(st.allow_registration);
      setCurrentUser(st.authenticated && st.user ? st.user : null);
    } catch {
      setCurrentUser(null);
    } finally {
      setAuthChecked(true);
    }
  };

  useEffect(() => {
    void checkAuth();
    const onUnauth = () => {
      setCurrentUser(null);
      setAuthInitialized(true);
    };
    window.addEventListener("ttt:unauthorized", onUnauth);
    return () => window.removeEventListener("ttt:unauthorized", onUnauth);
  }, []);

  useEffect(() => {
    const check = () =>
      fetch("/healthz")
        .then((r) => setHealthy(r.ok))
        .catch(() => setHealthy(false));
    void check();
    const timer = setInterval(() => void check(), 10000);
    return () => clearInterval(timer);
  }, []);

  const handleAuthenticated = (token: string, user: AuthUser) => {
    localStorage.setItem("ttt_admin_token", token);
    setAuthInitialized(true);
    setCurrentUser(user);
  };

  const handleLogout = async () => {
    try {
      await gatewayApi.logoutAdmin();
    } catch {
      // ignore network error on logout
    }
    localStorage.removeItem("ttt_admin_token");
    setCurrentUser(null);
  };

  const handleChangePassword = async () => {
    setPwError(null);
    if (newPw.length < 6) {
      setPwError("新密码长度至少 6 位");
      return;
    }
    if (newPw !== confirmNewPw) {
      setPwError("两次输入的新密码不一致");
      return;
    }
    setPwSaving(true);
    try {
      const res = await gatewayApi.changeAdminPassword(curPw, newPw);
      localStorage.setItem("ttt_admin_token", res.token);
      setPwModal(false);
      setCurPw("");
      setNewPw("");
      setConfirmNewPw("");
    } catch (e) {
      setPwError((e as Error).message);
    } finally {
      setPwSaving(false);
    }
  };

  if (!authChecked) {
    return (
      <div
        style={{
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}
        className="muted"
      >
        加载中...
      </div>
    );
  }

  if (!currentUser) {
    return (
      <LoginPage
        initialized={authInitialized}
        allowRegistration={allowRegistration}
        theme={theme}
        onToggleTheme={() => setTheme((t) => (t === "light" ? "dark" : "light"))}
        onAuthenticated={handleAuthenticated}
      />
    );
  }

  const isAdmin = currentUser.role === "admin";
  const navItems = ALL_NAV_ITEMS.filter((item) => !item.adminOnly || isAdmin);

  return (
    <BrowserRouter>
      <div className="app-shell">
        <header className="top-header">
          <div className="top-header-inner">
            <div className="top-header-left">
              <Link to="/" className="brand">
                <span className="brand-logo">TT</span>
                <span>TalkThatTalk</span>
              </Link>

              <nav className="top-nav" aria-label="主导航">
                {navItems.map((item) => (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    end={item.end}
                    className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}
                  >
                    {item.icon}
                    <span>{item.label}</span>
                  </NavLink>
                ))}
              </nav>
            </div>

            <div className="top-header-right">
              <span className="status-chip">
                <span className={`status-dot ${healthy === false ? "offline" : ""}`} />
                {healthy === false ? "离线" : "在线"}
              </span>

              <span className="chip" title={isAdmin ? "管理员" : "普通用户"}>
                {currentUser.username}
              </span>

              <button
                className="btn btn-ghost btn-icon"
                title={theme === "light" ? "切换到深色主题" : "切换到浅色主题"}
                aria-label="切换主题"
                onClick={() => setTheme((t) => (t === "light" ? "dark" : "light"))}
              >
                {theme === "light" ? <IconMoon /> : <IconSun />}
              </button>

              <button
                className="btn btn-ghost btn-icon"
                title="修改密码"
                aria-label="修改密码"
                onClick={() => {
                  setPwError(null);
                  setCurPw("");
                  setNewPw("");
                  setConfirmNewPw("");
                  setPwModal(true);
                }}
              >
                <IconShield />
              </button>

              <button
                className="btn btn-ghost btn-sm"
                onClick={() => void handleLogout()}
              >
                退出
              </button>
            </div>
          </div>
        </header>

        <main className="main">
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route
              path="/upstreams"
              element={<UpstreamsPage currentUser={currentUser} />}
            />
            <Route
              path="/proxies"
              element={isAdmin ? <ProxiesPage /> : <Navigate to="/" replace />}
            />
            <Route path="/keys" element={<KeysPage />} />
            <Route
              path="/users"
              element={isAdmin ? <UsersPage currentUser={currentUser} /> : <Navigate to="/" replace />}
            />
            <Route path="/logs" element={<LogsPage />} />
            <Route path="/playground" element={<PlaygroundPage />} />
          </Routes>
        </main>
      </div>

      {pwModal && (
        <div className="modal-backdrop" onClick={() => setPwModal(false)}>
          <div className="modal" style={{ maxWidth: 400 }} onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title">修改密码 · {currentUser.username}</div>
              <button className="btn btn-ghost btn-sm" onClick={() => setPwModal(false)}>
                关闭
              </button>
            </div>
            <div className="modal-body">
              {pwError && <div className="error-banner">{pwError}</div>}
              <div className="form-field">
                <label className="form-label">当前密码</label>
                <input
                  className="input"
                  type="password"
                  value={curPw}
                  onChange={(e) => setCurPw(e.target.value)}
                />
              </div>
              <div className="form-field">
                <label className="form-label">新密码</label>
                <input
                  className="input"
                  type="password"
                  value={newPw}
                  onChange={(e) => setNewPw(e.target.value)}
                  placeholder="至少 6 位"
                />
              </div>
              <div className="form-field">
                <label className="form-label">确认新密码</label>
                <input
                  className="input"
                  type="password"
                  value={confirmNewPw}
                  onChange={(e) => setConfirmNewPw(e.target.value)}
                />
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn btn-ghost" onClick={() => setPwModal(false)}>
                取消
              </button>
              <button
                className="btn"
                disabled={pwSaving}
                onClick={() => void handleChangePassword()}
              >
                {pwSaving ? "保存中..." : "保存"}
              </button>
            </div>
          </div>
        </div>
      )}
    </BrowserRouter>
  );
}
