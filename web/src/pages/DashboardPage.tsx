import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { gatewayApi } from "../api/client";
import { IconRefresh } from "../components/Icons";
import type { GatewayStatsSnapshot } from "../types/gateway";

function formatNumber(n: number): string {
  return n.toLocaleString("en-US");
}

function formatUptime(secs: number): string {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export function DashboardPage() {
  const [stats, setStats] = useState<GatewayStatsSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    try {
      setStats(await gatewayApi.getStats());
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  useEffect(() => {
    void load();
    const timer = setInterval(() => void load(), 5000);
    return () => clearInterval(timer);
  }, []);

  const successRate =
    stats && stats.total_requests > 0
      ? ((stats.success_requests / stats.total_requests) * 100).toFixed(1)
      : "100.0";

  const upstreamEntries = Object.entries(stats?.by_upstream ?? {}).sort(
    (a, b) => b[1].requests - a[1].requests
  );
  const maxUpstreamReq = Math.max(1, ...upstreamEntries.map(([, v]) => v.requests));

  const modelEntries = Object.entries(stats?.by_model ?? {}).sort((a, b) => b[1] - a[1]);
  const maxModelReq = Math.max(1, ...modelEntries.map(([, v]) => v));

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">数据看板</h1>
        <div className="actions-row">
          <Link to="/playground" className="btn btn-ghost">
            打开 Playground
          </Link>
          <button className="btn" onClick={() => void load()}>
            <IconRefresh width={14} height={14} />
            刷新
          </button>
        </div>
      </div>

      {error && <div className="error-banner">{error}</div>}

      <div className="kpi-grid">
        <div className="card card-accent">
          <div className="kpi-head">
            <div className="kpi-label" style={{ marginBottom: 0 }}>总请求数</div>
          </div>
          <div className="kpi-value">{stats ? formatNumber(stats.total_requests) : "—"}</div>
          <div className="kpi-sub">
            成功率 {successRate}% · 错误 {stats?.error_requests ?? 0}
          </div>
        </div>

        <div className="card card-accent card-accent-ok">
          <div className="kpi-head">
            <div className="kpi-label" style={{ marginBottom: 0 }} title="上游请求体发送完成到收到首个非空响应数据块">
              平均上游首包延迟 (TTFT)
            </div>
          </div>
          <div className="kpi-value" style={{ color: "var(--ok)" }}>
            {stats?.ttft_sample_count ? `${stats.avg_ttft_ms} ms` : "—"}
          </div>
        </div>

        <div className="card card-accent card-accent-blue">
          <div className="kpi-head">
            <div className="kpi-label" style={{ marginBottom: 0 }}>总 Token 消耗</div>
          </div>
          <div className="kpi-value" style={{ color: "var(--accent)" }}>
            {stats ? formatNumber(stats.total_tokens) : "—"}
          </div>
          <div className="kpi-sub">
            输入 {formatNumber(stats?.total_input_tokens ?? 0)} / 输出{" "}
            {formatNumber(stats?.total_output_tokens ?? 0)}
          </div>
        </div>

        <div className="card card-accent card-accent-purple">
          <div className="kpi-head">
            <div className="kpi-label" style={{ marginBottom: 0 }}>Prompt 缓存命中率</div>
          </div>
          <div className="kpi-value" style={{ color: "var(--ok)" }}>
            {stats ? `${stats.cache_hit_rate.toFixed(1)}%` : "—"}
          </div>
          <div className="kpi-sub">
            命中 {formatNumber(stats?.total_cache_read_tokens ?? 0)} · 请求命中{" "}
            {stats ? `${stats.cache_request_hit_rate.toFixed(1)}%` : "0.0%"}
            {(stats?.total_cache_write_tokens ?? 0) > 0
              ? ` · 写入 ${formatNumber(stats?.total_cache_write_tokens ?? 0)}`
              : ""}
          </div>
        </div>

        <div className="card card-accent">
          <div className="kpi-head">
            <div className="kpi-label" style={{ marginBottom: 0 }}>网关运行时间</div>
          </div>
          <div className="kpi-value">{stats ? formatUptime(stats.uptime_secs) : "—"}</div>
        </div>
      </div>

      <div className="two-col">
        <div className="card">
          <div className="card-header">
            <div className="card-title">上游渠道分布</div>
            <Link to="/upstreams" className="muted" style={{ textDecoration: "none" }}>
              管理渠道 →
            </Link>
          </div>
          {upstreamEntries.length === 0 ? (
            <p className="muted">暂无流量记录，前往 Playground 发一条测试请求试试。</p>
          ) : (
            upstreamEntries.map(([name, item]) => (
              <div className="bar-row" key={name}>
                <div className="bar-meta">
                  <span className="mono">{name}</span>
                  <span className="muted tabular">
                    {item.requests} reqs · {formatNumber(item.total_tokens)} tok
                    {item.input_tokens > 0 ? ` · 缓存 ${item.cache_hit_rate.toFixed(1)}%` : ""}
                  </span>
                </div>
                <div className="bar-track">
                  <div
                    className="bar-fill"
                    style={{ width: `${Math.round((item.requests / maxUpstreamReq) * 100)}%` }}
                  />
                </div>
              </div>
            ))
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">模型调用排行</div>
            <span className="muted">{modelEntries.length} 个模型</span>
          </div>
          {modelEntries.length === 0 ? (
            <p className="muted">暂无模型调用数据。</p>
          ) : (
            modelEntries.slice(0, 6).map(([model, count]) => (
              <div className="bar-row" key={model}>
                <div className="bar-meta">
                  <span className="mono">{model}</span>
                  <span className="muted tabular">{count} 次</span>
                </div>
                <div className="bar-track">
                  <div
                    className="bar-fill"
                    style={{ width: `${Math.round((count / maxModelReq) * 100)}%` }}
                  />
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      <div className="card card-flush">
        <div className="card-header" style={{ padding: "16px 20px 0" }}>
          <div className="card-title">最近请求 Trace</div>
          <Link to="/logs" className="muted" style={{ textDecoration: "none" }}>
            查看全部 →
          </Link>
        </div>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>请求 ID</th>
                <th>模型</th>
                <th>命中渠道</th>
                <th>状态</th>
                <th>TTFT</th>
                <th>总耗时</th>
                <th>Tokens</th>
                <th>缓存命中</th>
              </tr>
            </thead>
            <tbody>
              {(stats?.recent_requests ?? []).slice(0, 6).map((row) => {
                const rowHitPct =
                  row.input_tokens > 0 && row.cache_read_tokens > 0
                    ? `${Math.min(100, (row.cache_read_tokens / row.input_tokens) * 100).toFixed(1)}%`
                    : null;
                return (
                  <tr key={row.req_id}>
                    <td className="mono">{row.req_id}</td>
                    <td>
                      <span className="tag">{row.model ?? "-"}</span>
                    </td>
                    <td className="mono">{row.upstream}</td>
                    <td>
                      <span
                        className={`chip ${
                          row.status < 300 ? "chip-ok" : row.status < 500 ? "chip-warn" : "chip-err"
                        }`}
                      >
                        {row.status}
                      </span>
                    </td>
                    <td className="tabular">{row.ttft_measured ? `${row.ttft_ms} ms` : "—"}</td>
                    <td className="tabular">{row.duration_ms} ms</td>
                    <td className="tabular muted">
                      {row.input_tokens} / {row.output_tokens}
                    </td>
                    <td className="tabular">
                      {rowHitPct ? (
                        <span className="chip chip-ok">
                          {formatNumber(row.cache_read_tokens)} ({rowHitPct})
                        </span>
                      ) : (
                        <span className="muted">—</span>
                      )}
                    </td>
                  </tr>
                );
              })}
              {(!stats || stats.recent_requests.length === 0) && (
                <tr>
                  <td colSpan={8} className="muted" style={{ textAlign: "center", padding: 28 }}>
                    尚无请求记录
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
