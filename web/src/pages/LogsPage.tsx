import { useEffect, useMemo, useState } from "react";
import { gatewayApi } from "../api/client";
import { IconRefresh } from "../components/Icons";
import type { RequestLogEntry } from "../types/gateway";

function formatTime(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString();
}

export function LogsPage() {
  const [logs, setLogs] = useState<RequestLogEntry[]>([]);
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    try {
      const snap = await gatewayApi.getStats();
      setLogs(snap.recent_requests);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  useEffect(() => {
    void load();
    const timer = setInterval(() => void load(), 3000);
    return () => clearInterval(timer);
  }, []);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return logs.filter((row) => {
      if (statusFilter === "ok" && (row.status < 200 || row.status >= 400)) return false;
      if (statusFilter === "err" && row.status < 400) return false;
      if (!q) return true;
      return (
        row.req_id.toLowerCase().includes(q) ||
        row.upstream.toLowerCase().includes(q) ||
        (row.model ?? "").toLowerCase().includes(q) ||
        row.path.toLowerCase().includes(q)
      );
    });
  }, [logs, query, statusFilter]);

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">调用日志</h1>
        <button className="btn btn-ghost" onClick={() => void load()}>
          <IconRefresh width={14} height={14} />
          刷新
        </button>
      </div>

      {error && <div className="error-banner">{error}</div>}

      <div className="toolbar">
        <input
          className="input"
          style={{ width: 260 }}
          placeholder="搜索请求 ID、模型、渠道或路径..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <select
          className="select"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
        >
          <option value="all">全部状态</option>
          <option value="ok">成功 (2xx/3xx)</option>
          <option value="err">错误 (4xx/5xx)</option>
        </select>
        <span className="muted" style={{ marginLeft: "auto" }}>
          最近 {filtered.length} 条
        </span>
      </div>

      <div className="card card-flush">
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>时间</th>
                <th>请求 ID</th>
                <th>模型</th>
                <th>渠道</th>
                <th>路径</th>
                <th>状态</th>
                <th>TTFT</th>
                <th>总耗时</th>
                <th>Tokens (入/出/总)</th>
                <th>缓存命中</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((row) => {
                const hitPct =
                  row.input_tokens > 0 && row.cache_read_tokens > 0
                    ? `${Math.min(100, (row.cache_read_tokens / row.input_tokens) * 100).toFixed(1)}%`
                    : null;
                return (
                  <tr key={row.req_id}>
                    <td className="tabular muted">{formatTime(row.timestamp_secs)}</td>
                    <td className="mono">{row.req_id}</td>
                    <td>
                      <span className="tag">{row.model ?? "-"}</span>
                    </td>
                    <td className="mono">{row.upstream}</td>
                    <td className="mono muted">{row.path}</td>
                    <td>
                      <span
                        className={`chip ${
                          row.status < 300 ? "chip-ok" : row.status < 500 ? "chip-warn" : "chip-err"
                        }`}
                      >
                        {row.status}
                      </span>
                    </td>
                    <td className="tabular">{row.ttft_ms} ms</td>
                    <td className="tabular">{row.duration_ms} ms</td>
                    <td className="tabular muted">
                      {row.input_tokens} / {row.output_tokens} / <strong>{row.total_tokens}</strong>
                    </td>
                    <td className="tabular">
                      {hitPct ? (
                        <span className="chip chip-ok">
                          {row.cache_read_tokens.toLocaleString("en-US")} ({hitPct})
                        </span>
                      ) : row.cache_write_tokens > 0 ? (
                        <span className="chip chip-warn">
                          写 {row.cache_write_tokens.toLocaleString("en-US")}
                        </span>
                      ) : (
                        <span className="muted">—</span>
                      )}
                    </td>
                  </tr>
                );
              })}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={10} className="muted" style={{ textAlign: "center", padding: 32 }}>
                    暂无匹配的调用日志
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
