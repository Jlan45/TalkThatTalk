import { useEffect, useMemo, useState } from "react";
import { gatewayApi } from "../api/client";
import { IconRefresh } from "../components/Icons";
import { RequestStatus } from "../components/RequestStatus";
import { formatCacheHitRate } from "../format";
import type { ActiveRequest, ActiveRequestsSnapshot, RequestLogEntry } from "../types/gateway";

function formatTime(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString();
}

function matchesQuery(row: ActiveRequest | RequestLogEntry, query: string): boolean {
  return (
    !query ||
    row.req_id.toLowerCase().includes(query) ||
    (row.username ?? "").toLowerCase().includes(query) ||
    (row.user_id == null ? "" : `#${row.user_id}`).includes(query) ||
    row.upstream.toLowerCase().includes(query) ||
    (row.model ?? "").toLowerCase().includes(query) ||
    row.path.toLowerCase().includes(query)
  );
}

function ActiveRequests({ query, refresh }: { query: string; refresh: number }) {
  const [snapshot, setSnapshot] = useState<ActiveRequestsSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    let timer: number | undefined;
    let loading = false;
    const poll = async () => {
      if (loading || document.hidden) return;
      loading = true;
      window.clearTimeout(timer);
      try {
        const next = await gatewayApi.getActiveRequests(controller.signal);
        if (controller.signal.aborted) return;
        setSnapshot(next);
        setError(null);
      } catch (e) {
        if (controller.signal.aborted) return;
        setError((e as Error).message);
      } finally {
        loading = false;
        if (!controller.signal.aborted && !document.hidden) {
          timer = window.setTimeout(() => void poll(), 1000);
        }
      }
    };

    const onVisibilityChange = () => {
      if (document.hidden) window.clearTimeout(timer);
      else void poll();
    };
    document.addEventListener("visibilitychange", onVisibilityChange);
    void poll();
    return () => {
      controller.abort();
      window.clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisibilityChange);
    };
  }, [refresh]);

  const requests = snapshot?.requests ?? [];
  const filtered = requests.filter((row) => matchesQuery(row, query));

  return (
    <section className="card card-flush" style={{ marginBottom: 16 }} aria-labelledby="active-requests-title">
      <div className="card-header" style={{ padding: "12px 16px" }}>
        <h2 className="card-title" id="active-requests-title">正在处理</h2>
        {snapshot && (
          <span className="muted">
            {snapshot.total} 条
            {snapshot.total > requests.length && `，显示最新 ${requests.length} 条`}
          </span>
        )}
      </div>
      {error && <div className="error-banner">实时请求刷新失败 · {error}</div>}
      <div className="table-wrap">
        <table className="table" aria-labelledby="active-requests-title">
          <thead>
            <tr>
              <th>请求 ID</th>
              <th>调用用户</th>
              <th>模型</th>
              <th>渠道</th>
              <th>路径</th>
              <th>状态</th>
              <th>已耗时</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((row) => (
              <tr key={row.req_id}>
                <td className="mono">{row.req_id}</td>
                <td>{row.username ?? (row.user_id == null ? "—" : `#${row.user_id}`)}</td>
                <td>
                  <span className="tag">{row.model ?? "—"}</span>
                </td>
                <td className="mono">{row.upstream}</td>
                <td className="mono muted">{row.path}</td>
                <td>
                  <span className="chip chip-blue">
                    {row.is_stream == null ? "等待响应" : row.is_stream ? "流式响应中" : "响应中"}
                  </span>
                </td>
                <td className="tabular">{(row.elapsed_ms / 1000).toFixed(1)} s</td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={7} className="muted" style={{ textAlign: "center", padding: 24 }}>
                  {snapshot
                    ? (query ? "暂无匹配的进行中请求" : "暂无正在处理的请求")
                    : (error ? "实时请求暂不可用" : "正在加载…")}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export function LogsPage() {
  const [logs, setLogs] = useState<RequestLogEntry[]>([]);
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [error, setError] = useState<string | null>(null);
  const [activeRefresh, setActiveRefresh] = useState(0);
  const normalizedQuery = query.trim().toLowerCase();

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
    return logs.filter((row) => {
      const success = row.status >= 200 && row.status < 400 && !row.stream_failure;
      if (statusFilter === "ok" && !success) return false;
      if (statusFilter === "err" && success) return false;
      return matchesQuery(row, normalizedQuery);
    });
  }, [logs, normalizedQuery, statusFilter]);

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">调用日志</h1>
        <button className="btn btn-ghost" onClick={() => {
          void load();
          setActiveRefresh((current) => current + 1);
        }}>
          <IconRefresh width={14} height={14} />
          刷新
        </button>
      </div>

      {error && <div className="error-banner">{error}</div>}

      <div className="toolbar">
        <input
          className="input"
          style={{ width: 300 }}
          placeholder="搜索用户、请求 ID、模型、渠道或路径..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </div>

      <ActiveRequests query={normalizedQuery} refresh={activeRefresh} />

      <div className="toolbar">
        <h2 className="card-title">已完成</h2>
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
                <th>调用用户</th>
                <th>模型</th>
                <th>渠道</th>
                <th>路径</th>
                <th>状态</th>
                <th>响应类型</th>
                <th title="上游请求体发送完成到收到首个非空响应数据块">TTFT</th>
                <th>总耗时</th>
                <th>Tokens (入/出/总)</th>
                <th>缓存命中</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((row) => {
                const hitPct =
                  row.input_tokens > 0 && row.cache_read_tokens > 0
                    ? formatCacheHitRate((row.cache_read_tokens / row.input_tokens) * 100)
                    : null;
                return (
                  <tr key={row.req_id}>
                    <td className="tabular muted">{formatTime(row.timestamp_secs)}</td>
                    <td className="mono">{row.req_id}</td>
                    <td>{row.username ?? (row.user_id == null ? "—" : `#${row.user_id}`)}</td>
                    <td>
                      <span className="tag">{row.model ?? "-"}</span>
                    </td>
                    <td className="mono">{row.upstream}</td>
                    <td className="mono muted">{row.path}</td>
                    <td><RequestStatus row={row} /></td>
                    <td>
                      {row.is_stream == null ? (
                        <span className="muted">未知</span>
                      ) : row.is_stream ? (
                        "流式"
                      ) : (
                        "非流式"
                      )}
                    </td>
                    <td className="tabular">{row.ttft_measured ? `${row.ttft_ms} ms` : "—"}</td>
                    <td className="tabular">{row.duration_ms} ms</td>
                    <td className="tabular muted">
                      {row.input_tokens} / {row.output_tokens} / <strong>{row.total_tokens}</strong>
                    </td>
                    <td className="tabular">
                      {hitPct ? (
                        <span className="chip chip-ok" title={`命中 ${row.cache_read_tokens.toLocaleString("en-US")} / ${row.input_tokens.toLocaleString("en-US")} 个输入 token`}>
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
                  <td colSpan={12} className="muted" style={{ textAlign: "center", padding: 32 }}>
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
