import type { RequestLogEntry } from "../types/gateway";

const streamFailureLabels = {
  incomplete: "流式响应不完整",
  upstream_error: "上游流错误",
  client_disconnected: "客户端断开",
};

export function RequestStatus({ row }: { row: RequestLogEntry }) {
  const failure = row.stream_failure;
  const tone = failure ? "err" : row.status < 300 ? "ok" : row.status < 500 ? "warn" : "err";
  return (
    <span className={`chip chip-${tone}`}>
      {row.status}{failure ? ` · ${streamFailureLabels[failure]}` : ""}
    </span>
  );
}
