import { useEffect, useState } from "react";
import { gatewayApi } from "../api/client";
import { IconPlay } from "../components/Icons";

interface ChatTurn {
  id: string;
  role: "user" | "assistant";
  content: string;
  reasoning?: string;
  model?: string;
  upstream?: string;
  firstByteMs?: number;
  ttftMs?: number;
  firstAnswerMs?: number;
  durationMs?: number;
  streaming?: boolean;
}

export function PlaygroundPage() {
  const [models, setModels] = useState<string[]>([]);
  const [selectedModel, setSelectedModel] = useState("");
  const [loadingModels, setLoadingModels] = useState(true);
  const [modelError, setModelError] = useState<string | null>(null);
  const [prompt, setPrompt] = useState("");
  const [messages, setMessages] = useState<ChatTurn[]>([]);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const model = models.includes(selectedModel) ? selectedModel : models[0] ?? "";

  useEffect(() => {
    const controller = new AbortController();
    gatewayApi.listPlaygroundModels(controller.signal)
      .then(({ data }) => {
        if (!controller.signal.aborted) setModels(data.map(({ id }) => id));
      })
      .catch((err) => {
        if (!controller.signal.aborted) setModelError((err as Error).message);
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoadingModels(false);
      });
    return () => controller.abort();
  }, []);

  const handleSend = async () => {
    const text = prompt.trim();
    if (!text || sending || loadingModels || !model) return;

    setError(null);
    setPrompt("");
    const userTurn: ChatTurn = { id: `u-${Date.now()}`, role: "user", content: text };
    const assistantId = `a-${Date.now()}`;
    const assistantTurn: ChatTurn = {
      id: assistantId,
      role: "assistant",
      content: "",
      model,
      streaming: true,
    };

    const nextHistory = [...messages, userTurn];
    setMessages([...nextHistory, assistantTurn]);
    setSending(true);

    const startedAt = performance.now();
    let firstByteMs: number | undefined;
    let ttftMs: number | undefined;
    let firstAnswerMs: number | undefined;

    try {
      const res = await gatewayApi.streamPlaygroundChat(
        model,
        nextHistory
          .filter(({ role, content }) => role !== "assistant" || content !== "")
          .map(({ role, content }) => ({ role, content }))
      );

      const rawUpstreamHeader = res.headers.get("x-ttt-upstream");
      let upstreamHeader: string | undefined;
      if (rawUpstreamHeader) {
        try {
          upstreamHeader = decodeURIComponent(rawUpstreamHeader);
        } catch {
          upstreamHeader = rawUpstreamHeader;
        }
      }
      const reader = res.body?.getReader();
      if (!reader) throw new Error("Empty response stream");

      const decoder = new TextDecoder();
      let buf = "";
      let content = "";
      let reasoning = "";

      while (true) {
        const { done, value } = await reader.read();
        const elapsed = Math.round(performance.now() - startedAt);
        let changed = false;
        if (firstByteMs === undefined && value?.byteLength) {
          firstByteMs = elapsed;
          changed = true;
        }
        buf += decoder.decode(value, { stream: !done });
        const lines = buf.split("\n");
        buf = lines.pop() ?? "";
        if (done && buf) lines.push(buf);

        for (const rawLine of lines) {
          const line = rawLine.trim();
          if (!line.startsWith("data:")) continue;
          const payload = line.slice(5).trim();
          if (payload === "[DONE]") continue;
          try {
            const parsed = JSON.parse(payload);
            const delta = parsed?.choices?.[0]?.delta;
            if (typeof delta?.reasoning_content === "string" && delta.reasoning_content) {
              ttftMs ??= elapsed;
              reasoning += delta.reasoning_content;
              changed = true;
            }
            if (typeof delta?.content === "string" && delta.content) {
              ttftMs ??= elapsed;
              firstAnswerMs ??= elapsed;
              content += delta.content;
              changed = true;
            }
          } catch {
            // ignore non-JSON SSE keepalive lines
          }
        }

        if (changed) {
          const update = { content, reasoning, firstByteMs, ttftMs, firstAnswerMs, upstream: upstreamHeader };
          setMessages((prev) => prev.map((m) => m.id === assistantId ? { ...m, ...update } : m));
        }
        if (done) break;
      }

      const durationMs = Math.round(performance.now() - startedAt);
      setMessages((prev) =>
        prev.map((m) =>
          m.id === assistantId
            ? {
                ...m,
                content,
                reasoning,
                firstByteMs,
                ttftMs,
                firstAnswerMs,
                durationMs,
                upstream: upstreamHeader,
                streaming: false,
              }
            : m
        )
      );
    } catch (e) {
      setError((e as Error).message);
      setMessages((prev) => prev.filter((m) => m.id !== assistantId));
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="playground-shell">
      <div className="page-header" style={{ marginBottom: 14 }}>
        <h1 className="page-title">Playground</h1>
        <div className="actions-row">
          <button className="btn btn-ghost btn-sm" onClick={() => setMessages([])}>
            清空对话
          </button>
        </div>
      </div>

      {modelError ? (
        <div className="error-banner">{modelError}</div>
      ) : !loadingModels && models.length === 0 ? (
        <div className="muted">当前账号没有可用模型。请检查渠道和模型权限。</div>
      ) : null}
      {error && <div className="error-banner">{error}</div>}

      <div className="chat-stream">
        {messages.length === 0 && (
          <div
            className="card"
            style={{ margin: "auto", maxWidth: 460, textAlign: "center", padding: 28 }}
          >
            <div style={{ fontWeight: 600, marginBottom: 6 }}>TalkThatTalk Live Sandbox</div>
            <p className="muted">
              在下方 Prompt Bar 选择任意模型发起流式请求，实时观测首字延迟（TTFT）与命中渠道。
            </p>
          </div>
        )}

        {messages.map((m) => (
          <div className={`chat-item ${m.role}`} key={m.id}>
            {m.role === "assistant" && (
              <div className="trace-row">
                <span className="chip">{m.model}</span>
                {m.upstream && <span className="chip chip-blue">{m.upstream}</span>}
                {m.firstByteMs !== undefined && <span className="chip">首包 {m.firstByteMs} ms</span>}
                {m.ttftMs !== undefined && <span className="chip chip-ok" title="首段推理或正文">TTFT {m.ttftMs} ms</span>}
                {m.reasoning && m.firstAnswerMs !== undefined && m.firstAnswerMs !== m.ttftMs && (
                  <span className="chip">首正文 {m.firstAnswerMs} ms</span>
                )}
                {m.durationMs !== undefined && <span className="chip">总耗时 {m.durationMs} ms</span>}
                {m.streaming && <span className="chip chip-warn">生成中</span>}
              </div>
            )}
            {m.reasoning && (
              <details className="chat-reasoning" open={m.streaming}>
                <summary>推理过程</summary>
                <div className="chat-reasoning-stream"><div>{m.reasoning}</div></div>
              </details>
            )}
            {(m.content || !m.reasoning || !m.streaming) && (
              <div className="chat-bubble">{m.content || (m.streaming ? "等待输出…" : "未收到正文")}</div>
            )}
          </div>
        ))}
      </div>

      <div className="prompt-bar">
        <textarea
          className="prompt-input"
          placeholder="输入测试消息，按 Ctrl/Cmd + Enter 发送..."
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
          onKeyDown={(e) => {
            if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
              void handleSend();
            }
          }}
        />
        <div className="prompt-bar-footer">
          <div className="actions-row">
            <select
              className="select mono"
              aria-label="模型"
              value={model}
              disabled={loadingModels || models.length === 0}
              onChange={(e) => setSelectedModel(e.target.value)}
            >
              {models.length === 0 && <option value="">{loadingModels ? "正在加载模型…" : "无可用模型"}</option>}
              {models.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
            <span className="chip">SSE Stream</span>
          </div>
          <button className="btn" disabled={sending || loadingModels || !model || !prompt.trim()} onClick={() => void handleSend()}>
            <IconPlay width={13} height={13} />
            {sending ? "生成中..." : "发送"}
          </button>
        </div>
      </div>
    </div>
  );
}
