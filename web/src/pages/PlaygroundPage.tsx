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
  incomplete?: boolean;
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
    let upstreamHeader: string | undefined;
    let content = "";
    let reasoning = "";
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    const appendDelta = (delta: { content?: unknown; reasoning_content?: unknown } | undefined, elapsed: number) => {
      let changed = false;
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
      return changed;
    };

    try {
      const res = await gatewayApi.streamPlaygroundChat(
        model,
        nextHistory
          .filter(({ role, content, incomplete }) => role !== "assistant" || (content !== "" && !incomplete))
          .map(({ role, content }) => ({ role, content }))
      );

      const rawUpstreamHeader = res.headers.get("x-ttt-upstream");
      if (rawUpstreamHeader) {
        try {
          upstreamHeader = decodeURIComponent(rawUpstreamHeader);
        } catch {
          upstreamHeader = rawUpstreamHeader;
        }
      }
      const decoder = new TextDecoder();
      let buf = "";
      let eventType = "";
      let dataLines: string[] = [];
      let completed = false;
      if (res.headers.get("content-type")?.split(";")[0].trim().toLowerCase() === "application/json") {
        const payload = await res.json();
        if (payload?.error) throw new Error(payload.error.message ?? "上游响应失败");
        const message = payload?.choices?.[0]?.message;
        if (!message) throw new Error("上游未返回有效的回答");
        firstByteMs = Math.round(performance.now() - startedAt);
        appendDelta(message, firstByteMs);
        completed = true;
      } else {
        reader = res.body?.getReader();
        if (!reader) throw new Error("Empty response stream");
      }

      while (reader) {
        const { done, value } = await reader.read();
        const elapsed = Math.round(performance.now() - startedAt);
        let changed = false;
        if (firstByteMs === undefined && value?.byteLength) {
          firstByteMs = elapsed;
          changed = true;
        }
        buf += decoder.decode(value, { stream: !done });
        const endings = /\r\n|\r|\n/g;
        let start = 0;
        for (const ending of buf.matchAll(endings)) {
          const end = ending.index;
          if (!done && ending[0] === "\r" && end + 1 === buf.length) break;
          const line = buf.slice(start, end);
          start = end + ending[0].length;
          if (line !== "") {
            const colon = line.indexOf(":");
            const name = colon < 0 ? line : line.slice(0, colon);
            const field = colon < 0 ? "" : line.slice(colon + 1).replace(/^ /, "");
            if (name === "data") dataLines.push(field);
            else if (name === "event") eventType = field;
            continue;
          }

          const event = eventType;
          const payload = dataLines.join("\n").trim();
          eventType = "";
          dataLines = [];
          if (event === "ping" || (!payload && event !== "error")) continue;
          if (payload === "[DONE]") {
            completed = true;
            break;
          }
          const parsed = payload ? JSON.parse(payload) : null;
          if (event === "error" || parsed?.error) {
            throw new Error(parsed?.error?.message ?? parsed?.message ?? "上游流式响应失败");
          }
          const choice = parsed?.choices?.[0];
          if (appendDelta(choice?.delta, elapsed)) changed = true;
          if (typeof choice?.finish_reason === "string") completed = true;
        }
        buf = buf.slice(start);

        if (changed) {
          const update = { content, reasoning, firstByteMs, ttftMs, firstAnswerMs, upstream: upstreamHeader };
          setMessages((prev) => prev.map((m) => m.id === assistantId ? { ...m, ...update } : m));
        }
        if (done) break;
      }
      if (!completed) throw new Error("流式响应提前结束，已保留收到的内容");

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
      void reader?.cancel().catch(() => {});
      setError((e as Error).message);
      const durationMs = Math.round(performance.now() - startedAt);
      setMessages((prev) => prev
        .filter((m) => m.id !== assistantId || content || reasoning)
        .map((m) => m.id === assistantId ? {
          ...m, content, reasoning, firstByteMs, ttftMs, firstAnswerMs, durationMs,
          upstream: upstreamHeader, streaming: false, incomplete: true,
        } : m));
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
              在下方选择模型发起流式请求，查看浏览器收到首段输出的耗时和命中渠道。
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
                {m.ttftMs !== undefined && <span className="chip chip-ok" title="浏览器发起请求到首段推理或正文">首段输出 {m.ttftMs} ms</span>}
                {m.reasoning && m.firstAnswerMs !== undefined && m.firstAnswerMs !== m.ttftMs && (
                  <span className="chip">首正文 {m.firstAnswerMs} ms</span>
                )}
                {m.durationMs !== undefined && <span className="chip">总耗时 {m.durationMs} ms</span>}
                {m.streaming && <span className="chip chip-warn">生成中</span>}
                {m.incomplete && <span className="chip chip-warn">响应中断</span>}
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
