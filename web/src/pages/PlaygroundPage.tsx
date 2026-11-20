import { useEffect, useState } from "react";
import { IconPlay } from "../components/Icons";

interface ChatTurn {
  id: string;
  role: "user" | "assistant";
  content: string;
  model?: string;
  upstream?: string;
  ttftMs?: number;
  durationMs?: number;
  streaming?: boolean;
}

export function PlaygroundPage() {
  const [models, setModels] = useState<string[]>([]);
  const [selectedModel, setSelectedModel] = useState("gpt-4o");
  const [clientKey, setClientKey] = useState("");
  const [prompt, setPrompt] = useState("");
  const [messages, setMessages] = useState<ChatTurn[]>([]);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/v1/models")
      .then((r) => r.json())
      .then((data) => {
        const list: string[] = (data?.data ?? []).map((m: { id: string }) => m.id);
        setModels(list);
        if (list.length > 0) setSelectedModel(list[0]);
      })
      .catch(() => {});
  }, []);

  const handleSend = async () => {
    const text = prompt.trim();
    if (!text || sending) return;

    setError(null);
    setPrompt("");
    const userTurn: ChatTurn = { id: `u-${Date.now()}`, role: "user", content: text };
    const assistantId = `a-${Date.now()}`;
    const assistantTurn: ChatTurn = {
      id: assistantId,
      role: "assistant",
      content: "",
      model: selectedModel,
      streaming: true,
    };

    const nextHistory = [...messages, userTurn];
    setMessages([...nextHistory, assistantTurn]);
    setSending(true);

    const startedAt = performance.now();
    let ttftMs: number | undefined;

    try {
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (clientKey.trim()) {
        headers["Authorization"] = `Bearer ${clientKey.trim()}`;
      }

      const res = await fetch("/v1/chat/completions", {
        method: "POST",
        headers,
        body: JSON.stringify({
          model: selectedModel,
          stream: true,
          messages: nextHistory.map((m) => ({ role: m.role, content: m.content })),
        }),
      });

      const rawUpstreamHeader = res.headers.get("x-ttt-upstream");
      let upstreamHeader: string | undefined;
      if (rawUpstreamHeader) {
        try {
          upstreamHeader = decodeURIComponent(rawUpstreamHeader);
        } catch {
          upstreamHeader = rawUpstreamHeader;
        }
      }
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`HTTP ${res.status}: ${errText}`);
      }

      const reader = res.body?.getReader();
      if (!reader) throw new Error("Empty response stream");

      const decoder = new TextDecoder();
      let buf = "";
      let acc = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });

        let nl = buf.indexOf("\n");
        while (nl !== -1) {
          const line = buf.slice(0, nl).trim();
          buf = buf.slice(nl + 1);
          nl = buf.indexOf("\n");

          if (!line.startsWith("data:")) continue;
          const payload = line.slice(5).trim();
          if (payload === "[DONE]") continue;
          try {
            const parsed = JSON.parse(payload);
            const delta = parsed?.choices?.[0]?.delta?.content;
            if (typeof delta === "string" && delta.length > 0) {
              if (ttftMs === undefined) {
                ttftMs = Math.round(performance.now() - startedAt);
              }
              acc += delta;
              setMessages((prev) =>
                prev.map((m) =>
                  m.id === assistantId
                    ? { ...m, content: acc, ttftMs, upstream: upstreamHeader }
                    : m
                )
              );
            }
          } catch {
            // ignore non-JSON SSE keepalive lines
          }
        }
      }

      const durationMs = Math.round(performance.now() - startedAt);
      setMessages((prev) =>
        prev.map((m) =>
          m.id === assistantId
            ? {
                ...m,
                content: acc || "(empty response)",
                ttftMs,
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
          <input
            className="input mono"
            style={{ width: 220 }}
            type="password"
            placeholder="网关 Client Key（如已开启鉴权）"
            value={clientKey}
            onChange={(e) => setClientKey(e.target.value)}
          />
          <button className="btn btn-ghost btn-sm" onClick={() => setMessages([])}>
            清空对话
          </button>
        </div>
      </div>

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
                {m.ttftMs !== undefined && <span className="chip chip-ok">TTFT {m.ttftMs} ms</span>}
                {m.durationMs !== undefined && <span className="chip">{m.durationMs} ms</span>}
                {m.streaming && <span className="chip chip-warn">Streaming...</span>}
              </div>
            )}
            <div className="chat-bubble">{m.content || (m.streaming ? "Thinking..." : "")}</div>
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
              value={selectedModel}
              onChange={(e) => setSelectedModel(e.target.value)}
            >
              {models.length === 0 && <option value="gpt-4o">gpt-4o</option>}
              {models.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
            <span className="chip">SSE Stream</span>
          </div>
          <button className="btn" disabled={sending || !prompt.trim()} onClick={() => void handleSend()}>
            <IconPlay width={13} height={13} />
            {sending ? "生成中..." : "发送"}
          </button>
        </div>
      </div>
    </div>
  );
}
