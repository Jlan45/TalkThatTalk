import { useEffect, useState } from "react";
import { gatewayApi } from "../api/client";
import { IconExternal } from "./Icons";

interface Props {
  upstreamName: string;
  onClose: () => void;
  onSuccess: () => void;
}

export function OAuthLoginModal({ upstreamName, onClose, onSuccess }: Props) {
  const [authUrl, setAuthUrl] = useState("");
  const [state, setState] = useState("");
  const [callbackInput, setCallbackInput] = useState("");
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    gatewayApi
      .startOAuthAuthorize(upstreamName)
      .then((res) => {
        if (!active) return;
        setAuthUrl(res.authorize_url);
        setState(res.state);
      })
      .catch((e) => {
        if (!active) return;
        setError((e as Error).message);
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [upstreamName]);

  const handleSubmit = async () => {
    if (!callbackInput.trim()) {
      setError("请粘贴授权完成后的回调 URL 或 code#state");
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      await gatewayApi.submitOAuthCallback(upstreamName, callbackInput.trim(), state);
      onSuccess();
      onClose();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" style={{ maxWidth: 540 }} onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title">OAuth 2.0 PKCE 授权 · {upstreamName}</div>
          <button className="btn btn-ghost btn-sm" onClick={onClose}>
            关闭
          </button>
        </div>

        <div className="modal-body">
          {error && <div className="error-banner">{error}</div>}
          {loading ? (
            <p className="muted">正在生成 PKCE (S256) 授权链接...</p>
          ) : authUrl && (
            <>
              <div className="form-field">
                <div className="form-label">步骤 1：打开上游授权页面并完成登录</div>
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <input className="input mono" style={{ flex: 1 }} readOnly value={authUrl} />
                  <a
                    className="btn"
                    href={authUrl}
                    target="_blank"
                    rel="noreferrer"
                    style={{ textDecoration: "none" }}
                  >
                    打开授权
                    <IconExternal width={14} height={14} />
                  </a>
                </div>
              </div>

              <div className="form-field">
                <div className="form-label">步骤 2：粘贴回调 URL 或 code#state</div>
                <textarea
                  className="textarea"
                  rows={3}
                  placeholder="粘贴回调 URL 或 code#state"
                  value={callbackInput}
                  onChange={(e) => setCallbackInput(e.target.value)}
                />
              </div>
            </>
          )}
        </div>

        <div className="modal-footer">
          <button className="btn btn-ghost" onClick={onClose}>
            取消
          </button>
          <button
            className="btn"
            disabled={loading || submitting || !authUrl}
            onClick={() => void handleSubmit()}
          >
            {submitting ? "换取 Token 中..." : "完成绑定"}
          </button>
        </div>
      </div>
    </div>
  );
}
