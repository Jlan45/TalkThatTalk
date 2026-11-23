import { useState } from "react";
import { gatewayApi } from "../api/client";
import type { ProxyImportResult } from "../types/gateway";

export function ProxySubscriptionModal({
  onClose,
  onImported,
}: {
  onClose: () => void;
  onImported: () => Promise<void>;
}) {
  const [url, setUrl] = useState("");
  const [importing, setImporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ProxyImportResult | null>(null);

  const submit = async () => {
    setImporting(true);
    setError(null);
    setResult(null);
    try {
      const response = await gatewayApi.importProxySubscription(url.trim());
      setResult(response);
      setUrl("");
      await onImported();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setImporting(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={() => !importing && onClose()}>
      <form
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="proxy-subscription-title"
        onClick={(event) => event.stopPropagation()}
        onSubmit={(event) => {
          event.preventDefault();
          if (!importing && url.trim()) void submit();
        }}
      >
        <div className="modal-header">
          <div className="modal-title" id="proxy-subscription-title">导入 Clash 订阅</div>
          <button type="button" className="btn btn-ghost btn-sm" disabled={importing} onClick={onClose}>
            关闭
          </button>
        </div>
        <div className="modal-body">
          <div className="form-field">
            <label className="form-label" htmlFor="proxy-subscription-url">订阅地址</label>
            <input
              id="proxy-subscription-url"
              className="input mono"
              type="password"
              placeholder="https://..."
              autoComplete="off"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              disabled={importing}
              required
            />
          </div>
          {error && <div className="error-banner" role="alert">{error}</div>}
          {result && (
            <p role="status">
              已导入 {result.imported} 个节点，跳过 {result.duplicates} 个同名节点和 {result.skipped} 个无效或不兼容的节点。
            </p>
          )}
        </div>
        <div className="modal-footer">
          <button className="btn" type="submit" disabled={importing || !url.trim()}>
            {importing ? "导入中…" : "导入"}
          </button>
        </div>
      </form>
    </div>
  );
}
