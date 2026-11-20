import claudeColor from "@lobehub/icons-static-svg/icons/claude-color.svg";
import claudeCodeColor from "@lobehub/icons-static-svg/icons/claudecode-color.svg";
import codexColor from "@lobehub/icons-static-svg/icons/codex-color.svg";
import deepseekColor from "@lobehub/icons-static-svg/icons/deepseek-color.svg";
import geminiColor from "@lobehub/icons-static-svg/icons/gemini-color.svg";
import ollamaMono from "@lobehub/icons-static-svg/icons/ollama.svg";
import openaiMono from "@lobehub/icons-static-svg/icons/openai.svg";
import opencodeMono from "@lobehub/icons-static-svg/icons/opencode.svg";
import openrouterColor from "@lobehub/icons-static-svg/icons/openrouter-color.svg";
import qwenColor from "@lobehub/icons-static-svg/icons/qwen-color.svg";
import volcengineColor from "@lobehub/icons-static-svg/icons/volcengine-color.svg";

import type { OAuthPreset, ProtocolFamily } from "../types/gateway";
import { IconChannels, IconShield } from "./Icons";

export type ProviderLogoId =
  | "openai"
  | "codex"
  | "claude"
  | "claudecode"
  | "gemini"
  | "deepseek"
  | "openrouter"
  | "qwen"
  | "volcengine"
  | "opencode"
  | "ollama"
  | "custom_api"
  | "oauth";

export function detectProviderLogo(opts: {
  name?: string;
  baseUrl?: string;
  protocol?: ProtocolFamily;
  preset?: OAuthPreset;
}): ProviderLogoId {
  const n = (opts.name ?? "").toLowerCase();
  const u = (opts.baseUrl ?? "").toLowerCase();

  if (opts.preset === "codex" || n.includes("codex") || u.includes("chatgpt.com")) return "codex";
  if (
    n.includes("volc") ||
    n.includes("ark") ||
    n.includes("doubao") ||
    u.includes("volces.com")
  ) {
    return "volcengine";
  }
  if (opts.preset === "claude_code" || n.includes("claude-code") || n.includes("claudecode")) {
    return "claudecode";
  }
  if (
    opts.protocol === "anthropic" ||
    n.includes("claude") ||
    n.includes("anthropic") ||
    u.includes("anthropic.com")
  ) {
    return "claude";
  }
  if (
    opts.protocol === "gemini" ||
    n.includes("gemini") ||
    u.includes("generativelanguage.googleapis.com")
  ) {
    return "gemini";
  }
  if (n.includes("deepseek") || u.includes("deepseek.com")) return "deepseek";
  if (n.includes("openrouter") || u.includes("openrouter.ai")) return "openrouter";
  if (n.includes("opencode") || u.includes("opencode.ai")) return "opencode";
  if (n.includes("qwen") || u.includes("dashscope.aliyuncs.com")) return "qwen";
  if (n.includes("ollama") || n.includes("vllm") || n.includes("local") || u.includes("11434")) {
    return "ollama";
  }
  if (n.includes("openai") || u.includes("openai.com")) return "openai";
  if (opts.preset === "custom" || n.includes("oauth")) return "oauth";
  return "custom_api";
}

const LOGO_ASSETS: Record<
  Exclude<ProviderLogoId, "oauth" | "custom_api">,
  { src: string; mono?: boolean }
> = {
  openai: { src: openaiMono, mono: true },
  codex: { src: codexColor },
  claude: { src: claudeColor },
  claudecode: { src: claudeCodeColor },
  gemini: { src: geminiColor },
  deepseek: { src: deepseekColor },
  openrouter: { src: openrouterColor },
  qwen: { src: qwenColor },
  volcengine: { src: volcengineColor },
  opencode: { src: opencodeMono, mono: true },
  ollama: { src: ollamaMono, mono: true },
};

interface LogoProps {
  id: ProviderLogoId;
  size?: number;
}

export function ProviderLogo({ id, size = 20 }: LogoProps) {
  if (id === "oauth") {
    return <IconShield width={size} height={size} style={{ color: "var(--purple)" }} />;
  }
  if (id === "custom_api") {
    return <IconChannels width={size} height={size} style={{ color: "var(--accent)" }} />;
  }
  const asset = LOGO_ASSETS[id];
  return (
    <img
      src={asset.src}
      alt={id}
      width={size}
      height={size}
      className={asset.mono ? "provider-logo-mono" : undefined}
      style={{ display: "block", objectFit: "contain" }}
    />
  );
}
