export function formatCacheHitRate(percent: number): string {
  if (percent >= 100) return "100%";
  const rounded = percent.toFixed(2);
  if (rounded === "100.00") return "<100%";
  if (rounded === "0.00" && percent > 0) return "<0.01%";
  return `${rounded}%`;
}
