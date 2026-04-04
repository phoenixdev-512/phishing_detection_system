export function getScoreColor(score) {
  if (score >= 0.6) return '#ef4444';
  if (score >= 0.3) return '#eab308';
  return '#22c55e';
}
