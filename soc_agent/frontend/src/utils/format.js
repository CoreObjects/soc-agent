// 展示格式化(与后端 response/auto.STATUS_ZH 对齐 + 前端 verdict/path 标签)。

export const STATUS_ZH = {
  proposed: '待处置',
  approved: '待处置(已批,待执行)',
  executing: '处置中',
  executed: '已处置',
  failed: '处置失败',
  refused: '护栏拒绝',
  rejected: '已驳回',
  rollback_requested: '待回退',
  rolling_back: '回退中',
  rolled_back: '已回退',
  rollback_failed: '回退失败',
  none: '无需处置',
}

export function zhStatus(s) {
  return STATUS_ZH[s] || s || '未知'
}

export const VERDICT_ZH = {
  true_positive: '真实威胁',
  false_positive: '误报',
  benign: '良性',
  suspicious: '存疑',
}

export function verdictZh(v) {
  return VERDICT_ZH[v] || v || '-'
}

export function verdictTag(v) {
  return { true_positive: 'danger', false_positive: 'info', benign: 'success', suspicious: 'warning' }[v] || 'info'
}

export const PATH_ZH = { S: '浅层短路', A: '经验复用', B: '深度研判' }

export function pathLabel(p) {
  return PATH_ZH[p] || p || '-'
}

export function polarityTag(p) {
  return { red: 'danger', green: 'success', neutral: 'info' }[p] || 'info'
}

export function pct(n, d) {
  if (!d) return '0.0%'
  return ((n / d) * 100).toFixed(1) + '%'
}
