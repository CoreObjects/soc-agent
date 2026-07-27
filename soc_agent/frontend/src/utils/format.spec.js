import { describe, expect, it } from 'vitest'

import { pathLabel, pct, verdictTag, verdictZh, zhStatus } from './format'

describe('format', () => {
  it('zhStatus 对齐后端标签', () => {
    expect(zhStatus('proposed')).toBe('待处置')
    expect(zhStatus('executed')).toBe('已处置')
    expect(zhStatus('refused')).toBe('护栏拒绝')
    expect(zhStatus('weird')).toBe('weird')      // 未知原样
  })

  it('verdict 中文 + tag 色', () => {
    expect(verdictZh('true_positive')).toBe('真实威胁')
    expect(verdictTag('true_positive')).toBe('danger')
    expect(verdictTag('false_positive')).toBe('info')
  })

  it('path 标签(浅层/深度复用/深度研判)', () => {
    expect(pathLabel('S')).toBe('浅层')
    expect(pathLabel('A')).toBe('深度复用')
    expect(pathLabel('B')).toBe('深度研判')
  })

  it('pct 百分比', () => {
    expect(pct(10, 60)).toBe('16.7%')
    expect(pct(0, 0)).toBe('0.0%')
  })
})
