import { beforeEach, describe, expect, it, vi } from 'vitest'

import {
  getToken,
  makeResponseErrorHandler,
  requestInterceptor,
  setToken,
} from './client'

describe('token 存取', () => {
  beforeEach(() => localStorage.clear())

  it('set/get/clear', () => {
    expect(getToken()).toBe('')
    setToken('abc')
    expect(getToken()).toBe('abc')
    setToken('')
    expect(getToken()).toBe('')
  })
})

describe('请求拦截器', () => {
  beforeEach(() => localStorage.clear())

  it('有 token → 加 Bearer 头', () => {
    setToken('s3cret')
    const cfg = requestInterceptor({ headers: {} })
    expect(cfg.headers.Authorization).toBe('Bearer s3cret')
  })

  it('无 token → 不加头', () => {
    const cfg = requestInterceptor({ headers: {} })
    expect(cfg.headers.Authorization).toBeUndefined()
  })
})

describe('响应错误拦截器', () => {
  beforeEach(() => localStorage.clear())

  it('401 → 清 token 并回调登出', async () => {
    setToken('s3cret')
    const onUnauthorized = vi.fn()
    const handler = makeResponseErrorHandler(onUnauthorized)
    await expect(handler({ response: { status: 401 } })).rejects.toBeTruthy()
    expect(getToken()).toBe('')
    expect(onUnauthorized).toHaveBeenCalledOnce()
  })

  it('非 401 → 原样拒绝,不动 token', async () => {
    setToken('s3cret')
    const handler = makeResponseErrorHandler(vi.fn())
    await expect(handler({ response: { status: 500 } })).rejects.toBeTruthy()
    expect(getToken()).toBe('s3cret')
  })
})
