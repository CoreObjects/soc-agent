import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it } from 'vitest'

import { getToken } from '@/api/client'

import { useAuthStore } from './auth'

describe('auth store', () => {
  beforeEach(() => {
    localStorage.clear()
    setActivePinia(createPinia())
  })

  it('login 存 token + authed=true + 持久化', () => {
    const s = useAuthStore()
    expect(s.authed).toBe(false)
    s.login('s3cret')
    expect(s.token).toBe('s3cret')
    expect(s.authed).toBe(true)
    expect(getToken()).toBe('s3cret')            // 落 localStorage
  })

  it('logout 清 token', () => {
    const s = useAuthStore()
    s.login('s3cret')
    s.logout()
    expect(s.token).toBe('')
    expect(s.authed).toBe(false)
    expect(getToken()).toBe('')
  })
})
