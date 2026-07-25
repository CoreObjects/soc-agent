import { defineStore } from 'pinia'

import { getToken, setToken } from '@/api/client'

export const useAuthStore = defineStore('auth', {
  state: () => ({ token: getToken() }),
  getters: {
    authed: (s) => !!s.token,
  },
  actions: {
    login(t) {
      this.token = t || ''
      setToken(this.token)
    },
    logout() {
      this.token = ''
      setToken('')
    },
  },
})
