import { createRouter, createWebHashHistory } from 'vue-router'

const routes = [
  { path: '/', redirect: '/queue' },
  { path: '/login', name: 'login', component: () => import('@/views/Login.vue'), meta: { public: true } },
  { path: '/queue', name: 'queue', component: () => import('@/views/AlertQueue.vue') },
  { path: '/alerts/:uid', name: 'alert', component: () => import('@/views/AlertDetail.vue') },
  { path: '/approvals', name: 'approvals', component: () => import('@/views/Approvals.vue') },
  { path: '/dashboard', name: 'dashboard', component: () => import('@/views/Dashboard.vue') },
  { path: '/experience', name: 'experience', component: () => import('@/views/Experience.vue') },
  { path: '/copilot/:uid?', name: 'copilot', component: () => import('@/views/Copilot.vue') },
]

export default createRouter({
  history: createWebHashHistory(),
  routes,
})
