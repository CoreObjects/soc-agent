<script setup>
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { useAuthStore } from '@/stores/auth'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()

const menu = [
  { index: '/queue', label: '研判队列', icon: 'List' },
  { index: '/approvals', label: '处置审批', icon: 'CircleCheck' },
  { index: '/dashboard', label: '价值大盘', icon: 'DataLine' },
  { index: '/experience', label: '经验库', icon: 'Collection' },
  { index: '/copilot', label: 'Copilot', icon: 'ChatDotRound' },
]
const activeMenu = computed(() => '/' + (route.path.split('/')[1] || 'queue'))

function logout() {
  auth.logout()
  router.push('/login')
}
</script>

<template>
  <el-container class="app">
    <el-aside width="200px" class="aside">
      <div class="brand">🛡 SOC 控制台</div>
      <el-menu
        :default-active="activeMenu"
        router
        class="menu"
        background-color="#1f2733"
        text-color="#c8d3e0"
        active-text-color="#79bbff"
      >
        <el-menu-item v-for="m in menu" :key="m.index" :index="m.index">
          <el-icon><component :is="m.icon" /></el-icon>
          <span>{{ m.label }}</span>
        </el-menu-item>
      </el-menu>
    </el-aside>
    <el-container>
      <el-header class="header">
        <span class="subtitle">研判 + 处置控制台</span>
        <el-button v-if="auth.authed" text size="small" @click="logout">登出</el-button>
      </el-header>
      <el-main class="main">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<style>
html,
body,
#app {
  height: 100%;
  margin: 0;
}
.app {
  height: 100vh;
}
.aside {
  background: #1f2733;
  color: #cfd8e3;
}
.brand {
  font-size: 16px;
  font-weight: 600;
  padding: 18px 16px;
  color: #fff;
}
.menu {
  border-right: none;
}
/* 悬停/选中更清晰 */
.menu .el-menu-item:hover {
  background-color: #2c3a4d !important;
  color: #fff !important;
}
.menu .el-menu-item.is-active {
  background-color: #2c3a4d !important;
  border-left: 3px solid #79bbff;
}
.header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  border-bottom: 1px solid #eee;
}
.subtitle {
  color: #666;
}
.main {
  background: #f5f7fa;
}
</style>
