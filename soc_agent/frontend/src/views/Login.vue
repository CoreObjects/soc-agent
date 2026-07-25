<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'

import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const auth = useAuthStore()
const token = ref('')

function submit() {
  auth.login(token.value.trim())
  router.push('/queue')
}
</script>

<template>
  <div class="login">
    <el-card shadow="never" class="box" header="🛡 SOC 控制台登录">
      <p class="muted">输入 operator token(SOC_WEB_TOKEN);未配 token 的环境可留空直接进入。</p>
      <el-input v-model="token" placeholder="operator token" show-password @keyup.enter="submit" />
      <el-button type="primary" style="margin-top: 12px; width: 100%" @click="submit">进入</el-button>
    </el-card>
  </div>
</template>

<style scoped>
.login { display: flex; justify-content: center; align-items: center; height: 70vh; }
.box { width: 360px; }
.muted { color: #999; font-size: 12px; margin-bottom: 10px; }
</style>
