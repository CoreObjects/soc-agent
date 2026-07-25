<script setup>
import { ElMessage } from 'element-plus'
import { nextTick, ref } from 'vue'
import { useRoute } from 'vue-router'

import { api } from '@/api/client'

const route = useRoute()
const uid = ref(route.params.uid || '')
const input = ref('')
const messages = ref([]) // {role, content}
const sending = ref(false)
const listEl = ref(null)

const QUICK = ['为什么判这个结论?', '还缺哪些证据?', '涉及的账号/主机历史?', '该如何处置更稳妥?']

async function send(text) {
  const content = (text ?? input.value).trim()
  if (!content) return
  if (!uid.value) {
    ElMessage.warning('先在上方填入要分析的告警 uid(或从告警详情页进入)')
    return
  }
  messages.value.push({ role: 'user', content })
  input.value = ''
  sending.value = true
  await scroll()
  try {
    const { reply } = await api.chat(uid.value, messages.value)
    messages.value.push({ role: 'assistant', content: reply })
  } catch (e) {
    const detail = e.response?.data?.detail || e.message
    ElMessage.error('对话失败:' + detail)
    messages.value.push({ role: 'assistant', content: `(出错:${detail})` })
  } finally {
    sending.value = false
    await scroll()
  }
}

async function scroll() {
  await nextTick()
  if (listEl.value) listEl.value.scrollTop = listEl.value.scrollHeight
}
</script>

<template>
  <el-card shadow="never" class="copilot">
    <div class="top">
      <el-input v-model="uid" placeholder="告警 uid" style="width: 320px" />
      <span class="muted">以该告警的完整台账为上下文,多轮追问。</span>
    </div>
    <div ref="listEl" class="msgs">
      <el-empty v-if="!messages.length" description="就这条告警开始提问吧" />
      <div v-for="(m, i) in messages" :key="i" :class="['msg', m.role]">
        <div class="bubble">{{ m.content }}</div>
      </div>
      <div v-if="sending" class="msg assistant"><div class="bubble muted">思考中…</div></div>
    </div>
    <div class="quick">
      <el-tag v-for="q in QUICK" :key="q" class="q" @click="send(q)">{{ q }}</el-tag>
    </div>
    <div class="input">
      <el-input v-model="input" type="textarea" :rows="2" placeholder="输入问题,回车发送" @keyup.enter.exact.prevent="send()" />
      <el-button type="primary" :loading="sending" @click="send()">发送</el-button>
    </div>
  </el-card>
</template>

<style scoped>
.copilot { display: flex; flex-direction: column; height: calc(100vh - 120px); }
.top { display: flex; gap: 10px; align-items: center; margin-bottom: 8px; }
.msgs { flex: 1; overflow-y: auto; padding: 8px; background: #fafafa; border-radius: 6px; }
.msg { display: flex; margin: 8px 0; }
.msg.user { justify-content: flex-end; }
.bubble { max-width: 70%; padding: 8px 12px; border-radius: 8px; white-space: pre-wrap; }
.msg.user .bubble { background: #409eff; color: #fff; }
.msg.assistant .bubble { background: #fff; border: 1px solid #eee; }
.quick { margin: 8px 0; display: flex; gap: 6px; flex-wrap: wrap; }
.q { cursor: pointer; }
.input { display: flex; gap: 8px; align-items: flex-end; }
.muted { color: #999; font-size: 12px; }
</style>
