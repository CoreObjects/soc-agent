<script setup>
import { ElMessage, ElMessageBox } from 'element-plus'
import { onMounted, onUnmounted, ref } from 'vue'
import { useRouter } from 'vue-router'

import { api } from '@/api/client'
import { zhStatus } from '@/utils/format'

const router = useRouter()
const status = ref('proposed')
const plans = ref([])
const loading = ref(false)
const mode = ref('manual')
let timer = null

async function load(silent = false) {
  if (!silent) loading.value = true          // 静默轮询,避免遮罩闪烁
  try {
    plans.value = (await api.plans(status.value)).plans
  } catch (e) {
    if (!silent) ElMessage.error('加载失败:' + (e.response?.data?.detail || e.message))
  } finally {
    if (!silent) loading.value = false
  }
}

async function loadMode() {
  try {
    mode.value = (await api.getMode()).mode
  } catch {
    /* ignore */
  }
}

async function toggleMode(v) {
  try {
    await api.setMode(v)
    mode.value = v
    ElMessage.success(`处置模式 → ${v === 'auto' ? '自动' : '手动'}`)
  } catch (e) {
    ElMessage.error('切换失败:' + (e.response?.data?.detail || e.message))
    loadMode()
  }
}

async function act(id, kind) {
  try {
    if (kind === 'reject') {
      const { value } = await ElMessageBox.prompt('驳回理由', '驳回', { inputPlaceholder: '误报…' })
      await api.reject(id, value)
    } else if (kind === 'execute') {
      await ElMessageBox.confirm('确认执行?护栏对 DC/CA 仍拒绝。', '执行', { type: 'warning' })
      await api.execute(id)
    } else if (kind === 'approve') await api.approve(id)
    else if (kind === 'rollback') await api.rollback(id)
    ElMessage.success('已提交')
    load()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error(e.response?.data?.detail || e.message || '操作失败')
  }
}

onMounted(() => {
  load()
  loadMode()
  timer = setInterval(() => load(true), 8000)
})
onUnmounted(() => clearInterval(timer))
</script>

<template>
  <div>
    <el-card shadow="never">
      <div class="bar">
        <el-radio-group v-model="status" @change="load">
          <el-radio-button label="proposed">待处置</el-radio-button>
          <el-radio-button label="approved">已批待执行</el-radio-button>
          <el-radio-button label="executed">已处置</el-radio-button>
          <el-radio-button label="rejected">已驳回</el-radio-button>
        </el-radio-group>
        <div class="mode">
          处置模式
          <el-switch
            :model-value="mode === 'auto'"
            active-text="自动"
            inactive-text="手动"
            inline-prompt
            @change="(v) => toggleMode(v ? 'auto' : 'manual')"
          />
          <el-tooltip content="手动:仅生成待处置,人审后执行;自动:自动审批执行(DC/CA 仍被护栏留待处置)">
            <el-icon><InfoFilled /></el-icon>
          </el-tooltip>
        </div>
      </div>
    </el-card>

    <el-card shadow="never" style="margin-top: 12px" v-loading="loading">
      <el-empty v-if="!plans.length" description="无计划" />
      <div v-for="p in plans" :key="p.plan_id" class="plan">
        <div class="phead">
          <b @click="router.push(`/alerts/${p.plan_id}`)" class="link">{{ p.plan_id }}</b>
          <el-tag size="small" type="warning">{{ p.status_zh || zhStatus(p.status) }}</el-tag>
          <span class="muted">{{ p.verdict }} · {{ p.rationale }}</span>
        </div>
        <div v-for="s in p.steps" :key="s.step_key" class="step">
          {{ s.order }}. <b>{{ s.primitive }}</b> → {{ s.target || '—' }}
          <span class="muted">({{ s.risk }})</span>
          <el-tag size="small">{{ s.status_zh || zhStatus(s.status) }}</el-tag>
        </div>
        <div class="acts">
          <template v-if="p.status === 'proposed'">
            <el-button size="small" type="success" @click="act(p.plan_id, 'approve')">批准</el-button>
            <el-button size="small" type="warning" @click="act(p.plan_id, 'execute')">批准并执行</el-button>
            <el-button size="small" @click="act(p.plan_id, 'reject')">驳回</el-button>
          </template>
          <el-button v-else-if="p.status === 'approved'" size="small" type="warning" @click="act(p.plan_id, 'execute')">执行</el-button>
          <el-button v-else-if="p.status === 'executed'" size="small" @click="act(p.plan_id, 'rollback')">回退</el-button>
        </div>
      </div>
    </el-card>
  </div>
</template>

<style scoped>
.bar { display: flex; justify-content: space-between; align-items: center; }
.mode { display: flex; gap: 8px; align-items: center; color: #666; }
.plan { border: 1px solid #eee; border-radius: 6px; padding: 12px; margin-bottom: 10px; }
.phead { display: flex; gap: 10px; align-items: center; }
.link { color: #409eff; cursor: pointer; }
.step { margin: 4px 0 4px 14px; display: flex; gap: 6px; align-items: center; }
.muted { color: #999; font-size: 12px; }
.acts { margin-top: 8px; }
</style>
