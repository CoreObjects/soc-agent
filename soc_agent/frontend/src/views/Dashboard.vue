<script setup>
import { ElMessage } from 'element-plus'
import { computed, onMounted, onUnmounted, ref } from 'vue'

import { api } from '@/api/client'
import { pathLabel, pct, verdictZh } from '@/utils/format'

const s = ref(null)
let timer = null

async function load(silent = false) {
  try {
    s.value = await api.stats()
  } catch (e) {
    if (!silent) ElMessage.error('加载失败:' + (e.response?.data?.detail || e.message))
  }
}

const concludedDenom = computed(() => s.value?.progress?.concluded || 1)

// 成本构成 4 路(按研判方式拆,能与 verdict×path 的路径口径对上):
//   签名复用(reuse&S,零LLM)+ 深度经验复用(reuse&A) = 复用命中;浅层LLM直判(llm&S);深度LLM(llm&B)
const costRows = computed(() => {
  const r = s.value?.reuse
  if (!r) return []
  return [
    { label: '签名复用(零 LLM)', n: r.sig_reuse, color: '#409eff' },
    { label: '深度经验复用', n: r.deep_reuse, color: '#79bbff' },
    { label: '浅层 LLM 直判', n: r.shallow_short, color: '#67c23a' },
    { label: '深度 LLM 研判', n: r.deep, color: '#e6a23c' },
  ]
})

onMounted(() => {
  load()
  timer = setInterval(() => load(true), 8000)
})
onUnmounted(() => clearInterval(timer))
</script>

<template>
  <div v-if="s">
    <el-row :gutter="12">
      <el-col :span="6">
        <el-card shadow="never"><div class="stat"><div class="n">{{ s.progress.concluded }}</div><div class="l">已研判</div></div></el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="never"><div class="stat"><div class="n">{{ s.progress.backlog }}</div><div class="l">积压未研判</div></div></el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="never"><div class="stat"><div class="n green">{{ pct(s.auto_close.auto_closed, s.progress.concluded) }}</div><div class="l">自动结案率</div></div></el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="never"><div class="stat"><div class="n blue">{{ pct(s.reuse.reuse_hits, s.progress.concluded) }}</div><div class="l">复用命中率(越用越省)</div></div></el-card>
      </el-col>
    </el-row>

    <el-row :gutter="12" style="margin-top: 12px">
      <el-col :span="12">
        <el-card shadow="never" header="成本构成(按研判方式;越用越省)">
          <div v-for="row in costRows" :key="row.label" class="bar">
            <span class="bl">{{ row.label }}</span>
            <el-progress :percentage="+(row.n / concludedDenom * 100).toFixed(1)" :color="row.color" />
            <span class="bn">{{ row.n }}</span>
          </div>
          <p class="muted">
            复用命中率 = 签名复用 + 深度经验复用 =
            <b>{{ pct(s.reuse.reuse_hits, s.progress.concluded) }}</b>(随经验累计上涨 = 越用越省);
            浅层/深度 LLM = 真跑模型的少数。
            <br />注:签名复用走的是"浅层路径(S)",所以它与右侧 verdict×path 里"浅层(S)"的大头是同一批。
          </p>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card shadow="never" header="verdict × path 分布(按路径切)">
          <el-table :data="s.verdict_path" size="small">
            <el-table-column label="结论"><template #default="{ row }">{{ verdictZh(row.verdict) }}</template></el-table-column>
            <el-table-column label="路径"><template #default="{ row }">{{ pathLabel(row.path) }}</template></el-table-column>
            <el-table-column prop="n" label="数量" width="90" />
          </el-table>
          <p class="muted">注:"浅层(S)"里绝大多数是<b>签名复用</b>(=左侧的"签名复用",零 LLM),仅少数真跑浅层模型。此表按"路径"切、左表按"研判方式"切,同一批数据两种视角。</p>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="12" style="margin-top: 12px">
      <el-col :span="12">
        <el-card shadow="never" header="处置状态">
          <el-tag v-for="d in s.dispo_status" :key="d.status" style="margin: 4px" type="warning">
            {{ d.status_zh }}: {{ d.n }}
          </el-tag>
          <span v-if="!s.dispo_status.length" class="muted">无</span>
          <div class="muted" style="margin-top: 8px">毒告警跳过:{{ s.progress.poison }}</div>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card shadow="never" header="TP 抽样">
          <div v-for="t in s.tp_sample" :key="t.uid" class="tp">
            <b>{{ t.uid?.slice(0, 12) }}</b> · {{ t.plan }}
            <span class="muted">{{ (t.steps || []).map((x) => `${x.action}→${x.target}`).join(', ') }}</span>
          </div>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<style scoped>
.stat { text-align: center; padding: 8px; }
.stat .n { font-size: 26px; font-weight: 700; }
.stat .n.green { color: #67c23a; }
.stat .n.blue { color: #409eff; }
.stat .l { color: #888; margin-top: 4px; font-size: 13px; }
.bar { display: grid; grid-template-columns: 80px 1fr 50px; gap: 8px; align-items: center; margin: 8px 0; }
.bl { color: #666; font-size: 13px; }
.bn { text-align: right; color: #333; }
.muted { color: #999; font-size: 12px; }
.tp { margin: 6px 0; }
</style>
