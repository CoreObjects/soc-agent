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
        <el-card shadow="never" header="成本构成(收紧①:复用 vs 浅层短路 vs 深度)">
          <div class="bar">
            <span class="bl">复用命中</span>
            <el-progress :percentage="+(s.reuse.reuse_hits / concludedDenom * 100).toFixed(1)" color="#409eff" />
            <span class="bn">{{ s.reuse.reuse_hits }}</span>
          </div>
          <div class="bar">
            <span class="bl">浅层短路</span>
            <el-progress :percentage="+(s.reuse.shallow_short / concludedDenom * 100).toFixed(1)" color="#67c23a" />
            <span class="bn">{{ s.reuse.shallow_short }}</span>
          </div>
          <div class="bar">
            <span class="bl">深度研判</span>
            <el-progress :percentage="+(s.reuse.deep / concludedDenom * 100).toFixed(1)" color="#e6a23c" />
            <span class="bn">{{ s.reuse.deep }}</span>
          </div>
          <p class="muted">复用命中(签名+深度经验)随经验累计上涨=越用越省;浅层短路便宜结案、基本恒定;深度=稀有真研判。</p>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card shadow="never" header="verdict × path 分布">
          <el-table :data="s.verdict_path" size="small">
            <el-table-column label="结论"><template #default="{ row }">{{ verdictZh(row.verdict) }}</template></el-table-column>
            <el-table-column label="路径"><template #default="{ row }">{{ pathLabel(row.path) }}</template></el-table-column>
            <el-table-column prop="n" label="数量" width="90" />
          </el-table>
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
