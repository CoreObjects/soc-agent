<script setup>
import { ElMessage, ElMessageBox } from 'element-plus'
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { api } from '@/api/client'
import { pathLabel, polarityTag, verdictTag, verdictZh, zhStatus } from '@/utils/format'

const route = useRoute()
const router = useRouter()
const uid = route.params.uid
const d = ref(null)
const loading = ref(false)

const isTpProposed = computed(
  () => d.value?.verdict === 'true_positive' && (d.value?.dispositions || []).some((x) => x.status === 'proposed'),
)

async function load() {
  loading.value = true
  try {
    d.value = await api.alert(uid)
  } catch (e) {
    ElMessage.error('加载失败:' + (e.response?.data?.detail || e.message))
  } finally {
    loading.value = false
  }
}

async function act(kind) {
  try {
    if (kind === 'approve') await api.approve(uid)
    else if (kind === 'reject') {
      const { value } = await ElMessageBox.prompt('驳回理由', '驳回', { inputPlaceholder: '误报…' })
      await api.reject(uid, value)
    } else if (kind === 'execute') {
      await ElMessageBox.confirm('确认执行处置?护栏对 DC/CA 仍会拒绝。', '执行', { type: 'warning' })
      await api.execute(uid)
    }
    ElMessage.success('已提交')
    load()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error(e.response?.data?.detail || e.message || '操作失败')
  }
}
onMounted(load)
</script>

<template>
  <div v-loading="loading">
    <el-page-header @back="router.back()" :content="d?.alert?.rule_description || uid" style="margin-bottom: 12px" />
    <template v-if="d">
      <el-row :gutter="12">
        <el-col :span="16">
          <el-card shadow="never" header="完整研判流程">
            <el-timeline>
              <el-timeline-item timestamp="① 原始告警" placement="top" type="primary">
                <div class="k">{{ d.alert.source }} / {{ d.alert.sensor }} · {{ d.alert.technique_ids?.join(', ') }}</div>
                <el-input type="textarea" :rows="4" :model-value="JSON.stringify(d.raw, null, 2)" readonly />
              </el-timeline-item>

              <el-timeline-item timestamp="② 图上下文(seed)" placement="top">
                <pre class="ctx">{{ JSON.stringify(d.seed, null, 2) }}</pre>
              </el-timeline-item>

              <el-timeline-item timestamp="③ 取证发现(findings)" placement="top">
                <div v-if="!d.findings.length" class="muted">无 findings</div>
                <div v-for="f in d.findings" :key="f.finding_id" class="finding">
                  <el-tag :type="polarityTag(f.polarity)" size="small">{{ f.polarity }}</el-tag>
                  <b>{{ f.finding_id }}</b>
                  <span class="muted">{{ JSON.stringify(f.attrs) }}</span>
                </div>
              </el-timeline-item>

              <el-timeline-item
                :timestamp="`④ 研判结论 · ${pathLabel(d.path)} · ${d.method}`"
                placement="top"
                :type="d.verdict === 'true_positive' ? 'danger' : 'success'"
              >
                <el-tag :type="verdictTag(d.verdict)">{{ verdictZh(d.verdict) }}</el-tag>
                <span class="conf">置信 {{ d.confidence }}</span>
                <p class="rationale">{{ d.rationale || d.summary }}</p>
                <div class="muted">证据:{{ (d.evidence_refs || []).join(', ') || '—' }}</div>
                <div class="muted">缺失证据:{{ (d.missing_evidence || []).join(', ') || '—' }}</div>
                <el-alert
                  v-if="d.reuse_source"
                  type="info"
                  :closable="false"
                  style="margin-top: 8px"
                  :title="`经验复用来源:${d.reuse_source.origin_uid || '未知'} — ${d.reuse_source.summary || ''}`"
                />
              </el-timeline-item>

              <el-timeline-item timestamp="⑤ 处置计划" placement="top">
                <div v-if="!d.dispositions.length" class="muted">无需处置</div>
                <div v-for="(s, i) in d.dispositions" :key="i" class="dispo">
                  <el-tag size="small" type="warning">{{ s.status_zh }}</el-tag>
                  <b>{{ s.action }}</b> → {{ s.target || '—' }}
                  <span class="muted">({{ s.target_kind }}, risk={{ s.risk }})</span>
                </div>
                <div v-if="isTpProposed" style="margin-top: 10px">
                  <el-button type="success" size="small" @click="act('approve')">批准</el-button>
                  <el-button type="warning" size="small" @click="act('execute')">批准并执行</el-button>
                  <el-button size="small" @click="act('reject')">驳回</el-button>
                </div>
              </el-timeline-item>

              <el-timeline-item v-if="d.trace" timestamp="⑥ 逐步研判留痕(trace)" placement="top">
                <el-collapse>
                  <el-collapse-item :title="`共 ${d.trace.length} 步`">
                    <div v-for="(t, i) in d.trace" :key="i" class="trace">
                      <b>[{{ i + 1 }}] {{ t.tool }}</b>
                      <span v-if="t.query" class="muted"> q: {{ t.query }} → {{ t.rows }} 行</span>
                      <span v-else-if="t.content_len" class="muted"> prompt {{ t.content_len }} 字符</span>
                      <span v-else-if="t.decision" class="muted"> 护栏 {{ t.decision }}: {{ t.action }}→{{ t.target }}</span>
                    </div>
                  </el-collapse-item>
                </el-collapse>
              </el-timeline-item>
              <el-timeline-item v-else timestamp="⑥ 逐步留痕" placement="top">
                <span class="muted">此告警无逐步 trace(存量/复用),以上为台账重建流程</span>
              </el-timeline-item>
            </el-timeline>
          </el-card>
        </el-col>

        <el-col :span="8">
          <el-card shadow="never" header="深度分析">
            <p class="muted">对本告警的台账做多轮追问(为什么判 {{ verdictZh(d.verdict) }}?还缺哪些证据?)</p>
            <el-button type="primary" @click="router.push(`/copilot/${uid}`)">打开 Copilot</el-button>
          </el-card>
        </el-col>
      </el-row>
    </template>
  </div>
</template>

<style scoped>
.k { color: #666; margin-bottom: 6px; }
.ctx, .trace { font-size: 12px; color: #555; white-space: pre-wrap; }
.finding, .dispo { margin: 4px 0; display: flex; gap: 6px; align-items: center; }
.muted { color: #999; font-size: 12px; }
.conf { margin-left: 8px; color: #888; }
.rationale { margin: 8px 0; }
</style>
