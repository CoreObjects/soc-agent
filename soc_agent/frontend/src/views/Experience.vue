<script setup>
import { ElMessage } from 'element-plus'
import { onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'

import { api } from '@/api/client'

const router = useRouter()
const items = ref([])
const loading = ref(false)
const filters = reactive({ skill: '', kind: '' })

const KIND_ZH = { threat: '威胁指纹', benign_fp: '误报指纹', payload: '签名规则' }

async function load() {
  loading.value = true
  try {
    items.value = (await api.experience({ skill: filters.skill, kind: filters.kind })).items
  } catch (e) {
    ElMessage.error('加载失败:' + (e.response?.data?.detail || e.message))
  } finally {
    loading.value = false
  }
}
onMounted(load)
</script>

<template>
  <div>
    <el-card shadow="never">
      <el-form :inline="true" @submit.prevent>
        <el-form-item label="类型">
          <el-select v-model="filters.kind" clearable placeholder="全部" style="width: 150px" @change="load">
            <el-option label="威胁指纹" value="threat" />
            <el-option label="误报指纹" value="benign_fp" />
            <el-option label="签名规则" value="payload" />
          </el-select>
        </el-form-item>
        <el-form-item label="skill">
          <el-input v-model="filters.skill" clearable placeholder="skill" style="width: 160px" @keyup.enter="load" />
        </el-form-item>
        <el-form-item><el-button type="primary" @click="load">筛选</el-button></el-form-item>
      </el-form>
      <p class="muted">系统从真实研判中蒸馏出的经验 —— 命中即复用(越用越省)。点来源可回溯那条告警。</p>
    </el-card>

    <el-card shadow="never" style="margin-top: 12px" v-loading="loading">
      <el-table :data="items">
        <el-table-column prop="skill" label="skill" width="140" />
        <el-table-column label="类型" width="110">
          <template #default="{ row }">
            <el-tag size="small" :type="row.kind === 'threat' ? 'danger' : row.kind === 'payload' ? 'warning' : 'info'">
              {{ KIND_ZH[row.kind] || row.kind }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="verdict" label="结论" width="130" />
        <el-table-column prop="note" label="本质(蒸馏)" min-width="240" show-overflow-tooltip />
        <el-table-column prop="hit_count" label="命中次数" width="100" sortable />
        <el-table-column prop="status" label="状态" width="90" />
        <el-table-column label="来源" width="110">
          <template #default="{ row }">
            <el-button v-if="row.origin_case_id" link type="primary" @click="router.push(`/alerts/${row.origin_case_id}`)">
              溯源
            </el-button>
            <span v-else class="muted">—</span>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<style scoped>
.muted { color: #999; font-size: 12px; }
</style>
