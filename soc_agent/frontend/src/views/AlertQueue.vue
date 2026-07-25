<script setup>
import { ElMessage } from 'element-plus'
import { onMounted, onUnmounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'

import { api } from '@/api/client'
import { pathLabel, verdictTag, verdictZh } from '@/utils/format'

const router = useRouter()
const rows = ref([])
const total = ref(0)
const loading = ref(false)
const filters = reactive({ verdict: '', path: '', dispo_status: '', q: '', page: 1, size: 20 })
let timer = null

async function load() {
  loading.value = true
  try {
    const params = {
      page: filters.page, size: filters.size,
      verdict: filters.verdict, path: filters.path,
      dispo_status: filters.dispo_status, q: filters.q,
    }
    const data = await api.alerts(params)
    rows.value = data.items
    total.value = data.total
  } catch (e) {
    ElMessage.error('加载队列失败:' + (e.response?.data?.detail || e.message))
  } finally {
    loading.value = false
  }
}

function search() {
  filters.page = 1
  load()
}
function open(row) {
  router.push(`/alerts/${row.alert_uid}`)
}

onMounted(() => {
  load()
  timer = setInterval(load, 5000) // 轮询刷新
})
onUnmounted(() => clearInterval(timer))
</script>

<template>
  <div>
    <el-card shadow="never">
      <el-form :inline="true" @submit.prevent>
        <el-form-item label="结论">
          <el-select v-model="filters.verdict" clearable placeholder="全部" style="width: 130px" @change="search">
            <el-option label="真实威胁" value="true_positive" />
            <el-option label="误报" value="false_positive" />
            <el-option label="存疑" value="suspicious" />
            <el-option label="良性" value="benign" />
          </el-select>
        </el-form-item>
        <el-form-item label="路径">
          <el-select v-model="filters.path" clearable placeholder="全部" style="width: 130px" @change="search">
            <el-option label="浅层短路(S)" value="S" />
            <el-option label="经验复用(A)" value="A" />
            <el-option label="深度研判(B)" value="B" />
          </el-select>
        </el-form-item>
        <el-form-item label="处置">
          <el-select v-model="filters.dispo_status" clearable placeholder="全部" style="width: 120px" @change="search">
            <el-option label="待处置" value="proposed" />
            <el-option label="已处置" value="executed" />
          </el-select>
        </el-form-item>
        <el-form-item>
          <el-input v-model="filters.q" placeholder="规则/关键词" clearable style="width: 200px" @keyup.enter="search" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="search">筛选</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card shadow="never" style="margin-top: 12px">
      <el-table :data="rows" v-loading="loading" @row-click="open" style="cursor: pointer">
        <el-table-column prop="rule_description" label="告警" min-width="220" show-overflow-tooltip />
        <el-table-column label="结论" width="110">
          <template #default="{ row }">
            <el-tag :type="verdictTag(row.verdict)" size="small">{{ verdictZh(row.verdict) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="路径" width="100">
          <template #default="{ row }">{{ pathLabel(row.path) }}</template>
        </el-table-column>
        <el-table-column label="处置" width="90">
          <template #default="{ row }">
            <el-tag v-if="row.plan_status_zh" size="small" type="warning">{{ row.plan_status_zh }}</el-tag>
            <span v-else style="color: #bbb">—</span>
          </template>
        </el-table-column>
        <el-table-column prop="severity" label="等级" width="70" />
        <el-table-column prop="source" label="来源" width="100" />
        <el-table-column prop="concluded_at" label="研判时间" width="180" />
      </el-table>
      <el-pagination
        style="margin-top: 12px; justify-content: flex-end"
        layout="total, prev, pager, next"
        :total="total"
        :page-size="filters.size"
        :current-page="filters.page"
        @current-change="(p) => { filters.page = p; load() }"
      />
    </el-card>
  </div>
</template>
