<template>
  <div>
    <TopNav />
    
    <div class="d-flex justify-content-between align-items-center mb-4 border-bottom border-secondary pb-3">
      <h1 class="h4 mb-0 text-light">System Event Logs <span class="text-muted fs-6">(Last 500)</span></h1>
      <div>
        <router-link to="/" class="btn btn-outline-secondary btn-sm">&larr; Back to Dashboard</router-link>
      </div>
    </div>

    <div class="card shadow-sm border-secondary bg-dark">
      <div class="card-body p-0">
        
        <div v-if="loading" class="text-center py-5 text-info">
          <div class="spinner-border mb-3" role="status"></div>
          <div>Loading system audit trails...</div>
        </div>

        <div v-else class="table-responsive" style="max-height: 75vh;">
          <table class="table table-hover table-dark table-striped mb-0 text-nowrap align-middle">
            <thead class="sticky-top bg-dark">
              <tr>
                <th class="ps-3 border-secondary">Timestamp</th>
                <th class="border-secondary">Source Type</th>
                <th class="border-secondary">Device / User</th>
                <th class="border-secondary">Event Details</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="log in logs" :key="log.id">
                <td class="ps-3 text-muted small">{{ formatDate(log.timestamp) }}</td>
                <td><span class="badge bg-secondary">{{ log.device_type }}</span></td>
                <td class="fw-bold">{{ log.device_name }}</td>
                <td :class="statusClass(log.status)">{{ log.status }}</td>
              </tr>
              <tr v-if="logs.length === 0">
                <td colspan="4" class="text-center py-4 text-muted border-secondary">No events recorded in the database.</td>
              </tr>
            </tbody>
          </table>
        </div>

      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import axios from 'axios'
import TopNav from '../components/layout/TopNav.vue'

const logs = ref([])
const loading = ref(true)

onMounted(async () => {
  try {
    const res = await axios.get('/api/v1/history')
    logs.value = res.data
  } catch (error) {
    console.error("Failed to load logs:", error)
  } finally {
    loading.value = false
  }
})

const formatDate = (ts) => {
  return new Date(ts * 1000).toLocaleString()
}

const statusClass = (status) => {
  if (!status) return ''
  const s = status.toUpperCase()
  if (s.includes('UP') || s.includes('SUCCESS') || s.includes('LOGGED IN')) return 'text-success fw-bold'
  if (s.includes('DOWN') || s.includes('ERR') || s.includes('FAILOVER') || s.includes('DELETED')) return 'text-danger fw-bold'
  if (s.includes('SILENCED') || s.includes('MAINTENANCE') || s.includes('WARNING')) return 'text-warning fw-bold'
  return 'text-info fw-bold'
}
</script>
