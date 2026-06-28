<template>
  <div class="modal fade show d-block" style="background: rgba(0,0,0,0.85)" tabindex="-1">
    <div class="modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable">
      <div class="modal-content border-secondary bg-dark text-light">
        <div class="modal-header border-secondary bg-dark">
          <h5 class="modal-title text-warning">📡 Live L2 Hardware Discovery</h5>
          <button type="button" class="btn-close btn-close-white" @click="$emit('close')"></button>
        </div>
        
        <div class="modal-body bg-body-tertiary">
          <p class="small text-muted mb-3">
            Directly reading the Linux Kernel <code>/proc/net/arp</code> cache to bypass container NAT layers...
          </p>

          <div v-if="loading" class="text-center py-5 text-warning">
            <div class="spinner-border mb-3" role="status"></div>
            <div>Executing raw socket sweep...</div>
          </div>

          <div v-if="error" class="alert alert-danger border-secondary small">
            {{ error }}
          </div>

          <div v-if="!loading && !error">
            <div v-if="devices.length === 0" class="alert alert-warning border-secondary small text-center py-3">
              No active hardware found in cache. Is the physical cable connected?
            </div>
            
            <table v-else class="table table-dark table-sm table-hover align-middle border border-secondary mb-0">
              <thead class="table-active">
                <tr>
                  <th class="ps-3">IP Address</th>
                  <th>MAC Address</th>
                  <th>Interface</th>
                  <th v-if="isAdmin" class="text-end pe-3">Action</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="(dev, idx) in devices" :key="idx">
                  <td class="ps-3 text-info font-monospace">{{ dev.ip }}</td>
                  <td class="font-monospace text-light">{{ dev.mac }}</td>
                  <td><span class="badge bg-secondary">{{ dev.interface }}</span></td>
                  <td v-if="isAdmin" class="text-end pe-3">
                    <button class="btn btn-sm btn-outline-info fw-bold py-0" @click="$emit('provision', dev.ip)">➕ Provision</button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue'
import axios from 'axios'
import { useSystemStore } from '../../stores/systemStore'

const emit = defineEmits(['close', 'provision'])
const store = useSystemStore()

const loading = ref(true)
const error = ref(null)
const devices = ref([])

const isAdmin = computed(() => store.user?.role === 'admin')

onMounted(async () => {
  try {
    const res = await axios.get('/api/network/arp')
    if (res.data.status === 'success') {
      devices.value = res.data.devices
    } else {
      error.value = res.data.message || 'Unknown error fetching ARP table.'
    }
  } catch (err) {
    error.value = err.response?.data?.message || 'Network error / Endpoint unavailable.'
    store.addToast('Failed to execute ARP sweep.', 'danger')
  } finally {
    loading.value = false
  }
})
</script>
