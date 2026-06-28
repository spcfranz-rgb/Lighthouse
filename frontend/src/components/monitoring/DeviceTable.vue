<template>
  <div class="card h-100 shadow-sm border-secondary">
    <div class="card-header bg-dark border-secondary">
      <h5 class="mb-0">{{ title }}</h5>
    </div>
    <div class="card-body p-0">
      <div class="table-responsive">
        <table class="table table-sm table-hover align-middle text-nowrap mb-0">
          <thead>
            <tr>
              <th class="ps-3">Name</th>
              <th>IP/Host</th>
              <th v-if="type === 'cameras'">Switch</th>
              <th>Status</th>
              <th class="text-end pe-3">Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="device in devices" :key="device.id">
              <td class="ps-3">
                {{ device.name }}
                <button v-if="type === 'cameras'" class="btn btn-sm btn-outline-secondary ms-2 py-0" @click="$emit('preview', device)">Preview</button>
              </td>
              <td>
                <div class="fw-bold">{{ device.ip }}</div>
                <div class="small text-muted font-monospace" style="font-size: 0.75rem;">{{ device.mac_address || 'Waiting for ARP...' }}</div>
              </td>
              <td v-if="type === 'cameras'"><small class="text-muted">{{ device.switch_name || 'Standalone' }}</small></td>
              <td>
                <span class="badge" :class="statusClass(device.status)">{{ device.status }}</span>
              </td>
              <td class="text-end pe-3">
                <a :href="`/tunnel/${type.slice(0,-1)}/${device.id}/`" target="_blank" class="badge bg-info text-decoration-none me-2">WebUI</a>
                <button class="btn btn-sm" :class="device.is_silenced ? 'btn-warning' : 'btn-outline-secondary'" @click="toggleSilence(device)" :disabled="working === device.id">
                  {{ device.is_silenced ? '🔇' : '🔔' }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import axios from 'axios'
import { useSystemStore } from '../../stores/systemStore'

const props = defineProps(['title', 'type', 'devices'])
const emit = defineEmits(['preview'])
const store = useSystemStore()
const working = ref(null)

const statusClass = (status) => {
  if (status === 'UP') return 'bg-success'
  if (status?.includes('Silenced')) return 'bg-warning text-dark'
  if (status?.includes('DOWN') || status?.includes('UNREACHABLE') || status?.includes('ERR')) return 'bg-danger'
  return 'bg-secondary'
}

const toggleSilence = async (device) => {
  working.value = device.id
  const hours = device.is_silenced ? 0 : 24
  try {
    await axios.post('/api/v1/devices/silence', { type: props.type.slice(0,-1), id: device.id, hours })
    device.is_silenced = !device.is_silenced
    store.addToast(`Silence updated for ${device.name}`)
  } catch(e) {
    store.addToast('Failed to update silence', 'danger')
  } finally {
    working.value = null
  }
}
</script>
