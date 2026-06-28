<template>
  <div class="modal fade show d-block" style="background: rgba(0,0,0,0.8)" tabindex="-1">
    <div class="modal-dialog modal-dialog-centered">
      <div class="modal-content border-secondary bg-dark text-light">
        <div class="modal-header border-secondary">
          <h5 class="modal-title">Add Hardware</h5>
          <button type="button" class="btn-close btn-close-white" @click="$emit('close')"></button>
        </div>
        
        <div class="modal-body bg-body-tertiary">
          <ul class="nav nav-pills nav-fill mb-4">
            <li class="nav-item border border-secondary rounded overflow-hidden" style="cursor: pointer;">
              <a class="nav-link rounded-0" :class="{ 'active bg-primary text-white fw-bold': type === 'camera' }" @click="type = 'camera'">Camera</a>
            </li>
            <li class="nav-item border border-secondary border-start-0 rounded overflow-hidden" style="cursor: pointer;">
              <a class="nav-link rounded-0" :class="{ 'active bg-warning text-dark fw-bold': type === 'switch' }" @click="type = 'switch'">Switch</a>
            </li>
            <li class="nav-item border border-secondary border-start-0 rounded overflow-hidden" style="cursor: pointer;">
              <a class="nav-link rounded-0" :class="{ 'active bg-info text-dark fw-bold': type === 'nvr' }" @click="type = 'nvr'">NVR</a>
            </li>
          </ul>

          <form @submit.prevent="submitForm">
            <div class="mb-3">
              <label class="form-label text-muted small fw-bold">Device Name (Unique)</label>
              <input type="text" class="form-control bg-dark text-light border-secondary" v-model="form.name" required>
            </div>
            
            <div class="mb-3">
              <label class="form-label text-muted small fw-bold">IP Address</label>
              <input type="text" class="form-control bg-dark text-light border-secondary font-monospace" v-model="form.ip" required>
            </div>

            <div v-if="type === 'camera'" class="border-top border-secondary pt-3 mt-2">
              <div class="mb-3">
                <label class="form-label text-muted small fw-bold">RTSP Stream URL</label>
                <input type="text" class="form-control bg-dark text-light border-secondary font-monospace" placeholder="rtsp://192.168.1.X:554/live" v-model="form.stream_url" required>
              </div>

              <div class="row g-2 mb-3">
                <div class="col-6">
                  <label class="form-label text-muted small fw-bold">Uplink Switch</label>
                  <select class="form-select bg-dark text-light border-secondary" v-model="form.switch_id">
                    <option :value="null">Standalone</option>
                    <option v-for="sw in store.devices.switches" :key="sw.id" :value="sw.id">{{ sw.name }}</option>
                  </select>
                </div>
                <div class="col-6">
                  <label class="form-label text-muted small fw-bold">Manufacturer</label>
                  <select class="form-select bg-dark text-light border-secondary" v-model="form.manufacturer">
                    <option v-for="mfg in ['Other', 'Hikvision', 'Dahua', 'Amcrest', 'Axis', 'Foscam', 'Hanwha']" :key="mfg" :value="mfg">{{ mfg }}</option>
                  </select>
                </div>
              </div>

              <div class="row g-2">
                <div class="col-6">
                  <label class="form-label text-muted small fw-bold">Username</label>
                  <input type="text" class="form-control bg-dark text-light border-secondary" v-model="form.username">
                </div>
                <div class="col-6">
                  <label class="form-label text-muted small fw-bold">Password</label>
                  <input type="password" class="form-control bg-dark text-light border-secondary" v-model="form.password">
                </div>
              </div>
            </div>

            <button type="submit" class="btn w-100 fw-bold mt-4" :class="{
              'btn-primary': type === 'camera',
              'btn-warning': type === 'switch',
              'btn-info': type === 'nvr'
            }" :disabled="saving">
              {{ saving ? 'Saving...' : `Add ${type.toUpperCase()}` }}
            </button>
          </form>

        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import axios from 'axios'
import { useSystemStore } from '../../stores/systemStore'

const emit = defineEmits(['close'])
const store = useSystemStore()

const type = ref('camera')
const saving = ref(false)

const form = ref({
  name: '', ip: '', stream_url: '', 
  switch_id: null, manufacturer: 'Other', 
  username: '', password: ''
})

const submitForm = async () => {
  saving.value = true
  try {
    // Dynamically route plurals for the API endpoint
    const endpoint = type.value === 'camera' ? 'cameras' : `${type.value}s`
    
    await axios.post(`/api/v1/${endpoint}`, form.value)
    store.addToast(`${type.value.toUpperCase()} added successfully.`)
    await store.fetchSystemData() // Re-hydrate the DOM tables instantly
    emit('close')
  } catch (error) {
    store.addToast(error.response?.data?.message || 'Failed to add device.', 'danger')
  } finally {
    saving.value = false
  }
}
</script>
