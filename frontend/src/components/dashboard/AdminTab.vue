<template>
  <div class="row g-4">
    
    <div class="col-lg-6">
      <div class="card shadow-sm border-secondary h-100">
        <div class="card-header bg-dark border-secondary">
          <h5 class="mb-0">Gateway Settings</h5>
        </div>
        <div class="card-body bg-body-tertiary">
          <form @submit.prevent="saveSettings">
            <h6 class="text-muted border-bottom border-secondary pb-1 mb-3">MQTT Broker</h6>
            <div class="row g-2 mb-4">
              <div class="col-md-8">
                <label class="form-label small text-muted">Host</label>
                <input type="text" class="form-control form-control-sm bg-dark text-light border-secondary" v-model="form.mqtt_broker">
              </div>
              <div class="col-md-4">
                <label class="form-label small text-muted">Port</label>
                <input type="number" class="form-control form-control-sm bg-dark text-light border-secondary" v-model="form.mqtt_port">
              </div>
              <div class="col-12 mt-2">
                <label class="form-label small text-muted">Topic Prefix</label>
                <input type="text" class="form-control form-control-sm bg-dark text-light border-secondary" v-model="form.mqtt_prefix">
              </div>
            </div>

            <h6 class="text-muted border-bottom border-secondary pb-1 mb-3">SMTP Failover (Offline Alerts)</h6>
            <div class="row g-2 mb-4">
              <div class="col-md-8">
                <input type="text" class="form-control form-control-sm bg-dark text-light border-secondary" v-model="form.smtp_host" placeholder="smtp.gmail.com">
              </div>
              <div class="col-md-4">
                <input type="text" class="form-control form-control-sm bg-dark text-light border-secondary" v-model="form.smtp_port" placeholder="587">
              </div>
              <div class="col-md-6 mt-2">
                <input type="text" class="form-control form-control-sm bg-dark text-light border-secondary" v-model="form.smtp_user" placeholder="Username (Optional)">
              </div>
              <div class="col-md-6 mt-2">
                <input type="password" class="form-control form-control-sm bg-dark text-light border-secondary" v-model="form.smtp_pass" placeholder="Password (Optional)">
              </div>
              <div class="col-12 mt-2">
                <input type="email" class="form-control form-control-sm bg-dark text-light border-secondary" v-model="form.smtp_target" placeholder="Target Alert Email Address">
              </div>
            </div>

            <button type="submit" class="btn btn-warning w-100 fw-bold mt-2" :disabled="saving">
              {{ saving ? 'Saving...' : 'Apply Global Configuration' }}
            </button>
          </form>
        </div>
      </div>
    </div>

    <div class="col-lg-6 d-flex flex-column gap-4">
      
      <div class="card shadow-sm border-secondary">
        <div class="card-header bg-dark border-secondary">
          <h5 class="mb-0">Backup & Restore (CSV)</h5>
        </div>
        <div class="card-body bg-body-tertiary">
          <p class="small text-muted mb-3">Export your hardware configuration as a CSV file, or merge a CSV file into the current database.</p>
          
          <div class="d-flex gap-2">
            <a href="/api/v1/system/export" class="btn btn-outline-info w-50 fw-bold">⬇️ Export CSV</a>
            
            <button class="btn btn-outline-danger w-50 fw-bold" @click="triggerFileInput" :disabled="analyzing">
                {{ analyzing ? 'Analyzing...' : '⬆️ Import / Merge CSV' }}
            </button>
            
            <input type="file" ref="fileInput" accept=".csv" class="d-none" @change="handleAnalyze">
          </div>
        </div>
      </div>

      <div class="card shadow-sm border-secondary h-100">
        <div class="card-header bg-dark border-secondary">
          <h5 class="mb-0">Access Management</h5>
        </div>
        <div class="card-body bg-body-tertiary p-0">
          <table class="table table-sm table-dark table-striped mb-0 text-nowrap">
            <thead>
              <tr>
                <th class="ps-3">Username</th>
                <th>Role</th>
                <th class="text-end pe-3">Action</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="u in store.users" :key="u.id">
                <td class="ps-3">{{ u.username }}</td>
                <td><span class="badge" :class="u.role === 'admin' ? 'bg-danger' : 'bg-primary'">{{ u.role.toUpperCase() }}</span></td>
                <td class="text-end pe-3">
                  <button class="btn btn-sm btn-outline-danger py-0" @click="deleteUser(u.id)" :disabled="u.username === store.user.username || u.password?.startsWith('SSO_')">Delete</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
      
    </div>
  </div>

  <ImportResolutionModal 
    v-if="analysisData" 
    :analysis="analysisData" 
    @close="analysisData = null" 
    @merged="onMergeComplete" 
  />
</template>

<script setup>
import { ref, onMounted } from 'vue'
import axios from 'axios'
import { useSystemStore } from '../../stores/systemStore'
import ImportResolutionModal from '../modals/ImportResolutionModal.vue'

const store = useSystemStore()
const form = ref({})
const saving = ref(false)
const analyzing = ref(false)
const fileInput = ref(null)
const analysisData = ref(null)

onMounted(() => {
  form.value = { ...store.settings }
})

const saveSettings = async () => {
  saving.value = true;
  try {
    await axios.put('/api/v1/settings', form.value);
    store.settings = { ...form.value }; 
    store.addToast('Settings applied securely.');
  } catch (error) {
    store.addToast('Failed to apply settings.', 'danger');
  } finally {
    saving.value = false;
  }
}

const deleteUser = async (id) => {
  if (!confirm("Delete this user?")) return;
  try {
    await axios.delete(`/api/v1/users/${id}`);
    store.users = store.users.filter(u => u.id !== id);
    store.addToast('User deleted.');
  } catch (e) {
    store.addToast(e.response?.data?.message || 'Error deleting user', 'danger');
  }
}

// --- CSV Import Logic ---
const triggerFileInput = () => { fileInput.value.click() }

const handleAnalyze = async (event) => {
  const file = event.target.files[0]
  if (!file) return

  analyzing.value = true
  const formData = new FormData()
  formData.append('file', file) 

  try {
    await store.checkAuth() // Ensure CSRF token is fresh
    const response = await axios.post('/api/v1/system/import/analyze', formData, {
      headers: { 'Content-Type': 'multipart/form-data', 'X-CSRFToken': store.csrfToken }
    })
    
    if (response.data.success) {
      // The analysisData object will now contain 'conflicts' keyed by device name
      analysisData.value = response.data.analysis
    }
  } catch (error) {
    store.addToast(error.response?.data?.message || 'Failed to analyze CSV.', 'danger')
  } finally {
    analyzing.value = false
    event.target.value = '' // Reset input
  }
}

const onMergeComplete = () => {
  analysisData.value = null
}
</script>
