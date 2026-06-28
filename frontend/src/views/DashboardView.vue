<template>
  <div>
    <TopNav />
    
    <ul class="nav nav-tabs mb-4 border-secondary">
      <li class="nav-item">
        <a class="nav-link text-light" :class="{ 'active bg-dark border-secondary border-bottom-0 fw-bold': activeTab === 'monitoring' }" href="#" @click.prevent="activeTab = 'monitoring'">Monitoring</a>
      </li>
      <li class="nav-item">
        <a class="nav-link text-light" :class="{ 'active bg-dark border-secondary border-bottom-0 fw-bold': activeTab === 'diagnostics' }" href="#" @click.prevent="activeTab = 'diagnostics'">Diagnostics</a>
      </li>
      <li class="nav-item" v-if="store.user?.role === 'admin'">
        <a class="nav-link text-light" :class="{ 'active bg-dark border-secondary border-bottom-0 fw-bold': activeTab === 'admin' }" href="#" @click.prevent="activeTab = 'admin'">Administration</a>
      </li>
    </ul>

    <div v-if="activeTab === 'monitoring'">
      
      <div class="d-flex justify-content-between align-items-center mb-3">
        <h4 class="mb-0 text-light d-none d-md-block">Hardware Overview</h4>
        <div v-if="store.user?.role === 'admin'" class="btn-group w-100 w-md-auto shadow-sm">
          <button class="btn btn-outline-success fw-bold" @click="showScannerModal = true">🔍 Auto-Discover</button>
          <button class="btn btn-outline-info fw-bold" @click="showAddModal = true">➕ Add Device</button>
        </div>
      </div>

      <div class="row mb-4">
        <div class="col-lg-6 mb-4 mb-lg-0">
          <DeviceTable 
            title="Network Switches" 
            type="switches" 
            :devices="store.devices.switches" 
            @edit="openEdit" 
          />
        </div>
        <div class="col-lg-6">
          <DeviceTable 
            title="Network Video Recorders" 
            type="nvrs" 
            :devices="store.devices.nvrs" 
            @edit="openEdit" 
          />
        </div>
      </div>
      
      <div class="row">
        <div class="col-12">
          <DeviceTable 
            title="Cameras" 
            type="cameras" 
            :devices="store.devices.cameras" 
            @preview="openPreview" 
            @edit="openEdit" 
          />
        </div>
      </div>
    </div>

    <div v-if="activeTab === 'diagnostics'">
      <DiagnosticsTab />
    </div>

    <div v-if="activeTab === 'admin'">
      <AdminTab />
    </div>

    <WebRtcPreviewModal 
      v-if="previewCam" 
      :camera="previewCam" 
      @close="previewCam = null" 
    />
    
    <DeviceAddModal 
      v-if="showAddModal" 
      @close="showAddModal = false" 
    />
    
    <NetworkScannerModal 
      v-if="showScannerModal" 
      @close="showScannerModal = false" 
    />

    <DeviceEditModal 
      v-if="editingDevice" 
      :device="editingDevice" 
      :type="editingType" 
      @close="editingDevice = null" 
    />

  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'

// Sub-components
import TopNav from '../components/layout/TopNav.vue'
import DeviceTable from '../components/monitoring/DeviceTable.vue'
import DiagnosticsTab from '../components/dashboard/DiagnosticsTab.vue'
import AdminTab from '../components/dashboard/AdminTab.vue'

// Modals
import WebRtcPreviewModal from '../components/modals/WebRtcPreviewModal.vue'
import DeviceAddModal from '../components/modals/DeviceAddModal.vue'
import NetworkScannerModal from '../components/modals/NetworkScannerModal.vue'
import DeviceEditModal from '../components/modals/DeviceEditModal.vue'

// State Management
import { useSystemStore } from '../stores/systemStore'

const store = useSystemStore()
const activeTab = ref('monitoring')

// --- Modal Visibility States ---
const previewCam = ref(null)
const showAddModal = ref(false)
const showScannerModal = ref(false)
const editingDevice = ref(null)
const editingType = ref(null)

// --- Lifecycle ---
onMounted(() => {
  // Fetch hardware grid, settings, and latest speed test on load
  store.fetchSystemData()
})

// --- Action Handlers ---
const openPreview = (cam) => {
  previewCam.value = cam
}

const openEdit = (device, type) => {
  editingDevice.value = device
  editingType.value = type
}
</script>
