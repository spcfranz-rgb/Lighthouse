<template>
  <div class="d-flex flex-column flex-md-row justify-content-between align-items-md-center mb-4 border-bottom pb-3 gap-3">
    <div class="d-flex align-items-center justify-content-center justify-content-md-start">
      <img v-if="store.logos.company" :src="store.logos.company" alt="Company Logo" style="height: 30px; object-fit: contain;" class="me-3 border-end border-secondary pe-3">
      <img v-if="store.logos.customer" :src="store.logos.customer" alt="Customer Logo" style="height: 40px; object-fit: contain;" class="me-3">
      <h1 class="mb-0 h4">CCTV Dashboard</h1>
    </div>
    
    <div class="d-flex align-items-center gap-2">
      <span class="badge" :class="store.mqttOnline ? 'bg-success' : 'bg-danger'">MQTT: {{ store.mqttOnline ? 'Online' : 'Offline' }}</span>
      <span class="badge" :class="store.uiOnline ? 'bg-success' : 'bg-danger'">UI: {{ store.uiOnline ? 'Online' : 'Offline' }}</span>
    </div>

    <div class="d-flex flex-wrap align-items-center justify-content-center gap-2">
      <span class="small text-muted">User: <strong>{{ store.user?.username }}</strong></span>
      <button @click="store.logout" class="btn btn-outline-light btn-sm">Logout</button>
    </div>
  </div>
</template>

<script setup>
import { useSystemStore } from '../../stores/systemStore'
const store = useSystemStore()
</script>
