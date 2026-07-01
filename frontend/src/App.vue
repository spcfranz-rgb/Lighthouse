<template>
  <div class="container py-4">
    <div aria-live="polite" aria-atomic="true" class="position-relative">
      <div class="toast-container position-fixed bottom-0 end-0 p-3" style="z-index: 1060;">
        <div v-for="toast in store.toasts" :key="toast.id" class="toast show align-items-center text-white border-0" :class="`bg-${toast.type}`" role="alert">
          <div class="d-flex">
            <div class="toast-body fw-bold">{{ toast.message }}</div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" @click="removeToast(toast.id)"></button>
          </div>
        </div>
      </div>
    </div>
    <router-view />
  </div>
</template>

<script setup>
import { onMounted, onUnmounted } from 'vue'
import { useSystemStore } from './stores/systemStore'
import { useRouter } from 'vue-router'

const store = useSystemStore()
const router = useRouter()

let idleTimer
let throttleTimer = false

const resetIdleTimer = () => {
  // Throttle to a maximum of 1 execution per second to prevent CPU thrashing
  if (throttleTimer) return;
  throttleTimer = true;
  setTimeout(() => { throttleTimer = false }, 1000);

  clearTimeout(idleTimer)
  
  // Dynamically grab the timeout setting, default to 20 if undefined/null
  const timeoutMinutes = parseInt(store.settings?.inactive_timeout ?? 20)
  
  // If timeout is > 0, set the timer. If 0, inactivity logout is disabled.
  if (timeoutMinutes > 0) {
    idleTimer = setTimeout(() => {
      if (store.user) {
        store.logout()
        store.addToast('Logged out due to inactivity.', 'warning')
      }
    }, timeoutMinutes * 60 * 1000)
  }
}

onMounted(() => {
  // Add listeners for activity
  ['mousemove', 'keydown', 'scroll', 'mousedown'].forEach(evt => 
    window.addEventListener(evt, resetIdleTimer, { passive: true })
  )
  resetIdleTimer()
})

onUnmounted(() => {
  // Cleanup listeners
  ['mousemove', 'keydown', 'scroll', 'mousedown'].forEach(evt => 
    window.removeEventListener(evt, resetIdleTimer)
  )
  clearTimeout(idleTimer)
})

const removeToast = (id) => {
  store.toasts = store.toasts.filter(t => t.id !== id)
}
</script>
