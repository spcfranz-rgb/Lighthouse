import { defineStore } from 'pinia'
import { io } from 'socket.io-client'
import axios from 'axios'

export const useSystemStore = defineStore('system', {
  state: () => ({
    user: null,
    csrfToken: '',
    mqttOnline: false,
    uiOnline: false,
    logos: { company: null, customer: null },
    devices: { switches: [], nvrs: [], cameras: [] },
    toasts: []
  }),
  actions: {
    async checkAuth() {
      try {
        // Ping the auth status endpoint (does not require login)
        const response = await axios.get('/api/v1/auth/status')
        this.user = response.data.user
        this.csrfToken = response.data.csrf_token
        axios.defaults.headers.common['X-CSRFToken'] = this.csrfToken
        return true
      } catch (error) {
        // Even if 401 Unauthorized, Flask issues a CSRF token. We must save it for the login POST.
        if (error.response?.data?.csrf_token) {
          this.csrfToken = error.response.data.csrf_token
          axios.defaults.headers.common['X-CSRFToken'] = this.csrfToken
        }
        this.user = null
        return false
      }
    },

    async fetchSystemData() {
      try {
        // This requires login. It fetches the hardware data and logos.
        const { data } = await axios.get('/api/v1/system/init')
        this.devices = { switches: data.switches, nvrs: data.nvrs, cameras: data.cameras }
        this.logos = data.logos
        this.initSocket()
      } catch (error) {
        console.error("Failed to fetch system data:", error)
      }
    },

    async logout() {
      await axios.post('/api/v1/auth/logout')
      this.user = null
      window.location.href = '/login'
    },

    addToast(message, type = 'success') {
      const id = Date.now()
      this.toasts.push({ id, message, type })
      setTimeout(() => { this.toasts = this.toasts.filter(t => t.id !== id) }, 4000)
    },

    initSocket() {
      const socket = io()
      socket.on('connect', () => { this.uiOnline = true })
      socket.on('disconnect', () => { this.uiOnline = false; this.mqttOnline = false })
      socket.on('gateway_status', (data) => { this.mqttOnline = data.mqtt })
      socket.on('state_change', (data) => {
        const target = this.devices[data.type]?.find(d => d.id === data.id)
        if (target) target.status = data.status
      })
    }
  }
})
