import { defineStore } from 'pinia'
import { io } from 'socket.io-client'
import axios from 'axios'

export const useSystemStore = defineStore('system', {
  state: () => ({
    user: null,
    csrfToken: '',
    mqttOnline: false,
    uiOnline: false,
    socketId: null,
    logos: { company: null, customer: null },
    devices: { switches: [], nvrs: [], cameras: [] },
    settings: {},
    users: [],
    latestSpeedtest: null,
    defaultSubnet: '192.168.1.0/24',
    webrtcConfig: null, // <-- ADD THIS
    toasts: []
  }),
  actions: {
    async checkAuth() {
      try {
        const response = await axios.get('/api/v1/auth/status')
        this.user = response.data.user
        this.csrfToken = response.data.csrf_token
        axios.defaults.headers.common['X-CSRFToken'] = this.csrfToken
        return true
      } catch (error) {
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
        const { data } = await axios.get('/api/v1/system/init')
        this.devices = { switches: data.switches, nvrs: data.nvrs, cameras: data.cameras }
        this.logos = data.logos
        this.settings = data.settings || {}
        this.users = data.users || []
        this.latestSpeedtest = data.latest_speedtest || null
        this.defaultSubnet = data.default_subnet || '192.168.1.0/24'
        this.webrtcConfig = data.webrtc_config // <-- HYDRATE THIS
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
      if (this._socket) return;
      this._socket = io()
      this._socket.on('connect', () => { 
        this.uiOnline = true 
        this.socketId = this._socket.id
      })
      this._socket.on('disconnect', () => { this.uiOnline = false; this.mqttOnline = false })
      this._socket.on('gateway_status', (data) => { this.mqttOnline = data.mqtt })
      this._socket.on('state_change', (data) => {
        const target = this.devices[data.type]?.find(d => d.id === data.id)
        if (target) target.status = data.status
      })
      
      // PERMANENT LISTENER: Always catch automated speed tests running in the background
      this._socket.on('speedtest_result', (data) => {
        if (data.success) {
          this.latestSpeedtest = data;
        }
      })
    },
    listen(event, callback) { if (this._socket) this._socket.on(event, callback) },
    // FIX: Require the exact callback reference so we don't accidentally wipe the permanent listeners
    unlisten(event, callback) { if (this._socket) this._socket.off(event, callback) } 
  }
})
