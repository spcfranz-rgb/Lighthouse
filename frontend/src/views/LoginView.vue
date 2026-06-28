<template>
  <main class="form-signin w-100 m-auto mt-5" style="max-width: 400px;">
    <div class="card shadow-sm border-secondary">
      <div class="card-body p-4 text-center">
        <h1 class="h4 mb-4 fw-normal">Gateway Access</h1>
        
        <form @submit.prevent="handleLogin">
          <div class="form-floating mb-2">
            <input type="text" v-model="username" class="form-control bg-dark text-light border-secondary" placeholder="Username" required>
            <label>Username</label>
          </div>
          <div class="form-floating mb-3">
            <input type="password" v-model="password" class="form-control bg-dark text-light border-secondary" placeholder="Password" required>
            <label>Password</label>
          </div>
          <button class="btn btn-warning w-100 py-2 fw-bold" type="submit" :disabled="loading">
            {{ loading ? 'Authenticating...' : 'Local Sign In' }}
          </button>
        </form>
      </div>
    </div>
  </main>
</template>

<script setup>
import { ref } from 'vue'
import axios from 'axios'
import { useRouter } from 'vue-router'
import { useSystemStore } from '../stores/systemStore'

const username = ref('')
const password = ref('')
const loading = ref(false)
const router = useRouter()
const store = useSystemStore()

const handleLogin = async () => {
  loading.value = true
  try {
    await axios.post('/api/v1/auth/login', { username: username.value, password: password.value })
    await store.checkAuth()
    router.push('/')
  } catch (error) {
    alert("Invalid local credentials")
  } finally {
    loading.value = false
  }
}
</script>
