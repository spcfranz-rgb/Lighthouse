import { createRouter, createWebHistory } from 'vue-router'
import { useSystemStore } from '../stores/systemStore'
import DashboardView from '../views/DashboardView.vue'
import LoginView from '../views/LoginView.vue'
import EventLogsView from '../views/EventLogsView.vue' // <-- 1. Add static import here

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    { 
      path: '/', 
      name: 'dashboard', 
      component: DashboardView, 
      meta: { requiresAuth: true } 
    },
    { 
      path: '/logs', 
      name: 'logs', 
      component: EventLogsView, // <-- 2. Replace dynamic import with static component
      meta: { requiresAuth: true } 
    },
    { 
      path: '/login', 
      name: 'login', 
      component: LoginView 
    },
    // Catch-all route to redirect invalid paths to dashboard or login
    { 
      path: '/:pathMatch(.*)*', 
      redirect: '/' 
    }
  ]
})

router.beforeEach(async (to, from, next) => {
  const store = useSystemStore()
  
  // 1. Ensure we have authenticated against the backend before making routing decisions
  if (!store.user) {
    await store.checkAuth()
  }

  // 2. Route Protection Logic
  if (to.meta.requiresAuth) {
    if (store.user) {
      next()
    } else {
      next({ name: 'login', query: { redirect: to.fullPath } })
    }
  } else if (to.name === 'login' && store.user) {
    // Prevent logged-in users from hitting the login page
    next({ name: 'dashboard' })
  } else {
    next()
  }
})

export default router
