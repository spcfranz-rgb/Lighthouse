import { createRouter, createWebHistory } from 'vue-router'
import { useSystemStore } from '../stores/systemStore'
import DashboardView from '../views/DashboardView.vue'
import LoginView from '../views/LoginView.vue'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    { path: '/', name: 'dashboard', component: DashboardView, meta: { requiresAuth: true } },
    { path: '/login', name: 'login', component: LoginView },
    // You can easily add the HistoryView later: 
    // { path: '/history', name: 'history', component: () => import('../views/HistoryView.vue'), meta: { requiresAuth: true } }
  ]
})

router.beforeEach(async (to, from, next) => {
  const store = useSystemStore()
  
  // ALWAYS hydrate auth state & CSRF token on first load
  if (!store.csrfToken) {
    await store.checkAuth()
  }

  if (to.meta.requiresAuth && !store.user) {
    next({ name: 'login' })
  } else if (to.name === 'login' && store.user) {
    next({ name: 'dashboard' })
  } else {
    next()
  }
})

export default router
