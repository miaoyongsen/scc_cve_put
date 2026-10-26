import { createApp } from 'vue'
import { createPinia } from 'pinia'
import { createRouter, createWebHistory } from 'vue-router'
import { create, NConfigProvider, NMessageProvider } from 'naive-ui'
import App from './App.vue'
import Login from './views/Login.vue'
import Vulnerabilities from './views/Vulnerabilities.vue'
import Sources from './views/Sources.vue'
import PushSettings from './views/PushSettings.vue'
const router = createRouter({history:createWebHistory(),routes:[
{path:'/login',component:Login},
{path:'/',redirect:'/vulnerabilities'},
{path:'/vulnerabilities',component:Vulnerabilities},
{path:'/sources',component:Sources},
{path:'/push-settings',component:PushSettings}
]})
router.beforeEach(to=>{if(to.path!='/login'&&!localStorage.getItem('token'))return '/login'})
createApp(App).use(createPinia()).use(router).mount('#app')
