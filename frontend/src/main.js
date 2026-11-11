import { createApp } from 'vue'
import { createPinia } from 'pinia'
import { createRouter, createWebHistory } from 'vue-router'
import { create, NConfigProvider, NMessageProvider } from 'naive-ui'
import App from './App.vue'
import Login from './views/Login.vue'
import Vulnerabilities from './views/Vulnerabilities.vue'
import Sources from './views/Sources.vue'
import PushSettings from './views/PushSettings.vue'
import AISettings from './views/AISettings.vue'
import SkillSettings from './views/SkillSettings.vue'
import RunRecords from './views/RunRecords.vue'
import Dashboard from './views/Dashboard.vue'
import MSOCLogs from './views/MSOCLogs.vue'
import MSOCPushSettings from './views/MSOCPushSettings.vue'
const router = createRouter({history:createWebHistory(),routes:[
{path:'/login',component:Login},
{path:'/',redirect:'/dashboard'},
{path:'/dashboard',component:Dashboard},
{path:'/vulnerabilities',component:Vulnerabilities},
{path:'/sources',component:Sources},
{path:'/run-records',component:RunRecords},
{path:'/push-settings',component:PushSettings},
{path:'/ai-settings',component:AISettings},
{path:'/skill-settings',component:SkillSettings},
{path:'/msoc-logs',component:MSOCLogs},
{path:'/msoc-push-settings',component:MSOCPushSettings}
]})
router.beforeEach(to=>{if(to.path!='/login'&&!localStorage.getItem('token'))return '/login'})
createApp(App).use(createPinia()).use(router).mount('#app')
