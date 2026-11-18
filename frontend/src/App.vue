<template>
  <n-config-provider>
    <n-message-provider>
      <router-view v-if="route.path === '/login'"/>
      <div v-else class="app-layout" :class="{ 'nav-hidden': !sidebarOpen }">
        <button v-if="sidebarOpen" class="mobile-overlay" aria-label="关闭菜单" @click="toggleSidebar"></button>
        <aside v-show="sidebarOpen" class="sidebar" aria-label="主导航">
          <div class="brand"><strong>SCC CVE</strong><button class="toggle close-toggle" aria-label="隐藏侧边栏" title="隐藏侧边栏" @click="toggleSidebar">‹</button></div>
          <nav>
            <router-link class="menu-parent dashboard-link" to="/dashboard" @click="closeOnMobile">运行看板</router-link>
            <section v-for="group in groups" :key="group.key" class="menu-group">
              <button class="menu-parent" :class="{ 'group-active': group.children.some(child => child.path === route.path) }" :aria-expanded="expanded[group.key]" @click="toggleGroup(group.key)">
                <span>{{ group.label }}</span><span class="chevron" :class="{ rotated: expanded[group.key] }" aria-hidden="true">›</span>
              </button>
              <div v-show="expanded[group.key]" class="submenu">
                <router-link v-for="child in group.children" :key="child.path" :to="child.path" @click="closeOnMobile">{{ child.label }}</router-link>
              </div>
            </section>
          </nav>
        </aside>
        <div class="workspace">
          <div class="workspace-bar">
            <button v-if="!sidebarOpen" class="toggle open-toggle" aria-label="展开侧边栏" title="展开侧边栏" @click="toggleSidebar">☰</button>
            <span class="breadcrumb">{{ currentLabel }}</span>
          </div>
          <div class="workspace-content"><router-view/></div>
        </div>
      </div>
    </n-message-provider>
  </n-config-provider>
</template>
<script setup>
import { ref, reactive, computed, watch } from 'vue'
import { useRoute } from 'vue-router'
import { NConfigProvider, NMessageProvider } from 'naive-ui'

const route = useRoute()
const groups = [
  { key: 'cve', label: 'CVE情报', children: [
    { label: '漏洞监控', path: '/vulnerabilities' },
    { label: '运行记录', path: '/run-records' },
    { label: '情报来源配置', path: '/sources' },
    { label: 'CVE情报推送配置', path: '/push-settings' }
  ] },
  { key: 'msoc', label: 'MSOC推送', children: [
    { label: 'MSOC日志', path: '/msoc-logs' },
    { label: 'MSOC推送配置', path: '/msoc-push-settings' }
  ] },
  { key: 'mail', label: '邮件推送', children: [
    { label: '邮件推送列表', path: '/mail-tasks' },
    { label: '邮件模版', path: '/mail-templates' }
  ] },
  { key: 'common', label: '公共配置', children: [
    { label: 'AI配置', path: '/ai-settings' }
  ] }
]
const isMobile = () => window.matchMedia('(max-width: 760px)').matches
const sidebarOpen = ref(!isMobile() && localStorage.getItem('scc-sidebar-open') !== 'false')
const expanded = reactive({ cve: false, msoc: false, mail: false, common: false })
function toggleSidebar() {
  sidebarOpen.value = !sidebarOpen.value
  if (!isMobile()) localStorage.setItem('scc-sidebar-open', String(sidebarOpen.value))
}
function closeOnMobile() {
  if (isMobile()) sidebarOpen.value = false
}
function toggleGroup(key) { expanded[key] = !expanded[key] }
watch(() => route.path, path => {
  const active = groups.find(group => group.children.some(child => child.path === path))
  if (active) expanded[active.key] = true
  if (path === '/skill-settings') expanded.common = true
}, { immediate: true })
const currentLabel = computed(() => {
  if (route.path === '/dashboard') return '运行看板'
  if (route.path === '/skill-settings') return '公共配置 / AI配置 / Skill 配置'
  for (const group of groups) {
    const child = group.children.find(item => item.path === route.path)
    if (child) return group.label + ' / ' + child.label
  }
  return 'SCC CVE'
})
</script>
<style>
html,body,#app{margin:0;min-height:100%;width:100%}
</style>
<style scoped>
.app-layout{--sidebar-width:232px;min-height:100vh;background:#f5f7fa;color:#243447}
.sidebar{position:fixed;inset:0 auto 0 0;width:var(--sidebar-width);box-sizing:border-box;background:#17253a;color:#dce7f4;display:flex;flex-direction:column;z-index:30;overflow-y:auto}
.brand{height:62px;flex-shrink:0;padding:0 17px 0 22px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #314158}
.brand strong{font-size:20px;letter-spacing:.5px;color:#fff}
.sidebar nav{padding:15px 12px 24px}
.menu-parent{display:flex;align-items:center;justify-content:space-between;box-sizing:border-box;width:100%;padding:12px 13px;border:0;border-radius:6px;background:transparent;color:#dce7f4;font:inherit;font-weight:600;font-size:14px;text-decoration:none;text-align:left;cursor:pointer}
.menu-parent:hover,.submenu a:hover{background:#243a55;color:#fff}
.menu-parent.group-active{color:#85caff}
.dashboard-link.router-link-active,.submenu a.router-link-active{background:#26496b;color:#a5d8ff;font-weight:600}
.menu-group{margin-top:5px}
.chevron{font-size:20px;line-height:1;transition:transform .15s}
.chevron.rotated{transform:rotate(90deg)}
.submenu{padding:3px 0 5px 12px}
.submenu a{display:block;padding:10px 12px;margin:3px 0;border-radius:5px;text-decoration:none;color:#c4d3e5;font-size:13px;overflow-wrap:anywhere}
.workspace{margin-left:var(--sidebar-width);min-width:0}
.nav-hidden .workspace{margin-left:0}
.workspace-bar{display:flex;align-items:center;gap:14px;min-height:52px;padding:0 20px;background:#fff;border-bottom:1px solid #e4eaf1;box-sizing:border-box}
.breadcrumb{font-size:13px;color:#65758a}
.toggle{border:0;background:transparent;cursor:pointer;border-radius:5px;font-size:19px;line-height:1;padding:7px 10px}
.close-toggle{color:#dce7f4;font-size:26px}
.close-toggle:hover{background:#243a55}
.open-toggle{color:#243447}
.open-toggle:hover{background:#eef2f6}
.workspace-content{min-width:0;max-width:100%;overflow-x:auto;min-height:calc(100vh - 53px)}
.mobile-overlay{display:none}
@media(max-width:760px){
  .workspace{margin-left:0}
  .sidebar{width:min(var(--sidebar-width),85vw)}
  .mobile-overlay{display:block;position:fixed;inset:0;border:0;background:rgba(15,23,42,.36);z-index:29}
  .workspace-bar{padding:0 12px}
}
</style>
