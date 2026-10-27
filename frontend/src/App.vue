<template>
  <n-config-provider>
    <n-message-provider>
      <div v-if="$route.path !== '/login'" class="global-nav">
        <strong>SCC CVE</strong>
        <nav>
          <router-link to="/vulnerabilities">漏洞监控</router-link>
          <router-link to="/sources">情报来源配置</router-link>
          <router-link to="/push-settings">推送配置</router-link>
          <router-link to="/ai-settings">AI 配置</router-link>
          <router-link to="/skill-settings">Skill 配置</router-link>
        </nav>
        <span class="build">AI 来源联动 · 2026-10-27</span>
      </div>
      <router-view/>
    </n-message-provider>
  </n-config-provider>
</template>
<script setup>
import {NConfigProvider,NMessageProvider} from 'naive-ui'
</script>
<style scoped>
.global-nav{display:flex;align-items:center;gap:24px;flex-wrap:wrap;padding:14px 28px;background:#17253a;color:white}
.global-nav nav{display:flex;flex-wrap:wrap;gap:18px}
.global-nav a{color:#dce7f4;text-decoration:none}
.global-nav a.router-link-active{color:#69c0ff;font-weight:700}
.build{margin-left:auto;color:#9fb1c6;font-size:12px}
</style>