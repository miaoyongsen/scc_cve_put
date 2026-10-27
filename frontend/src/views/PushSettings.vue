<template>
<div style="max-width:950px;margin:35px auto;padding:20px">
<n-space justify="space-between" align="center"><h2>推送配置</h2><n-button @click="$router.push('/sources')">返回来源配置</n-button></n-space>
<n-alert type="info" style="margin-bottom:16px">一级情报自动推送，二级情报审核后推送。此处配置通知渠道及额外过滤规则；静默时间内跳过推送，不会自动补发。</n-alert>
<n-card title="企业微信机器人" style="margin-bottom:16px">
<n-space align="center"><span>启用企业微信</span><n-switch v-model:value="form.wecom_enabled"/></n-space>
<n-form-item label="机器人 Webhook（留空保留已保存密钥）"><n-input v-model:value="form.wecom_webhook" type="password" show-password-on="click" placeholder="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=..."/></n-form-item>
<n-text depth="3">{{hasWebhook?'已保存 Webhook（不会回显）':'尚未保存 Webhook'}}</n-text>
<n-space style="margin-top:12px"><n-button type="primary" :loading="saving" @click="save">保存配置</n-button><n-button :loading="testing" @click="test">发送测试消息</n-button></n-space>
</n-card>
<n-card title="推送规则">
<n-form-item label="允许推送的等级（不勾选表示不限等级）"><n-checkbox-group v-model:value="form.severity_filter"><n-space><n-checkbox v-for="x in levels" :key="x" :value="x" :label="x"/></n-space></n-checkbox-group></n-form-item>
<n-form-item label="允许推送的来源（英文逗号分隔；留空表示全部来源）"><n-input v-model:value="form.source_filter" placeholder="奇安信,GitHub Advisory"/></n-form-item>
<n-form-item label="静默开始时间（HH:MM，服务器本地时间）"><n-input v-model:value="form.quiet_start" placeholder="例如 23:00"/></n-form-item>
<n-form-item label="静默结束时间（HH:MM）"><n-input v-model:value="form.quiet_end" placeholder="例如 08:00"/></n-form-item>
<n-button type="primary" :loading="saving" @click="save">保存全部规则</n-button>
</n-card><n-card title="企业微信推送模板" style="margin-top:16px"><n-alert type="info" style="margin-bottom:12px">支持变量：{title} 标题、{cve} 编号、{severity} 等级、{source} 来源、{disclosure} 日期、{description} 描述、{solutions} 修复建议、{url} 原始链接。修改后保存即生效。</n-alert><n-input v-model:value="form.message_template" type="textarea" :rows="12" placeholder="输入 Markdown 推送模板"/><n-space style="margin-top:12px"><n-button type="primary" :loading="saving" @click="save">保存推送模板</n-button><n-button @click="resetTemplate">恢复默认模板（需保存）</n-button></n-space><h3>实时预览</h3><pre style="white-space:pre-wrap;background:#f5f7fa;padding:16px;border-radius:6px">{{preview}}</pre></n-card></div>
</template>
<script setup>
import {ref,computed,onMounted} from 'vue'
import axios from 'axios'
import {NCard,NSpace,NButton,NAlert,NFormItem,NInput,NSwitch,NText,NCheckbox,NCheckboxGroup,useMessage} from 'naive-ui'
const msg=useMessage(),saving=ref(false),testing=ref(false),hasWebhook=ref(false),levels=['严重','高危','中危','低危','未知']
const defaultTemplate="## WatchVuln 漏洞情报\n> **标题**：{title}\n> **CVE**：{cve}\n> **等级**：{severity}\n> **来源**：{source}\n> **披露日期**：{disclosure}\n> 请前往 IP Sentinel 漏洞监控查看详情"
const form=ref({wecom_enabled:false,wecom_webhook:'',severity_filter:[],source_filter:'',quiet_start:'',quiet_end:'',dedup_hours:0,message_template:defaultTemplate})
function resetTemplate(){form.value.message_template=defaultTemplate}
const preview=computed(()=>{const sample={title:'Apache 示例漏洞',cve:'CVE-2026-12345',severity:'高危',source:'奇安信',disclosure:'2026-10-26',description:'示例漏洞描述',solutions:'参考官方修复公告',url:'https://example.com'};let result=(form.value.message_template||'').split(String.fromCharCode(92)+'n').join(String.fromCharCode(10));for(const [key,value] of Object.entries(sample))result=result.split('{'+key+'}').join(value);return result})
const http=axios.create({baseURL:'/api/v1/settings/push'})
http.interceptors.request.use(c=>{c.headers.Authorization='Bearer '+(localStorage.getItem('token')||'');return c})
async function load(){try{const d=(await http.get('')).data.data;hasWebhook.value=d.has_webhook;form.value={...form.value,...d,wecom_webhook:''}}catch(e){msg.error(String(e.response?.data?.detail||e.message))}}
async function save(){saving.value=true;try{await http.put('',form.value);msg.success('配置已保存');await load()}catch(e){msg.error(String(e.response?.data?.detail||e.message))}finally{saving.value=false}}
async function test(){testing.value=true;try{await http.post('/test');msg.success('测试消息已发送')}catch(e){msg.error(String(e.response?.data?.detail||e.message))}finally{testing.value=false}}
onMounted(load)
</script>