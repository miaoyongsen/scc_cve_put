<template><div class="settings"><h2>AI 配置</h2><n-alert type="info">已适配 DeepSeek 官方 API，可保存密钥并测试连接。漏洞分析自动调用尚未接入。</n-alert><n-card title="模型设置" style="margin-top:16px"><n-form-item label="服务商"><n-input value="DeepSeek" disabled/></n-form-item><n-form-item label="模型"><n-select v-model:value="form.model" :options="modelOptions"/></n-form-item><n-form-item label="API 地址"><n-input value="https://api.deepseek.com/chat/completions" disabled/></n-form-item><n-form-item label="DeepSeek API Key（留空保持原密钥）"><n-input v-model:value="form.api_key" type="password" show-password-on="click" placeholder="sk-..."/></n-form-item><n-text depth="3">{{form.has_api_key?'已保存 API Key（不会回显）':'尚未保存 API Key'}}</n-text><n-form-item label="系统提示词"><n-input v-model:value="form.system_prompt" type="textarea" :rows="10"/></n-form-item><n-form-item label="启用 Skill"><n-select v-model:value="form.active_skill" :options="options"/></n-form-item><n-space><n-button type="primary" :loading="saving" @click="save">保存配置</n-button><n-button :loading="testing" @click="test">测试 DeepSeek 连接</n-button><n-button @click="preview">预览最终提示词</n-button></n-space></n-card><n-modal v-model:show="visible" preset="card" title="最终提示词" style="width:min(850px,95vw)"><pre style="white-space:pre-wrap">{{prompt}}</pre></n-modal></div></template>
<script setup>
import {ref,computed,onMounted} from 'vue'
import axios from 'axios'
import {NAlert,NCard,NFormItem,NInput,NSelect,NButton,NSpace,NModal,NText,useMessage} from 'naive-ui'
const msg=useMessage(),saving=ref(false),testing=ref(false)
const modelOptions=[{label:'DeepSeek V3（deepseek-chat）',value:'deepseek-chat'},{label:'DeepSeek R1（deepseek-reasoner）',value:'deepseek-reasoner'}]
const form=ref({provider:'DeepSeek',model:'deepseek-chat',api_url:'https://api.deepseek.com',api_key:'',has_api_key:false,system_prompt:'',active_skill:0})
const skills=ref([]),visible=ref(false),prompt=ref('')
const options=computed(()=>[{label:'不使用 Skill',value:0},...skills.value.map(x=>({label:x.name,value:x.id}))])
const http=axios.create({baseURL:'/api/v1/settings/ai'})
http.interceptors.request.use(c=>{c.headers.Authorization='Bearer '+(localStorage.getItem('token')||'');return c})
async function load(){try{form.value={...form.value,...(await http.get('')).data.data,api_key:'',provider:'DeepSeek',api_url:'https://api.deepseek.com',model:(await http.get('')).data.data.model||'deepseek-chat'};skills.value=(await http.get('/skills')).data.data}catch(e){msg.error(e.response?.data?.detail||e.message)}}
async function save(){saving.value=true;try{await http.put('',{...form.value,provider:'DeepSeek',api_url:'https://api.deepseek.com'});msg.success('已保存');await load()}catch(e){msg.error(e.response?.data?.detail||e.message)}finally{saving.value=false}}
async function test(){testing.value=true;try{const r=await http.post('/test');msg.success('连接成功：'+(r.data.data.reply||'DeepSeek 已响应'))}catch(e){msg.error(e.response?.data?.detail||e.message)}finally{testing.value=false}}
async function preview(){try{prompt.value=(await http.get('/prompt')).data.data.prompt;visible.value=true}catch(e){msg.error(e.response?.data?.detail||e.message)}}
onMounted(load)
</script>
<style scoped>.settings{max-width:920px;margin:35px auto;padding:20px}</style>