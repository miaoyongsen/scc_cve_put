<template><div class="settings"><h2>AI 配置</h2><n-alert type="info">管理模型连接参数与全局回复规范。模型调用尚未接入；配置保存后供后续 AI 分析流程使用。</n-alert><n-card title="模型设置" style="margin-top:16px"><n-form-item label="服务商"><n-input v-model:value="form.provider" placeholder="OpenAI-compatible"/></n-form-item><n-form-item label="模型名称"><n-input v-model:value="form.model" placeholder="模型 ID"/></n-form-item><n-form-item label="API 地址"><n-input v-model:value="form.api_url" placeholder="https://..."/></n-form-item><n-form-item label="系统提示词"><n-input v-model:value="form.system_prompt" type="textarea" :rows="10"/></n-form-item><n-form-item label="启用 Skill"><n-select v-model:value="form.active_skill" :options="options"/></n-form-item><n-space><n-button type="primary" @click="save">保存配置</n-button><n-button @click="preview">预览最终提示词</n-button></n-space></n-card><n-modal v-model:show="visible" preset="card" title="最终提示词" style="width:min(850px,95vw)"><pre style="white-space:pre-wrap">{{prompt}}</pre></n-modal></div></template>
<script setup>
import {ref,computed,onMounted} from 'vue'
import axios from 'axios'
import {NAlert,NCard,NFormItem,NInput,NSelect,NButton,NSpace,NModal,useMessage} from 'naive-ui'
const msg=useMessage()
const form=ref({provider:'',model:'',api_url:'',system_prompt:'',active_skill:0})
const skills=ref([]),visible=ref(false),prompt=ref('')
const options=computed(()=>[{label:'不使用 Skill',value:0},...skills.value.map(x=>({label:x.name,value:x.id}))])
const http=axios.create({baseURL:'/api/v1/settings/ai'})
http.interceptors.request.use(c=>{c.headers.Authorization='Bearer '+(localStorage.getItem('token')||'');return c})
async function load(){try{form.value=(await http.get('')).data.data;skills.value=(await http.get('/skills')).data.data}catch(e){msg.error(e.response?.data?.detail||e.message)}}
async function save(){try{await http.put('',form.value);msg.success('已保存')}catch(e){msg.error(e.response?.data?.detail||e.message)}}
async function preview(){try{prompt.value=(await http.get('/prompt')).data.data.prompt;visible.value=true}catch(e){msg.error(e.response?.data?.detail||e.message)}}
onMounted(load)
</script>
<style scoped>.settings{max-width:920px;margin:35px auto;padding:20px}</style>