<template><div style="max-width:1000px;margin:35px auto;padding:20px"><n-space justify="space-between" align="center"><h2>情报来源配置</h2><n-space><n-button @click="$router.push('/vulnerabilities')">返回漏洞列表</n-button><n-button type="primary" @click="newSource">新增来源</n-button></n-space></n-space><n-alert type="warning" style="margin-bottom:20px">目前支持 RSS/Atom 公开 HTTPS 订阅源。适配器填 rss，备注填订阅地址。爬虫模式可选择，但目前尚未实现爬虫适配器，选择后不会执行抓取。原 9 个专用采集器也尚未迁移。</n-alert><n-card title="自动采集设置" style="margin-bottom:20px"><n-space align="center"><span>采集间隔</span><n-select v-model:value="intervalMinutes" :options="intervalOptions" style="width:180px"/><n-button type="primary" :loading="savingInterval" @click="saveInterval">保存周期</n-button></n-space><p style="color:#888">保存后立即生效，无需重启服务；默认每 60 分钟采集一次。</p></n-card><n-data-table :data="rows" :columns="columns"/><n-modal v-model:show="visible" preset="card" title="情报来源" style="max-width:540px"><n-form><n-form-item label="名称"><n-input v-model:value="form.name"/></n-form-item><n-form-item label="采集方式"><n-select v-model:value="form.adapter" :options="sourceTypes"/></n-form-item><n-form-item label="订阅 URL（RSS 时填写在此）"><n-input v-model:value="form.notes"/></n-form-item><n-form-item label="API Key（留空不修改）"><n-input v-model:value="apiKey" type="password" placeholder="可选密钥"/></n-form-item><n-form-item label="请求头名称"><n-input v-model:value="headerName" placeholder="Authorization 或 X-API-Key"/></n-form-item><n-form-item label="启用"><n-switch v-model:value="form.enabled"/></n-form-item><n-button type="primary" @click="save">保存</n-button></n-form></n-modal></div></template>
<script setup>
import {ref,h,onMounted} from 'vue'
import {NButton,NSpace,NDataTable,NModal,NForm,NFormItem,NInput,NSelect,NCard,NSwitch,NAlert,useMessage} from 'naive-ui'
import axios from 'axios'
const intervalMinutes=ref(60),savingInterval=ref(false)
const intervalOptions=[15,30,60,180,360,720,1440].map(n=>({label:n<60?n+' 分钟':n/60+' 小时',value:n}))
const collectionHttp=axios.create({baseURL:'/api/v1/settings/collection'})
collectionHttp.interceptors.request.use(c=>{c.headers.Authorization='Bearer '+(localStorage.getItem('token')||'');return c})
async function loadInterval(){try{intervalMinutes.value=(await collectionHttp.get('')).data.data.interval_minutes}catch(e){msg.error('读取采集周期失败：'+(e.response?.data?.detail||e.message))}}
async function saveInterval(){savingInterval.value=true;try{await collectionHttp.put('',{interval_minutes:intervalMinutes.value});msg.success('采集周期已保存，无需重启')}catch(e){msg.error(e.response?.data?.detail||e.message)}finally{savingInterval.value=false}}
const sourceTypes=[{label:'RSS / Atom（可用）',value:'rss'},{label:'网页爬虫（开发中）',value:'crawler',disabled:true}]
const apiKey=ref(''),headerName=ref('Authorization')
const msg=useMessage(),rows=ref([]),visible=ref(false),editing=ref(null),form=ref({name:'',adapter:'',notes:'',enabled:false})
const http=axios.create({baseURL:'/api/v1/settings/sources'})
http.interceptors.request.use(c=>{c.headers.Authorization='Bearer '+(localStorage.getItem('token')||'');return c})
async function load(){try{rows.value=(await http.get('')).data.data}catch(e){msg.error(e.response?.data?.detail||e.message)}}
function newSource(){apiKey.value='';headerName.value='Authorization';editing.value=null;form.value={name:'',adapter:'',notes:'',enabled:false};visible.value=true}
function edit(r){apiKey.value='';headerName.value='Authorization';editing.value=r.id;form.value={...r};visible.value=true}
async function save(){try{let id=editing.value;if(id)await http.put('/'+id,form.value);else id=(await http.post('',form.value)).data.data.id;if(apiKey.value)await http.put('/'+id+'/credential',{api_key:apiKey.value,header_name:headerName.value});visible.value=false;await load()}catch(e){msg.error(e.response?.data?.detail||e.message)}}
async function remove(r){if(!confirm('确定删除 '+r.name+'？'))return;try{await http.delete('/'+r.id);await load()}catch(e){msg.error(e.message)}}
const columns=[{title:'来源',key:'name'},{title:'适配器',key:'adapter'},{title:'启用',key:'enabled',render:r=>r.enabled?'是':'否'},{title:'备注',key:'notes'},{title:'操作',key:'actions',render:r=>h(NSpace,{},()=>[h(NButton,{size:'small',onClick:()=>edit(r)},()=> '编辑'),h(NButton,{size:'small',type:'error',onClick:()=>remove(r)},()=> '删除')])}]
onMounted(()=>{load();loadInterval()})
</script>