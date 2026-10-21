<template><div style="max-width:1000px;margin:35px auto;padding:20px"><n-space justify="space-between" align="center"><h2>情报来源配置</h2><n-space><n-button @click="$router.push('/vulnerabilities')">返回漏洞列表</n-button><n-button type="primary" @click="newSource">新增来源</n-button></n-space></n-space><n-alert type="warning" style="margin-bottom:20px">启用来源不代表采集器已实现。请在完成 Python 采集适配器后再启用自动采集。</n-alert><n-data-table :data="rows" :columns="columns"/><n-modal v-model:show="visible" preset="card" title="情报来源" style="max-width:540px"><n-form><n-form-item label="名称"><n-input v-model:value="form.name"/></n-form-item><n-form-item label="适配器标识"><n-input v-model:value="form.adapter" placeholder="对应 Python 采集器标识"/></n-form-item><n-form-item label="备注"><n-input v-model:value="form.notes"/></n-form-item><n-form-item label="启用"><n-switch v-model:value="form.enabled"/></n-form-item><n-button type="primary" @click="save">保存</n-button></n-form></n-modal></div></template>
<script setup>
import {ref,h,onMounted} from 'vue'
import {NButton,NSpace,NDataTable,NModal,NForm,NFormItem,NInput,NSwitch,NAlert,useMessage} from 'naive-ui'
import axios from 'axios'
const msg=useMessage(),rows=ref([]),visible=ref(false),editing=ref(null),form=ref({name:'',adapter:'',notes:'',enabled:false})
const http=axios.create({baseURL:'/api/v1/settings/sources'})
http.interceptors.request.use(c=>{c.headers.Authorization='Bearer '+(localStorage.getItem('token')||'');return c})
async function load(){try{rows.value=(await http.get('')).data.data}catch(e){msg.error(e.response?.data?.detail||e.message)}}
function newSource(){editing.value=null;form.value={name:'',adapter:'',notes:'',enabled:false};visible.value=true}
function edit(r){editing.value=r.id;form.value={...r};visible.value=true}
async function save(){try{if(editing.value)await http.put('/'+editing.value,form.value);else await http.post('',form.value);visible.value=false;await load()}catch(e){msg.error(e.response?.data?.detail||e.message)}}
async function remove(r){if(!confirm('确定删除 '+r.name+'？'))return;try{await http.delete('/'+r.id);await load()}catch(e){msg.error(e.message)}}
const columns=[{title:'来源',key:'name'},{title:'适配器',key:'adapter'},{title:'启用',key:'enabled',render:r=>r.enabled?'是':'否'},{title:'备注',key:'notes'},{title:'操作',key:'actions',render:r=>h(NSpace,{},()=>[h(NButton,{size:'small',onClick:()=>edit(r)},()=> '编辑'),h(NButton,{size:'small',type:'error',onClick:()=>remove(r)},()=> '删除')])}]
onMounted(load)
</script>