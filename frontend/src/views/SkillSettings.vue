<template><div class="settings"><n-space justify="space-between" align="center"><h2>Skill 配置</h2><n-button type="primary" @click="create">新增 Skill</n-button></n-space><n-alert type="info" style="margin-bottom:16px">每个 Skill 定义 AI 的分析原则和输出格式。到 AI 配置页面选择启用的 Skill。</n-alert><n-data-table :columns="columns" :data="rows" :row-key="r=>r.id"/><n-modal v-model:show="visible" preset="card" :title="editing?'编辑 Skill':'新增 Skill'" style="width:min(850px,95vw)"><n-form-item label="名称"><n-input v-model:value="form.name"/></n-form-item><n-form-item label="分析规范"><n-input v-model:value="form.instructions" type="textarea" :rows="10"/></n-form-item><n-form-item label="输出模板"><n-input v-model:value="form.output_format" type="textarea" :rows="8"/></n-form-item><n-button type="primary" @click="save">保存 Skill</n-button></n-modal></div></template>
<script setup>
import {h,ref,onMounted} from 'vue'
import axios from 'axios'
import {NButton,NSpace,NAlert,NDataTable,NModal,NFormItem,NInput,useMessage} from 'naive-ui'
const msg=useMessage(),rows=ref([]),visible=ref(false),editing=ref(0)
const form=ref({name:'',instructions:'',output_format:''})
const http=axios.create({baseURL:'/api/v1/settings/ai/skills'})
http.interceptors.request.use(c=>{c.headers.Authorization='Bearer '+(localStorage.getItem('token')||'');return c})
async function load(){try{rows.value=(await http.get('')).data.data}catch(e){msg.error(e.response?.data?.detail||e.message)}}
function create(){editing.value=0;form.value={name:'',instructions:'',output_format:''};visible.value=true}
function edit(r){editing.value=r.id;form.value={name:r.name,instructions:r.instructions,output_format:r.output_format};visible.value=true}
async function save(){if(!form.value.name.trim()||!form.value.instructions.trim())return msg.warning('请填写名称和分析规范');try{if(editing.value)await http.put('/'+editing.value,form.value);else await http.post('',form.value);visible.value=false;msg.success('已保存');await load()}catch(e){msg.error(e.response?.data?.detail||e.message)}}
async function remove(r){if(!confirm('确定删除 '+r.name+'？'))return;try{await http.delete('/'+r.id);msg.success('已删除');await load()}catch(e){msg.error(e.response?.data?.detail||e.message)}}
const columns=[{title:'名称',key:'name'},{title:'分析规范',key:'instructions',ellipsis:{tooltip:true}},{title:'输出模板',key:'output_format',ellipsis:{tooltip:true}},{title:'操作',key:'actions',width:180,render:r=>h(NSpace,{},()=>[h(NButton,{size:'small',onClick:()=>edit(r)},()=> '编辑'),h(NButton,{size:'small',type:'error',onClick:()=>remove(r)},()=> '删除')])}]
onMounted(load)
</script>
<style scoped>.settings{max-width:1000px;margin:35px auto;padding:20px}</style>