<template><div class="settings"><n-space justify="space-between" align="center"><h2>Skill 配置</h2><n-button type="primary" @click="create">新增 Skill</n-button></n-space><n-alert type="info" style="margin-bottom:16px">在此维护全部 Skill 和 CVE 推送研判关联；邮件 AI 使用的固定 Skill 在邮件推送列表的 AI配置中设置。</n-alert><n-card title="AI 调用关联" style="margin-bottom:18px"><n-form-item label="CVE情报 → 最终推送 AI研判"><n-select v-model:value="bindings.cve_push" :options="options"/></n-form-item><n-form-item label="邮件推送 → CVE邮件 AI填充"><n-space align="center"><span>{{options.find(x=>x.value===mailSkill)?.label||"未选择"}}</span><n-button size="small" @click="$router.push('/mail-tasks')">前往邮件 AI配置</n-button></n-space></n-form-item><n-button type="primary" :loading="bindingSaving" @click="saveBindings">保存调用关联</n-button></n-card><n-data-table :columns="columns" :data="rows" :row-key="r=>r.id" :scroll-x="1000"/><n-modal v-model:show="visible" preset="card" :title="editing?'编辑 Skill':'新增 Skill'" style="width:min(850px,95vw)"><n-form-item label="名称"><n-input v-model:value="form.name"/></n-form-item><n-form-item label="分析规范"><n-input v-model:value="form.instructions" type="textarea" :rows="10"/></n-form-item><n-form-item label="输出模板"><n-input v-model:value="form.output_format" type="textarea" :rows="8"/></n-form-item><n-button type="primary" @click="save">保存 Skill</n-button></n-modal></div></template>
<script setup>
import {h,ref,computed,onMounted} from 'vue'
import axios from 'axios'
import {NButton,NSpace,NAlert,NDataTable,NModal,NFormItem,NInput,NCard,NSelect,useMessage} from 'naive-ui'
const msg=useMessage(),rows=ref([]),visible=ref(false),editing=ref(0)
const bindings=ref({cve_push:0}),mailSkill=ref(0),bindingSaving=ref(false)
const options=computed(()=>[{label:'不使用 Skill（默认规范）',value:0},...rows.value.map(r=>({label:r.name,value:r.id}))])
const form=ref({name:'',instructions:'',output_format:''})
const http=axios.create({baseURL:'/api/v1/settings/ai/skills'})
http.interceptors.request.use(c=>{c.headers.Authorization='Bearer '+(localStorage.getItem('token')||'');return c})
async function load(){try{rows.value=(await http.get('')).data.data;const b=(await http.get('/api/v1/settings/ai/skill-bindings',{baseURL:''})).data.data;mailSkill.value=b.mail_skill||0;bindings.value={cve_push:b.cve_push||0}}catch(e){msg.error(e.response?.data?.detail||e.message)}}
async function saveBindings(){bindingSaving.value=true;try{await http.put('/api/v1/settings/ai/skill-bindings',bindings.value,{baseURL:''});msg.success('调用关联已保存');await load()}catch(e){msg.error(e.response?.data?.detail||e.message)}finally{bindingSaving.value=false}}
function create(){editing.value=0;form.value={name:'',instructions:'',output_format:''};visible.value=true}
function edit(r){editing.value=r.id;form.value={name:r.name,instructions:r.instructions,output_format:r.output_format};visible.value=true}
async function save(){if(!form.value.name.trim()||!form.value.instructions.trim())return msg.warning('请填写名称和分析规范');try{if(editing.value)await http.put('/'+editing.value,form.value);else await http.post('',form.value);visible.value=false;msg.success('已保存');await load()}catch(e){msg.error(e.response?.data?.detail||e.message)}}
async function remove(r){if(!confirm('确定删除 '+r.name+'？'))return;try{await http.delete('/'+r.id);msg.success('已删除');await load()}catch(e){msg.error(e.response?.data?.detail||e.message)}}
const columns=[{title:'名称',key:'name'},{title:'分析规范',key:'instructions',ellipsis:{tooltip:true}},{title:'输出模板',key:'output_format',ellipsis:{tooltip:true}},{title:'关联调用',key:'usage',minWidth:180,render:r=>(r.usage||[]).join('；')||'未关联'},{title:'操作',key:'actions',width:180,render:r=>h(NSpace,{},()=>[h(NButton,{size:'small',onClick:()=>edit(r)},()=> '编辑'),h(NButton,{size:'small',type:'error',onClick:()=>remove(r)},()=> '删除')])}]
onMounted(load)
</script>
<style scoped>.settings{max-width:1000px;margin:35px auto;padding:20px}</style>