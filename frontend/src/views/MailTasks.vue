<template>
<div class="mail-page">
  <n-space justify="space-between" align="center"><h2>邮件推送列表</h2><n-button type="primary" @click="open">创建任务</n-button></n-space>
  <n-space style="margin:16px 0"><n-input v-model:value="q" clearable placeholder="搜索任务 / CVE / 邮件主题 / 收件人" @keyup.enter="search"/><n-button @click="search">查询</n-button></n-space>
  <n-data-table :columns="columns" :data="rows" :loading="loading" :row-key="r=>r.id" :pagination="false" :scroll-x="1100"/>
  <n-space justify="end" style="margin-top:16px"><n-pagination :page="page" :page-size="20" :item-count="total" @update:page="changePage"/></n-space>
  <n-modal v-model:show="visible" preset="card" title="创建任务" style="width:min(850px,95vw)" :mask-closable="false">
    <n-form label-placement="top">
      <n-form-item label="任务名称"><n-input v-model:value="form.name"/></n-form-item>
      <n-form-item label="CVE 编号（选填）"><n-input v-model:value="form.cve"/></n-form-item>
      <n-form-item label="邮件模版（选填）"><n-select v-model:value="form.template_id" :options="templateOptions" clearable @update:value="applyTemplate"/></n-form-item>
      <n-form-item label="收件人"><n-input v-model:value="form.recipients" placeholder="多个邮箱用逗号或分号分隔"/></n-form-item>
      <n-form-item label="抄送（选填）"><n-input v-model:value="form.cc"/></n-form-item>
      <n-form-item label="邮件主题"><n-input v-model:value="form.subject"/></n-form-item>
      <n-form-item label="邮件正文"><n-input v-model:value="form.body" type="textarea" :autosize="{minRows:10,maxRows:24}"/></n-form-item>
    </n-form>
    <n-space justify="end"><n-button @click="visible=false">取消</n-button><n-button type="primary" :disabled="!ready" :loading="saving" @click="save">创建任务</n-button></n-space>
  </n-modal>
  <n-modal v-model:show="detailOpen" preset="card" title="任务详情" style="width:min(850px,95vw)">
    <n-descriptions bordered :column="1"><n-descriptions-item label="任务名称">{{detail.name}}</n-descriptions-item><n-descriptions-item label="CVE">{{detail.cve||'—'}}</n-descriptions-item><n-descriptions-item label="收件人">{{detail.recipients}}</n-descriptions-item><n-descriptions-item label="抄送">{{detail.cc||'—'}}</n-descriptions-item><n-descriptions-item label="邮件主题">{{detail.subject}}</n-descriptions-item><n-descriptions-item label="状态">{{detail.status}}</n-descriptions-item></n-descriptions>
    <pre class="body">{{detail.body}}</pre>
  </n-modal>
</div>
</template>
<script setup>
import {ref,computed,h,onMounted} from 'vue'
import axios from 'axios'
import {NButton,NDataTable,NDescriptions,NDescriptionsItem,NForm,NFormItem,NInput,NModal,NPagination,NSelect,NSpace,NTag,useMessage} from 'naive-ui'
const msg=useMessage(),rows=ref([]),q=ref(''),page=ref(1),total=ref(0),loading=ref(false),saving=ref(false),visible=ref(false),detailOpen=ref(false),detail=ref({}),templates=ref([])
const blank=()=>({name:'',cve:'',template_id:null,recipients:'',cc:'',subject:'',body:''})
const form=ref(blank())
const ready=computed(()=>['name','recipients','subject','body'].every(k=>form.value[k].trim()))
const templateOptions=computed(()=>templates.value.map(r=>({label:r.name,value:r.id})))
const http=axios.create({baseURL:'/api/v1/mail'})
http.interceptors.request.use(c=>{c.headers.Authorization='Bearer '+(localStorage.getItem('token')||'');return c})
const time=v=>v?new Date(/[zZ]$|[+-][0-9]{2}:[0-9]{2}$/.test(v)?v:v+'Z').toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false}):'—'
const columns=[
 {title:'ID',key:'id',width:65},{title:'任务名称',key:'name',minWidth:160},{title:'CVE',key:'cve',width:155},{title:'邮件主题',key:'subject',minWidth:230,ellipsis:{tooltip:true}},
 {title:'收件人',key:'recipients',minWidth:180,ellipsis:{tooltip:true}},{title:'状态',key:'status',width:90,render:r=>h(NTag,{type:'warning'},()=>r.status)},
 {title:'创建时间',key:'created_at',width:180,render:r=>time(r.created_at)},{title:'操作',key:'action',width:120,render:r=>h(NSpace,{size:8},()=>[h(NButton,{text:true,type:'primary',onClick:()=>view(r)},()=> '查看'),h(NButton,{text:true,type:'error',onClick:()=>remove(r)},()=> '删除')])}
]
async function load(){loading.value=true;try{const d=(await http.get('/tasks',{params:{q:q.value,page:page.value,size:20}})).data.data;total.value=d.total;if(page.value>Math.max(1,Math.ceil(total.value/20))){page.value=Math.max(1,Math.ceil(total.value/20));const next=(await http.get('/tasks',{params:{q:q.value,page:page.value,size:20}})).data.data;rows.value=next.list;total.value=next.total}else rows.value=d.list}catch(e){msg.error(e.response?.data?.detail||e.message)}finally{loading.value=false}}
function search(){page.value=1;load()}
function changePage(v){page.value=v;load()}
async function open(){form.value=blank();templates.value=[];visible.value=true;try{templates.value=(await http.get('/templates')).data.data}catch(e){msg.error('读取邮件模版失败')}}
function applyTemplate(id){const t=templates.value.find(r=>r.id===id);if(t){form.value.subject=t.subject;form.value.body=t.body}}
async function save(){if(!ready.value||saving.value)return;saving.value=true;try{await http.post('/tasks',form.value);visible.value=false;msg.success('任务已创建，尚未发送邮件');q.value='';page.value=1;await load()}catch(e){msg.error(e.response?.data?.detail||e.message)}finally{saving.value=false}}
async function view(r){try{detail.value=(await http.get('/tasks/'+r.id)).data.data;detailOpen.value=true}catch(e){msg.error(e.response?.data?.detail||e.message)}}
async function remove(r){if(!confirm('确认删除任务 '+r.name+'？'))return;try{await http.delete('/tasks/'+r.id);msg.success('已删除');await load()}catch(e){msg.error(e.response?.data?.detail||e.message)}}
onMounted(load)
</script>
<style scoped>
.mail-page{box-sizing:border-box;margin:16px auto;width:calc(100% - 32px);background:#fff;border-radius:10px;padding:24px;min-width:0}
.body{white-space:pre-wrap;overflow-wrap:anywhere;max-height:55vh;overflow:auto;font:inherit;line-height:1.7;background:#f5f7fa;padding:16px}
</style>
