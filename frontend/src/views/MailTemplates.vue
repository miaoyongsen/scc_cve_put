<template>
  <div class="mail-page">
    <n-space justify="space-between" align="center"><h2>邮件模版</h2><n-button type="primary" @click="open()">创建模版</n-button></n-space>
    <n-space align="center" style="margin:16px 0"><n-input v-model:value="q" clearable placeholder="搜索模版名称 / 邮件主题" @keyup.enter="load"/><n-button @click="load">查询</n-button></n-space>
    <n-data-table :columns="columns" :data="rows" :loading="loading" :row-key="r=>r.id" :pagination="{pageSize:20}" :scroll-x="850"/>
    <n-modal v-model:show="visible" preset="card" :title="editing?'编辑模版':'创建模版'" style="width:min(850px,95vw)" :mask-closable="false">
      <n-form label-placement="top">
        <n-form-item label="模版名称"><n-input v-model:value="form.name" placeholder="例如：CTI安全预警"/></n-form-item>
        <n-form-item label="邮件主题"><n-input v-model:value="form.subject"/></n-form-item>
        <n-form-item label="邮件正文"><n-input v-model:value="form.body" type="textarea" :autosize="{minRows:10,maxRows:24}"/></n-form-item>
      </n-form>
      <n-space justify="end"><n-button @click="visible=false">取消</n-button><n-button type="primary" :loading="saving" :disabled="!ready" @click="save">保存模版</n-button></n-space>
    </n-modal>
    <n-modal v-model:show="detailOpen" preset="card" title="模版详情" style="width:min(850px,95vw)">
      <h3>{{detail.name}}</h3><p><strong>邮件主题：</strong>{{detail.subject}}</p><pre class="body">{{detail.body}}</pre>
      <n-space justify="end"><n-button @click="detailOpen=false">关闭</n-button></n-space>
    </n-modal>
  </div>
</template>
<script setup>
import {ref,computed,h,onMounted} from 'vue'
import axios from 'axios'
import {NButton,NDataTable,NForm,NFormItem,NInput,NModal,NSpace,useMessage} from 'naive-ui'
const msg=useMessage(),rows=ref([]),q=ref(''),loading=ref(false),saving=ref(false),visible=ref(false),editing=ref(null),detailOpen=ref(false),detail=ref({})
const blank=()=>({name:'',subject:'',body:''})
const form=ref(blank())
const ready=computed(()=>Object.values(form.value).every(v=>String(v).trim()))
const http=axios.create({baseURL:'/api/v1/mail/templates'})
http.interceptors.request.use(c=>{c.headers.Authorization='Bearer '+(localStorage.getItem('token')||'');return c})
const time=v=>v?new Date(/[zZ]$|[+-]\d{2}:\d{2}$/.test(v)?v:v+'Z').toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false}):'—'
const columns=[
  {title:'ID',key:'id',width:70},
  {title:'模版名称',key:'name',minWidth:170},
  {title:'邮件主题',key:'subject',minWidth:250,ellipsis:{tooltip:true}},
  {title:'更新时间',key:'updated_at',width:180,render:r=>time(r.updated_at)},
  {title:'操作',key:'action',width:190,render:r=>h(NSpace,{size:8},()=>[
    h(NButton,{text:true,type:'primary',onClick:()=>{detail.value=r;detailOpen.value=true}},()=> '查看'),
    h(NButton,{text:true,type:'primary',onClick:()=>open(r)},()=> '编辑'),
    h(NButton,{text:true,type:'error',onClick:()=>remove(r)},()=> '删除')
  ])}
]
async function load(){loading.value=true;try{rows.value=(await http.get('',{params:{q:q.value}})).data.data}catch(e){msg.error(e.response?.data?.detail||e.message)}finally{loading.value=false}}
function open(r){editing.value=r?.id??null;form.value=r?{name:r.name,subject:r.subject,body:r.body}:blank();visible.value=true}
async function save(){if(!ready.value||saving.value)return;saving.value=true;try{if(editing.value)await http.put('/'+editing.value,form.value);else await http.post('',form.value);visible.value=false;msg.success('模版已保存');await load()}catch(e){msg.error(e.response?.data?.detail||e.message)}finally{saving.value=false}}
async function remove(r){if(!confirm('确认删除模版 '+r.name+'？已有任务的邮件内容不会改变。'))return;try{await http.delete('/'+r.id);msg.success('已删除');await load()}catch(e){msg.error(e.response?.data?.detail||e.message)}}
onMounted(load)
</script>
<style scoped>
.mail-page{box-sizing:border-box;margin:16px auto;width:calc(100% - 32px);background:#fff;border-radius:10px;padding:24px;min-width:0}
.body{white-space:pre-wrap;overflow-wrap:anywhere;max-height:55vh;overflow:auto;font:inherit;line-height:1.7;background:#f5f7fa;padding:16px}
</style>
