<template>
<div class="page">
  <h2>邮箱配置</h2>
  <n-card title="Teams Webhook 发信配置">
    <n-form label-placement="top">
      <n-form-item label="Teams Webhook URL"><n-input v-model:value="webhookUrl" type="password" show-password-on="click" :placeholder="configured?'已保存，留空保留':'粘贴 Power Automate 的 HTTP POST URL'"/></n-form-item>
      <n-alert type="info" style="margin-bottom:16px">通过 HTTPS 443 提交 Adaptive Card 格式的邮件任务。请使用公司授权的工作流，妥善保管带签名的 URL，并在流程中限制允许的收件人。Webhook 接收成功不代表 Outlook 已发送。</n-alert>
      <n-space align="center"><n-button type="primary" :loading="saving" @click="save">保存配置</n-button><n-tag :type="configured?'success':'warning'">{{configured?'已配置':'未配置'}}</n-tag></n-space>
    </n-form>
  </n-card>
  <n-card title="邮件发送记录" style="margin-top:16px">
    <template #header-extra><n-button @click="loadLogs">刷新</n-button></template>
    <n-data-table :columns="columns" :data="rows" :loading="logsLoading" :pagination="false" :row-key="r=>r.id" :scroll-x="1200"/>
    <n-space justify="end" style="margin-top:16px"><n-pagination :page="page" :page-size="10" :item-count="total" @update:page="changePage"/><span>共 {{total}} 条，每页 10 条</span></n-space>
  </n-card>
  <n-modal v-model:show="detailOpen" preset="card" title="邮件发送详情" style="width:min(950px,95vw);max-height:92vh;overflow:auto">
    <n-descriptions bordered :column="1">
      <n-descriptions-item label="发件人">{{detail.sender}}</n-descriptions-item>
      <n-descriptions-item label="收件人">{{detail.recipient}}</n-descriptions-item>
      <n-descriptions-item label="主题">{{detail.subject}}</n-descriptions-item>
      <n-descriptions-item label="关联任务">{{detail.task_id||'—'}}</n-descriptions-item>
      <n-descriptions-item label="发送时间">{{time(detail.created_at)}}</n-descriptions-item>
      <n-descriptions-item label="状态">{{detail.status}}</n-descriptions-item>
    </n-descriptions>
    <n-alert v-if="detail.error" type="warning" style="margin-top:12px">{{detail.error}}</n-alert>
    <h3>发送内容</h3><pre class="mail-body">{{detail.body}}</pre>
  </n-modal>
</div>
</template>
<script setup>
import {ref,h,onMounted} from 'vue'
import axios from 'axios'
import {NAlert,NButton,NCard,NDataTable,NDescriptions,NDescriptionsItem,NForm,NFormItemGi,NGrid,NInput,NInputNumber,NModal,NPagination,NSelect,NSpace,NTag,useMessage} from 'naive-ui'
const msg=useMessage(),saving=ref(false),configured=ref(false),webhookUrl=ref(''),logsLoading=ref(false),rows=ref([]),total=ref(0),page=ref(1),detailOpen=ref(false),detail=ref({})
const http=axios.create({baseURL:'/api/v1/settings/email',timeout:120000})
http.interceptors.request.use(c=>{c.headers.Authorization='Bearer '+(localStorage.getItem('token')||'');return c})
const err=e=>typeof e.response?.data?.detail==='string'?e.response.data.detail:e.message
const time=v=>v?new Date(/[zZ]$|[+-][0-9]{2}:[0-9]{2}$/.test(v)?v:v+'Z').toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false}):'—'
const columns=[
 {title:'ID',key:'id',width:65},{title:'发送时间',key:'created_at',width:180,render:r=>time(r.created_at)},
 {title:'发件人',key:'sender',minWidth:180,ellipsis:{tooltip:true}},{title:'收件人',key:'recipient',minWidth:180,ellipsis:{tooltip:true}},
 {title:'邮件主题',key:'subject',minWidth:220,ellipsis:{tooltip:true}},{title:'状态',key:'status',width:120,render:r=>h(NTag,{type:['SMTP已接收','Webhook已接收'].includes(r.status)?'success':r.status==='发送失败'?'error':'warning'},()=>r.status)},
 {title:'操作',key:'action',width:120,render:r=>h(NButton,{text:true,type:'primary',onClick:()=>view(r)},()=> '查看内容')}
]
async function loadSettings(){try{configured.value=(await http.get('/teams')).data.data.configured}catch(e){msg.error(err(e))}}
async function save(){saving.value=true;try{configured.value=(await http.put('/teams',{webhook_url:webhookUrl.value})).data.data.configured;webhookUrl.value='';msg.success('Webhook 配置已保存')}catch(e){msg.error(err(e))}finally{saving.value=false}}
async function loadLogs(){logsLoading.value=true;try{const d=(await http.get('/logs',{params:{page:page.value}})).data.data;rows.value=d.list;total.value=d.total}catch(e){msg.error(err(e))}finally{logsLoading.value=false}}
function changePage(v){page.value=v;loadLogs()}
async function view(r){try{detail.value=(await http.get('/logs/'+r.id)).data.data;detailOpen.value=true}catch(e){msg.error(err(e))}}
onMounted(()=>{loadSettings();loadLogs()})
</script>
<style scoped>
.page{box-sizing:border-box;margin:16px auto;width:calc(100% - 32px);padding:0 0 24px;min-width:0}
.mail-body{white-space:pre-wrap;overflow-wrap:anywhere;background:#f6f7fa;padding:16px;border-radius:6px;max-height:55vh;overflow:auto}
</style>
