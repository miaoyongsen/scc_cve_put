<template>
<div class="page">
  <h2>邮箱配置</h2>
  <n-card title="SMTP 发信配置">
    <n-form label-placement="top">
      <n-grid :cols="2" :x-gap="16" responsive="screen" item-responsive>
        <n-form-item-gi span="2 m:1" label="邮箱账号"><n-input v-model:value="form.username" placeholder="user@example.com"/></n-form-item-gi>
        <n-form-item-gi span="2 m:1" label="邮箱密码 / SMTP 授权码"><n-input v-model:value="form.password" type="password" show-password-on="click" :placeholder="hasPassword?'已保存，留空保留':'输入邮箱授权码或密码'"/></n-form-item-gi>
        <n-form-item-gi span="2 m:1" label="SMTP 服务器"><n-input v-model:value="form.host" placeholder="smtp.example.com"/></n-form-item-gi>
        <n-form-item-gi span="2 m:1" label="加密方式"><n-select v-model:value="form.security" :options="securityOptions" @update:value="changeSecurity"/></n-form-item-gi>
        <n-form-item-gi span="2 m:1" label="SMTP 端口"><n-input-number v-model:value="form.port" :min="1" :max="65535" style="width:100%"/></n-form-item-gi>
        <n-form-item-gi span="2 m:1" label="微软流接收邮箱"><n-input v-model:value="form.flow_recipient" placeholder="绑定 Power Automate 的公司邮箱"/></n-form-item-gi>
      </n-grid>
      <n-alert type="info" style="margin-bottom:16px">请使用已获授权的 SMTP 邮箱。连接测试使用当前输入的配置，无需先保存，不发送邮件；CVE任务将向微软流接收邮箱发送 SCC-CTI-TASK JSON 正文邮件。</n-alert>
      <n-space><n-button type="primary" :loading="saving" :disabled="testing" @click="save">保存配置</n-button><n-button :loading="testing" :disabled="saving" @click="test">测试连接</n-button></n-space>
      <n-alert v-if="testResult" :type="testResult.ok?'success':'error'" style="margin-top:12px">{{testResult.text}}</n-alert>
      <div v-if="testResult?.steps?.length" style="margin-top:16px">
        <n-space justify="space-between" align="center"><strong>SMTP 连接诊断</strong><n-button size="small" @click="copyDiagnosis">复制诊断日志</n-button></n-space>
        <n-data-table style="margin-top:12px" :columns="diagnosisColumns" :data="testResult.steps" :pagination="false" :row-key="r=>r.name" :scroll-x="650"/>
        <pre class="mail-body" style="max-height:240px">{{diagnosisText()}}</pre>
      </div>
    </n-form>
  </n-card>
  <n-card title="发送测试邮件" style="margin-top:16px">
    <n-space align="center"><n-input v-model:value="testRecipient" placeholder="测试收件邮箱" style="width:min(320px,70vw)"/><n-button :loading="testSending" :disabled="!testRecipient.trim()" @click="sendTest">发送测试邮件</n-button></n-space>
    <p style="color:#777">使用普通测试主题，不触发 SCC-CTI-TASK 邮件流。使用已保存的 SMTP 配置。</p>
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
const msg=useMessage(),saving=ref(false),testing=ref(false),testSending=ref(false),logsLoading=ref(false),hasPassword=ref(false),testResult=ref(null),testRecipient=ref(''),rows=ref([]),total=ref(0),page=ref(1),detailOpen=ref(false),detail=ref({})
const form=ref({host:'',port:465,security:'ssl',username:'',password:'',flow_recipient:''})
const securityOptions=[{label:'SSL/TLS',value:'ssl'},{label:'STARTTLS',value:'starttls'}]
const http=axios.create({baseURL:'/api/v1/settings/email',timeout:120000})
http.interceptors.request.use(c=>{c.headers.Authorization='Bearer '+(localStorage.getItem('token')||'');return c})
const err=e=>typeof e.response?.data?.detail==='string'?e.response.data.detail:e.message
const time=v=>v?new Date(/[zZ]$|[+-][0-9]{2}:[0-9]{2}$/.test(v)?v:v+'Z').toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false}):'—'
const columns=[
 {title:'ID',key:'id',width:65},{title:'发送时间',key:'created_at',width:180,render:r=>time(r.created_at)},
 {title:'发件人',key:'sender',minWidth:180,ellipsis:{tooltip:true}},{title:'收件人',key:'recipient',minWidth:180,ellipsis:{tooltip:true}},
 {title:'邮件主题',key:'subject',minWidth:220,ellipsis:{tooltip:true}},{title:'状态',key:'status',width:120,render:r=>h(NTag,{type:r.status==='SMTP已接收'?'success':r.status==='发送失败'?'error':'warning'},()=>r.status)},
 {title:'操作',key:'action',width:120,render:r=>h(NButton,{text:true,type:'primary',onClick:()=>view(r)},()=> '查看内容')}
]
function changeSecurity(v){form.value.port=v==='ssl'?465:587}
function apply(d){form.value={host:d.host,port:d.port,security:d.security,username:d.username,password:'',flow_recipient:d.flow_recipient};hasPassword.value=d.has_password}
async function loadSettings(){try{apply((await http.get('')).data.data)}catch(e){msg.error(err(e))}}
async function save(){saving.value=true;testResult.value=null;try{apply((await http.put('',form.value)).data.data);msg.success('邮箱配置已保存')}catch(e){msg.error(err(e))}finally{saving.value=false}}
const diagnosisColumns=[
 {title:'诊断阶段',key:'name',width:150},
 {title:'结果',key:'status',width:90,render:r=>h(NTag,{type:r.status==='成功'?'success':r.status==='失败'?'error':'default'},()=>r.status)},
 {title:'耗时',key:'elapsed_ms',width:100,render:r=>r.elapsed_ms==null?'—':r.elapsed_ms+' ms'},
 {title:'详细响应 / 错误',key:'detail',minWidth:300,render:r=>h('span',{style:'white-space:pre-wrap;overflow-wrap:anywhere'},r.detail||'—')}
]
function diagnosisText(){
 const d=testResult.value
 if(!d)return ''
 return [d.text,'SMTP服务器：'+(d.server||'—'),'加密方式：'+(d.security||'—'),...(d.steps||[]).map(r=>r.name+' | '+r.status+' | '+(r.elapsed_ms==null?'—':r.elapsed_ms+' ms')+' | '+(r.detail||'—'))].join('\n')
}
async function copyDiagnosis(){
 try{await navigator.clipboard.writeText(diagnosisText());msg.success('已复制诊断日志')}
 catch(e){const a=document.createElement('textarea');a.value=diagnosisText();document.body.appendChild(a);a.select();try{if(!document.execCommand('copy'))throw Error('copy failed');msg.success('已复制诊断日志')}catch(e){msg.warning('请手动选择下方日志复制')}finally{a.remove()}}
}
async function test(){testing.value=true;testResult.value=null;try{const d=(await http.post('/test',form.value)).data.data;testResult.value={ok:d.success,text:d.message,steps:d.steps,server:d.server,security:d.security};if(d.success)msg.success(d.message);else msg.error(d.message)}catch(e){testResult.value={ok:false,text:err(e)};msg.error(err(e))}finally{testing.value=false}}
async function loadLogs(){logsLoading.value=true;try{const d=(await http.get('/logs',{params:{page:page.value}})).data.data;rows.value=d.list;total.value=d.total}catch(e){msg.error(err(e))}finally{logsLoading.value=false}}
function changePage(v){page.value=v;loadLogs()}
async function view(r){try{detail.value=(await http.get('/logs/'+r.id)).data.data;detailOpen.value=true}catch(e){msg.error(err(e))}}
async function sendTest(){if(!confirm('确认发送测试邮件至 '+testRecipient.value+'？'))return;testSending.value=true;try{const d=(await http.post('/send-test',{recipient:testRecipient.value})).data.data;if(d.status==='SMTP已接收')msg.success('SMTP 已接收测试邮件');else msg.warning(d.error||d.status)}catch(e){msg.error(err(e))}finally{testSending.value=false;page.value=1;await loadLogs()}}
onMounted(()=>{loadSettings();loadLogs()})
</script>
<style scoped>
.page{box-sizing:border-box;margin:16px auto;width:calc(100% - 32px);padding:0 0 24px;min-width:0}
.mail-body{white-space:pre-wrap;overflow-wrap:anywhere;background:#f6f7fa;padding:16px;border-radius:6px;max-height:55vh;overflow:auto}
</style>
