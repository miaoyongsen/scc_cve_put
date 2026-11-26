<template>
  <div class="page">
    <n-space justify="space-between" align="center">
      <div>
        <h2>MSOC 推送配置</h2>
        <n-text depth="3">独立于 SCC_CVE 漏洞推送。定时查询 SCC_TT 最近时间窗口，发送状态保存在 SCC_CVE。</n-text>
      </div>
      <n-space>
        <n-button @click="refreshStatus">刷新状态</n-button>
        <n-button type="primary" :loading="polling" @click="pollNow">立即查询</n-button>
      </n-space>
    </n-space>

    <n-alert type="info" style="margin:14px 0">
      查询间隔同时代表查询时间范围：选择 3 分钟，就只查询最近 3 分钟的数据；选择 5 分钟，就只查询最近 5 分钟的数据。MSOC 日志会自动补齐 SCC_TT 各月份的历史记录；补录历史只用于查看和复盘，不会补推旧消息。正常企业微信推送仍只针对最近时间窗口内的首次待发送记录；发送失败不会自动重试。
    </n-alert>

    <n-grid :cols="4" :x-gap="12" :y-gap="12" responsive="screen" style="margin-bottom:16px">
      <n-grid-item><n-card size="small"><n-statistic label="监控状态" :value="status.enabled?'运行中':'已停止'"/></n-card></n-grid-item>
      <n-grid-item><n-card size="small"><n-statistic label="日志总数" :value="status.total_records||0"/></n-card></n-grid-item>
      <n-grid-item><n-card size="small"><n-statistic label="已发送" :value="status.sent_records||0"/></n-card></n-grid-item>
      <n-grid-item><n-card size="small"><n-statistic label="未发送" :value="status.unsent_records||0"/></n-card></n-grid-item>
    </n-grid>

    <n-alert v-if="status.last_error" type="error" style="margin-bottom:14px">
      最近一次异常：{{ status.last_error }}
    </n-alert>

    <n-card title="数据库监控设置">
      <n-form-item label="启用 MSOC 独立监控">
        <n-switch v-model:value="form.enabled"/>
        <n-text style="margin-left:10px">{{form.enabled?'启用后后台按设定间隔查询':'关闭后停止查询，不影响 SCC_CVE 漏洞采集和推送'}}</n-text>
      </n-form-item>
      <n-form-item label="SCC_TT SQLite 数据库路径">
        <n-input v-model:value="form.db_path" placeholder="/home/msocadmin/SCC_TT/data/webhook.db"/>
      </n-form-item>
      <n-form-item label="查询间隔 / 最近时间窗口">
        <n-select v-model:value="form.poll_interval" :options="intervalOptions" style="width:300px"/>
      </n-form-item>
      <n-text depth="3" style="display:block;margin-bottom:12px">
        例如选择 3 分钟：每 3 分钟执行一次查询，每次只读取 received_at 位于最近 3 分钟内的记录。
      </n-text>
      <n-space>
        <n-button type="primary" :loading="saving" @click="save">保存监控设置</n-button>
        <n-button :loading="testingDb" @click="testDb">测试数据库连接</n-button>
        <n-tag :type="status.worker_alive?'success':'warning'">后台任务：{{status.worker_alive?'已启动':'未启动'}}</n-tag>
        <n-tag v-if="status.running" type="info">正在查询/推送</n-tag>
      </n-space>
    </n-card>

    <n-card title="正常日志推送机器人" style="margin-top:16px">
      <n-alert type="info" style="margin-bottom:12px">
        关闭正常推送时，监控仍会把查询到的日志保存到 SCC_CVE，状态显示为未发送。只推送当前查询窗口内首次待发送的记录；发送失败后保留未发送状态，不自动补推。
      </n-alert>
      <n-form-item label="启用正常推送"><n-switch v-model:value="form.wecom_enabled"/></n-form-item>
      <n-form-item label="企业微信机器人 Webhook">
        <n-input v-model:value="form.wecom_webhook" placeholder="企业微信机器人 Webhook URL"/>
      </n-form-item>
      <n-text depth="3">{{status.has_wecom_webhook?'已保存 Webhook，可直接查看':'尚未保存 Webhook'}}</n-text>
      <n-space style="margin-top:12px">
        <n-button type="primary" :loading="saving" @click="save">保存正常推送配置</n-button>
        <n-button :loading="testing" @click="testNormal">发送测试消息</n-button>
      </n-space>
    </n-card>

    <n-card title="企业微信推送模板" style="margin-top:16px">
      <n-alert type="info" style="margin-bottom:12px">
        推送内容由此模板控制。可用变量：{ticket_identifier}、{priority}、{cause}、{escalation}、{disposal}、{ticket_url}、{ticket_link}、{id}、{month}、{received_at}。
        {disposal} 保留原始内容和换行；{ticket_link} 在工单 URL 为空时不显示。仅影响后续新推送，不补推历史日志。
      </n-alert>
      <n-input v-model:value="form.message_template" type="textarea" :rows="12" maxlength="8000" show-count placeholder="输入 Markdown 模板"/>
      <n-space style="margin-top:12px">
        <n-button type="primary" :loading="saving" @click="save">保存推送模板</n-button>
        <n-button @click="resetTemplate">恢复默认模板（需保存）</n-button>
        <n-button :loading="testing" @click="testNormal">发送模板测试消息</n-button>
      </n-space>
      <h3>实时预览（示例 JSON）</h3>
      <pre class="template-preview">{{ templatePreview }}</pre>
    </n-card>

    <n-card title="异常告警机器人" style="margin-top:16px">
      <n-alert type="warning" style="margin-bottom:12px">
        数据库不可访问、查询失败、正常推送失败时，使用此独立机器人发送异常告警。同一异常 15 分钟内最多告警一次，避免故障时刷屏。
      </n-alert>
      <n-form-item label="启用异常告警"><n-switch v-model:value="form.error_enabled"/></n-form-item>
      <n-form-item label="异常告警 Webhook">
        <n-input v-model:value="form.error_webhook" placeholder="异常告警 Webhook URL"/>
      </n-form-item>
      <n-text depth="3">{{status.has_error_webhook?'已保存异常告警 Webhook，可直接查看':'尚未保存异常告警 Webhook'}}</n-text>
      <n-space style="margin-top:12px">
        <n-button type="primary" :loading="saving" @click="save">保存异常告警配置</n-button>
        <n-button :loading="testingError" @click="testError">发送异常测试消息</n-button>
      </n-space>
    </n-card>

    <n-card title="最近运行情况" style="margin-top:16px">
      <n-descriptions bordered :column="2" label-placement="left">
        <n-descriptions-item label="最后查询时间">{{formatTime(status.last_query)}}</n-descriptions-item>
        <n-descriptions-item label="最后推送时间">{{formatTime(status.last_push)}}</n-descriptions-item>
        <n-descriptions-item label="上次窗口发现">{{status.last_query_count??0}} 条</n-descriptions-item>
        <n-descriptions-item label="本次新增入库">{{status.last_captured_count??0}} 条</n-descriptions-item>
        <n-descriptions-item label="后台线程">{{status.worker_alive?'正常':'未启动'}}</n-descriptions-item>
        <n-descriptions-item label="未发送记录">{{status.unsent_records??0}} 条</n-descriptions-item>
      </n-descriptions>
      <n-text depth="3" style="display:block;margin-top:10px">
        每次轮询会补齐 SCC_TT 中尚未同步的历史日志，并在 SCC_CVE 中保留源月份、源记录 ID、原始 JSON、接收时间、发送状态和失败原因。历史补录只更新日志列表，不触发企业微信补推。
      </n-text>
    </n-card>

    <n-card title="导出数据库内容" style="margin-top:16px">
      <n-text depth="3" style="display:block;margin-bottom:12px">
        只读导出 SCC_TT SQLite 中最新的日志，跨月份合并，保留原始 JSON 内容，不影响 MSOC 推送状态。
      </n-text>
      <n-space align="center">
        <n-select v-model:value="exportCount" :options="exportOptions" style="width:180px"/>
        <n-button type="primary" :loading="exporting" @click="exportDatabase">导出 CSV</n-button>
      </n-space>
    </n-card>
  </div>
</template>

<script setup>
import {ref,computed,onMounted,onUnmounted} from 'vue'
import axios from 'axios'
import {
  NAlert,NButton,NCard,NDescriptions,NDescriptionsItem,NFormItem,NGrid,NGridItem,
  NInput,NSelect,NSpace,NStatistic,NSwitch,NTag,NText,useMessage
} from 'naive-ui'

const msg=useMessage()
const api=axios.create({baseURL:'/api/v1/msoc'})
api.interceptors.request.use(c=>{
  c.headers.Authorization='Bearer '+(localStorage.getItem('token')||'')
  return c
})

const defaultMessageTemplate="## MSOC 安全告警通知\n> **工单编号**：{ticket_identifier}\n> **告警等级**：<font color=\"warning\">{priority}</font>\n> **告警状态**：{cause}\n> **告警类型**：{escalation}\n\n{disposal}\n\n{ticket_link}"
const exampleAlert={
  escalation:'AWS_Guardduty_Guardduty Findings - 172.24.254.254',
  cause:'Escalated',priority:'Medium',ticket_url:'',ticket_identifier:'300-205029',
  disposal:'告警详情：\n告警标题：An EC2 instance is communicating with a remote host on an unusual server port.\n源地址IP：172.24.254.245\n远程IP：39.96.62.230\n\n告警分析：\nGuardDuty 检测到异常端口通信。\n\n建议：\n请确认该通信是否为授权操作。'
}
const templatePreview=computed(()=>{
  const raw=form.value.message_template||''
  const fields={...exampleAlert,id:'123',month:'202611',received_at:'2026-11-26 09:00:00',
    ticket_link:exampleAlert.ticket_url?'[查看工单]('+exampleAlert.ticket_url+')':''}
  return raw.replace(/\\n/g,'\n').replace(/\{([a-zA-Z_][a-zA-Z0-9_]*)\}/g,(match,key)=>Object.prototype.hasOwnProperty.call(fields,key)?String(fields[key]):match)
})
function resetTemplate(){form.value.message_template=defaultMessageTemplate}
const saving=ref(false)
const testing=ref(false)
const testingError=ref(false)
const testingDb=ref(false)
const polling=ref(false)
const exporting=ref(false)
const exportCount=ref(100)
const exportOptions=[10,50,100,200,1000].map(n=>({label:`最近 ${n} 条`,value:n}))
const form=ref({
  enabled:false,
  db_path:'/home/msocadmin/SCC_TT/data/webhook.db',
  poll_interval:3,
  wecom_enabled:false,
  wecom_webhook:'',
  message_template:defaultMessageTemplate,
  error_enabled:false,
  error_webhook:''
})
const status=ref({})
const intervalOptions=[1,3,5,10,15,30].map(x=>({
  label:'最近 '+x+' 分钟（每 '+x+' 分钟查询）',
  value:x
}))
function formatTime(v){return v?String(v).replace('T',' ').replace(/\+.*$/,''):'—'}

async function load(){
  try{
    const d=(await api.get('/config')).data.data
    form.value={...form.value,...d}
    await refreshStatus()
  }catch(e){
    msg.error(e.response?.data?.detail||e.message)
  }
}
async function refreshStatus(){
  try{status.value=(await api.get('/status')).data.data}
  catch(e){msg.error(e.response?.data?.detail||e.message)}
}
async function save(){
  saving.value=true
  try{
    await api.put('/config',form.value)
    msg.success('MSOC 配置已保存')
    await load()
  }catch(e){
    msg.error(e.response?.data?.detail||e.message)
  }finally{
    saving.value=false
  }
}
async function testDb(){
  testingDb.value=true
  try{
    const d=(await api.post('/test-db')).data.data
    msg.success('数据库连接成功：'+d.months.length+' 个月表，共 '+d.total+' 条记录')
  }catch(e){
    msg.error(e.response?.data?.detail||e.message)
  }finally{
    testingDb.value=false
  }
}
async function testNormal(){
  testing.value=true
  try{
    await api.post('/test')
    msg.success('正常推送测试消息已发送')
  }catch(e){
    msg.error(e.response?.data?.detail||e.message)
  }finally{
    testing.value=false
  }
}
async function testError(){
  testingError.value=true
  try{
    await api.post('/test-error')
    msg.success('异常告警测试消息已发送')
  }catch(e){
    msg.error(e.response?.data?.detail||e.message)
  }finally{
    testingError.value=false
  }
}
async function pollNow(){
  polling.value=true
  try{
    const d=(await api.post('/poll')).data.data
    msg.success('窗口内 '+(d.count||0)+' 条，历史补录 '+(d.backfilled||0)+' 条，本次入库 '+(d.captured||0)+' 条，推送 '+(d.pushed||0)+' 条')
    await refreshStatus()
  }catch(e){
    msg.error(e.response?.data?.detail||e.message)
    await refreshStatus()
  }finally{
    polling.value=false
  }
}
async function exportDatabase(){
  exporting.value=true
  try{
    const response=await api.get('/export',{params:{limit:exportCount.value},responseType:'blob'})
    const blob=new Blob([response.data],{type:'text/csv;charset=utf-8'})
    const url=URL.createObjectURL(blob)
    const a=document.createElement('a')
    a.href=url
    a.download='msoc_webhook_'+exportCount.value+'_'+new Date().toISOString().slice(0,10)+'.csv'
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
    msg.success('数据库内容已导出')
  }catch(e){
    let detail=e.message
    if(e.response?.data instanceof Blob){
      try{detail=JSON.parse(await e.response.data.text()).detail||detail}catch(_){/* ignore */}
    }
    msg.error(detail)
  }finally{
    exporting.value=false
  }
}
let timer
onMounted(()=>{
  load()
  timer=setInterval(refreshStatus,10000)
})
onUnmounted(()=>{
  if(timer)clearInterval(timer)
})
</script>

<style scoped>
.page{max-width:1050px;margin:30px auto;padding:20px}.template-preview{white-space:pre-wrap;overflow-wrap:anywhere;background:#f5f7fa;padding:16px;border-radius:6px;max-height:430px;overflow:auto}
</style>