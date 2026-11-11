<template>
  <div class="page">
    <n-space justify="space-between" align="center">
      <div>
        <h2>MSOC 推送配置</h2>
        <n-text depth="3">独立于 SCC_CVE 漏洞推送。监控 SCC_TT 数据库，发现新记录后推送企业微信。</n-text>
      </div>
      <n-space>
        <n-button @click="refreshStatus">刷新状态</n-button>
        <n-button type="primary" :loading="polling" @click="pollNow">立即查询</n-button>
      </n-space>
    </n-space>

    <n-alert type="info" style="margin:14px 0">
      SCC_TT 数据库采用只读连接。MSOC 推送配置、处理游标和运行状态均保存在 SCC_CVE 自己的数据库中，不会改动 SCC_TT。
    </n-alert>

    <n-grid :cols="4" :x-gap="12" :y-gap="12" responsive="screen" style="margin-bottom:16px">
      <n-grid-item><n-card size="small"><n-statistic label="监控状态" :value="status.enabled?'运行中':'已停止'"/></n-card></n-grid-item>
      <n-grid-item><n-card size="small"><n-statistic label="累计推送" :value="status.total_pushed||0"/></n-card></n-grid-item>
      <n-grid-item><n-card size="small"><n-statistic label="最后查询" :value="formatTime(status.last_query)"/></n-card></n-grid-item>
      <n-grid-item><n-card size="small"><n-statistic label="最后推送" :value="formatTime(status.last_push)"/></n-card></n-grid-item>
    </n-grid>

    <n-alert v-if="status.last_error" type="error" style="margin-bottom:14px">
      最近一次异常：{{ status.last_error }}
    </n-alert>

    <n-card title="数据库监控设置">
      <n-form-item label="启用 MSOC 独立监控">
        <n-switch v-model:value="form.enabled"/>
        <n-text style="margin-left:10px">{{form.enabled?'启用后后台定时查询':'关闭后停止查询，不影响 SCC_CVE 漏洞采集和推送'}}</n-text>
      </n-form-item>
      <n-form-item label="SCC_TT SQLite 数据库路径">
        <n-input v-model:value="form.db_path" placeholder="/home/msocadmin/SCC_TT/data/webhook.db"/>
      </n-form-item>
      <n-form-item label="数据库查询间隔">
        <n-select v-model:value="form.poll_interval" :options="intervalOptions" style="width:220px"/>
      </n-form-item>
      <n-space>
        <n-button type="primary" :loading="saving" @click="save">保存监控设置</n-button>
        <n-tag :type="status.worker_alive?'success':'warning'">后台任务：{{status.worker_alive?'已启动':'未启动'}}</n-tag>
        <n-tag v-if="status.running" type="info">正在查询/推送</n-tag>
      </n-space>
    </n-card>

    <n-card title="正常日志推送机器人" style="margin-top:16px">
      <n-alert type="info" style="margin-bottom:12px">检测到新日志后，按接收顺序推送。推送成功后记录游标；失败会保留记录并在后续轮询重试。</n-alert>
      <n-form-item label="启用正常推送"><n-switch v-model:value="form.wecom_enabled"/></n-form-item>
      <n-form-item label="企业微信机器人 Webhook">
        <n-input v-model:value="form.wecom_webhook" type="password" show-password-on="click" placeholder="留空则保留已保存的 Webhook"/>
      </n-form-item>
      <n-text depth="3">{{status.has_wecom_webhook?'已保存 Webhook（不会回显）':'尚未保存 Webhook'}}</n-text>
      <n-space style="margin-top:12px">
        <n-button type="primary" :loading="saving" @click="save">保存正常推送配置</n-button>
        <n-button :loading="testing" @click="testNormal">发送测试消息</n-button>
      </n-space>
    </n-card>

    <n-card title="异常告警机器人" style="margin-top:16px">
      <n-alert type="warning" style="margin-bottom:12px">数据库不可访问、查询失败、正常推送失败时，使用此独立机器人发送异常告警。同一异常 15 分钟内最多告警一次，避免故障时刷屏。</n-alert>
      <n-form-item label="启用异常告警"><n-switch v-model:value="form.error_enabled"/></n-form-item>
      <n-form-item label="异常告警 Webhook">
        <n-input v-model:value="form.error_webhook" type="password" show-password-on="click" placeholder="留空则保留已保存的 Webhook"/>
      </n-form-item>
      <n-text depth="3">{{status.has_error_webhook?'已保存异常告警 Webhook（不会回显）':'尚未保存异常告警 Webhook'}}</n-text>
      <n-space style="margin-top:12px">
        <n-button type="primary" :loading="saving" @click="save">保存异常告警配置</n-button>
        <n-button :loading="testingError" @click="testError">发送异常测试消息</n-button>
      </n-space>
    </n-card>

    <n-card title="处理游标与运行状态" style="margin-top:16px">
      <n-descriptions bordered :column="2" label-placement="left">
        <n-descriptions-item label="当前处理月份">{{status.cursor_month||'尚未初始化'}}</n-descriptions-item>
        <n-descriptions-item label="最后处理记录 ID">{{status.cursor_id??0}}</n-descriptions-item>
        <n-descriptions-item label="上次查询发现">{{status.last_query_count??0}} 条</n-descriptions-item>
        <n-descriptions-item label="后台线程">{{status.worker_alive?'正常':'未启动'}}</n-descriptions-item>
      </n-descriptions>
      <n-text depth="3" style="display:block;margin-top:10px">首次启用时默认将当前最新记录设为起始位置，只推送启用后的新增日志，避免把历史数据一次性发送到企业微信。停用期间新增的数据会在重新启用后补推。</n-text>
    </n-card>
  </div>
</template>

<script setup>
import {ref,onMounted,onUnmounted} from 'vue'
import axios from 'axios'
import {NAlert,NButton,NCard,NDescriptions,NDescriptionsItem,NFormItem,NGrid,NGridItem,NInput,NSelect,NSpace,NStatistic,NSwitch,NTag,NText,useMessage} from 'naive-ui'
const msg=useMessage(),api=axios.create({baseURL:'/api/v1/msoc'})
api.interceptors.request.use(c=>{c.headers.Authorization='Bearer '+(localStorage.getItem('token')||'');return c})
const saving=ref(false),testing=ref(false),testingError=ref(false),polling=ref(false)
const form=ref({enabled:false,db_path:'/home/msocadmin/SCC_TT/data/webhook.db',poll_interval:3,wecom_enabled:false,wecom_webhook:'',error_enabled:false,error_webhook:''})
const status=ref({})
const intervalOptions=[1,3,5,10,15,30].map(x=>({label:x+' 分钟',value:x}))
function formatTime(v){return v?String(v).replace('T',' ').replace(/\+.*$/,''):'—'}
async function load(){
  try{
    const d=(await api.get('/config')).data.data
    form.value={...form.value,...d,wecom_webhook:'',error_webhook:''}
    await refreshStatus()
  }catch(e){msg.error(e.response?.data?.detail||e.message)}
}
async function refreshStatus(){try{status.value=(await api.get('/status')).data.data}catch(e){msg.error(e.response?.data?.detail||e.message)}}
async function save(){
  saving.value=true
  try{await api.put('/config',form.value);msg.success('MSOC 配置已保存');await load()}
  catch(e){msg.error(e.response?.data?.detail||e.message)}
  finally{saving.value=false}
}
async function testNormal(){
  testing.value=true
  try{await api.post('/test');msg.success('正常推送测试消息已发送')}
  catch(e){msg.error(e.response?.data?.detail||e.message)}
  finally{testing.value=false}
}
async function testError(){
  testingError.value=true
  try{await api.post('/test-error');msg.success('异常告警测试消息已发送')}
  catch(e){msg.error(e.response?.data?.detail||e.message)}
  finally{testingError.value=false}
}
async function pollNow(){
  polling.value=true
  try{const d=(await api.post('/poll')).data.data;msg.success('查询完成：发现 '+(d.count||0)+' 条，推送 '+(d.pushed||0)+' 条');await refreshStatus()}
  catch(e){msg.error(e.response?.data?.detail||e.message);await refreshStatus()}
  finally{polling.value=false}
}
let timer
onMounted(()=>{load();timer=setInterval(refreshStatus,10000)})
onUnmounted(()=>{if(timer)clearInterval(timer)})
</script>

<style scoped>
.page{max-width:1050px;margin:30px auto;padding:20px}
</style>