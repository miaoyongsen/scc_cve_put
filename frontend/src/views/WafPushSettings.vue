<template>
  <div class="waf-settings">
    <n-space justify="space-between" align="center">
      <h2>WAF推送配置</h2>
      <n-space>
        <n-button :loading="statusLoading" @click="loadStatus">刷新状态</n-button>
        <n-button type="primary" :loading="polling" @click="pollNow">立即查询</n-button>
      </n-space>
    </n-space>

    <n-alert type="info" style="margin:14px 0 16px">
      后台定时查询已提交的 WAF 封禁请求。只有 S3 回执状态为 Done（成功）或 Failed（失败）时才向对应企业微信机器人推送一次；pending / Processing 会继续等待。没有回执不推送。
    </n-alert>

    <n-grid :cols="4" :x-gap="12" :y-gap="12" responsive="screen" style="margin-bottom:16px">
      <n-grid-item><n-card size="small"><n-statistic label="监控状态" :value="status.enabled?'已启用':'未启用'"/></n-card></n-grid-item>
      <n-grid-item><n-card size="small"><n-statistic label="待查询请求" :value="status.waiting_requests??0"/></n-card></n-grid-item>
      <n-grid-item><n-card size="small"><n-statistic label="已推送通知" :value="status.notifications_sent??0"/></n-card></n-grid-item>
      <n-grid-item><n-card size="small"><n-statistic label="推送失败" :value="status.notifications_failed??0"/></n-card></n-grid-item>
    </n-grid>

    <n-alert v-if="status.last_error" type="warning" style="margin-bottom:14px">
      最近查询异常：{{status.last_error}}
    </n-alert>

    <n-card title="回执查询设置">
      <n-form-item label="启用 WAF 自动查询">
        <n-switch v-model:value="form.enabled"/>
        <n-text depth="3" style="margin-left:10px">{{form.enabled?'后台按设定间隔自动查询':'关闭后停止自动查询，手动查询仍可使用'}}</n-text>
      </n-form-item>
      <n-form-item label="查询间隔">
        <n-select v-model:value="form.interval_minutes" :options="intervalOptions" style="width:280px"/>
      </n-form-item>
      <n-text depth="3">仅查询已提交且尚未结束的申请，不限定提交时间范围。查询结果会同步更新「WAF封禁」列表。</n-text>
      <n-space align="center" style="margin-top:14px">
        <n-button type="primary" :loading="saving" @click="save">保存配置</n-button>
        <n-tag :type="status.worker_alive?'success':'warning'">后台任务：{{status.worker_alive?'已启动':'未启动'}}</n-tag>
        <n-tag v-if="status.running" type="info">正在查询</n-tag>
      </n-space>
    </n-card>

    <n-card title="封禁成功企业微信推送" style="margin-top:16px">
      <n-alert type="success" style="margin-bottom:12px">仅当回执状态为 Done 时推送到此机器人。</n-alert>
      <n-form-item label="成功通知 Webhook 地址">
        <n-input v-model:value="form.success_webhook" type="password" show-password-on="click"
                 placeholder="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=..."/>
      </n-form-item>
      <n-space align="center">
        <n-tag :type="status.has_success_webhook?'success':'warning'">{{status.has_success_webhook?'已配置':'未配置'}}</n-tag>
        <n-checkbox v-model:checked="form.clear_success_webhook">清除已保存地址</n-checkbox>
      </n-space>
    </n-card>

    <n-card title="封禁失败企业微信推送" style="margin-top:16px">
      <n-alert type="warning" style="margin-bottom:12px">仅当回执状态为 Failed 时推送到此机器人。查询异常或没有回执不算封禁失败。</n-alert>
      <n-form-item label="失败通知 Webhook 地址">
        <n-input v-model:value="form.failure_webhook" type="password" show-password-on="click"
                 placeholder="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=..."/>
      </n-form-item>
      <n-space align="center">
        <n-tag :type="status.has_failure_webhook?'success':'warning'">{{status.has_failure_webhook?'已配置':'未配置'}}</n-tag>
        <n-checkbox v-model:checked="form.clear_failure_webhook">清除已保存地址</n-checkbox>
      </n-space>
      <n-space style="margin-top:16px">
        <n-button type="primary" :loading="saving" @click="save">保存推送配置</n-button>
      </n-space>
    </n-card>

    <n-card title="最近运行情况" style="margin-top:16px">
      <n-descriptions bordered :column="2">
        <n-descriptions-item label="最近查询时间">{{time(status.last_run)}}</n-descriptions-item>
        <n-descriptions-item label="上次查询数">{{status.last_queried??0}}</n-descriptions-item>
        <n-descriptions-item label="上次返回回执">{{status.last_found??0}}</n-descriptions-item>
        <n-descriptions-item label="上次成功推送">{{status.last_notified??0}}</n-descriptions-item>
      </n-descriptions>
      <n-text depth="3" style="display:block;margin-top:10px">
        每个请求只自动尝试通知一次，已发送记录不会重复通知。企业微信发送失败会保留失败记录，不会自动反复重试。
      </n-text>
    </n-card>
  </div>
</template>

<script setup>
import {ref,onMounted} from 'vue'
import axios from 'axios'
import {
  NAlert,NButton,NCard,NCheckbox,NDescriptions,NDescriptionsItem,NFormItem,
  NGrid,NGridItem,NInput,NSelect,NSpace,NStatistic,NSwitch,NTag,NText,useMessage
} from 'naive-ui'

const msg=useMessage()
const api=axios.create({baseURL:'/api/v1/waf/monitor',timeout:120000})
api.interceptors.request.use(c=>{
  c.headers.Authorization='Bearer '+(localStorage.getItem('token')||'')
  return c
})
const intervalOptions=[1,3,5,10,15,30,60].map(n=>({label:'每 '+n+' 分钟查询',value:n}))
const form=ref({enabled:false,interval_minutes:3,success_webhook:'',failure_webhook:'',
                clear_success_webhook:false,clear_failure_webhook:false})
const status=ref({})
const saving=ref(false),polling=ref(false),statusLoading=ref(false)
const time=v=>v?new Date(v).toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false}):'—'

async function load(){
  try{
    const d=(await api.get('/config')).data.data
    form.value={...form.value,...d,success_webhook:'',failure_webhook:'',
                clear_success_webhook:false,clear_failure_webhook:false}
    await loadStatus()
  }catch(e){msg.error(e.response?.data?.detail||e.message)}
}
async function loadStatus(){
  statusLoading.value=true
  try{
    const config=(await api.get('/config')).data.data
    status.value={...(await api.get('/status')).data.data,...config}
  }catch(e){msg.error(e.response?.data?.detail||e.message)}
  finally{statusLoading.value=false}
}
async function save(){
  if(saving.value)return
  saving.value=true
  try{
    await api.put('/config',form.value)
    msg.success('WAF推送配置已保存')
    await load()
  }catch(e){msg.error(e.response?.data?.detail||e.message)}
  finally{saving.value=false}
}
async function pollNow(){
  if(polling.value)return
  polling.value=true
  try{
    const r=(await api.post('/poll')).data.data
    msg.success('查询完成：检查 '+r.queried+' 条，获得回执 '+r.found+' 条，推送 '+r.notified+' 条')
    if(r.errors?.length)msg.warning('部分请求查询失败，请查看最近异常')
    await loadStatus()
  }catch(e){msg.error(e.response?.data?.detail||e.message)}
  finally{polling.value=false}
}
onMounted(load)
</script>

<style scoped>
.waf-settings{box-sizing:border-box;margin:16px auto;width:calc(100% - 32px);background:#fff;border-radius:10px;padding:24px;min-width:0}
@media(max-width:760px){.waf-settings{margin:10px auto;padding:16px;width:calc(100% - 20px)}}
</style>
