<template>
  <div class="waf-page">
    <n-space justify="space-between" align="center">
      <h2>WAF封禁</h2>
      <n-button type="primary" @click="openCreate">提交封禁</n-button>
    </n-space>

    <n-alert type="info" :show-icon="false" style="margin:12px 0 16px">
      通过 S3 提交封禁请求并读取处理回执。提交成功仅代表请求文件已上传，最终封禁状态以回执为准。
    </n-alert>

    <n-space align="center" style="margin:16px 0">
      <n-input v-model:value="q" clearable placeholder="搜索请求编号 / IP / 工单编号 / 状态" style="max-width:420px" @keyup.enter="search"/>
      <n-button @click="search">查询</n-button>
      <n-button :loading="loading" @click="load">刷新列表</n-button>
    </n-space>

    <n-data-table :columns="columns" :data="rows" :loading="loading" :row-key="r=>r.id" :pagination="false" :scroll-x="1150"/>
    <n-space justify="end" style="margin-top:16px">
      <n-pagination :page="page" :page-size="20" :item-count="total" @update:page="changePage"/>
    </n-space>

    <n-modal v-model:show="createOpen" preset="card" title="提交 WAF 封禁请求" style="width:min(720px,95vw)" :mask-closable="false">
      <n-form label-placement="top">
        <n-form-item label="封禁 IP / CIDR（必填）">
          <n-input v-model:value="blockIp" type="textarea" :rows="5" placeholder="支持多个 IP/CIDR，使用英文逗号或换行分隔&#10;例如：192.168.15.12/32,192.168.15.13/32"/>
        </n-form-item>
        <n-alert type="info" :show-icon="false" style="margin-bottom:12px">
          仅 IP/CIDR 可编辑。封禁平台范围、封禁原因和请求编号由系统自动生成。
        </n-alert>
        <n-descriptions bordered :column="1" size="small">
          <n-descriptions-item label="封禁平台">CN AWS、CN Aliyun、CN Azure、SEA HKT Azure、GCP、AWS</n-descriptions-item>
          <n-descriptions-item label="封禁原因">Malicious IP detected by MSOC</n-descriptions-item>
          <n-descriptions-item label="请求编号">提交时自动生成（北京时间 + 当日自增序号）</n-descriptions-item>
        </n-descriptions>
      </n-form>
      <n-space justify="end" style="margin-top:18px">
        <n-button @click="createOpen=false" :disabled="submitting">取消</n-button>
        <n-button type="primary" :disabled="!blockIp.trim()" :loading="submitting" @click="submit">确认提交</n-button>
      </n-space>
    </n-modal>

    <n-modal v-model:show="detailOpen" preset="card" title="封禁请求详情" style="width:min(850px,95vw);max-height:92vh;overflow:auto">
      <n-descriptions bordered :column="1">
        <n-descriptions-item label="Client Request ID">{{detail.client_request_id||'—'}}</n-descriptions-item>
        <n-descriptions-item label="Service Request ID">{{detail.service_request_id||'—'}}</n-descriptions-item>
        <n-descriptions-item label="封禁 IP">{{detail.block_ip||'—'}}</n-descriptions-item>
        <n-descriptions-item label="处理状态"><n-tag :type="statusType(detail.status)">{{statusText(detail.status)}}</n-tag></n-descriptions-item>
        <n-descriptions-item label="提交时间">{{time(detail.created_at)}}</n-descriptions-item>
        <n-descriptions-item label="最近查询">{{time(detail.updated_at)}}</n-descriptions-item>
      </n-descriptions>
      <n-alert v-if="detail.last_error" type="error" style="margin-top:12px">{{detail.last_error}}</n-alert>
      <pre v-if="detail.response" class="json">{{JSON.stringify(detail.response,null,2)}}</pre>
      <n-space justify="end" style="margin-top:14px">
        <n-button @click="detailOpen=false">关闭</n-button>
        <n-button type="primary" :loading="queryingId===detail.client_request_id" @click="queryResult(detail)">查询最新结果</n-button>
      </n-space>
    </n-modal>
  </div>
</template>

<script setup>
import {ref,h,onMounted,onUnmounted} from 'vue'
import axios from 'axios'
import {NAlert,NButton,NDataTable,NDescriptions,NDescriptionsItem,NForm,NFormItem,NInput,NModal,NPagination,NSpace,NTag,useMessage} from 'naive-ui'

const msg=useMessage()
const http=axios.create({baseURL:'/api/v1/waf',timeout:30000})
http.interceptors.request.use(c=>{c.headers.Authorization='Bearer '+(localStorage.getItem('token')||'');return c})
const rows=ref([]),q=ref(''),page=ref(1),total=ref(0),loading=ref(false)
const createOpen=ref(false),blockIp=ref(''),submitting=ref(false),queryingId=ref(''),detailOpen=ref(false),detail=ref({})
let pollTimer=null

const time=v=>v?new Date(/[zZ]$|[+-][0-9]{2}:[0-9]{2}$/.test(v)?v:v+'Z').toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false}):'—'
const statusText=s=>({
  '已提交，待回执':'等待回执',
  pending:'等待处理',
  processing:'处理中',
  Processing:'处理中',
  done:'处理完成',
  Done:'处理完成',
  success:'处理完成',
  failed:'处理失败',
  Failed:'处理失败',
  '提交失败':'提交失败',
  '提交中':'提交中'
}[s]||s||'未知')
const statusType=s=>{
  if(['done','Done','success'].includes(s))return 'success'
  if(['failed','Failed','提交失败'].includes(s))return 'error'
  if(['pending','processing','Processing','已提交，待回执','提交中'].includes(s))return 'warning'
  return 'default'
}
const columns=[
  {title:'请求编号',key:'client_request_id',width:190},
  {title:'封禁 IP',key:'block_ip',minWidth:230,ellipsis:{tooltip:true}},
  {title:'工单编号',key:'service_request_id',width:160,render:r=>r.service_request_id||'—'},
  {title:'处理状态',key:'status',width:120,render:r=>h(NTag,{type:statusType(r.status),bordered:false},()=>statusText(r.status))},
  {title:'提交时间',key:'created_at',width:180,render:r=>time(r.created_at)},
  {title:'操作',key:'actions',width:190,render:r=>h(NSpace,{size:8},()=>[
    h(NButton,{text:true,type:'primary',onClick:()=>view(r)},()=> '详情'),
    h(NButton,{text:true,type:'info',loading:queryingId.value===r.client_request_id,onClick:()=>queryResult(r)},()=> '查询结果')
  ])}
]

async function load(){
  loading.value=true
  try{
    const d=(await http.get('/requests',{params:{q:q.value,page:page.value,size:20}})).data.data
    rows.value=d.list||[];total.value=d.total||0
  }catch(e){msg.error(e.response?.data?.detail||e.message)}
  finally{loading.value=false}
}
function search(){page.value=1;load()}
function changePage(v){page.value=v;load()}
function openCreate(){blockIp.value='';createOpen.value=true}
async function submit(){
  if(submitting.value||!blockIp.value.trim())return
  if(!confirm('确认提交以下 IP/CIDR 的 WAF 封禁请求？\n\n'+blockIp.value.trim()))return
  submitting.value=true
  try{
    const result=(await http.post('/requests',{block_ip:blockIp.value})).data.data
    createOpen.value=false
    blockIp.value=''
    msg.success('封禁请求已上传：'+result.client_request_id)
    q.value='';page.value=1
    await load()
  }catch(e){msg.error(e.response?.data?.detail||e.message)}
  finally{submitting.value=false}
}
async function queryResult(r){
  if(!r?.client_request_id||queryingId.value)return
  queryingId.value=r.client_request_id
  try{
    const data=(await http.post('/requests/'+encodeURIComponent(r.client_request_id)+'/query')).data.data
    if(data.found){
      msg.success('已获取最新封禁回执')
      if(detailOpen.value&&detail.value.client_request_id===r.client_request_id)detail.value=data.request
    }else{
      msg.info('暂未收到回执，稍后将自动再次查询')
      if(detailOpen.value&&detail.value.client_request_id===r.client_request_id)detail.value=data.request
    }
    await load()
  }catch(e){msg.error(e.response?.data?.detail||e.message)}
  finally{queryingId.value=''}
}
async function view(r){
  try{detail.value=(await http.get('/requests/'+encodeURIComponent(r.client_request_id))).data.data;detailOpen.value=true}
  catch(e){msg.error(e.response?.data?.detail||e.message)}
}
async function pollPending(){
  const pending=rows.value.filter(r=>['已提交，待回执','pending','processing','Processing','提交中'].includes(r.status))
  for(const row of pending){
    if(queryingId.value)break
    await queryResult(row)
  }
}
onMounted(async()=>{
  await load()
  pollTimer=setInterval(pollPending,60000)
})
onUnmounted(()=>{if(pollTimer)clearInterval(pollTimer)})
</script>

<style scoped>
.waf-page{box-sizing:border-box;margin:16px auto;width:calc(100% - 32px);background:#fff;border-radius:10px;padding:24px;min-width:0}
.json{white-space:pre-wrap;overflow-wrap:anywhere;max-height:42vh;overflow:auto;font:inherit;line-height:1.6;background:#f5f7fa;padding:14px;border-radius:6px}
@media(max-width:760px){.waf-page{padding:16px;margin:10px auto;width:calc(100% - 20px)}}
</style>
