<template>
  <div class="page">
    <n-space justify="space-between" align="center">
      <div>
        <h2>MSOC 日志</h2>
        <n-text depth="3">日志内容和发送状态均从 SCC_CVE 自己的数据库读取，SCC_TT 仅作为原始数据源。</n-text>
      </div>
      <n-button @click="load">刷新</n-button>
    </n-space>

    <n-grid :cols="3" :x-gap="12" :y-gap="12" responsive="screen" style="margin:14px 0">
      <n-grid-item><n-card size="small"><n-statistic label="记录总数" :value="counts.total_records||0"/></n-card></n-grid-item>
      <n-grid-item><n-card size="small"><n-statistic label="已发送" :value="counts.sent_records||0"/></n-card></n-grid-item>
      <n-grid-item><n-card size="small"><n-statistic label="未发送" :value="counts.unsent_records||0"/></n-card></n-grid-item>
    </n-grid>

    <n-card>
      <n-space align="center" wrap>
        <n-select v-model:value="month" :options="monthOptions" placeholder="全部月份" clearable style="width:150px" @update:value="search"/>
        <n-select v-model:value="sendStatus" :options="statusOptions" style="width:140px" @update:value="search"/>
        <n-input v-model:value="keyword" placeholder="搜索日志内容" clearable style="width:260px" @keyup.enter="search"/>
        <n-button type="primary" @click="search">搜索</n-button>
        <n-button @click="reset">重置</n-button>
      </n-space>

      <n-data-table
        style="margin-top:14px"
        :columns="columns"
        :data="rows"
        :loading="loading"
        :pagination="false"
        :row-key="r=>r.id"
        :scroll-x="1150"
      />
      <n-space justify="end" style="margin-top:14px">
        <n-pagination v-model:page="page" :page-size="size" :item-count="total" show-quick-jumper @update:page="load"/>
      </n-space>
    </n-card>

    <n-modal v-model:show="visible" preset="card" title="MSOC 日志详情" style="width:min(900px,96vw)">
      <n-descriptions bordered :column="2" label-placement="left" style="margin-bottom:14px">
        <n-descriptions-item label="SCC_CVE 记录 ID">{{detail.id}}</n-descriptions-item>
        <n-descriptions-item label="SCC_TT 源记录 ID">{{detail.source_id}}</n-descriptions-item>
        <n-descriptions-item label="接收时间">{{detail.received_at}}</n-descriptions-item>
        <n-descriptions-item label="发送状态">
          <n-tag :type="detail.sent?'success':'warning'">{{detail.sent?'已发送':'未发送'}}</n-tag>
        </n-descriptions-item>
        <n-descriptions-item label="发送时间">{{detail.sent_at||'—'}}</n-descriptions-item>
        <n-descriptions-item label="尝试次数">{{detail.attempt_count??0}}</n-descriptions-item>
        <n-descriptions-item label="最近发送错误" :span="2">{{detail.last_error||'—'}}</n-descriptions-item>
      </n-descriptions>
      <pre class="raw">{{ rawContent }}</pre>
      <n-space justify="end"><n-button @click="copyRaw">复制原文</n-button></n-space>
    </n-modal>
  </div>
</template>

<script setup>
import {ref,computed,h,onMounted} from 'vue'
import axios from 'axios'
import {
  NButton,NCard,NDataTable,NDescriptions,NDescriptionsItem,NGrid,NGridItem,
  NInput,NModal,NPagination,NSelect,NSpace,NStatistic,NTag,NText,useMessage
} from 'naive-ui'

const msg=useMessage()
const api=axios.create({baseURL:'/api/v1/msoc'})
api.interceptors.request.use(c=>{
  c.headers.Authorization='Bearer '+(localStorage.getItem('token')||'')
  return c
})

const rows=ref([])
const months=ref([])
const month=ref(null)
const sendStatus=ref('all')
const keyword=ref('')
const page=ref(1)
const size=ref(30)
const total=ref(0)
const loading=ref(false)
const visible=ref(false)
const detail=ref({})
const counts=ref({total_records:0,sent_records:0,unsent_records:0})

const monthOptions=computed(()=>months.value.map(x=>({
  label:x.slice(0,4)+'年'+x.slice(4)+'月',
  value:x
})))
const statusOptions=[
  {label:'全部状态',value:'all'},
  {label:'已发送',value:'sent'},
  {label:'未发送',value:'unsent'}
]
const rawContent=computed(()=>{
  const raw=detail.value.content||''
  try{return JSON.stringify(JSON.parse(raw),null,2)}catch{return raw}
})

const columns=[
  {title:'源记录 ID',key:'source_id',width:110},
  {title:'接收时间',key:'received_at',width:200},
  {
    title:'发送状态',key:'sent',width:110,
    render:r=>h(NTag,{type:r.sent?'success':'warning',bordered:false},()=>r.sent?'已发送':'未发送')
  },
  {title:'尝试次数',key:'attempt_count',width:100},
  {
    title:'发送错误',key:'last_error',width:240,
    ellipsis:{tooltip:true},
    render:r=>r.last_error||'—'
  },
  {
    title:'内容预览',key:'content',ellipsis:{tooltip:true},width:300,
    render:r=>h('span',r.content?.slice(0,180)||'')
  },
  {
    title:'操作',key:'action',width:100,
    render:r=>h(NButton,{size:'small',type:'primary',onClick:()=>openDetail(r)},()=> '查看详情')
  }
]

async function load(){
  loading.value=true
  try{
    const d=(await api.get('/logs',{params:{
      month:month.value||'',
      page:page.value,
      size:size.value,
      q:keyword.value,
      sent:sendStatus.value
    }})).data.data
    rows.value=d.list||[]
    total.value=d.total||0
    months.value=d.months||months.value
    await loadCounts()
  }catch(e){
    msg.error(e.response?.data?.detail||e.message)
  }finally{
    loading.value=false
  }
}
async function loadCounts(){
  try{
    const d=(await api.get('/status')).data.data
    counts.value={
      total_records:d.total_records||0,
      sent_records:d.sent_records||0,
      unsent_records:d.unsent_records||0
    }
  }catch(e){}
}
function search(){
  page.value=1
  load()
}
function reset(){
  month.value=null
  sendStatus.value='all'
  keyword.value=''
  page.value=1
  load()
}
async function openDetail(r){
  try{
    detail.value=(await api.get('/logs/'+r.source_month+'/'+r.id)).data.data
    visible.value=true
  }catch(e){
    msg.error(e.response?.data?.detail||e.message)
  }
}
async function copyRaw(){
  try{
    await navigator.clipboard.writeText(detail.value.content||'')
    msg.success('已复制')
  }catch(e){
    msg.error('复制失败，请手动选择文本')
  }
}
onMounted(load)
</script>

<style scoped>
.page{max-width:1350px;margin:30px auto;padding:20px}
.raw{white-space:pre-wrap;overflow-wrap:anywhere;max-height:65vh;overflow:auto;background:#f5f7fa;padding:16px;border-radius:6px;font-size:13px}
</style>