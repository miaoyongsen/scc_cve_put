<template>
  <div class="page">
    <n-space justify="space-between" align="center">
      <div>
        <h2>MSOC 日志</h2>
        <n-text depth="3">只读查看 SCC_TT SQLite 接收记录，不会修改原始数据库。</n-text>
      </div>
      <n-button @click="load">刷新</n-button>
    </n-space>
    <n-alert type="info" style="margin:14px 0">
      数据库：{{ dbPath || '读取配置中…' }} · 按月分表 · 支持关键字搜索和 JSON 原文查看
    </n-alert>
    <n-card>
      <n-space align="center" wrap>
        <n-select v-model:value="month" :options="monthOptions" placeholder="选择月份" style="width:150px" @update:value="search"/>
        <n-input v-model:value="keyword" placeholder="搜索日志内容" clearable style="width:280px" @keyup.enter="search"/>
        <n-button type="primary" @click="search">搜索</n-button>
        <n-button @click="reset">重置</n-button>
      </n-space>
      <n-data-table style="margin-top:14px" :columns="columns" :data="rows" :loading="loading" :pagination="false" :row-key="r=>r.id" :scroll-x="900"/>
      <n-space justify="end" style="margin-top:14px">
        <n-pagination v-model:page="page" :page-size="size" :item-count="total" show-quick-jumper @update:page="load"/>
      </n-space>
    </n-card>
    <n-modal v-model:show="visible" preset="card" title="Webhook 日志原文" style="width:min(900px,96vw)">
      <n-space style="margin-bottom:10px">
        <n-tag>月份：{{ detail.month }}</n-tag>
        <n-tag>记录 ID：{{ detail.id }}</n-tag>
        <n-tag>{{ detail.received_at }}</n-tag>
      </n-space>
      <pre class="raw">{{ rawContent }}</pre>
      <n-space justify="end"><n-button @click="copyRaw">复制原文</n-button></n-space>
    </n-modal>
  </div>
</template>

<script setup>
import {ref,computed,h,onMounted} from 'vue'
import axios from 'axios'
import {NAlert,NButton,NCard,NDataTable,NInput,NModal,NPagination,NSelect,NSpace,NTag,NText,useMessage} from 'naive-ui'
const msg=useMessage()
const api=axios.create({baseURL:'/api/v1/msoc'})
api.interceptors.request.use(c=>{c.headers.Authorization='Bearer '+(localStorage.getItem('token')||'');return c})
const rows=ref([]),months=ref([]),month=ref(''),keyword=ref(''),page=ref(1),size=ref(30),total=ref(0),loading=ref(false),visible=ref(false),detail=ref({}),dbPath=ref('')
const monthOptions=computed(()=>months.value.map(x=>({label:x.slice(0,4)+'年'+x.slice(4)+'月',value:x})))
const rawContent=computed(()=>{const raw=detail.value.content||'';try{return JSON.stringify(JSON.parse(raw),null,2)}catch{return raw}})
const columns=[
  {title:'ID',key:'id',width:90},
  {title:'接收时间',key:'received_at',width:190},
  {title:'内容预览',key:'content',ellipsis:{tooltip:true},render:r=>h('span',r.content?.slice(0,180)||'')},
  {title:'操作',key:'action',width:100,render:r=>h(NButton,{size:'small',type:'primary',onClick:()=>openDetail(r)},()=> '查看原文')}
]
async function loadMonths(){
  try{const d=(await api.get('/months')).data.data;months.value=d||[];if(!month.value&&months.value.length)month.value=months.value[months.value.length-1]}
  catch(e){msg.error(e.response?.data?.detail||e.message)}
}
async function load(){
  loading.value=true
  try{
    const d=(await api.get('/logs',{params:{month:month.value,page:page.value,size:size.value,q:keyword.value}})).data.data
    rows.value=d.list||[];total.value=d.total||0;months.value=d.months||months.value
    if(d.month)month.value=d.month
  }catch(e){msg.error(e.response?.data?.detail||e.message)}
  finally{loading.value=false}
}
async function loadConfig(){try{dbPath.value=(await api.get('/config')).data.data.db_path||''}catch(e){}}
function search(){page.value=1;load()}
function reset(){keyword.value='';page.value=1;load()}
async function openDetail(r){
  try{detail.value=(await api.get('/logs/'+r.month+'/'+r.id)).data.data;detail.value.month=r.month;visible.value=true}
  catch(e){msg.error(e.response?.data?.detail||e.message)}
}
async function copyRaw(){
  try{await navigator.clipboard.writeText(detail.value.content||'');msg.success('已复制')}
  catch(e){msg.error('复制失败，请手动选择文本')}
}
onMounted(async()=>{await loadConfig();await loadMonths();await load()})
</script>

<style scoped>
.page{max-width:1250px;margin:30px auto;padding:20px}
.raw{white-space:pre-wrap;overflow-wrap:anywhere;max-height:65vh;overflow:auto;background:#f5f7fa;padding:16px;border-radius:6px;font-size:13px}
</style>