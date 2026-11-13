<template><div class="shell"><main><div class="head"><div><h2>漏洞监控</h2><n-text depth="3">WatchVuln 多源高价值漏洞情报</n-text></div><n-space><n-button type="error" :disabled="!checkedIds.length" :loading="deleting" @click="bulkDelete">批量删除（{{checkedIds.length}}）</n-button><n-button :loading="enriching" @click="enrichOld">补全历史等级</n-button><n-button @click="openReviews">人工审核（{{pending.length}}）</n-button><n-button type="primary" :loading="refreshing" @click="refreshNow">立即采集</n-button></n-space></div><n-space style="margin:20px 0"><n-input v-model:value="q" clearable placeholder="搜索标题 / CVE" @keyup.enter="load"/><n-select v-model:value="severity" multiple clearable placeholder="严重程度" style="width:130px" :options="options" @update:value="load"/><n-input v-model:value="source" clearable placeholder="来源" @keyup.enter="load"/><n-button @click="load">查询</n-button><n-text depth="3">共 {{total}} 条</n-text></n-space><n-data-table remote striped :row-key="row=>row.id" v-model:checked-row-keys="checkedIds" :columns="columns" :data="rows" :loading="loading" @update:expanded-row-keys="expandRows" :pagination="pagination" @update:page="changePage" @update:page-size="changePageSize" @update:sorter="changeSorter"/><n-modal v-model:show="show" preset="card" :title="selected?.title||'漏洞详情'" style="width:min(850px,95vw)"><n-descriptions v-if="selected" bordered :column="2"><n-descriptions-item label="CVE">{{selected.cve||'--'}}</n-descriptions-item><n-descriptions-item label="严重程度">{{selected.severity}}</n-descriptions-item><n-descriptions-item label="来源">{{selected.from}}</n-descriptions-item><n-descriptions-item label="内容类型">{{contentLabel(selected)}}</n-descriptions-item><n-descriptions-item label="披露时间">{{formatDate(selected.disclosure)}}</n-descriptions-item><n-descriptions-item label="采集时间">{{formatDate(selected.first_seen)}}</n-descriptions-item><n-descriptions-item label="描述" :span="2"><div style="white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.7;max-height:340px;overflow:auto">{{selected.description||'暂无描述'}}</div></n-descriptions-item><n-descriptions-item label="原始数据" :span="2"><a v-if="rawLink(selected)" :href="rawLink(selected)" target="_blank" rel="noopener noreferrer">查看原始数据 ↗</a><span v-else>无原始链接</span></n-descriptions-item><n-descriptions-item label="修复建议" :span="2">{{selected.solutions}}</n-descriptions-item><n-descriptions-item v-if="selected.cve" label="完整 AI 研判" :span="2"><div style="white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.7;max-height:480px;overflow:auto">{{aiLoading?"正在加载……":aiDetail?.result||"暂无 AI 研判结果"}}</div></n-descriptions-item></n-descriptions></n-modal><n-modal v-model:show="showReviews" preset="card" title="待人工确认的漏洞" style="width:min(1100px,95vw)"><n-space align="center" style="margin-bottom:14px"><n-input v-model:value="reviewSearch" clearable placeholder="搜索漏洞标题 / CVE / 命中关键词 / 来源" style="width:min(420px,65vw)"/><n-text depth="3">找到 {{filteredPending.length}} / {{pending.length}} 条</n-text><n-button type="error" :disabled="!checkedReviewIds.length" :loading="deletingReviews" @click="deleteSelectedReviews">批量删除（{{checkedReviewIds.length}}）</n-button></n-space><n-alert type="warning" style="margin-bottom:12px">永久删除：所选待审核记录及相同 CVE 的其他来源情报、相关审核和爬虫原始记录也会删除；历史运行记录保留。删除后若来源再次采集，可能重新入库。</n-alert><n-data-table v-model:checked-row-keys="checkedReviewIds" :row-key="row=>row.id" :columns="reviewColumns" :data="filteredPending" :pagination="reviewPagination" :max-height="550"/></n-modal><n-modal v-model:show="showProgress" :mask-closable="false" preset="card" title="本次采集进度" style="width:min(760px,95vw)"><div style="max-height:380px;overflow:auto"><div v-for="(item,i) in progressSummary.details" :key="i" style="padding:10px;border-bottom:1px solid #ddd"><strong>{{i+1}}. {{item.name}} — {{item.status==='running'?'采集中':item.status==='error'?'失败':'完成'}}</strong><div>检测 {{item.items}}　→ 一级 {{item.primary}}　→ 二级 {{item.secondary}}　→ 新增 {{item.new}}</div><div style="font-size:12px;color:#888;margin-top:5px">过滤：等级 {{item.filtered_severity||0}} / 时间 {{item.filtered_date||0}} / 日期缺失 {{item.missing_date||0}} / 关键词 {{item.filtered_keyword||0}} / 其他规则 {{item.filtered_rule||0}}</div></div></div><div style="margin-top:14px"><strong>{{progressStatus==='running'?'正在采集……':'采集结束'}}</strong><p>本次检测 {{progressSummary.items||0}} 条；一级 {{progressSummary.primary||0}} 条；二级 {{progressSummary.secondary||0}} 条；新增 {{progressSummary.new||0}} 条</p><p v-if="progressSummary.errors?.length" style="color:red">{{progressSummary.errors.join('；')}}</p></div><template #footer><n-button @click="closeProgress">关闭</n-button></template></n-modal></main></div></template>
<script setup>
import{h,ref,reactive,computed,onMounted}from'vue'
import{useRouter}from'vue-router'
import{useMessage,NButton,NDataTable,NInput,NSelect,NSpace,NText,NTag,NModal,NDescriptions,NDescriptionsItem}from'naive-ui'
import{list,detail,refresh}from'../api'
import axios from 'axios'
const router=useRouter(),msg=useMessage(),rows=ref([]),total=ref(0),loading=ref(false),refreshing=ref(false),page=ref(1),q=ref(''),severity=ref(["严重","高危"]),source=ref(''),show=ref(false),selected=ref(null)
const aiLoading=ref(false),aiDetail=ref(null)
const enriching=ref(false)
async function enrichOld(){enriching.value=true;try{const d=(await axios.post('/api/v1/vulnerabilities/enrich-severity',{}, {headers:{Authorization:'Bearer '+(localStorage.getItem('token')||'')}})).data.data;msg.info('本次检查 '+d.checked+' 条，成功补全 '+d.updated+' 条；每次最多检查 8 条');await load()}catch(e){msg.error(e.response?.data?.detail||e.message)}finally{enriching.value=false}}
const related=ref({}),expanded=ref([])
async function expandRows(keys){expanded.value=keys;for(const id of keys){if(related.value[id]!==undefined)continue;related.value={...related.value,[id]:null};try{const d=await axios.get('/api/v1/vulnerabilities/'+id+'/related',{headers:{Authorization:'Bearer '+(localStorage.getItem('token')||'')}});related.value={...related.value,[id]:d.data.data}}catch(e){related.value={...related.value,[id]:[]};msg.error('读取关联漏洞失败')}}}
const reviewPagination={pageSize:50,pageSizes:[10,20,50],showSizePicker:true};const pending=ref([]),reviewSearch=ref(""),filteredPending=computed(()=>{const term=reviewSearch.value.trim().toLocaleLowerCase();return term?pending.value.filter(row=>[row.title,row.cve,row.matched_keyword,row.from,row.source].some(v=>String(v??"").toLocaleLowerCase().includes(term))):pending.value}),showReviews=ref(false),checkedIds=ref([]),deleting=ref(false),checkedReviewIds=ref([]),deletingReviews=ref(false)
async function bulkDelete(){if(!checkedIds.value.length)return;if(!confirm('确定永久删除选中的 '+checkedIds.value.length+' 条漏洞？关联审核记录也将删除。'))return;deleting.value=true;try{const response=await axios.post('/api/v1/vulnerabilities/bulk-delete',{ids:checkedIds.value},{headers:{Authorization:'Bearer '+(localStorage.getItem('token')||'')}});msg.success('已删除 '+response.data.data.deleted+' 条');checkedIds.value=[];await load();await loadReviews()}catch(e){msg.error(e.response?.data?.detail||e.message)}finally{deleting.value=false}}
const reviewHttp=axios.create({baseURL:'/api/v1/reviews'})
reviewHttp.interceptors.request.use(c=>{c.headers.Authorization='Bearer '+(localStorage.getItem('token')||'');return c})
async function loadReviews(){try{pending.value=(await reviewHttp.get('')).data.data;const available=new Set(pending.value.map(r=>r.id));checkedReviewIds.value=checkedReviewIds.value.filter(id=>available.has(id))}catch(e){msg.error(e.response?.data?.detail||e.message)}}
async function openReviews(){checkedReviewIds.value=[];await loadReviews();showReviews.value=true}
async function reviewAction(row,action){if(action==='approve'&&!confirm('确认推送该漏洞？'))return;try{await reviewHttp.post('/'+row.id+'/'+action);msg.success(action==='approve'?'已确认并推送':'已忽略');await loadReviews();await load()}catch(e){msg.error(e.response?.data?.detail||e.message)}}
async function deleteReviews(ids){
  if(!ids.length||deletingReviews.value)return
  const selectedRows=pending.value.filter(row=>ids.includes(row.id))
  const cves=[...new Set(selectedRows.map(row=>row.cve).filter(Boolean))]
  const scope=cves.length?'这些 CVE 的全部来源情报也会删除：\\n'+cves.slice(0,15).join('、')+(cves.length>15?' 等 '+cves.length+' 个':''):'选中项目没有 CVE，仅删除对应情报'
  if(!confirm('确定永久删除 '+ids.length+' 条待审核项目？\\n'+scope+'\\n同时删除关联审核、原始爬虫和 AI 研判数据；历史运行记录保留。此操作不可撤销。'))return
  deletingReviews.value=true
  try{
    const response=await reviewHttp.post('/bulk-delete',{ids})
    const result=response.data.data
    msg.success('删除成功：审核 '+result.deleted_reviews+' 条，情报 '+result.deleted_vulnerabilities+' 条，爬虫原始记录 '+result.deleted_crawler_findings+' 条')
    checkedReviewIds.value=[]
    await loadReviews()
    await load()
  }catch(e){msg.error(e.response?.data?.detail||e.message)}
  finally{deletingReviews.value=false}
}
async function deleteSelectedReviews(){await deleteReviews([...checkedReviewIds.value])}
async function deleteOneReview(row){await deleteReviews([row.id])}
const reviewColumns=[
  {type:'selection',multiple:true},
  {title:'漏洞标题',key:'title',minWidth:280},
  {title:'CVE',key:'cve',width:165,render:r=>r.cve||'—'},
  {title:'审核原因',key:'matched_keyword',width:130},
  {title:'来源',key:'from',width:150,render:r=>r.from||r.source||'--'},
  {title:'采集时间',key:'first_seen',width:190,render:r=>formatDate(r.first_seen)},
  {title:'操作',key:'actions',width:230,render:r=>h(NSpace,{},()=>[
    h(NButton,{size:'small',type:'primary',onClick:()=>reviewAction(r,'approve')},()=> '确认推送'),
    h(NButton,{size:'small',onClick:()=>reviewAction(r,'reject')},()=> '忽略'),
    h(NButton,{size:'small',type:'error',loading:deletingReviews.value,onClick:()=>deleteOneReview(r)},()=> '删除')
  ])}
]
function contentLabel(row){return row.content_type==='article'||row.content_type==='article_review'?'安全文章':'漏洞情报'}
function rawLink(row){const links=Array.isArray(row.references)?row.references:[];return links.find(x=>{try{const u=new URL(x);return u.protocol==='https:'||u.protocol==='http:'}catch{return false}})||''}
function rawButton(row){const url=rawLink(row);return url?h(NButton,{size:'small',text:true,type:'primary',tag:'a',href:url,target:'_blank',rel:'noopener noreferrer'},()=> '原始数据'):h(NButton,{size:'small',text:true,disabled:true},()=> '无原始链接')}
const options=['严重','高危','中危','低危','未知'].map(v=>({label:v,value:v}))
const pageSize=ref(100),sortBy=ref("disclosure"),sortOrder=ref("desc")
const pagination=reactive({page:1,pageSize:100,itemCount:0,showSizePicker:true,pageSizes:[20,50,100,200,500],prefix:({itemCount})=>`共 ${itemCount} 条`})
function changePageSize(size){pageSize.value=size;pagination.pageSize=size;page.value=1;pagination.page=1;checkedIds.value=[];load()}
function changeSorter(sorter){
  // Naive UI cycles ascend -> descend -> false. Never leave the table in an unsorted state.
  const key=(sorter?.columnKey === 'from' ? 'source' : sorter?.columnKey) || 'disclosure'
  const order=sorter?.order
  sortBy.value=key
  sortOrder.value=order==='ascend'?'asc':'desc'
  page.value=1
  pagination.page=1
  checkedIds.value=[]
  load()
}
function columnSortOrder(key){
  return sortBy.value===key?(sortOrder.value==='asc'?'ascend':'descend'):false
}
function formatDate(value){if(!value)return '--';let normalized=String(value).trim();if(/^\d{4}-\d\d-\d\d[T ]\d\d:\d\d/.test(normalized)&&!/(Z|[+-]\d\d:?\d\d)$/.test(normalized))normalized=normalized.replace(' ','T')+'Z';let d=new Date(normalized);if(Number.isNaN(d.getTime()))return value;return new Intl.DateTimeFormat('zh-CN',{timeZone:'Asia/Shanghai',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}).format(d)}
const columns = computed(() => [
  {
    type: 'expand',
    expandable: row => (row.group_count || 1) > 1,
    renderExpand: row => {
      if (related.value[row.id] === null) return h('span', '正在加载...')
      const relatedColumns = [
        { title: '标题', key: 'title', minWidth: 250, render: item => h(NButton, { text: true, type: 'primary', onClick: () => open(item.id) }, () => item.title) },
        { title: '等级', key: 'severity', width: 90 },
        { title: '内容类型', key: 'content_type', width: 110, render: item => contentLabel(item) },
        { title: '来源', key: 'from', width: 140 },
        { title: '披露时间', key: 'disclosure', width: 190, render: item => formatDate(item.disclosure) },
        { title: '采集时间', key: 'first_seen', width: 190, render: item => formatDate(item.first_seen) },
        { title: '原始数据', key: 'raw', width: 100, render: item => rawButton(item) }
      ]
      return h('div', { style: { padding: '10px 12px' } }, [
        h('div', { style: { marginBottom: '8px', color: '#666' } }, '相同 CVE 的其他 ' + (related.value[row.id]?.length || 0) + ' 条情报'),
        h(NDataTable, { size: 'small', bordered: true, columns: relatedColumns, data: related.value[row.id] || [], rowKey: item => item.id })
      ])
    }
  },
  { type: 'selection', multiple: true },
  { title: '等级', key: 'severity', sorter: true, sortOrder: columnSortOrder('severity'), width: 90, render: row => h(NTag, { type: row.severity === '严重' ? 'error' : 'warning' }, () => row.severity || '未知') },
  { title: '漏洞标题', key: 'title', sorter: true, sortOrder: columnSortOrder('title'), minWidth: 300, render: row => h(NButton, { text: true, type: 'primary', onClick: () => open(row.id) }, () => h('span', { style: { whiteSpace: 'normal', overflowWrap: 'anywhere', textAlign: 'left', lineHeight: '1.5', display: 'inline-block' } }, row.title)) },
  { title: '内容类型', key: 'content_type', width: 110, render: row => h(NTag, { type: row.content_type==='article'?'info':'success' }, () => contentLabel(row)) },
  { title: 'CVE', key: 'cve', sorter: true, sortOrder: columnSortOrder('cve'), width: 160 },
  { title: '来源', key: 'from', sorter: true, sortOrder: columnSortOrder('source'), width: 150, ellipsis: { tooltip: true } },
  { title: '披露时间', key: 'disclosure', sorter: true, sortOrder: columnSortOrder('disclosure'), width: 185, render: row => formatDate(row.disclosure) },
  { title: '采集时间', key: 'first_seen', sorter: true, sortOrder: columnSortOrder('first_seen'), width: 185, render: row => formatDate(row.first_seen) },
  { title: '原始数据', key: 'raw', width: 100, render: row => rawButton(row) }
])
async function load(){loading.value=true;try{const r=await list({page:page.value,size:pageSize.value,grouped:true,sort_by:sortBy.value,sort_order:sortOrder.value,q:q.value,severity:severity.value.join(","),source:source.value});rows.value=r.data.list;related.value={};total.value=r.data.total;pagination.itemCount=total.value}catch(e){msg.error(e.message)}finally{loading.value=false}}
async function open(id){
  try{
    selected.value=(await detail(id)).data
    show.value=true
    aiDetail.value=null
    if(!selected.value.cve)return
    aiLoading.value=true
    try{
      const response=await axios.get('/api/v1/settings/ai/results/by-cve/'+encodeURIComponent(selected.value.cve),{headers:{Authorization:'Bearer '+localStorage.getItem('token')}})
      aiDetail.value=response.data.data
    }catch(e){msg.error('读取 AI 研判失败')}
    finally{aiLoading.value=false}
  }catch(e){msg.error(e.message)}
}
const showProgress=ref(false),progressStatus=ref('running'),progressSummary=ref({details:[]})
let progressTimer=null,autoCloseTimer=null
function closeProgress(){showProgress.value=false;if(autoCloseTimer)clearTimeout(autoCloseTimer)}
async function refreshNow(){
  if(refreshing.value)return
  refreshing.value=true
  showProgress.value=true
  progressStatus.value='running'
  progressSummary.value={details:[],items:0,primary:0,secondary:0,new:0,errors:[]}
  if(autoCloseTimer)clearTimeout(autoCloseTimer)
  try{
    const headers={Authorization:'Bearer '+(localStorage.getItem('token')||'')}
    const start=await axios.post('/api/v1/vulnerabilities/refresh/start',{},{headers})
    const jobId=start.data.data.job_id
    const poll=async()=>{
      try{
        const res=await axios.get('/api/v1/vulnerabilities/refresh/status/'+jobId,{headers})
        const job=res.data.data
        progressSummary.value=job.summary
        progressStatus.value=job.status
        if(job.status!=='running'){
          clearInterval(progressTimer)
          progressTimer=null
          refreshing.value=false
          await load()
          if(job.status==='error')msg.error(job.error||'采集失败')
          if(job.status==='done'&&!job.summary.new&&!job.summary.errors?.length)
            autoCloseTimer=setTimeout(()=>{showProgress.value=false},3000)
        }
      }catch(e){
        clearInterval(progressTimer)
        progressTimer=null
        refreshing.value=false
        progressStatus.value='error'
        msg.error(e.message)
      }
    }
    await poll()
    if(progressStatus.value==='running')progressTimer=setInterval(poll,1000)
  }catch(e){refreshing.value=false;progressStatus.value='error';msg.error(e.response?.data?.detail||e.message)}
}
function changePage(p){page.value=p;pagination.page=p;checkedIds.value=[];load()}
function logout(){localStorage.removeItem('token');router.push('/login')}
onMounted(()=>{load();loadReviews()})
</script>
<style scoped>.shell{min-height:100vh;background:#f5f7fa;color:#243447}header{height:64px;background:#fff;display:flex;align-items:center;gap:36px;padding:0 32px;border-bottom:1px solid #eee}header strong{color:#2080f0;font-size:20px}header nav{flex:1}main{max-width:1500px;margin:32px auto;background:#fff;padding:24px;border-radius:10px;overflow-x:auto}.head{display:flex;justify-content:space-between;align-items:center}.head h2{margin:0}</style>