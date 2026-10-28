<template>
<div style="max-width:1200px;margin:28px auto;padding:20px">
<n-space justify="space-between" align="center"><h2>采集运行记录</h2><n-button @click="load">刷新</n-button></n-space>
<n-alert type="info" style="margin-bottom:14px">每次采集只显示一行，点击展开查看本次 RSS / Python 来源、HTTP 状态码、CVE 数量、重复内容、一级/二级情报及实际推送结果。不同采集入口各自记录一次运行。</n-alert>
<n-data-table :columns="columns" :data="rows" :loading="loading" :pagination="false" :row-key="r=>r.id"/>
<n-space justify="end" style="margin-top:14px"><n-pagination v-model:page="page" :page-size="20" :item-count="total" @update:page="load"/></n-space>
<n-modal v-model:show="visible" preset="card" title="本次运行详情" style="width:1000px;max-width:96vw">
<n-space style="margin-bottom:12px"><n-tag>运行 #{{detail.id}}</n-tag><n-tag>{{detail.mode}}</n-tag><n-tag :type="detail.status==='完成'?'success':'warning'">{{detail.status}}</n-tag></n-space>
<n-alert v-if="detail.summary?.error" type="error">{{detail.summary.error}}</n-alert>
<n-card v-for="(src,i) in detail.summary?.details||[]" :key="i" :title="(src.name||('爬虫 #'+src.id))+' · '+(src.adapter||'python')" size="small" style="margin-bottom:12px">
<n-space style="margin-bottom:10px"><n-tag>HTTP：{{src.http_status??'不适用/未获取'}}</n-tag><n-tag>采集 {{src.items??src.count??0}}</n-tag><n-tag type="success">新增 {{src.new??src.inserted??0}}</n-tag><n-tag type="info">一级 {{src.primary??0}}</n-tag><n-tag type="warning">二级 {{src.secondary??0}}</n-tag><n-tag>推送 {{src.notifications??src.pushed?.length??0}}</n-tag><n-tag>重复 {{src.duplicates?.length??0}}</n-tag><n-tag :type="src.status==='error'||src.ok===false?'error':'success'">{{src.status|| (src.ok===false?'失败':'完成')}}</n-tag></n-space>
<p v-if="src.error" style="color:#d03050">{{src.error}}</p>
<n-collapse>
<n-collapse-item title="重复记录" name="dup"><div v-for="(x,j) in src.duplicates||[]" :key="j">{{x.cve||'-'}} · {{x.title}} · {{x.reason}}</div><n-empty v-if="!src.duplicates?.length" description="无"/></n-collapse-item>
<n-collapse-item title="实际推送" name="push"><div v-for="(x,j) in src.pushed||[]" :key="j">{{x.cve||'-'}} · {{x.title}}</div><n-empty v-if="!src.pushed?.length" description="无"/></n-collapse-item>
<n-collapse-item title="二级待审核" name="pending"><div v-for="(x,j) in src.pending||[]" :key="j">{{x.cve||'-'}} · {{x.title}}</div><n-empty v-if="!src.pending?.length" description="无"/></n-collapse-item>
</n-collapse>
</n-card>
<h3>本次采集情报明细（{{detail.items?.length||0}} 条事件）</h3>
<n-data-table :columns="itemColumns" :data="detail.items||[]" :pagination="{pageSize:10}" :row-key="r=>r.id" :scroll-x="850"/>
</n-modal>
</div>
</template>
<script setup>
import {ref,h,onMounted} from 'vue'
import axios from 'axios'
import {NDataTable,NButton,NSpace,NPagination,NModal,NTag,NAlert,NCard,NCollapse,NCollapseItem,NEmpty,useMessage} from 'naive-ui'
const msg=useMessage(),rows=ref([]),page=ref(1),total=ref(0),loading=ref(false),visible=ref(false),detail=ref({})
const http=axios.create({baseURL:'/api/v1/collection-runs'})
http.interceptors.request.use(c=>{c.headers.Authorization='Bearer '+(localStorage.getItem('token')||'');return c})
const columns=[{title:'运行编号',key:'id',width:110},{title:'开始时间',key:'started_at',render:r=>String(r.started_at||'').replace('T',' ').slice(0,19)},{title:'采集类型',key:'mode'},{title:'来源数',key:'sources',render:r=>r.summary?.details?.length??0},{title:'采集总量',key:'items',render:r=>r.summary?.items??(r.summary?.details||[]).reduce((a,x)=>a+(x.count??x.items??0),0)},{title:'状态',key:'status'},{title:'操作',key:'action',render:r=>h(NButton,{type:'primary',text:true,onClick:()=>open(r)},()=> '展开详情')}]
const tierLabel=x=>({primary:'一级',secondary:'二级',article:'文章'})[x]||x||'-'
const itemColumns=[{title:'来源',key:'source',width:130},{title:'级别',key:'tier',width:90,render:r=>tierLabel(r.tier)},{title:'标题',key:'title',ellipsis:{tooltip:true},render:r=>r.url?h('a',{href:r.url,target:'_blank',rel:'noopener noreferrer'},r.title):r.title},{title:'CVE',key:'cve',width:160},{title:'处理结果',key:'status',width:110},{title:'说明',key:'detail',width:180,ellipsis:{tooltip:true}}]
async function load(){loading.value=true;try{const d=(await http.get('',{params:{page:page.value,size:20}})).data.data;rows.value=d.list;total.value=d.total}catch(e){msg.error(e.response?.data?.detail||e.message)}finally{loading.value=false}}
async function open(r){try{detail.value=(await http.get('/'+r.id)).data.data;visible.value=true}catch(e){msg.error(e.response?.data?.detail||e.message)}}
onMounted(load)
</script>