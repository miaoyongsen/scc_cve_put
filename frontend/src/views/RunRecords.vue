<template>
<div style="max-width:1200px;margin:30px auto;padding:20px">
<h2>运行记录</h2>
<n-space style="margin-bottom:16px">
<n-select v-model:value="tier" :options="tiers" style="width:150px" @update:value="reload"/>
<n-select v-model:value="status" :options="statuses" style="width:160px" @update:value="reload"/>
<n-input v-model:value="q" placeholder="搜索标题、CVE、来源" clearable style="width:260px" @keyup.enter="reload"/>
<n-button type="primary" @click="reload">查询</n-button>
<n-button @click="reload">刷新</n-button>
</n-space>
<n-data-table :columns="columns" :data="rows" :loading="loading" :row-key="row=>row.id" :pagination="false" :scroll-x="1050"/>
<n-space justify="end" style="margin-top:16px"><n-pagination v-model:page="page" :page-size="30" :item-count="total" @update:page="load"/></n-space>
<n-modal v-model:show="visible" preset="card" title="运行详情" style="max-width:650px">
<p><b>标题：</b>{{selected.title}}</p><p><b>来源：</b>{{selected.source}}</p><p><b>等级：</b>{{tierLabel(selected.tier)}}</p><p><b>状态：</b>{{selected.status}}</p><p><b>时间：</b>{{selected.created_at}}</p><p><b>说明：</b>{{selected.detail||'-'}}</p>
<n-button v-if="selected.url" tag="a" :href="selected.url" target="_blank" rel="noopener noreferrer" type="primary">打开原始内容</n-button>
</n-modal>
</div>
</template>
<script setup>
import {ref,h,onMounted} from 'vue'
import axios from 'axios'
import {NDataTable,NButton,NSpace,NSelect,NInput,NPagination,NModal,useMessage} from 'naive-ui'
const msg=useMessage(),rows=ref([]),page=ref(1),total=ref(0),loading=ref(false),tier=ref(''),status=ref(''),q=ref(''),visible=ref(false),selected=ref({})
const tiers=[{label:'全部级别',value:''},{label:'一级',value:'primary'},{label:'二级',value:'secondary'},{label:'安全文章',value:'article'}]
const statuses=['','待推送','待审核','未推送','推送成功','推送未成功','推送失败'].map(x=>({label:x||'全部状态',value:x}))
const tierLabel=x=>({primary:'一级',secondary:'二级',article:'安全文章'})[x]||x||'-'
const columns=[{title:'运行时间',key:'created_at',width:190,render:r=>r.created_at?String(r.created_at).replace('T',' ').slice(0,19):'-'},{title:'级别',key:'tier',width:95,render:r=>tierLabel(r.tier)},{title:'来源',key:'source',width:140},{title:'标题',key:'title',ellipsis:{tooltip:true},render:r=>h(NButton,{text:true,type:'primary',onClick:()=>{selected.value=r;visible.value=true}},()=>r.title)},{title:'CVE',key:'cve',width:160},{title:'推送状态',key:'status',width:125},{title:'操作',key:'action',width:90,render:r=>h(NButton,{size:'small',onClick:()=>{selected.value=r;visible.value=true}},()=> '查看')}]
async function load(){loading.value=true;try{const d=(await axios.get('/api/v1/run-records',{params:{page:page.value,size:30,tier:tier.value,status:status.value,q:q.value},headers:{Authorization:'Bearer '+(localStorage.getItem('token')||'')}})).data.data;rows.value=d.list;total.value=d.total}catch(e){msg.error(e.response?.data?.detail||e.message)}finally{loading.value=false}}
function reload(){page.value=1;load()}
onMounted(load)
</script>