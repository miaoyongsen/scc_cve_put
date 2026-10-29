<template>
<div class="dash">
  <n-space justify="space-between" align="center"><h2>运行监控看板</h2><n-space><n-select v-model:value="days" :options="options" style="width:130px"/><n-button :loading="loading" @click="load">刷新</n-button></n-space></n-space>
  <n-alert v-if="error" type="error" style="margin-bottom:16px">{{error}}</n-alert>
  <n-alert type="info" style="margin-bottom:16px">统计仅覆盖主库保留的运行历史。推送成功率不计入过滤、待审核及未配置渠道；无数据时显示「—」。</n-alert>
  <div class="cards">
    <n-card v-for="card in cards" :key="card.name" :title="card.name"><div class="number">{{card.value}}</div><n-text depth="3">{{card.note}}</n-text></n-card>
  </div>
  <n-card title="每日采集趋势" style="margin-top:18px"><div v-if="!data.trend?.length">暂无采集数据</div><div v-for="d in data.trend||[]" :key="d.date" class="trend"><span>{{d.date}}</span><div class="track"><div class="fill" :style="{width:(100*d.items/maxItems)+'%'}"></div></div><span>{{d.items}} 条 / {{d.runs}} 次 / {{d.failed}} 异常</span></div></n-card>
  <n-card title="来源运行健康度" style="margin-top:18px"><n-data-table :columns="sourceColumns" :data="data.sources||[]" :pagination="{pageSize:10}" /></n-card>
  <n-card title="最近运行任务" style="margin-top:18px"><n-data-table :columns="runColumns" :data="data.recent||[]" :pagination="{pageSize:10}" /></n-card>
  <n-text depth="3" style="display:block;margin-top:12px">重复率 = 来源报告重复条数 / 抓取条数；失败率 = 失败及部分失败任务 / 总任务数。</n-text>
</div>
</template>
<script setup>
import {ref,computed,onMounted} from 'vue'
import axios from 'axios'
import {NCard,NSpace,NButton,NSelect,NAlert,NDataTable,NText,useMessage} from 'naive-ui'
const msg=useMessage(),days=ref(7),loading=ref(false),error=ref('')
const options=[{label:'最近 7 天',value:7},{label:'最近 30 天',value:30},{label:'最近 90 天',value:90}]
const data=ref({totals:{},rates:{},trend:[],sources:[],recent:[]})
const pct=v=>v==null?'—':v.toFixed(2)+'%'
const cards=computed(()=>[
 {name:'任务失败率',value:pct(data.value.rates.failure_rate),note:'失败 + 部分失败'},
 {name:'情报重复率',value:pct(data.value.rates.duplicate_rate),note:'来源报告的重复情报'},
 {name:'推送成功率',value:pct(data.value.rates.push_success_rate),note:'成功 / (成功 + 失败)'},
 {name:'采集任务',value:data.value.totals.runs||0,note:'最近所选时间范围'},
 {name:'抓取情报',value:data.value.totals.items||0,note:'包含重复数据'},
 {name:'新增情报',value:data.value.totals.new||0,note:'新写入数据库'},
 {name:'推送成功',value:data.value.totals.push_success||0,note:'发送成功的消息'},
 {name:'历史漏洞',value:data.value.totals.vulnerabilities||0,note:'主库情报总数'}
])
const maxItems=computed(()=>Math.max(1,...(data.value.trend||[]).map(x=>x.items)))
const sourceColumns=[{title:'情报来源',key:'name'},{title:'运行次数',key:'runs'},{title:'异常次数',key:'failed'},{title:'抓取数量',key:'items'},{title:'重复数量',key:'duplicates'}]
const runColumns=[{title:'任务 ID',key:'id'},{title:'时间',key:'date'},{title:'任务类型',key:'mode'},{title:'状态',key:'status'},{title:'错误摘要',key:'errors',render:row=>(row.errors||[]).join('；')||'—'}]
async function load(){loading.value=true;error.value='';try{const res=await axios.get('/api/v1/dashboard',{params:{days:days.value},headers:{Authorization:'Bearer '+localStorage.getItem('token')}});data.value=res.data.data}catch(e){error.value=e.response?.data?.detail||e.message;msg.error('看板加载失败')}finally{loading.value=false}}
onMounted(load)
</script>
<style scoped>
.dash{max-width:1400px;margin:26px auto;padding:0 20px 36px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px}.number{font-size:30px;font-weight:700;color:#1769aa;margin:6px 0 12px}.trend{display:flex;gap:12px;align-items:center;padding:7px 0;font-size:13px}.trend>span:first-child{width:92px;flex-shrink:0}.trend>span:last-child{width:170px;flex-shrink:0}.track{height:13px;background:#eef2f6;border-radius:8px;flex:1}.fill{height:100%;background:#3e91d7;border-radius:8px;min-width:0}
</style>
