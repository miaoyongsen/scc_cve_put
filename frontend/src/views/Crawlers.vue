<template>
<n-card title="Python 爬虫管理（独立于 RSS）" style="margin:24px 0">
  <n-alert type="info" style="margin-bottom:12px">Python 脚本直接使用服务器 Python 运行，无需 Docker。仅允许可信管理员编辑脚本；脚本拥有后端服务账号的文件和网络访问权限。试运行允许任意输出（包括网页访问失败的报错），不入库；仅“采集入库”要求输出 Crawler JSON v1.0。</n-alert>
  <n-space style="margin-bottom:12px">
    <n-button type="primary" :loading="running" @click="collectAll">一键采集全部 Python</n-button>
    <n-button @click="load">刷新列表</n-button>
    <n-select v-model:value="selectedId" :options="scripts.map(s=>({label:s.name,value:s.id}))" placeholder="选择脚本" style="width:260px" @update:value="choose"/>
    <n-button @click="newScript">新建</n-button>
    <n-button type="primary" :loading="saving" @click="saveScript">保存脚本</n-button>
    <n-button :disabled="!selectedId" :loading="running" @click="runTest">试运行</n-button>
    <n-button :disabled="!selectedId" :loading="running" @click="collect">采集入库</n-button>
    <n-button type="error" :disabled="!selectedId" @click="remove">删除脚本</n-button>
    <n-button @click="loadFindings">查看采集结果</n-button>
  </n-space>
  <n-data-table :columns="columns" :data="scripts" :row-key="row=>row.id" style="margin-bottom:16px"/>
  <n-modal v-model:show="editorVisible" preset="card" title="Python 脚本配置" style="max-width:900px">
  <n-input v-model:value="name" placeholder="脚本名称" style="margin-bottom:12px"/>
  <n-select v-model:value="contentType" :options="typeOptions" style="width:320px;margin-bottom:12px"/>
  <n-input v-model:value="code" type="textarea" :autosize="{minRows:15,maxRows:32}" style="font-family:monospace" placeholder="输入 Python 代码"/>
  <n-space style="margin-top:12px"><n-button type="primary" :loading="saving" @click="saveScript">保存配置</n-button><n-button @click="editorVisible=false">关闭</n-button></n-space>
  </n-modal>
  <n-h4>试运行输出（在线查看）</n-h4>
  <n-text depth="3">试运行原样显示 stdout、stderr 和退出码，不要求 JSON；采集入库时才校验 JSON。</n-text>
  <pre style="white-space:pre-wrap;word-break:break-word;max-height:420px;overflow:auto;background:#f4f6f8;padding:12px">{{output}}</pre>
  <n-h4>爬虫采集记录（仅按 CVE 聚合，最早采集的记录在前）</n-h4>
  <n-collapse>
    <n-collapse-item v-for="group in findings" :key="group.cve||group.items[0]?.id" :title="(group.cve||group.items[0]?.title)+'（'+group.count+' 条）'">
      <n-card v-for="item in group.items" :key="item.id" size="small" style="margin-bottom:8px">
        <strong>{{item.title}}</strong> · {{item.severity}} · {{item.first_seen}}<br/>
        <span>{{item.description}}</span><br/>
        <a :href="item.url" target="_blank" rel="noopener noreferrer">原始数据 ↗</a>
        <pre style="white-space:pre-wrap;word-break:break-word">{{JSON.stringify(item,null,2)}}</pre>
      </n-card>
    </n-collapse-item>
  </n-collapse>
</n-card>
</template>
<script setup>
import {ref,onMounted,h} from 'vue'
import axios from 'axios'
import {useMessage,NCard,NAlert,NSpace,NSelect,NButton,NInput,NH4,NText,NCollapse,NCollapseItem,NDataTable,NModal} from 'naive-ui'
const msg=useMessage(),scripts=ref([]),selectedId=ref(null),name=ref(''),code=ref(''),saving=ref(false),running=ref(false),output=ref('暂无运行结果'),findings=ref([])
const editorVisible=ref(false),contentType=ref('vulnerability')
const columns=[{title:'脚本名称',key:'name'},{title:'内容类型',key:'content_type',render:r=>({vulnerability:'漏洞情报',article:'安全文章',article_review:'文章审核'}[r.content_type]||'漏洞情报')},{title:'更新时间',key:'updated_at'},{title:'操作',key:'actions',render:r=>h(NSpace,{},()=>[h(NButton,{size:'small',onClick:()=>choose(r.id)},()=> '编辑'),h(NButton,{size:'small',loading:running.value,onClick:()=>{selectedId.value=r.id;execute('test')}},()=> '试运行'),h(NButton,{size:'small',loading:running.value,onClick:()=>{selectedId.value=r.id;execute('collect')}},()=> '采集'),h(NButton,{size:'small',type:'error',onClick:()=>{selectedId.value=r.id;remove()}},()=> '删除')])}]
const typeOptions=[{label:'漏洞情报',value:'vulnerability'},{label:'安全文章（仅入库）',value:'article'},{label:'安全文章（人工审核）',value:'article_review'}]
const http=axios.create({baseURL:'/api/v1/crawlers',timeout:45000})
http.interceptors.request.use(c=>{c.headers.Authorization='Bearer '+(localStorage.getItem('token')||'');return c})
const example=`import json
import sys

# 仅为输出协议示例，替换为你的爬取逻辑
result = {
    "version": "1.0",
    "items": [{
        "title": "示例漏洞公告",
        "url": "https://example.com/advisory/123",
        "cve": "CVE-2026-12345",
        "severity": "高危",
        "cvss_score": 8.8,
        "description": "示例描述",
        "disclosure": "2026-10-22T08:30:00+08:00",
        "solutions": "升级修复",
        "tags": ["example"]
    }]
}
print(json.dumps(result, ensure_ascii=False))
`
function newScript(){selectedId.value=null;name.value='';contentType.value='vulnerability';code.value=example;output.value='暂无运行结果';editorVisible.value=true}
function choose(id){const x=scripts.value.find(s=>s.id===id);if(x){name.value=x.name;contentType.value=x.content_type||"vulnerability";code.value=x.code;output.value='暂无运行结果';editorVisible.value=true}}
async function load(){try{scripts.value=(await http.get('')).data.data}catch(e){msg.error(e.message)}}
async function saveScript(){if(!name.value.trim()||!code.value.trim()){msg.warning('请填写名称和代码');return}saving.value=true;try{const body={name:name.value,code:code.value,content_type:contentType.value};const response=selectedId.value?await http.put('/'+selectedId.value,body):await http.post('',body);selectedId.value=response.data.data.id;await load();editorVisible.value=false;msg.success('脚本已保存')}catch(e){msg.error(JSON.stringify(e.response?.data?.detail||e.message))}finally{saving.value=false}}
async function execute(path){running.value=true;output.value='正在执行...';try{const r=await http.post('/'+selectedId.value+'/'+path);const data=r.data.data;output.value=path==='test'?('退出码：'+data.exit_code+'\n\nstdout：\n'+(data.stdout||'(空)')+'\n\nstderr：\n'+(data.stderr||'(空)')):JSON.stringify(data,null,2);if(path==='test'&&data.exit_code!==0)msg.warning('脚本执行报错，已显示输出');else msg.success(path==='test'?'试运行结束':'已采集入库');if(path==='collect')await loadFindings()}catch(e){output.value=JSON.stringify(e.response?.data?.detail||e.message,null,2);msg.error('执行失败，请查看输出')}finally{running.value=false}}
async function collectAll(){running.value=true;output.value='正在依次采集全部 Python 脚本...';try{const d=(await http.post('/collect-all',{},{timeout:600000})).data.data;output.value=JSON.stringify(d,null,2);msg.success('完成 '+d.success+'/'+d.total+' 个脚本');await loadFindings()}catch(e){output.value=String(e.response?.data?.detail||e.message);msg.error('批量采集失败')}finally{running.value=false}}
async function runTest(){await execute('test')}
async function collect(){await execute('collect')}
async function remove(){if(!confirm('删除当前脚本？已入库记录保留。'))return;try{await http.delete('/'+selectedId.value);newScript();await load();msg.success('已删除')}catch(e){msg.error(e.message)}}
async function loadFindings(){try{findings.value=(await http.get('/findings')).data.data}catch(e){msg.error(e.message)}}
onMounted(()=>{newScript();load();loadFindings()})
</script>