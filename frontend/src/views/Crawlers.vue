<template>
<n-card title="Python 爬虫管理（独立于 RSS）" style="margin:24px 0">
  <n-alert type="info" style="margin-bottom:12px">Python 脚本直接使用服务器 Python 运行，无需 Docker。仅允许可信管理员编辑脚本；脚本拥有后端服务账号的文件和网络访问权限。标准输出须为 Crawler JSON v1.0。试运行不入库，点击“采集入库”才保存。</n-alert>
  <n-space style="margin-bottom:12px">
    <n-select v-model:value="selectedId" :options="scripts.map(s=>({label:s.name,value:s.id}))" placeholder="选择脚本" style="width:260px" @update:value="choose"/>
    <n-button @click="newScript">新建</n-button>
    <n-button type="primary" :loading="saving" @click="saveScript">保存脚本</n-button>
    <n-button :disabled="!selectedId" :loading="running" @click="runTest">试运行</n-button>
    <n-button :disabled="!selectedId" :loading="running" @click="collect">采集入库</n-button>
    <n-button type="error" :disabled="!selectedId" @click="remove">删除脚本</n-button>
    <n-button @click="loadFindings">查看采集结果</n-button>
  </n-space>
  <n-input v-model:value="name" placeholder="脚本名称" style="margin-bottom:12px"/>
  <n-input v-model:value="code" type="textarea" :autosize="{minRows:15,maxRows:32}" style="font-family:monospace" placeholder="输入 Python 代码"/>
  <n-h4>试运行输出（在线查看）</n-h4>
  <n-text depth="3">测试只解析 JSON，不写入数据库。调试日志写 stderr。</n-text>
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
import {ref,onMounted} from 'vue'
import axios from 'axios'
import {useMessage,NCard,NAlert,NSpace,NSelect,NButton,NInput,NH4,NText,NCollapse,NCollapseItem} from 'naive-ui'
const msg=useMessage(),scripts=ref([]),selectedId=ref(null),name=ref(''),code=ref(''),saving=ref(false),running=ref(false),output=ref('暂无运行结果'),findings=ref([])
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
function newScript(){selectedId.value=null;name.value='';code.value=example;output.value='暂无运行结果'}
function choose(id){const x=scripts.value.find(s=>s.id===id);if(x){name.value=x.name;code.value=x.code;output.value='暂无运行结果'}}
async function load(){try{scripts.value=(await http.get('')).data.data}catch(e){msg.error(e.message)}}
async function saveScript(){if(!name.value.trim()||!code.value.trim()){msg.warning('请填写名称和代码');return}saving.value=true;try{const body={name:name.value,code:code.value};const response=selectedId.value?await http.put('/'+selectedId.value,body):await http.post('',body);selectedId.value=response.data.data.id;await load();msg.success('脚本已保存')}catch(e){msg.error(JSON.stringify(e.response?.data?.detail||e.message))}finally{saving.value=false}}
async function execute(path){running.value=true;output.value='正在执行...';try{const r=await http.post('/'+selectedId.value+'/'+path);output.value=JSON.stringify(r.data.data,null,2);msg.success(path==='test'?'试运行成功':'已采集入库');if(path==='collect')await loadFindings()}catch(e){output.value=JSON.stringify(e.response?.data?.detail||e.message,null,2);msg.error('执行失败，请查看输出')}finally{running.value=false}}
async function runTest(){await execute('test')}
async function collect(){await execute('collect')}
async function remove(){if(!confirm('删除当前脚本？已入库记录保留。'))return;try{await http.delete('/'+selectedId.value);newScript();await load();msg.success('已删除')}catch(e){msg.error(e.message)}}
async function loadFindings(){try{findings.value=(await http.get('/findings')).data.data}catch(e){msg.error(e.message)}}
onMounted(()=>{newScript();load();loadFindings()})
</script>