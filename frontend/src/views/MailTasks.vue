<template>
<div class="mail-page">
  <n-space justify="space-between" align="center"><h2>邮件推送列表</h2><n-space><n-button @click="openSettings">AI配置</n-button><n-button type="primary" @click="open()">创建任务</n-button></n-space></n-space>
  <n-space align="center" style="margin:10px 0 16px"><n-tag type="info">当前 Skill：{{settings.skill_name||"未选择"}}</n-tag><n-tag :type="settings.smtp_ready?'success':'warning'">Teams Webhook：{{settings.smtp_ready?"已配置":"未配置"}}</n-tag></n-space>
  <n-space style="margin:16px 0"><n-input v-model:value="q" clearable placeholder="搜索任务 / CVE / 邮件主题 / 收件人" @keyup.enter="search"/><n-button @click="search">查询</n-button></n-space>
  <n-data-table :columns="columns" :data="rows" :loading="loading" :row-key="r=>r.id" :pagination="false" :scroll-x="1750"/>
  <n-space justify="end" style="margin-top:16px"><n-pagination :page="page" :page-size="20" :item-count="total" @update:page="changePage"/></n-space>
  <n-modal v-model:show="visible" preset="card" :title="editing?'编辑邮件任务':'创建邮件任务'" style="width:min(1150px,96vw);max-height:94vh;overflow:auto" :mask-closable="false" :closable="!busy">
    <n-form label-placement="top" :disabled="busy">
      <n-form-item label="任务名称（选填，默认使用漏洞标题）"><n-input v-model:value="form.name"/></n-form-item>
      <n-space align="end" :wrap="true" style="width:100%" size="large">
        <n-form-item label="当前 AI Skill" style="flex:1;min-width:220px"><n-tag type="info">{{settings.skill_name||"未选择"}}</n-tag></n-form-item>
        <n-form-item label="截止时间（北京时间，必填）" style="width:280px;max-width:100%">
          <n-date-picker v-model:value="form.deadline" type="datetime" format="yyyy-MM-dd HH:mm" clearable placeholder="选择截止日期和时间" style="width:100%"/>
        </n-form-item>
      </n-space>
      <n-form-item label="CVE 编号">
        <n-space align="center" style="width:100%"><n-input v-model:value="form.data.cve_id" placeholder="CVE-2026-12345" style="width:min(340px,60vw)"/><n-button type="info" :loading="generating" :disabled="!validCve||busy||!settings.skill_id" @click="generate">AI 自动填充</n-button></n-space>
      </n-form-item>
      <n-form-item label="补充情报资料（AI生成时使用，选填）"><n-input v-model:value="evidence" type="textarea" :rows="2" placeholder="粘贴厂商公告正文、准确版本范围、修复信息等；AI不会自动读取链接网页"/></n-form-item>
      <n-alert type="info" style="margin-bottom:16px">AI为可选辅助功能；所有内容均可人工填写或微调。发送前请核实影响版本、升级版本和官方链接。</n-alert>
      <n-form-item label="危害等级"><n-select v-model:value="form.data.severity" :options="levels" style="max-width:240px"/></n-form-item>
      <n-form-item label="漏洞标题"><n-input v-model:value="form.data.title"/></n-form-item>
      <n-form-item label="漏洞概述"><n-input v-model:value="form.data.vulnerability_summary" type="textarea" :rows="4"/></n-form-item>
      <n-space justify="space-between" align="center"><h3>受影响产品及修复版本</h3><n-button size="small" @click="form.data.affected_products.push(product())">新增一行</n-button></n-space>
      <div class="table-wrap">
        <table class="edit-table"><thead><tr><th>产品</th><th>影响版本</th><th>升级版本</th><th>漏洞影响</th><th>操作</th></tr></thead><tbody>
          <tr v-for="(p,i) in form.data.affected_products" :key="i"><td><n-input v-model:value="p.product" type="textarea" :rows="2"/></td><td><n-input v-model:value="p.affected_version" type="textarea" :rows="2"/></td><td><n-input v-model:value="p.upgrade_version" type="textarea" :rows="2"/></td><td><n-input v-model:value="p.vulnerability_impact" type="textarea" :rows="2"/></td><td><n-button text type="error" @click="form.data.affected_products.splice(i,1)">删除</n-button></td></tr>
        </tbody></table>
      </div>
      <n-form-item label="升级建议"><n-input v-model:value="form.data.upgrade_recommendation" type="textarea" :rows="2"/></n-form-item>
      <n-form-item label="必要处置措施"><n-input v-model:value="form.data.required_actions" type="textarea" :rows="4"/></n-form-item>
      <n-space justify="space-between" align="center"><h3>官方参考链接</h3><n-button size="small" @click="form.data.references.push(reference())">新增链接</n-button></n-space>
      <div v-for="(r,i) in form.data.references" :key="i" class="ref-row"><n-input v-model:value="r.name" placeholder="链接名称"/><n-input v-model:value="r.url" placeholder="https://..."/><n-button text type="error" @click="form.data.references.splice(i,1)">删除</n-button></div>
      <n-form-item label="收件人"><n-dynamic-tags v-model:value="to" :input-props="{placeholder:'输入邮箱后回车'}"/></n-form-item>
      <n-form-item label="抄送（选填）"><n-dynamic-tags v-model:value="cc" :input-props="{placeholder:'输入邮箱后回车'}"/></n-form-item>
    </n-form>
    <n-space justify="end" style="margin-top:16px">
      <n-button :disabled="busy" @click="visible=false">取消</n-button><n-button :disabled="busy||!form.deadline" :loading="saving" @click="save(false)">保存草稿</n-button><n-button :disabled="busy" @click="previewOpen=true">邮件预览</n-button><n-button type="primary" :disabled="busy||!ready" :loading="sending" @click="save(true)">确认发送</n-button>
    </n-space>
  </n-modal>
  <n-modal v-model:show="settingsOpen" preset="card" title="邮件 AI 配置" style="width:min(650px,95vw)" :mask-closable="false">
    <n-form label-placement="top">
      <n-form-item label="邮件 AI 使用的 Skill"><n-select v-model:value="settingsForm.skill_id" :options="skillOptions" placeholder="选择 Skill"/></n-form-item>
      <n-alert type="info" style="margin-bottom:16px">保存后，所有新建或编辑邮件任务的 AI 自动填充均使用此 Skill，无需每次选择。Skill 内容在公共配置中维护。</n-alert>
      <n-alert type="info" style="margin-bottom:12px">邮件发送使用公共配置 → 邮箱配置中的 Teams Webhook，由 Power Automate 使用 Outlook 发送。</n-alert>
      <n-form-item label="微软流模板标识（固定）"><n-input v-model:value="settingsForm.template_code"/></n-form-item>
      <n-space justify="end"><n-button @click="settingsOpen=false">取消</n-button><n-button type="primary" :loading="settingsSaving" @click="saveSettings">保存配置</n-button></n-space>
    </n-form>
  </n-modal>
  <n-modal v-model:show="previewOpen" preset="card" title="邮件预览（最终排版以微软流为准）" style="width:min(1000px,95vw);max-height:93vh;overflow:auto">
    <div class="preview"><p class="muted">邮件主题</p><h3>{{subject}}</h3><hr/><p>Dear All,</p><p>According to the official security advisory, <span class="red">{{form.data.vulnerability_summary}}</span></p><p>System owners are requested to promptly check their usage and complete the upgrade as soon as possible.</p>
      <h3>1. Affected Products and Remediation</h3><div class="table-wrap"><table><thead><tr><th>Product</th><th>Affected Version</th><th>Upgrade Version</th><th>Vulnerability Impact</th></tr></thead><tbody><tr v-for="(p,i) in form.data.affected_products" :key="i"><td>{{p.product}}</td><td>{{p.affected_version}}</td><td>{{p.upgrade_version}}</td><td>{{p.vulnerability_impact}}</td></tr></tbody></table></div>
      <p class="red"><strong>Upgrade target:</strong> {{form.data.upgrade_recommendation}}</p><h3>2. Required Actions</h3><p>{{form.data.required_actions}}</p><p class="red">Please report the affected assets and the estimated remediation time.</p><h3>3. Official References</h3><p v-for="(r,i) in form.data.references" :key="i">{{r.name}} — {{r.url}}</p><p>Best regards,</p><p>Security Team</p>
    </div>
  </n-modal>
  <n-modal v-model:show="detailOpen" preset="card" title="任务详情" style="width:min(950px,95vw);max-height:93vh;overflow:auto">
    <n-descriptions bordered :column="1"><n-descriptions-item label="任务名称">{{detail.name}}</n-descriptions-item><n-descriptions-item label="邮件主题">{{detail.subject}}</n-descriptions-item><n-descriptions-item label="收件人">{{detail.recipients}}</n-descriptions-item><n-descriptions-item label="抄送">{{detail.cc||'—'}}</n-descriptions-item><n-descriptions-item label="状态">{{detail.status}}</n-descriptions-item><n-descriptions-item label="发送时间">{{time(detail.sent_at)}}</n-descriptions-item><n-descriptions-item label="截止时间">{{time(detail.deadline)}}</n-descriptions-item></n-descriptions>
    <n-alert v-if="detail.last_error" type="warning" style="margin-top:12px">{{detail.last_error}}</n-alert><pre class="body">{{detail.data?JSON.stringify(detail.data,null,2):detail.body}}</pre>
  </n-modal>
  <n-modal v-model:show="trackerOpen" preset="card" title="Tracker 链路" style="width:min(1200px,96vw);max-height:94vh;overflow:auto">
    <n-space justify="space-between" align="center" style="margin-bottom:14px">
      <n-space><n-tag type="info">{{tracker.task_id||'—'}}</n-tag><n-tag :type="tracker.status==='Webhook已接收'?'info':'default'">{{tracker.status||'—'}}</n-tag></n-space>
      <n-button size="small" :loading="trackerLoading" @click="reloadTracker">刷新链路</n-button>
    </n-space>
    <n-alert v-if="trackerError" type="error">{{trackerError}}</n-alert>
    <n-alert type="info" style="margin-bottom:16px">仅追踪正式收件人。自动邮件回传尚未配置，可先手工登记真实回复；Webhook 已接收不等于 Outlook 已送达。</n-alert>
    <div class="tracker-stats">
      <div>收件人 <strong>{{branches.length}}</strong></div>
      <div>已记录回复 <strong>{{branches.filter(b=>b.replies.length).length}}</strong></div>
      <div>已闭环 <strong>{{branches.filter(b=>b.closed).length}}</strong></div>
    </div>
    <div class="tracker-canvas">
      <div class="tracker-root"><span class="tracker-kicker">原始邮件</span><strong>{{tracker.cve||tracker.task_id}}</strong><div>{{tracker.subject}}</div><small>提交时间：{{time(tracker.sent_at)}}</small><small>截止时间：{{time(tracker.deadline)}}</small></div>
      <div class="tracker-branches">
        <div v-for="b in branches" :key="b.recipient" class="tracker-branch">
          <div class="tracker-person" :class="{'is-closed':b.closed}">
            <strong>{{b.recipient}}</strong>
            <n-tag size="small" :type="b.closed?'success':b.replies.length?'info':'default'">{{b.closed?'已闭环':b.replies.length?'已回复 / 待闭环':'暂无回复记录'}}</n-tag>
            <n-space size="small" v-if="canTrack"><n-button text type="primary" size="small" @click="recordReply(b)">登记回复</n-button><n-button text :type="b.closed?'warning':'success'" size="small" :disabled="trackerSaving" @click="toggleClosure(b)">{{b.closed?'重新打开':'确认闭环'}}</n-button></n-space>
            <small v-if="b.closed">闭环：{{time(b.closed_at)}}</small>
          </div>
          <div class="tracker-replies">
            <div v-if="!b.replies.length" class="tracker-empty">暂无回复记录</div>
            <div v-for="(reply,i) in b.replies" :key="reply.id" class="tracker-reply">
              <div class="tracker-reply-head"><strong>回复 {{i+1}}</strong><n-tag size="small" :bordered="false">{{reply.source==='integration'?'接口回传':'手工登记'}}</n-tag></div>
              <small>{{time(reply.received_at)}}</small><div v-if="reply.subject" class="tracker-subject">{{reply.subject}}</div>
              <div class="tracker-excerpt">{{reply.body}}</div>
              <n-button text type="primary" size="small" @click="showReply(reply)">查看完整回复</n-button>
            </div>
          </div>
        </div>
        <div v-if="!branches.length" class="tracker-empty">{{trackerLoading?'加载中…':'暂无正式收件人'}}</div>
      </div>
    </div>
  </n-modal>
  <n-modal v-model:show="replyOpen" preset="card" title="登记邮件回复" style="width:min(680px,95vw)" :mask-closable="false">
    <n-form label-placement="top">
      <n-form-item label="回复人"><n-input :value="replyForm.recipient" disabled/></n-form-item>
      <n-form-item label="实际收到邮件的时间（北京时间）"><n-date-picker v-model:value="replyForm.received_at" type="datetime" format="yyyy-MM-dd HH:mm" clearable placeholder="选择实际收到邮件的日期和时间" style="width:100%"/></n-form-item>
      <n-form-item label="邮件主题（选填）"><n-input v-model:value="replyForm.subject"/></n-form-item>
      <n-form-item label="回复内容"><n-input v-model:value="replyForm.body" type="textarea" :rows="8"/></n-form-item>
      <n-space justify="end"><n-button @click="replyOpen=false">取消</n-button><n-button type="primary" :loading="trackerSaving" :disabled="!replyForm.body.trim()||!replyForm.received_at" @click="saveReply">保存回复</n-button></n-space>
    </n-form>
  </n-modal>
  <n-modal v-model:show="replyDetailOpen" preset="card" title="邮件回复详情" style="width:min(850px,95vw);max-height:90vh;overflow:auto">
    <p><strong>{{replyDetail.recipient}}</strong> · {{time(replyDetail.received_at)}}</p><p>{{replyDetail.subject}}</p><pre class="body">{{replyDetail.body}}</pre>
  </n-modal>
</div>
</template>
<script setup>
import {ref,computed,h,onMounted} from 'vue'
import axios from 'axios'
import {NAlert,NButton,NDataTable,NDatePicker,NDescriptions,NDescriptionsItem,NDynamicTags,NForm,NFormItem,NInput,NModal,NPagination,NSelect,NSpace,NTag,useMessage} from 'naive-ui'
const msg=useMessage(),rows=ref([]),q=ref(''),page=ref(1),total=ref(0),loading=ref(false),saving=ref(false),sending=ref(false),generating=ref(false),visible=ref(false),detailOpen=ref(false),previewOpen=ref(false),detail=ref({}),editing=ref(null),evidence=ref(''),to=ref([]),cc=ref([])
const trackerOpen=ref(false),trackerLoading=ref(false),trackerSaving=ref(false),trackerError=ref(''),tracker=ref({}),trackerId=ref(null),replyOpen=ref(false),replyDetailOpen=ref(false),replyDetail=ref({}),replyForm=ref({recipient:'',subject:'',body:'',received_at:null})
const branches=computed(()=>tracker.value.recipients||[])
const canTrack=computed(()=>['Webhook已接收','SMTP已接收','已发送','待确认','发送中'].includes(tracker.value.status))
async function openTracker(r){trackerId.value=r.id;tracker.value={};trackerOpen.value=true;await reloadTracker()}
async function reloadTracker(){const id=trackerId.value;if(id==null)return;trackerLoading.value=true;trackerError.value='';try{const d=(await http.get('/tasks/'+id+'/tracker')).data.data;if(id===trackerId.value)tracker.value=d}catch(e){if(id===trackerId.value)trackerError.value=e.response?.data?.detail||e.message}finally{if(id===trackerId.value)trackerLoading.value=false}}
function recordReply(b){replyForm.value={recipient:b.recipient,subject:'',body:'',received_at:null};replyOpen.value=true}
function showReply(r){replyDetail.value=r;replyDetailOpen.value=true}
async function saveReply(){if(trackerSaving.value)return;if(!replyForm.value.received_at){msg.error('请选择实际收到邮件的日期和时间');return}trackerSaving.value=true;try{await http.post('/tasks/'+trackerId.value+'/tracker/replies',{...replyForm.value,received_at:beijingIsoFromPicker(replyForm.value.received_at)});replyOpen.value=false;msg.success('已登记回复');await reloadTracker();await load()}catch(e){msg.error(e.response?.data?.detail||e.message)}finally{trackerSaving.value=false}}
async function toggleClosure(b){if(trackerSaving.value||!confirm((b.closed?'重新打开 ':'确认闭环 ')+b.recipient+'？'))return;trackerSaving.value=true;try{await http.put('/tasks/'+trackerId.value+'/tracker/closure',{recipient:b.recipient,closed:!b.closed});await reloadTracker()}catch(e){msg.error(e.response?.data?.detail||e.message)}finally{trackerSaving.value=false}}
const product=()=>({product:'',affected_version:'',upgrade_version:'',vulnerability_impact:''})
const reference=()=>({name:'',url:''})
const blankData=()=>({cve_id:'',severity:'',title:'',vulnerability_summary:'',affected_products:[product()],upgrade_recommendation:'',required_actions:'',references:[reference()]})
const blank=()=>({name:'',deadline:null,data:blankData()})
const form=ref(blank())
const levels=['Critical','High','Medium','Low','Unknown'].map(v=>({label:v,value:v}))
const validCve=computed(()=>/^CVE-\d{4}-\d{4,}$/i.test(form.value.data.cve_id.trim()))
const busy=computed(()=>saving.value||sending.value||generating.value)
const subject=computed(()=> '['+form.value.data.severity+' Security Alert] '+form.value.data.title+' ('+form.value.data.cve_id+')')
const settings=ref({skill_id:0,skill_name:'未选择',smtp_ready:false,template_code:'cve_alert_en'})
const settingsOpen=ref(false),settingsSaving=ref(false),skills=ref([])
const settingsForm=ref({skill_id:0,template_code:'cve_alert_en'})
const skillOptions=computed(()=>[{label:'未选择（仅人工填写）',value:0},...skills.value.map(r=>({label:r.name,value:r.id}))])
const ready=computed(()=>form.value.deadline!=null && validCve.value && settings.value.smtp_ready && to.value.length>0 && ['severity','title','vulnerability_summary','upgrade_recommendation','required_actions'].every(k=>form.value.data[k].trim()) && form.value.data.affected_products.length>0 && form.value.data.affected_products.every(p=>Object.values(p).every(v=>v.trim())) && form.value.data.references.length>0 && form.value.data.references.every(r=>r.name.trim()&&/^https?:\/\//i.test(r.url)))
const http=axios.create({baseURL:'/api/v1/mail',timeout:120000})
http.interceptors.request.use(c=>{c.headers.Authorization='Bearer '+(localStorage.getItem('token')||'');return c})
const time=v=>v?new Date(/[zZ]$|[+-][0-9]{2}:[0-9]{2}$/.test(v)?v:v+'Z').toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false}):'—'
// Keep date-picker wall-clock values in Beijing time even if the browser is in another timezone.
const beijingIsoFromPicker=ms=>{const d=new Date(ms);const pad=n=>String(n).padStart(2,'0');return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}:00+08:00`}
const pickerValueFromBeijing=v=>{if(!v)return null;const d=new Date(/[zZ]$|[+-][0-9]{2}:[0-9]{2}$/.test(v)?v:v+'Z');const b=new Date(d.getTime()+8*60*60*1000);return new Date(b.getUTCFullYear(),b.getUTCMonth(),b.getUTCDate(),b.getUTCHours(),b.getUTCMinutes()).getTime()}
const editable=r=>['草稿','待发送','发送失败'].includes(r.status)
const columns=[
 {title:'ID',key:'id',width:65},{title:'任务名称',key:'name',minWidth:160},{title:'CVE',key:'cve',width:155},{title:'截止时间',key:'deadline',width:180,render:r=>time(r.deadline)},
 {title:'任务进度',key:'progress',width:390,render:r=>h(NSpace,{size:6,wrap:false},()=>[
   h(NTag,{type:'info',bordered:false,size:'small'},()=> '总发送 '+(r.progress?.total_sent??0)),
   h(NTag,{type:'warning',bordered:false,size:'small'},()=> '跟进中 '+(r.progress?.following_up??0)),
   h(NTag,{type:'success',bordered:false,size:'small'},()=> '已处置 '+(r.progress?.disposed??0)),
   h(NTag,{type:'error',bordered:false,size:'small'},()=> '已超期 '+(r.progress?.overdue??0))
 ])},
 {title:'收件人',key:'recipients',minWidth:180,ellipsis:{tooltip:true}},{title:'状态',key:'status',width:95,render:r=>{const accepted=['已发送','SMTP已接收','Webhook已接收'].includes(r.status);return h(NTag,{type:accepted?'success':'default',bordered:false},()=>accepted?'已接收':'未接收')}},
 {title:'创建时间',key:'created_at',width:180,render:r=>time(r.created_at)},{title:'操作',key:'action',width:260,render:r=>h(NSpace,{size:8},()=>[h(NButton,{text:true,type:'primary',onClick:()=>view(r)},()=> '查看'),h(NButton,{text:true,type:'info',onClick:()=>openTracker(r)},()=> 'Tracker链路'),editable(r)?h(NButton,{text:true,type:'primary',onClick:()=>open(r)},()=> '编辑'):null,h(NButton,{text:true,type:'error',disabled:r.status==='发送中',onClick:()=>remove(r)},()=> '删除')])}
]
async function load(){loading.value=true;try{let d=(await http.get('/tasks',{params:{q:q.value,page:page.value,size:20}})).data.data;total.value=d.total;if(page.value>Math.max(1,Math.ceil(total.value/20))){page.value=Math.max(1,Math.ceil(total.value/20));d=(await http.get('/tasks',{params:{q:q.value,page:page.value,size:20}})).data.data;total.value=d.total}rows.value=d.list}catch(e){msg.error(e.response?.data?.detail||e.message)}finally{loading.value=false}}
function search(){page.value=1;load()}
function changePage(v){page.value=v;load()}
function split(v){return (v||'').split(/[,;\s，；]+/).filter(Boolean)}
async function open(r){if(busy.value)return;editing.value=r?.id??null;evidence.value='';form.value=blank();to.value=[];cc.value=[];if(r){form.value.name=r.name;form.value.deadline=pickerValueFromBeijing(r.deadline);form.value.data=r.data?JSON.parse(JSON.stringify(r.data)):{...blankData(),cve_id:r.cve||'',title:r.subject||'',vulnerability_summary:r.body||''};to.value=split(r.recipients);cc.value=split(r.cc)}visible.value=true;await loadSettings()}
async function generate(){if(!validCve.value||busy.value)return;if(!confirm('AI生成结果将填充并替换当前情报字段，是否继续？'))return;generating.value=true;try{const data=(await http.post('/generate',{cve:form.value.data.cve_id,evidence:evidence.value})).data.data;form.value.data=data;msg.success('AI已填充，请人工核实和修改')}catch(e){msg.error(e.response?.data?.detail||e.message)}finally{generating.value=false}}
async function save(send){if(busy.value||send&&!ready.value)return;if(!form.value.deadline){msg.error('请选择任务截止日期和时间');return}if(send&&!confirm('确认向 '+to.value.join('; ')+' 发送该邮件？'))return;saving.value=true;try{
  const payload={...form.value,deadline:form.value.deadline?beijingIsoFromPicker(form.value.deadline):null,recipients:to.value.join(';'),cc:cc.value.join(';')};
  const response=editing.value?await http.put('/drafts/'+editing.value,payload):await http.post('/drafts',payload);
  editing.value=response.data.data.id;
  if(send){sending.value=true;const r=(await http.post('/tasks/'+editing.value+'/send')).data.data;visible.value=false;if(r.status==='Webhook已接收')msg.success('Webhook已接收任务，请在微软流确认正式邮件发送结果');else msg.warning(r.last_error||r.status)}
  else{visible.value=false;msg.success('草稿已保存')}
  q.value='';page.value=1;await load()
}catch(e){msg.error(e.response?.data?.detail||e.message);await load()}finally{saving.value=false;sending.value=false}}
async function view(r){try{detail.value=(await http.get('/tasks/'+r.id)).data.data;detailOpen.value=true}catch(e){msg.error(e.response?.data?.detail||e.message)}}
async function remove(r){if(!confirm('确认删除任务 '+r.name+'？'))return;try{await http.delete('/tasks/'+r.id);msg.success('已删除');await load()}catch(e){msg.error(e.response?.data?.detail||e.message)}}
async function loadSettings(){try{settings.value=(await http.get('/settings')).data.data}catch(e){msg.error('读取邮件配置失败：'+(e.response?.data?.detail||e.message))}}
async function openSettings(){try{settings.value=(await http.get('/settings')).data.data;skills.value=(await http.get('/api/v1/settings/ai/skills',{baseURL:''})).data.data;settingsForm.value={skill_id:settings.value.skill_id,flow_url:'',template_code:settings.value.template_code};settingsOpen.value=true}catch(e){msg.error(e.response?.data?.detail||e.message)}}
async function saveSettings(){if(settingsSaving.value)return;settingsSaving.value=true;try{settings.value=(await http.put('/settings',settingsForm.value)).data.data;settingsOpen.value=false;msg.success('邮件 AI 配置已保存')}catch(e){msg.error(e.response?.data?.detail||e.message)}finally{settingsSaving.value=false}}
onMounted(()=>{load();loadSettings()})
</script>
<style scoped>
.mail-page{box-sizing:border-box;margin:16px auto;width:calc(100% - 32px);background:#fff;border-radius:10px;padding:24px;min-width:0}
.body{white-space:pre-wrap;overflow-wrap:anywhere;max-height:55vh;overflow:auto;font:inherit;line-height:1.7;background:#f5f7fa;padding:16px}
.table-wrap{overflow-x:auto;margin:10px 0 20px}table{width:100%;border-collapse:collapse}th,td{padding:10px;text-align:left;border:1px solid #e0e4eb;vertical-align:top}th{background:#f5f7fa}.edit-table{min-width:800px}.edit-table td:not(:last-child){width:24%}.ref-row{display:grid;grid-template-columns:1fr 2fr auto;gap:10px;align-items:center;margin-bottom:12px}.preview{font-family:Arial,sans-serif;font-size:15px;line-height:1.7;color:#171717;overflow-wrap:anywhere}.preview p,.preview td{white-space:pre-wrap}.preview h3{font-size:17px}.red{color:#d03050}.muted{color:#888}
.tracker-stats{display:flex;gap:16px;flex-wrap:wrap;margin:14px 0}.tracker-stats>div{background:#f4f7fb;border:1px solid #e4e9f1;border-radius:8px;padding:12px 18px;flex:1;min-width:100px;color:#596579}.tracker-stats strong{font-size:22px;color:#172b4d;margin-left:8px}.tracker-canvas{display:flex;align-items:center;gap:30px;background:#f7f9fc;border:1px solid #e4e9f1;border-radius:12px;padding:24px;overflow-x:auto;min-height:240px}.tracker-root{position:relative;flex:0 0 220px;padding:18px;border:1px solid #95b5e4;border-left:4px solid #2080f0;border-radius:8px;background:white;display:grid;gap:8px;overflow-wrap:anywhere}.tracker-root:after{content:'';position:absolute;width:31px;height:1px;background:#9db1cc;left:100%;top:50%}.tracker-kicker{font-size:12px;color:#66809f}.tracker-root strong{font-size:17px;color:#234a83}.tracker-canvas small{font-size:12px;color:#778398}.tracker-branches{display:flex;flex-direction:column;position:relative;gap:20px;flex:1;min-width:560px}.tracker-branches:before{content:'';position:absolute;left:0;top:var(--unused,0);bottom:0;width:1px;background:#9db1cc}.tracker-branch{display:flex;align-items:center;position:relative;padding-left:22px;gap:24px}.tracker-branch:before{content:'';position:absolute;left:0;top:50%;width:22px;height:1px;background:#9db1cc}.tracker-person{position:relative;display:grid;justify-items:start;gap:9px;flex:0 0 200px;padding:13px;border:1px solid #cbd7e7;border-radius:8px;background:white;overflow-wrap:anywhere;min-width:0}.tracker-person strong{max-width:100%;overflow-wrap:anywhere}.tracker-person.is-closed{border-color:#73bf98;background:#f1fbf5}.tracker-person:after{content:'';position:absolute;left:100%;width:24px;top:50%;height:1px;background:#9db1cc}.tracker-replies{display:flex;gap:18px;align-items:stretch;flex:1}.tracker-reply,.tracker-empty{position:relative;flex:0 0 220px;padding:13px;border:1px solid #d5e0eb;border-radius:8px;background:white;overflow-wrap:anywhere}.tracker-reply:not(:last-child):after{content:'';position:absolute;left:100%;width:18px;top:50%;height:1px;background:#9db1cc}.tracker-empty{flex:0 0 160px;color:#8792a3;border-style:dashed;align-self:center}.tracker-reply-head{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:5px}.tracker-subject{font-weight:500;margin:8px 0}.tracker-excerpt{white-space:pre-wrap;display:-webkit-box;-webkit-line-clamp:4;-webkit-box-orient:vertical;overflow:hidden;color:#40516b;margin:8px 0}.tracker-root,.tracker-person,.tracker-reply{box-shadow:0 2px 8px #1b34500a}
</style>
