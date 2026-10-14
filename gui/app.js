'use strict';
const bootstrap = JSON.parse(document.getElementById('bootstrap').textContent);
// The server never publishes its session token in HTML or an API response.
// It arrives in a URL fragment (not sent in HTTP), then persists only for
// this browser tab/session. Clear the fragment from browser history.
const fragment = new URLSearchParams(location.hash.slice(1));
const launchToken = fragment.get('session');
if (launchToken) {
  sessionStorage.setItem('wcaGuiSessionToken', launchToken);
  history.replaceState(null, '', location.pathname + location.search);
}
const token = launchToken || sessionStorage.getItem('wcaGuiSessionToken') || '';
const $ = id => document.getElementById(id);
const state = {assessment: localStorage.getItem('wcaSelectedAssessment') || '', status: null, review: null, selectedReview: null, jobId: null, jobAssessment: null, jobKind: null, pollBusy: false, reviewCache: new Map(), reviewLoadedAt: 0, runtime: null, lastLog: null, captureWasActive: false, guideOpen: new Map()};
const notificationHistory = [];
function notice(message, error = false) {
  const detail = message instanceof Error ? message : null;
  const content = detail?.message || String(message);
  const entry = {operation:detail?.operation || (error?'GUI operation':'Information'),
    message:content, code:detail?.code || (error?'GUI_ERROR':'INFO'),
    outcome:detail?.outcome || (error?'NOT CONFIRMED':'INFORMATIONAL'),
    next:detail?.nextStep || '', at:new Date().toLocaleString(), error:!!error};
  notificationHistory.unshift(entry);
  if(notificationHistory.length>30)notificationHistory.pop();
  $('notificationCount').textContent=notificationHistory.length;
  renderNotifications();
  const n=$('notice');n.replaceChildren();n.hidden=false;n.classList.toggle('error',!!error);
  const top=el('div',undefined,'notice-top');
  top.appendChild(el('strong',entry.operation));
  const close=el('button','×','notice-close');close.type='button';close.setAttribute('aria-label','Dismiss notification');
  close.addEventListener('click',clearNotice);top.appendChild(close);n.appendChild(top);
  n.appendChild(el('div',entry.message));
  if(entry.next)n.appendChild(el('div',entry.next,'notice-next'));
  n.appendChild(el('small',`${entry.code} · ${entry.outcome} · ${entry.at}`));
  const actions=el('div',undefined,'notice-actions');
  const details=el('button','Recent notifications','button subtle');details.type='button';
  details.addEventListener('click',toggleNotificationHistory);actions.appendChild(details);
  const copy=el('button','Copy diagnostics','button subtle');copy.type='button';
  copy.addEventListener('click',()=>{navigator.clipboard?.writeText(
    `${entry.at} | ${entry.operation} | ${entry.code} | ${entry.outcome} | ${entry.message} | ${entry.next}`)
    .catch(()=>{});});actions.appendChild(copy);n.appendChild(actions);
}
function clearNotice(){$('notice').hidden=true;}
function renderNotifications(){
 const holder=$('notificationEntries');holder.replaceChildren();
 for(const e of notificationHistory){const node=el('section',undefined,'notification-entry');
  node.appendChild(el('strong',`${e.operation} · ${e.code}`));
  node.appendChild(el('div',e.message));
  if(e.next)node.appendChild(el('div',e.next,'muted'));
  node.appendChild(el('small',`${e.outcome} · ${e.at}`));holder.appendChild(node);}
}
function toggleNotificationHistory(){const panel=$('notificationHistory');panel.hidden=!panel.hidden;
 $('notificationsBtn').setAttribute('aria-expanded',String(!panel.hidden));}
$('notificationsBtn').addEventListener('click',toggleNotificationHistory);
$('notificationHistoryClose').addEventListener('click',toggleNotificationHistory);

function value(id){return $(id).value.trim();}
function el(tag,text,cls){const node=document.createElement(tag);if(text!==undefined)node.textContent=String(text);if(cls)node.className=cls;return node;}
async function request(route, options = {}) {
  const response = await fetch(route, {method: options.method || 'GET', headers:{'X-WCA-Token':token, ...(options.method ? {'Content-Type':'application/json'} : {})}, body: options.body?JSON.stringify(options.body):undefined, cache:'no-store'});
  const result = await response.json();
  if (!result.ok) {
    const problem=new Error(result.message || result.errors?.[0]?.message || 'Operation failed.');
    problem.code=result.code || `HTTP_${response.status}`;
    problem.operation=result.operation || (route.split('?')[0].replace('/api/','') || 'Backend request');
    problem.outcome=result.outcome || 'NOT CONFIRMED';
    problem.nextStep=result.next_step || '';
    throw problem;
  }
  return result;
}
function params(data){return new URLSearchParams(Object.entries(data).filter(([,v])=>v!==undefined&&v!==null));}
async function backend(action,assessment = state.assessment){return request('/api/backend?'+params({action,assessment}));}
function makeTable(columns, rows){const tbl=el('table',undefined,'table');const thead=el('thead');const hrow=el('tr');columns.forEach(name=>hrow.appendChild(el('th',name)));thead.appendChild(hrow);tbl.appendChild(thead);const body=el('tbody');rows.forEach(row=>{const tr=el('tr');row.forEach(cell=>{const td=el('td');if(cell instanceof Node)td.appendChild(cell);else td.textContent=String(cell??'—');tr.appendChild(td);});body.appendChild(tr);});tbl.appendChild(body);return tbl;}
function replace(node,content){node.replaceChildren(content);}
function go(tab){
 document.querySelectorAll('.page').forEach(x=>x.classList.toggle('active',x.id==='page-'+tab));
 document.querySelectorAll('.nav-link').forEach(x=>x.classList.toggle('active',x.dataset.tab===tab));
 $('sectionLabel').textContent={dashboard:'Overview',new:'New assessment',review:'Guided review',reports:'Reports',tools:'Tool readiness',management:'Assessment Management',help:'Help & About'}[tab];
 // Notifications remain until explicitly dismissed; page switching must not hide failures.
 if(tab==='review' && (!state.review?.items || Date.now()-state.reviewLoadedAt>30000))loadReview();
 if(tab==='reports')loadReports();
 if(tab==='tools')loadTools();
 if(tab==='management')loadManagement();
 if(tab==='help')loadAbout();
}
document.querySelectorAll('.nav-link').forEach(x=>x.addEventListener('click',()=>go(x.dataset.tab)));
document.querySelectorAll('[data-go]').forEach(x=>x.addEventListener('click',()=>go(x.dataset.go)));
async function loadAssessment(){
 const chosen=value('assessmentPath');if(!chosen)return notice('Enter an assessment directory.',true);
 state.assessment=chosen;localStorage.setItem('wcaSelectedAssessment',chosen);
 try{await request('/api/select',{method:'POST',body:{assessment:chosen}});}catch(e){notice('Cannot register assessment: '+e.message,true);}
 state.review=null;state.reviewCache.clear();await refresh();await loadRecent();
}
async function refresh(){
 if(!state.assessment)return;
 try{
  const result=await request('/api/overview?'+params({assessment:state.assessment}));
  const d=result.data.status;state.status=d;state.runtime=result.data.runtime;
  $('assessmentPath').value=state.assessment;$('emptyState').hidden=true;$('overviewData').hidden=false;
  set('metricState',d.status);set('metricStage',d.stage);
  set('metricIntegrity',d.integrity?.status||'NOT FINALIZED');set('metricCoverage',d.coverage||'—');
  set('metricMode',`${d.target_type||'—'} · ${d.mode||'—'}`);
  const rows=Object.entries(d.stages||{});set('checkpointCount',`${rows.length} stages`);
  replace($('checkpointTable'),makeTable(['Checkpoint','Status'],rows));
  $('guidedRuntimeBtn').disabled=!(d.status==='COMPLETED'&&d.mode==='full'&&d.framework_version===bootstrap.version&&d.integrity?.status==='PASS');
  $('appendixBtn').disabled=!(d.available_actions||[]).includes('export_appendix_with_confirmation');
  if(!$('appendixOutput').value||!$('appendixOutput').value.startsWith(state.assessment))$('appendixOutput').value=state.assessment.replace(/[\\/]+$/,'')+'-ClientAppendix.zip';
  const review=result.data.review;
  set('metricReview',`${review.total-review.pending}/${review.total}`);
  set('metricReviewHint',`${review.pending} pending`);
  renderRuntimeHistory(state.runtime);
 }catch(e){$('overviewData').hidden=true;$('emptyState').hidden=false;notice(e,true);}
}
async function loadRecent(){
 try{
  const response=await request('/api/recent');const items=response.assessments||[];
  const holder=$('recentTable');
  if(!items.length){replace(holder,el('div','No assessments registered yet. Browse to an assessment or start a new one.','empty-small'));return;}
  const rows=items.map(item=>{
   const button=el('button',item.name,'recent-entry');button.type='button';
   button.addEventListener('click',()=>{$('assessmentPath').value=item.path;loadAssessment();});
   const stateText=item.job==='RUNNING'?'RUNNING':item.state;
   return [button,`${item.target_type||'—'} · ${item.mode||'—'}`,stateText,`${item.review.completed}/${item.review.total}`,item.last_activity||'—',item.integrity==='NOT VERIFIED'?'Open to verify':item.integrity];
  });
  replace(holder,makeTable(['Assessment','Type / mode','State','Reviewed','Last activity','Integrity'],rows));
 }catch(e){replace($('recentTable'),el('div','Recent assessments unavailable: '+e.message,'empty-small'));}
}
function renderRuntimeHistory(history){
 const label=history?.state||'NOT RUN';set('runtimeStatus',label);
 const sessions=history?.sessions||[];
 const target=$('runtimeHistory');
 if(!sessions.length){replace(target,el('div','No completed Guided Runtime session recorded for this assessment.','muted'));$('runtimeReportBtn').hidden=true;return;}
 replace(target,makeTable(['Completed (UTC)','Capture','Duration','Events','Processes'],sessions.map(x=>[
  x.captured_at||'—',x.capture_status||'—',`${x.duration_seconds||0}s`,x.events??0,x.target_processes??0])));
 $('runtimeReportBtn').hidden=false;
}
async function loadManagement(){
 if(!state.assessment){set('managementStatus','Select an assessment in Overview.');return;}
 set('managementStatus','Verifying assessment integrity…');
 $('resumeBtn').disabled=true;$('regenerateBtn').disabled=true;
 try{
  const status=await backend('status');const d=status.data;state.status=d;
  const checks=d.integrity?.checks||[];
  set('managementIntegrity',d.integrity?.status||'NOT VERIFIED');
  set('managementStatus',`${d.name||'Assessment'} · ${d.status} · ${d.recovery_guidance||''}`);
  replace($('managementChecks'),makeTable(['Check','Status','Issues','Details'],checks.map(x=>[x.name,x.status,x.issue_count,x.details])));
  const actions=d.available_actions||[];
  const resume=actions.includes('resume_assessment_cli_only')&&d.framework_version===bootstrap.version;
  const regen=actions.includes('regenerate_reports_with_confirmation');
  $('resumeBtn').disabled=!resume;$('regenerateBtn').disabled=!regen;
  set('resumeReason',resume?'Eligible safe checkpoint; tester must explicitly continue.':
    d.status==='COMPLETED'?'Not required — assessment completed successfully.':
    'Unavailable — no eligible current-version recovery checkpoint.');
  set('regenerateReason',regen?'Eligible derived reports only; authoritative state and evidence must remain intact.':
    d.integrity?.status==='PASS'?'Not required — assessment integrity is PASS.':
    'Unavailable — repairs are not safe with the current supporting evidence.');
 }catch(e){set('managementStatus','Verification unavailable: '+e.message);}
}
async function loadAbout(){
 try{
  const data=await request('/api/about');
  replace($('aboutInfo'),makeTable(['Property','Value'],[
   ['Framework',`${data.framework} ${data.version}`],['Backend schema',data.backend_schema],
   ['Methodology',data.methodology],['Artifact catalog',data.artifact_catalog],
   ['Python',data.python_version],['External tool versions',data.external_versions]]));
  const t=await request('/api/tool-versions');
  replace($('helpTools'),makeTable(['Tool','Detected','File version'],(t.tools||[]).map(x=>[x.name,x.found?'YES':'NO',x.version])));
 }catch(e){notice(e,true);}
}
function set(id,text){$(id).textContent=String(text??'—');}
$('loadBtn').addEventListener('click',loadAssessment);$('assessmentPath').addEventListener('keydown',e=>{if(e.key==='Enter')loadAssessment();});$('refreshBtn').addEventListener('click',refresh);
async function loadTools(){try{const result=await backend('tool_readiness');const tools=result.data.tools||[];set('toolCount',`${tools.filter(t=>t.found).length}/${tools.length}`);const required=tools.filter(t=>t.level==='REQUIRED');set('coreTools',`${required.filter(t=>t.found).length}/${required.length}`);replace($('toolTable'),makeTable(['Tool','Level','Usage','Available'],tools.map(t=>[t.name,t.level,t.usage,t.found?'YES':'NO'])));}catch(e){notice(e,true);}}
$('toolsRefresh').addEventListener('click',loadTools);
$('recentRefresh').addEventListener('click',loadRecent);
$('managementRefresh').addEventListener('click',loadManagement);
$('runtimeReportBtn').addEventListener('click',async()=>{go('reports');await loadReport('guided_runtime_observation.txt');});
document.querySelectorAll('[data-help]').forEach(b=>b.addEventListener('click',async()=>{
 try{const result=await request('/api/help?'+params({doc:b.dataset.help}));set('helpDocTitle',result.name);set('helpDocBody',result.content);}catch(e){notice('Guide unavailable: '+e.message,true);}
}));
async function loadReview(){
 if(!state.assessment)return;
 try{
  const result=await backend('review');state.review=result.data;state.reviewLoadedAt=Date.now();state.reviewCache.clear();
  set('reviewCount',`${result.data.total} conditions · ${result.data.pending} pending`);
  renderReviewList();
  const selected=(result.data.items||[]).find(i=>i.id===state.selectedReview?.id);
  if(selected){await editReview(selected,false)}else{$('reviewEditor').hidden=true;$('reviewEmpty').hidden=false;state.selectedReview=null;}
 }catch(e){replace($('reviewTable'),el('div','Review unavailable: '+e.message,'empty-small'));$('reviewEditor').hidden=true;$('reviewEmpty').hidden=false;state.selectedReview=null;}
}
function renderReviewList(){
 const filter=value('reviewFilter'), search=value('reviewSearch').trim().toLowerCase();
 const rows=(state.review?.items||[]).filter(i=>(!filter||i.status===filter)&&(!search||`${i.title} ${i.module}`.toLowerCase().includes(search)));
 const list=el('div',undefined,'review-list');
 rows.forEach(item=>{
  const button=el('button',undefined,'review-item');button.type='button';
  button.classList.toggle('selected',item.id===state.selectedReview?.id);
  button.appendChild(el('div',item.title,'review-item-title'));
  button.appendChild(el('div',`${item.status} · ${item.severity} · ${item.module}`,'review-item-sub'));
  button.addEventListener('click',()=>editReview(item,true));list.appendChild(button);
 });
 if(!rows.length)list.appendChild(el('div','No matching review conditions.','empty-small'));
 replace($('reviewTable'),list);
}
$('reviewSearch').addEventListener('input',renderReviewList);
$('reviewFilter').addEventListener('change',renderReviewList);
function guideSection(index,label,body,open=false){
 const details=el('details',undefined,'review-guide-section');
 const key=state.assessment+'|'+(state.selectedReview?.id||'')+'|'+index;
 details.open=state.guideOpen.has(key)?state.guideOpen.get(key):open;
 details.addEventListener('toggle',()=>{if(details.isConnected)state.guideOpen.set(key,details.open);});
 details.appendChild(el('summary',`${index} / 10  ${label}`));
 const content=el('div',undefined,'review-guide-content');
 if(typeof body==='string')content.appendChild(el('p',body||'No additional guidance for this candidate.',''));
 else if(body)content.appendChild(body);
 details.appendChild(content);return details;
}
function guideCommands(commands){
 const box=el('div');if(!commands?.length){box.appendChild(el('div','No candidate-specific commands. Check the relevant assessment test cases.','review-guide-muted'));return box;}
 commands.forEach(cmd=>{const line=el('div',undefined,'review-command');line.appendChild(el('pre',cmd));const button=el('button','Copy','button subtle');button.type='button';button.addEventListener('click',async()=>{try{await navigator.clipboard.writeText(cmd);notice('Command copied. Execution remains tester-controlled.');}catch(_){notice('Copy unavailable; select the text manually.',true);}});line.appendChild(button);box.appendChild(line);});return box;
}
function guidePoc(poc){const box=el('div');
 box.appendChild(el('p',poc?.resource||'No bundled PoC resource is applicable to this condition.'));
 for(const key of ['architecture','requires_compilation','expected_output']){if(poc?.[key])box.appendChild(el('p',`${key.replaceAll('_',' ')}: ${poc[key]}`));}
 for(const key of ['build_or_invocation','verification']){if(poc?.[key]?.length){box.appendChild(el('strong',key.replaceAll('_',' ')));poc[key].forEach((step,i)=>box.appendChild(el('p',`${i+1}. ${step}`)));}}
 box.appendChild(el('p','All PoC builds and execution are initiated by the tester, never the web interface.','review-guide-muted'));return box;}
function guideReports(artifacts){const box=el('div');if(!artifacts?.length)return el('p','No supporting reports linked.');
 artifacts.forEach(name=>{const button=el('button',name,'button outline review-guide-link');button.type='button';button.addEventListener('click',async()=>{go('reports');await loadReports();await loadReport(name);});box.appendChild(button);});return box;}
function renderGuide(detail){
 const holder=el('div');holder.appendChild(el('h3','Validation and evidence guide'));
 holder.appendChild(guideSection(1,'Observed evidence',`${detail.evidence||'See supporting reports.'}

Affected component: ${detail.component||'Not specified'}\nMatching events: ${detail.matching_events||0}`,true));
 holder.appendChild(guideSection(2,'Why validate it',detail.description));
 holder.appendChild(guideSection(3,'Prerequisites',detail.prerequisites));
 holder.appendChild(guideSection(4,'Starting checks',guideCommands(detail.commands),true));
 holder.appendChild(guideSection(5,'Manual validation procedure',detail.manual_validation));
 holder.appendChild(guideSection(6,'PoC resources and build guidance',guidePoc(detail.poc)));
 holder.appendChild(guideSection(7,'Tester execution',detail.tester_execution));
 holder.appendChild(guideSection(8,'Expected evidence',detail.expected_evidence));
 const interpret=el('div');interpret.appendChild(el('strong','Expected secure behavior'));interpret.appendChild(el('p',detail.secure||''));interpret.appendChild(el('strong','Potential security impact'));interpret.appendChild(el('p',detail.impact||''));
 holder.appendChild(guideSection(9,'Interpretation',interpret));
 holder.appendChild(guideSection(10,'When not to report',detail.not_report));
 const refs=el('div');refs.appendChild(el('h3','Supporting reports'));refs.appendChild(guideReports(detail.artifacts));holder.appendChild(refs);
 return holder;
}
async function editReview(item,scroll=true){
 const requested=item.id;state.selectedReview=item;renderReviewList();
 try{
  const key=state.assessment+'|'+requested;
  const cached=state.reviewCache.get(key);
  const response=cached&&Date.now()-cached.saved<30000 ? {detail:cached.detail} : await request('/api/review-detail?'+params({assessment:state.assessment,id:requested}));
  if(!cached || Date.now()-cached.saved>=30000){state.reviewCache.set(key,{detail:response.detail,saved:Date.now()});
   if(state.reviewCache.size>24)state.reviewCache.delete(state.reviewCache.keys().next().value);}
  if(state.selectedReview?.id!==requested)return;
  const d=response.detail;
  state.reviewDetail=d;$('reviewEmpty').hidden=true;$('reviewEditor').hidden=false;
  set('reviewTitle',d.title);set('reviewDetails',`${d.module} · ${d.severity} · ${d.id} · Evidence ${d.changed_evidence?'changed — recheck required':'unchanged'} · ${d.artifacts.join(', ')}`);
  replace($('reviewValidation'),renderGuide(d));$('reviewDecision').value=d.status;
  $('reviewNotes').value=d.notes||'';
  set('reviewSaveHint','Existing notes loaded. Click Save to explicitly record a changed decision or notes.');
  if(scroll&&window.innerWidth<1000)$('reviewEditor').scrollIntoView({behavior:'smooth',block:'start'});
 }catch(e){if(state.selectedReview?.id===requested){$('reviewEditor').hidden=true;$('reviewEmpty').hidden=false;notice('Validation guidance unavailable: '+e.message,true);}}
}
for(const [buttonId,expanded] of [['reviewExpandAll',true],['reviewCollapseAll',false]]){
 $(buttonId).addEventListener('click',()=>{
  document.querySelectorAll('#reviewValidation details.review-guide-section').forEach((node,index)=>{
   node.open=expanded;
   const key=state.assessment+'|'+(state.selectedReview?.id||'')+'|'+(index+1);
   state.guideOpen.set(key,expanded);
  });
 });
}
$('reviewRefresh').addEventListener('click',loadReview);
$('saveReview').addEventListener('click',async()=>{
 const d=state.reviewDetail;if(!d||!state.selectedReview||d.id!==state.selectedReview.id)return;
 const decision=value('reviewDecision'), notes=$('reviewNotes').value;
 if(decision===d.status&&notes===d.notes){notice('No changes to save.');return;}
 if(d.changed_evidence){notice('Evidence has changed; validate the condition again before saving.',true);return;}
 // The Save button is the explicit tester confirmation. Do not add a second browser popup.
 const save=$('saveReview');save.disabled=true;save.textContent='Saving…';
 try{
  const result=await request('/api/mutate',{method:'POST',body:{action:'save_review',assessment:state.assessment,candidate_id:d.id,fingerprint:d.fingerprint,disposition:decision,notes,confirmed:true}});
  notice(result.message);state.reviewCache.clear();state.review=null;await loadReview();await refresh();
 }catch(e){e.operation=e.operation||'Guided Review save';e.nextStep=e.nextStep||'Verify assessment integrity before retrying.';notice(e,true);}
 finally{save.disabled=false;save.textContent='Save decision';}
});
async function loadReports(){if(!state.assessment)return;try{const result=await request('/api/reports?'+params({assessment:state.assessment}));set('reportsCount',`${result.reports.length} files`);const container=$('reportFiles');container.replaceChildren();result.reports.forEach(r=>{const button=el('button',r.name);button.addEventListener('click',()=>loadReport(r.name,button));container.appendChild(button);});if(!result.reports.length)container.textContent='No eligible reports found.';}catch(e){notice(e,true);}}
async function loadReport(name,button){try{const result=await request('/api/report?'+params({assessment:state.assessment,name}));set('reportTitle',result.name);set('reportBody',result.content);document.querySelectorAll('#reportFiles button').forEach(x=>x.classList.toggle('selected',x===button));}catch(e){notice(e,true);}}
$('reportsRefresh').addEventListener('click',loadReports);
async function mutate(action,body){return request('/api/mutate',{method:'POST',body:{action,assessment:state.assessment,confirmed:true,...body}});}
$('appendixBtn').addEventListener('click',async()=>{if(!confirm('Export a sanitized, reviewed Client Appendix ZIP to the specified location?'))return;try{const result=await mutate('export_appendix',{output:value('appendixOutput')});notice(`Verified appendix exported: ${result.data.filename}`);}catch(e){notice(e,true);}});
$('regenerateBtn').addEventListener('click',async()=>{if(!confirm('Regenerate ONLY eligible derived reports from intact authoritative evidence?'))return;try{const result=await mutate('regenerate_reports',{});notice(result.message);await refresh();}catch(e){notice(e,true);}});
async function startJob(kind,data){
 try{
  const result=await request('/api/start',{method:'POST',body:{kind,confirmed:true,...data}});
  state.jobId=result.job.id;state.jobAssessment=kind==='assessment'?`${data.output.replace(/[\\/]+$/,'')}\\${data.name}`:data.assessment;
  state.jobFinished=false;state.pendingCheckpointId='';state.jobKind=kind;state.captureWasActive=false;state.lastLog=null;
  if(kind==='runtime'){set('runtimeStatus','STARTING');set('runtimeLive','Starting Procmon observation. Waiting for capture readiness…');$('runtimeStopBtn').hidden=true;}
  localStorage.setItem('wcaActiveJob',state.jobId);
  notice(result.job.message);go('dashboard');$('assessmentPath').value=state.jobAssessment;
  state.assessment=state.jobAssessment;localStorage.setItem('wcaSelectedAssessment',state.assessment);await loadRecent();await pollJob();
 }catch(e){notice(e,true);}
}
$('createBtn').addEventListener('click',()=>{
 const data={target:value('newTarget'),target_type:value('newType'),mode:value('newMode'),name:value('newName'),output:value('newOutput'),primary_executable:value('newPrimary'),
 extract_installer:$('optExtract').checked,filesystem_snapshot:$('optFilesystem').checked,
 surface_review:$('optSurface').checked,runtime_capture:$('optCapture').checked};
 startJob('assessment',data);
});
function updateNewModeOptions(){
 const full=value('newMode')==='full';$('fullOptions').hidden=!full;
 if(!full){$('optCapture').checked=false;}
}
$('newMode').addEventListener('change',updateNewModeOptions);
updateNewModeOptions();
$('guidedRuntimeBtn').addEventListener('click',()=>startJob('runtime',{assessment:state.assessment}));
$('resumeBtn').addEventListener('click',()=>startJob('resume',{assessment:state.assessment}));
async function submitCheckpoint(id,answer){
 const buttons=$('jobChoices').querySelectorAll('button');buttons.forEach(b=>b.disabled=true);
 try{
  await request('/api/job/respond',{method:'POST',body:{id:state.jobId,checkpoint_id:id,answer,confirmed:true}});
  set('jobQuestion','Response accepted — worker continuing');$('jobChoices').replaceChildren();
  await pollJob();
 }catch(e){e.operation=e.operation||'Worker checkpoint';notice(e,true);buttons.forEach(b=>b.disabled=false);}
}
function checkpointButton(label,id,answer,cls='button primary'){
 const b=el('button',label,cls);b.type='button';b.addEventListener('click',()=>submitCheckpoint(id,answer));return b;
}
function renderCheckpoint(cp){
 const card=$('jobCheckpoint');card.hidden=false;
 if(state.pendingCheckpointId===cp.id){if(cp.submitted){set('jobQuestion','Response accepted — worker continuing');$('jobChoices').replaceChildren();}return;}
 state.pendingCheckpointId=cp.id;
 set('jobQuestion',cp.message);
 const controls=$('jobChoices');controls.replaceChildren();
 if(cp.submitted){set('jobQuestion','Response accepted — worker continuing');return;}
 if(cp.kind==='continue'){
  const stop=/stop|capture|observation/i.test(cp.message);
  controls.appendChild(checkpointButton(stop?'Stop capture / Continue':'Continue assessment',cp.id,'continue'));
 }else if(cp.kind==='confirm'){
  controls.appendChild(checkpointButton('Yes',cp.id,'yes'));
  controls.appendChild(checkpointButton('No',cp.id,'no','button outline'));
 }else if(cp.kind==='choice'){
  for(const option of cp.choices)controls.appendChild(checkpointButton(option,cp.id,option,'button outline'));
 }else if(cp.kind==='text'){
  const field=el('input');field.type='text';field.value=cp.default||'';field.maxLength=2048;
  controls.appendChild(field);const send=el('button','Submit response','button primary');
  send.type='button';send.addEventListener('click',()=>submitCheckpoint(cp.id,field.value));
  field.addEventListener('keydown',e=>{if(e.key==='Enter')send.click();});controls.appendChild(send);
 }
}
function renderTelemetry(stats){
 const holder=$('jobTelemetry');holder.replaceChildren();holder.hidden=!stats;
 if(!stats)return;
 const fields=[['Capture seconds',stats.duration_seconds],['Trace size (MB)',Math.round((stats.pml_size_bytes||0)/1048576)],
  ['Target processes',stats.current_target_processes],['Processes seen',stats.target_processes_seen],
  ['Connections',stats.current_connections],['Process starts',stats.process_starts],['I/O changes',stats.io_changes]];
 fields.forEach(([label,n])=>{const card=el('div',undefined,'telemetry-card');card.appendChild(el('small',label));card.appendChild(el('strong',String(n??0)));holder.appendChild(card);});
}
async function pollJob(){
 if(!state.jobId||state.pollBusy)return;
 state.pollBusy=true;
 try{
  const result=await request('/api/job?'+params({id:state.jobId}));const j=result.job;
  state.jobKind=j.kind;set('jobLabel',j.state);
  const global=$('globalJobStatus');
  global.hidden=false;
  const cpLabel=j.checkpoint&&!j.checkpoint.submitted?' · Action required':'';
  global.textContent=`${j.kind==='runtime'?'Guided Runtime':'Assessment'}: ${j.state}${cpLabel}`;
  set('jobSummary',`${j.kind}: ${j.state} · exit code ${j.exit_code??'pending'}`);
  set('jobProgress',j.progress?`Stage: ${j.progress.stage} · ${j.progress.completed}/${j.progress.total} completed · ${j.progress.message}`:'');
  // Keep the SAME pre element and only update when the log changes.
  const log=$('jobLog');const incoming=j.log||'';
  if(incoming!==state.lastLog){
   const nearBottom=log.scrollHeight-log.scrollTop-log.clientHeight<45 || state.lastLog===null;
   log.textContent=incoming;state.lastLog=incoming;
   if(nearBottom)log.scrollTop=log.scrollHeight;
  }
  if(j.checkpoint){renderCheckpoint(j.checkpoint);}else{$('jobCheckpoint').hidden=true;state.pendingCheckpointId='';}
  renderTelemetry(j.telemetry);
  const normalizeJobPath=p=>String(p||'').replace(/[\\/]+/g,'/').replace(/\/+$/,'').toLowerCase();
  const matchesSelected=normalizeJobPath(j.assessment)===normalizeJobPath(state.assessment);
  if(j.kind==='runtime'&&matchesSelected){
   const active=j.state==='RUNNING', cp=j.checkpoint;
   const canStop=active&&cp?.kind==='continue'&&!cp?.submitted&&(cp?.capture_ready===true||j.telemetry?.capture_ready===true);
   if(j.telemetry?.capture_ready===true)state.captureWasActive=true;
   const stage=!active?(j.state==='COMPLETED'?'COMPLETED':'FAILED / INTERRUPTED'):
    canStop?'CAPTURING':(state.captureWasActive&&cp&&!cp.submitted?'CAPTURING':(state.captureWasActive||cp?.submitted?'PROCESSING':'STARTING'));
   set('runtimeStatus',stage);
   $('runtimeStopBtn').hidden=!canStop;$('runtimeStopBtn').disabled=!canStop;
   $('runtimeStopBtn').onclick=canStop?()=>{
     $('runtimeStopBtn').disabled=true;set('runtimeStatus','STOPPING');set('runtimeLive','Stopping Procmon gracefully; processing evidence will follow…');
     submitCheckpoint(cp.id,'continue');
   }:null;
   const stats=j.telemetry;
   set('runtimeLive',stats?`${stage} · ${stats.duration_seconds||0}s elapsed · ${Math.round((stats.pml_size_bytes||0)/1048576)} MB trace · ${stats.current_target_processes||0} current target processes`:
     `${stage} · ${j.progress?.message||'Check worker progress below.'}`);
  }
  if(j.state!=='RUNNING'&&!state.jobFinished){state.jobFinished=true;await refresh();await loadRecent();
   if(j.kind==='runtime'&&matchesSelected&&j.state!=='COMPLETED'){set('runtimeStatus','FAILED / INTERRUPTED');set('runtimeLive','Latest observation failed or was interrupted. Check worker output and assessment integrity.');}
  }
 }catch(e){set('jobLabel','Unavailable');
  if(e.message==='Requested information unavailable.'){
   state.jobId=null;localStorage.removeItem('wcaActiveJob');$('jobCheckpoint').hidden=true;
   set('jobLabel','No active job');
   set('runtimeLive','Worker connection unavailable. Consult integrity and recorded runtime history before another capture.');
  }else{notice('Worker status unavailable: '+e.message,true);}
 }finally{state.pollBusy=false;}
}
Array.from(document.querySelectorAll('.browse')).forEach(btn=>btn.addEventListener('click',async()=>{try{const result=await request('/api/pick',{method:'POST',body:{kind:btn.dataset.pick}});if(result.path)$(btn.dataset.target).value=result.path;}catch(e){notice('Native picker unavailable; enter the full path manually.',true);}}));
$('globalJobStatus').addEventListener('click',()=>go('dashboard'));
$('versionPill').textContent=bootstrap.version;$('footerVersion').textContent=bootstrap.version;$('assessmentPath').value=state.assessment;if(!token){notice('Open the private GUI session URL printed in the WCA terminal. The plain localhost address is not sufficient.',true);}else{if(state.assessment)refresh();loadRecent();const previous=localStorage.getItem('wcaActiveJob');if(previous){state.jobId=previous;state.lastLog=null;pollJob();}}setInterval(()=>{if(state.jobId&&!state.jobFinished)pollJob();},2500);
