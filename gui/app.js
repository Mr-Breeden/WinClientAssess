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
const state = {assessment: localStorage.getItem('wcaSelectedAssessment') || '', status: null, review: null, selectedReview: null, jobId: null, jobAssessment: null, jobKind: null, pollBusy: false, reviewCache: new Map(), reviewLoadedAt: 0, runtime: null, lastLog: null, captureWasActive: false, guideOpen: new Map(), manual: null, selectedManual: null, workspacePane: 'overview', manualOverview: null, activeQueue: null, jobStarting: false, runtimeIntroAssessment: null};
const notificationHistory = [];
function notice(message, error = false) {
  // Routine successes and informational actions belong in their owning workspace,
  // not in global error notifications. The history counter tracks actionable issues.
  if (!error) return;
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
// Optional workspace preflight: a PASS Guided Runtime session is necessary to
// claim observation completed. A local skip is an acknowledgement, not evidence.
function runtimeObservationCompleted(){
 return (state.runtime?.sessions||[]).some(session=>session.capture_status==='PASS');
}
function runtimeStepEligible(){
 return state.assessment&&state.status?.status==='COMPLETED'&&state.status?.mode==='full'&&
   state.status?.integrity?.status==='PASS'&&!runtimeObservationCompleted();
}
function runtimeSkipKey(){return 'wcaRuntimeObservationSkip:'+state.assessment;}
function runtimeSkipped(){return !!state.assessment&&localStorage.getItem(runtimeSkipKey())==='yes';}
function runtimeCanStart(){
 return runtimeStepEligible()&&state.status.framework_version===bootstrap.version&&
   !state.jobStarting&&!(state.jobId&&state.jobKind==='runtime'&&!state.jobFinished);
}
function updateRuntimeStep(){
 const eligible=runtimeStepEligible(), skipped=runtimeSkipped();
 const shouldShow=eligible&&!skipped;
 $('workspaceRuntimeTab').hidden=!shouldShow;
 $('workspaceRuntimeReminder').hidden=!eligible;
 if(eligible){
  const isCompatible=state.status.framework_version===bootstrap.version;
  set('workspaceRuntimeBadge',state.runtime?.state||'NOT RUN');
  $('workspaceRuntimeStart').disabled=!runtimeCanStart();
  set('workspaceRuntimeReason',!isCompatible?
   `Runtime capture requires an assessment created by WCA ${bootstrap.version}; this older assessment remains available for read-only review.`:
   state.jobId&&state.jobKind==='runtime'&&!state.jobFinished?'Observation is active. Return to Overview to monitor or stop it.':
   'No successful Guided Runtime session found in verified assessment history.');
  set('workspaceRuntimeReminderText',skipped?
   'Guided Runtime was skipped in this browser. No completed runtime observation is recorded. You may revisit it at any time.':
   'Runtime observation is recommended before reviewing WCRs and completing manual test cases.');
 }
 if(!shouldShow&&state.workspacePane==='runtime')showWorkspacePane('overview');
}
function preferredWorkspacePane(){
 if(runtimeStepEligible()&&!runtimeSkipped()&&state.runtimeIntroAssessment!==state.assessment){
  state.runtimeIntroAssessment=state.assessment;
  return 'runtime';
 }
 return state.workspacePane==='runtime'&&!runtimeStepEligible()?'overview':state.workspacePane;
}
function go(tab){
 const page=(tab==='review'||tab==='workflow')?'workspace':tab;
 document.querySelectorAll('.page').forEach(x=>x.classList.toggle('active',x.id==='page-'+page));
 document.querySelectorAll('.nav-link').forEach(x=>x.classList.toggle('active',x.dataset.tab===page));
 $('sectionLabel').textContent={dashboard:'Overview',new:'New assessment',workspace:'Tester Workspace',reports:'Reports',tools:'Tool readiness',management:'Assessment Management',help:'Help & About'}[page];
 if(page==='workspace'){
  showWorkspacePane(tab==='review'||tab==='workflow'?'queue':preferredWorkspacePane());
 }
 if(page==='reports')loadReports();
 if(page==='tools')loadTools();
 if(page==='management')loadManagement();
 if(page==='help')loadAbout();
}
function showWorkspacePane(pane='overview'){
 state.workspacePane=pane;
 document.querySelectorAll('.workspace-pane').forEach(node=>{node.hidden=node.id!=='workspace-pane-'+pane;});
 document.querySelectorAll('[data-workspace-pane]').forEach(button=>{
  const active=button.dataset.workspacePane===pane;
  button.classList.toggle('active',active);button.setAttribute('aria-pressed',String(active));
 });
 if(!state.assessment)return;
 if(pane==='final'&&!$('workspaceAppendixOutput').value)$('workspaceAppendixOutput').value=$('appendixOutput').value;
 if(pane==='final')loadClientNotesPreview();
 if(pane==='review'&&(!state.review?.items||Date.now()-state.reviewLoadedAt>30000))loadReview();
 if(pane==='manual'&&!state.manual)loadManualTests();
 if(pane==='queue')loadTestingQueue();
 renderWorkspaceSummary();
}
document.querySelectorAll('[data-workspace-pane]').forEach(button=>button.addEventListener('click',()=>showWorkspacePane(button.dataset.workspacePane)));
document.querySelectorAll('[data-workspace-target]').forEach(button=>button.addEventListener('click',()=>showWorkspacePane(button.dataset.workspaceTarget)));
$('workspaceRefresh').addEventListener('click',async()=>{if(!state.assessment)return notice('Select an assessment first.',true);
 await refresh();await loadReview();await loadManualTests();renderTestingQueue();renderWorkspaceSummary();});
function renderWorkspaceSummary(){
 updateRuntimeStep();
 const status=state.status||{};const manual=state.manual||state.manualOverview||{};const review=state.review||{};
 const queue=manual.testing_queue||{};
 const done=Math.max(0,(review.total||0)-(review.pending||0));
 const cards=[['Assessment',status.status||'Not loaded'],['Integrity',status.integrity?.status||'Not verified'],
  ['Guided Review',review.total!==undefined?`${done}/${review.total} dispositioned`:'Open Guided Review to load'],
  ['Testing activities',queue.total!==undefined?`${queue.resolved}/${queue.total} addressed`:'Open Testing Queue to load']];
 const holder=$('workspaceProgress');holder.replaceChildren();
 cards.forEach(([title,value])=>{const cell=el('div',undefined,'metric');cell.appendChild(el('span',title));cell.appendChild(el('strong',value));holder.appendChild(cell);});
 set('workspaceNext',status.status!=='COMPLETED'?'Complete evidence collection first.':runtimeStepEligible()&&!runtimeSkipped()?'Recommended first: complete or explicitly skip Guided Runtime Observation before reviewing candidates.':reviewNext(manual,review,status));
 const checklist=$('workspaceFinalChecks');checklist.replaceChildren();
 for(const [label,detail] of [
  ['Collection',status.status==='COMPLETED'?'Completed; review coverage gaps':`Current state: ${status.status||'Unavailable'}`],
  ['Integrity',status.integrity?.status==='PASS'?'PASS':'Not PASS — verify before exporting'],
  ['Automated candidates',review.total===undefined?'Open Testing Queue to load':`${review.pending||0} pending`],
  ['Testing activities',queue.total===undefined?'Open Testing Queue to load':`${queue.remaining||0} remaining, ${queue.pending_guided_review||0} WCR pending, ${manual.by_status?.BLOCKED||0} blocked`],
  ['Additional scope','Consult the attack-surface plan as guidance within your testing activities; document engagement-specific tests in your separate pentest report'],
  ['Client delivery','Use Generate Client Appendix below. Evidence integrity and review eligibility are checked automatically; incomplete manual testing is disclosed before export']
 ]){const item=el('div',undefined,'workspace-check');item.appendChild(el('strong',label));item.appendChild(el('span',detail));checklist.appendChild(item);}
}
document.querySelectorAll('.nav-link').forEach(x=>x.addEventListener('click',()=>go(x.dataset.tab)));
document.querySelectorAll('[data-go]').forEach(x=>x.addEventListener('click',()=>go(x.dataset.go)));
async function loadAssessment(){
 const chosen=value('assessmentPath');if(!chosen)return notice('Enter an assessment directory.',true);
 state.assessment=chosen;localStorage.setItem('wcaSelectedAssessment',chosen);
 try{await request('/api/select',{method:'POST',body:{assessment:chosen}});}catch(e){notice('Cannot register assessment: '+e.message,true);}
 state.review=null;state.manual=null;state.manualOverview=null;state.selectedManual=null;state.selectedReview=null;state.reviewCache.clear();await refresh();await loadRecent();
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
  $('guidedRuntimeBtn').disabled=state.jobStarting||(state.jobId&&state.jobKind==='runtime'&&!state.jobFinished)||!(d.status==='COMPLETED'&&d.mode==='full'&&d.framework_version===bootstrap.version&&d.integrity?.status==='PASS');
  $('appendixBtn').disabled=!(d.available_actions||[]).includes('export_appendix_with_confirmation');
  if(!$('appendixOutput').value||!$('appendixOutput').value.startsWith(state.assessment))$('appendixOutput').value=state.assessment.replace(/[\\/]+$/,'')+'-ClientAppendix.zip';
  if(!$('workspaceAppendixOutput').value||!$('workspaceAppendixOutput').value.startsWith(state.assessment))$('workspaceAppendixOutput').value=$('appendixOutput').value;
  const manual=result.data.manual||{};state.manualOverview=manual;
  set('workflowCompletion',manual.available&&manual.testing_queue?`${manual.testing_queue.resolved}/${manual.testing_queue.total} addressed`:'Not available');
  const nextAction = d.integrity?.status!=='PASS' ? 'Verify assessment integrity and resolve collection issues first.' : reviewNext(manual,result.data.review,d);
  set('workflowNextAction',nextAction);
  const review=result.data.review;
  set('metricReview',`${review.total-review.pending}/${review.total}`);
  set('metricReviewHint',`${review.pending} pending`);
  renderRuntimeHistory(state.runtime);
  renderWorkspaceSummary();
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
  renderReviewList();renderTestingQueue();renderWorkspaceSummary();
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
function guideSection(index,label,body,open=false,guideId=state.selectedReview?.id||''){
 const details=el('details',undefined,'review-guide-section');
 const key=state.assessment+'|'+guideId+'|'+index;
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
 commands.forEach(cmd=>{const line=el('div',undefined,'review-command');line.appendChild(el('pre',cmd));const button=el('button','Copy','button subtle');button.type='button';button.addEventListener('click',async()=>{try{await navigator.clipboard.writeText(cmd);button.textContent='Copied';}catch(_){notice('Copy unavailable; select the text manually.',true);}});line.appendChild(button);box.appendChild(line);});return box;
}
function guidePoc(poc){const box=el('div');
 box.appendChild(el('p',poc?.resource||'No bundled PoC resource is applicable to this condition.'));
 for(const key of ['architecture','requires_compilation','expected_output']){if(poc?.[key])box.appendChild(el('p',`${key.replaceAll('_',' ')}: ${poc[key]}`));}
 for(const key of ['build_or_invocation','verification']){if(poc?.[key]?.length){box.appendChild(el('strong',key.replaceAll('_',' ')));poc[key].forEach((step,i)=>box.appendChild(el('p',`${i+1}. ${step}`)));}}
 box.appendChild(el('p','All PoC builds and execution are initiated by the tester, never the web interface.','review-guide-muted'));return box;}
async function previewQueueReport(name){
 const pane=$('queueReportPane');pane.hidden=false;
 set('queueReportName',name);set('queueReportContent','Loading verified report…');
 try{const result=await request('/api/report?'+params({assessment:state.assessment,name}));set('queueReportContent',result.content);}
 catch(e){set('queueReportContent','Report unavailable: '+e.message);}
}
$('queueReportClose').addEventListener('click',()=>{$('queueReportPane').hidden=true;set('queueReportContent','');});
function guideReports(artifacts){const box=el('div');if(!artifacts?.length)return el('p','No supporting reports linked.');
 artifacts.forEach(name=>{const button=el('button',name,'button outline review-guide-link');button.type='button';button.addEventListener('click',()=>previewQueueReport(name));box.appendChild(button);});return box;}
function renderGuide(detail){
 const holder=el('div');holder.appendChild(el('h3','Validation and evidence guide'));
 holder.appendChild(guideSection(1,'Observed evidence',`${detail.evidence||'See supporting reports.'}

Affected component: ${detail.component||'Not specified'}\nMatching events: ${detail.matching_events||0}`,true,detail.id));
 holder.appendChild(guideSection(2,'Why validate it',detail.description,false,detail.id));
 holder.appendChild(guideSection(3,'Prerequisites',detail.prerequisites,false,detail.id));
 holder.appendChild(guideSection(4,'Starting checks',guideCommands(detail.commands),true,detail.id));
 holder.appendChild(guideSection(5,'Manual validation procedure',detail.manual_validation,false,detail.id));
 holder.appendChild(guideSection(6,'PoC resources and build guidance',guidePoc(detail.poc),false,detail.id));
 holder.appendChild(guideSection(7,'Tester execution',detail.tester_execution,false,detail.id));
 holder.appendChild(guideSection(8,'Expected evidence',detail.expected_evidence,false,detail.id));
 const interpret=el('div');interpret.appendChild(el('strong','Expected secure behavior'));interpret.appendChild(el('p',detail.secure||''));interpret.appendChild(el('strong','Potential security impact'));interpret.appendChild(el('p',detail.impact||''));
 holder.appendChild(guideSection(9,'Interpretation',interpret,false,detail.id));
 holder.appendChild(guideSection(10,'When not to report',detail.not_report,false,detail.id));
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
  $('reviewNotes').value=d.notes||'';$('reviewClientNotes').value=d.client_notes||'';
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
 const decision=value('reviewDecision'), notes=$('reviewNotes').value, clientNotes=$('reviewClientNotes').value;
 if(decision===d.status&&notes===d.notes&&clientNotes===(d.client_notes||'')){set('reviewSaveHint','No changes to save.');return;}
 if(d.changed_evidence){notice('Evidence has changed; validate the condition again before saving.',true);return;}
 // The Save button is the explicit tester confirmation. Do not add a second browser popup.
 const save=$('saveReview');save.disabled=true;save.textContent='Saving…';
 try{
  const result=await request('/api/mutate',{method:'POST',body:{action:'save_review',assessment:state.assessment,candidate_id:d.id,fingerprint:d.fingerprint,disposition:decision,notes,client_notes:clientNotes,confirmed:true}});
  state.reviewCache.clear();state.review=null;await loadReview();await loadManualTests();await refresh();
  set('reviewSaveHint',result.message||'Decision saved.');
 }catch(e){e.operation=e.operation||'Guided Review save';e.nextStep=e.nextStep||'Verify assessment integrity before retrying.';notice(e,true);}
 finally{save.disabled=false;save.textContent='Save decision';}
});
async function loadReports(){if(!state.assessment)return;try{const result=await request('/api/reports?'+params({assessment:state.assessment}));set('reportsCount',`${result.reports.length} files`);const container=$('reportFiles');container.replaceChildren();result.reports.forEach(r=>{const button=el('button',r.name);button.addEventListener('click',()=>loadReport(r.name,button));container.appendChild(button);});if(!result.reports.length)container.textContent='No eligible reports found.';}catch(e){notice(e,true);}}
async function loadReport(name,button){try{const result=await request('/api/report?'+params({assessment:state.assessment,name}));set('reportTitle',result.name);set('reportBody',result.content);document.querySelectorAll('#reportFiles button').forEach(x=>x.classList.toggle('selected',x===button));}catch(e){notice(e,true);}}
$('reportsRefresh').addEventListener('click',loadReports);
async function mutate(action,body){return request('/api/mutate',{method:'POST',body:{action,assessment:state.assessment,confirmed:true,...body}});}
async function generateAppendix(outputId,hintId,buttonId){
 if(!state.assessment)return notice('Open a completed assessment first.',true);
 const output=value(outputId);
 if(!output){set(hintId,'Select a destination ZIP outside the assessment directory.');$(outputId).focus();return;}
 const button=$(buttonId);button.disabled=true;
 try{
  // Recheck the live assessment, not stale page state. Backend performs its own
  // complete integrity and readiness checks again on the mutation request.
  const result=await request('/api/overview?'+params({assessment:state.assessment}));
  const current=result.data.status||{};const manual=result.data.manual||{};
  state.status=current;state.manualOverview=manual;
  if(current.integrity?.status!=='PASS')throw new Error('Assessment integrity verification is not PASS. Open Assessment Management to inspect the issue before exporting.');
  if(!(current.available_actions||[]).includes('export_appendix_with_confirmation'))throw new Error('Client Appendix export is not eligible. Complete the required review and assessment checkpoints.');
  const remaining=manual.available?(manual.testing_queue?.remaining??manual.remaining??0):null;
  const warning=remaining===null?'Manual test completion is unavailable; verify testing status before delivery.':remaining>0?
    `${remaining} testing activit${remaining===1?'y':'ies'} remain unresolved, including ${manual.by_status?.BLOCKED||0} blocked manual case(s). The appendix is not proof that testing is complete.`:'';
  const question=(warning?warning+'\n\n':'')+'Generate the sanitized, reviewed Client Appendix ZIP at the specified location?';
  if(!confirm(question)){set(hintId,'Export canceled; no evidence was modified.');return;}
  const exported=await mutate('export_appendix',{output});
  set(hintId,`Verified Client Appendix generated: ${exported.data.filename}`);
  set('actionsHint',`Verified Client Appendix generated: ${exported.data.filename}`);
 }catch(e){e.operation=e.operation||'Client Appendix export';notice(e,true);set(hintId,`Export did not complete: ${e.message}`);}
 finally{button.disabled=false;}
}
async function loadClientNotesPreview(){
 const holder=$('clientNotesPreview');
 if(!state.assessment){holder.textContent='Open an assessment first.';return;}
 try{
  const r=await request('/api/client-notes?'+params({assessment:state.assessment}));
  holder.replaceChildren();
  if(!r.notes?.length){holder.appendChild(el('p','No client-facing notes saved. That is fine; the appendix can be generated without them.','hint'));return;}
  r.notes.forEach(n=>{const block=el('div',undefined,'workspace-check');block.appendChild(el('strong',`${n.id} — ${n.title}`));block.appendChild(el('span',n.notes));holder.appendChild(block);});
 }catch(e){holder.textContent='Client note preview unavailable: '+e.message;}
}
$('appendixBtn').addEventListener('click',()=>generateAppendix('appendixOutput','actionsHint','appendixBtn'));
$('workspaceAppendixBtn').addEventListener('click',()=>generateAppendix('workspaceAppendixOutput','workspaceAppendixHint','workspaceAppendixBtn'));
$('regenerateBtn').addEventListener('click',async()=>{if(!confirm('Regenerate ONLY eligible derived reports from intact authoritative evidence?'))return;try{const result=await mutate('regenerate_reports',{});set('regenerateReason',result.message||'Eligible derived reports regenerated.');await refresh();}catch(e){notice(e,true);}});
async function startJob(kind,data){
 if(state.jobStarting)return;
 state.jobStarting=true;
 if(kind==='runtime'){$('guidedRuntimeBtn').disabled=true;$('guidedRuntimeBtn').textContent='Starting Guided Runtime…';set('runtimeStatus','STARTING');}
 try{
  const result=await request('/api/start',{method:'POST',body:{kind,confirmed:true,...data}});
  state.jobId=result.job.id;state.jobAssessment=kind==='assessment'?`${data.output.replace(/[\\/]+$/,'')}\\${data.name}`:data.assessment;
  state.jobFinished=false;state.pendingCheckpointId='';state.jobKind=kind;state.captureWasActive=false;state.lastLog=null;
  if(kind==='runtime'){set('runtimeStatus','STARTING');set('runtimeLive','Starting Procmon observation. Waiting for capture readiness…');$('runtimeStopBtn').hidden=true;}
  localStorage.setItem('wcaActiveJob',state.jobId);
  notice(result.job.message);go('dashboard');$('assessmentPath').value=state.jobAssessment;
  state.assessment=state.jobAssessment;localStorage.setItem('wcaSelectedAssessment',state.assessment);await loadRecent();await pollJob();
 }catch(e){notice(e,true);}
 finally{state.jobStarting=false;if(kind==='runtime'){$('guidedRuntimeBtn').textContent='Start Guided Runtime Observation';if(!state.jobId||state.jobFinished){if(state.status?.status==='COMPLETED'&&state.status?.integrity?.status==='PASS')$('guidedRuntimeBtn').disabled=false;}}}
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
$('workspaceRuntimeStart').addEventListener('click',()=>{
 if(!runtimeCanStart())return;
 startJob('runtime',{assessment:state.assessment});
});
$('workspaceRuntimeSkip').addEventListener('click',()=>{
 if(!runtimeStepEligible())return;
 localStorage.setItem(runtimeSkipKey(),'yes');
 showWorkspacePane('overview');
});
$('workspaceRuntimeResume').addEventListener('click',()=>{
 if(!runtimeStepEligible())return;
 localStorage.removeItem(runtimeSkipKey());
 showWorkspacePane('runtime');
});

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


function reviewNext(manual,review,d){
 if(d.status!=='COMPLETED')return 'Complete collection and its tester checkpoints first.';
 if((review?.pending||0)>0)return `Disposition ${review.pending} remaining Guided Review candidates, then continue manual testing.`;
 if(!manual.available)return 'Open Testing Queue to review the applicable test procedures.';
 if((manual.testing_queue?.remaining??manual.remaining)>0)return `Continue ${manual.testing_queue?.remaining??manual.remaining} outstanding testing activities in the unified Testing Queue.`;
 return 'All tracked activities addressed. Review broader engagement scope and prepare the Client Appendix.';
}
// Unified Testing Queue is a read-only projection of existing, separately
// integrity-protected candidate dispositions and manual-test state.
let queueLoading=false;
async function loadTestingQueue(){
 if(!state.assessment||queueLoading)return;
 queueLoading=true;
 try{
  if(!state.review?.items)await loadReview();
  if(!state.manual?.items)await loadManualTests();
  renderTestingQueue();
 }finally{queueLoading=false;}
}
function queueActivities(){
 // Use the same integrity-verified backend projection as Overview and the
 // Final Checklist. A completed manual test cannot conceal a pending WCR.
 return state.manual?.testing_queue?.items||[];
}
function reviewPending(activity){return activity.pending_candidates||0;}
function manualPending(activity){return activity.type==='manual'&&!activity.manual_complete;}
function renderTestingQueue(){
 const items=queueActivities(), filter=value('queueFilter'), q=value('queueSearch').toLowerCase();
 const resolved=items.filter(x=>x.addressed).length;
 set('queueProgress',`${resolved}/${items.length} activities addressed · ${items.length-resolved} remaining · ${items.reduce((n,a)=>n+reviewPending(a),0)} pending Guided Review candidates. Manual and guided requirements must both be addressed.`);
 const filtered=items.filter(x=>(filter==='all'||(filter==='addressed'?x.addressed:filter==='pending-review'?reviewPending(x)>0:filter==='pending-manual'?manualPending(x):!x.addressed))&&
  (!q||`${x.id} ${x.title} ${x.status} ${(x.related_candidates||[]).map(c=>c.id+' '+c.title).join(' ')}`.toLowerCase().includes(q)));
 const list=el('div',undefined,'review-list');
 for(const a of filtered){const button=el('button',undefined,'review-item');button.type='button';
  button.classList.toggle('selected',a.id===state.activeQueue?.id);
  button.appendChild(el('div',`${a.id} — ${a.title}`,'review-item-title'));
  button.appendChild(el('div',`${a.addressed?'ADDRESSED':'NEEDS TESTING'} · ${a.status}`+
   ((a.related_candidates||[]).length?` · ${(a.related_candidates||[]).length} linked candidate(s)`:'')+(reviewPending(a)?` · ${reviewPending(a)} WCR PENDING`:'')+(a.changed?' · REVALIDATE EVIDENCE':''),'review-item-sub'));
  button.addEventListener('click',()=>openQueueActivity(a));list.appendChild(button);
 }
 if(!filtered.length)list.appendChild(el('div','No testing activities match this view.','empty-small'));
 replace($('queueItems'),list);
}
async function openQueueActivity(a){
 state.activeQueue={id:a.id,type:a.type};
 $('queueReportPane').hidden=true;set('queueReportContent','');
 const slot=$('queueDetail');$('queueEmpty').hidden=true;
 if(a.type==='manual'){
  const item=(state.manual?.items||[]).find(x=>x.id===a.id);
  if(!item)return;
  slot.appendChild($('manualEditor'));$('reviewEditor').hidden=true;
  await editManual(item);
 }else{
  const item=(state.review?.items||[]).find(x=>x.id===a.id);
  if(!item)return;
  slot.appendChild($('reviewEditor'));$('manualEditor').hidden=true;
  await editReview(item,false);
 }
 renderTestingQueue();
}
$('queueFilter').addEventListener('change',renderTestingQueue);
$('queueSearch').addEventListener('input',renderTestingQueue);
$('queueRefresh').addEventListener('click',async()=>{state.review=null;state.manual=null;await loadTestingQueue();await refresh();});
const MANUAL_CATEGORIES={AS:'Application-level',IN:'Installer',TG:'Target',SG:'Signature',MS:'MSI',PE:'PE & binaries',CF:'Configuration',LS:'Local storage',FS:'Filesystem',RG:'Registry',SV:'Services',TS:'Scheduled tasks',PB:'Privilege boundary',DR:'Drivers',PM:'Procmon',DL:'DLL loading',AR:'Advanced runtime',MC:'Memory/crypto',NW:'Network',IP:'IPC',UP:'Updater'};
function caseCategory(id){return id.split('-')[1]||'OTHER';}
function renderManualList(){
 const items=state.manual?.items||[];
 const search=value('manualSearch').toLowerCase(), status=value('manualStatusFilter'), category=value('manualCategoryFilter'), guided=value('manualGuidedFilter');
 const filtered=items.filter(item=>(!status||item.status===status)&&(!category||caseCategory(item.id)===category)&&
  (!guided||(guided==='linked'?(item.related_candidates||[]).length>0:(item.related_candidates||[]).length===0))&&
  (!search||`${item.id} ${item.title} ${(item.reports||[]).join(' ')}`.toLowerCase().includes(search)));
 set('manualFilterCount',`Showing ${filtered.length} of ${items.length} applicable test cases`);
 const list=el('div',undefined,'review-list');
 filtered.forEach(item=>{
  const b=el('button',undefined,'review-item');b.type='button';
  b.classList.toggle('selected',item.id===state.selectedManual?.id);
  b.appendChild(el('div',`${item.id} — ${item.title}`,'review-item-title'));
  b.appendChild(el('div',item.status+(item.changed_evidence?' · CHANGED EVIDENCE':'')+
   ((item.related_candidates||[]).length?` · ${(item.related_candidates||[]).length} related review candidate(s)`:''),'review-item-sub'));
  b.addEventListener('click',()=>editManual(item));list.appendChild(b);
 });
 if(!filtered.length)list.appendChild(el('div','No test cases match these filters.','empty-small'));
 replace($('manualCaseList'),list);
}
async function loadManualTests(){
 if(!state.assessment){set('workflowHint','Open a verified assessment first.');return;}
 try{
  const response=await request('/api/manual-tests?'+params({assessment:state.assessment}));
  state.manual=response.data;
  set('workflowCount',`${state.manual.testing_queue?.resolved??0}/${state.manual.testing_queue?.total??0} activities addressed · ${state.manual.testing_queue?.remaining??0} remaining`);
  set('workflowHint',`${state.manual.changed_evidence||0} case(s) changed since earlier review. Only current-version assessments can be modified; older assessments remain read-only.`);
  const filter=$('manualCategoryFilter'),current=filter.value;
  filter.replaceChildren();const all=el('option','All categories');all.value='';filter.appendChild(all);
  const cats=[...new Set(state.manual.items.map(item=>caseCategory(item.id)))].sort();
  cats.forEach(cat=>{const option=el('option',`${cat} — ${MANUAL_CATEGORIES[cat]||'Other'}`);option.value=cat;filter.appendChild(option);});
  filter.value=cats.includes(current)?current:'';
  renderManualList();renderTestingQueue();renderWorkspaceSummary();
  const selected=(state.manual.items||[]).find(x=>x.id===state.selectedManual?.id);
  if(selected)await editManual(selected);else{$('manualEditor').hidden=true;$('manualEmpty').hidden=false;}
 }catch(e){set('workflowHint','Manual workflow unavailable: '+e.message);$('manualEditor').hidden=true;}
}
async function previewManualReport(name){
 if(!state.assessment||!state.selectedManual?.reports?.includes(name))return;
 $('manualReportPane').hidden=false;
 set('manualReportName',name);set('manualReportContent','Opening verified report…');
 try{
  const result=await request('/api/report?'+params({assessment:state.assessment,name}));
  if(state.selectedManual?.reports?.includes(result.name))set('manualReportContent',result.content);
 }catch(e){set('manualReportContent','Unable to open report: '+e.message);}
}
$('manualReportClose').addEventListener('click',()=>{$('manualReportPane').hidden=true;set('manualReportContent','');});
// An independent WCR editor for each related candidate. Unlike the legacy
// shared reviewEditor this does not move DOM nodes, hide sibling candidates, or
// discard unsaved manual-test input when a candidate disposition is saved.
async function loadInlineCandidate(candidate,card,container){
 const result=await request('/api/review-detail?'+params({assessment:state.assessment,id:candidate.id}));
 const d=result.detail;
 if(!card.isConnected||state.selectedManual?.related_candidates?.every(x=>x.id!==d.id))return;
 const form=el('div',undefined,'linked-wcr-content');
 form.appendChild(el('p',`${d.module} · ${d.severity} · ${d.id} · Evidence ${d.changed_evidence?'changed — revalidation required':'unchanged'}`,'hint'));
 form.appendChild(renderGuide(d));
 const decision=el('div',undefined,'linked-wcr-decision');
 decision.appendChild(el('h4','Candidate review decision'));
 decision.appendChild(el('p','Record the WCR disposition independently from manual test completion. VALIDATED does not prove exploitability.','hint'));
 const statusLabel=el('label','Disposition');const status=el('select');
 for(const value of ['PENDING','VALIDATED','NOT APPLICABLE','INFORMATIONAL']){const o=el('option',value);o.value=value;status.appendChild(o);}
 status.value=d.status;statusLabel.appendChild(status);decision.appendChild(statusLabel);
 const notesLabel=el('label','Internal Tester Notes (optional — excluded from client deliverables)');
 const notes=el('textarea');notes.rows=3;notes.maxLength=4000;notes.value=d.notes||'';notesLabel.appendChild(notes);decision.appendChild(notesLabel);
 const clientLabel=el('label','Client-Facing Notes (optional)');
 const clientNotes=el('textarea');clientNotes.rows=3;clientNotes.maxLength=4000;clientNotes.value=d.client_notes||'';clientLabel.appendChild(clientNotes);decision.appendChild(clientLabel);
 decision.appendChild(el('p','Client deliverable: client-facing notes WILL appear in the Client Appendix; internal notes are excluded.','hint'));
 const save=el('button','Save WCR decision','button primary');save.type='button';
 const hint=el('span','Changes are saved only after clicking Save.','hint');
 const actions=el('div',undefined,'linked-wcr-save');actions.appendChild(save);actions.appendChild(hint);decision.appendChild(actions);
 save.disabled=state.status?.framework_version!==bootstrap.version;
 const updateUnsaved=()=>{card.dataset.unsaved=String(status.value!==d.status||notes.value!==(d.notes||'')||clientNotes.value!==(d.client_notes||''));};
 status.addEventListener('change',updateUnsaved);
 notes.addEventListener('input',updateUnsaved);clientNotes.addEventListener('input',updateUnsaved);
 updateUnsaved();
 save.addEventListener('click',async()=>{
  if(status.value===d.status&&notes.value===(d.notes||'')&&clientNotes.value===(d.client_notes||'')){
   hint.textContent='No changes to save.';return;
  }
  if(d.changed_evidence){hint.textContent='Evidence changed; refresh and revalidate this candidate before saving.';return;}
  save.disabled=true;save.textContent='Saving…';
  try{
   const resp=await request('/api/mutate',{method:'POST',body:{action:'save_review',assessment:state.assessment,
    candidate_id:d.id,fingerprint:d.fingerprint,disposition:status.value,notes:notes.value,
    client_notes:clientNotes.value,confirmed:true}});
   d.status=status.value;d.notes=notes.value;d.client_notes=clientNotes.value;updateUnsaved();
   const chip=card.querySelector('.linked-wcr-status');if(chip)chip.textContent=d.status;
   card.open=true;
   // Refresh the verified queue projection without rebuilding open WCR cards.
   // Otherwise unsaved notes in sibling WCRs or the manual test would be lost.
   state.review=(await backend('review')).data;
   state.reviewLoadedAt=Date.now();state.reviewCache.clear();
   state.manual=(await request('/api/manual-tests?'+params({assessment:state.assessment}))).data;
   const latest=(state.manual.items||[]).find(x=>x.id===state.selectedManual?.id);
   if(latest){
    state.selectedManual={...state.selectedManual,related_candidates:latest.related_candidates};
    const eligible=latest.related_candidates?.length&&latest.related_candidates.every(c=>
     ['VALIDATED','INFORMATIONAL','NOT APPLICABLE'].includes(c.status)&&!c.changed_evidence);
    const option=[...$('manualStatus').options].find(o=>o.value==='ADDRESSED IN GUIDED REVIEW');
    if(option){option.hidden=!eligible;option.disabled=!eligible;}
    const count=latest.related_candidates.filter(x=>x.status==='PENDING'||x.changed_evidence).length;
    set('manualChanged',count?`${count} linked candidate(s) still pending. Manual completion alone does not close this activity.`:
      'All linked WCR candidates dispositioned. Complete any remaining manual testing.');
    const header=$('manualRelated').querySelector('.linked-wcr-header .hint');
    if(header)header.textContent=`${count} pending · All related candidates are shown below. Each saves independently.`;
   }
   renderTestingQueue();renderWorkspaceSummary();await refresh();
   hint.textContent=resp.message||'WCR decision saved.';
  }catch(e){hint.textContent='WCR save failed: '+e.message;notice(e,true);}
  finally{save.disabled=state.status?.framework_version!==bootstrap.version;save.textContent='Save WCR decision';}
 });
 form.appendChild(decision);replace(container,form);
}

async function editManual(item){
 try{
  const result=await request('/api/manual-test?'+params({assessment:state.assessment,case_id:item.id}));
  if(result.data.fingerprint!==item.fingerprint)throw new Error('Test case changed; refresh the list.');
  item=result.data;
 }catch(e){notice('Manual test details unavailable: '+e.message,true);return;}
 state.selectedManual=item;
 $('manualEditor').hidden=false;$('manualEmpty').hidden=true;
 $('manualReportPane').hidden=true;
 set('manualReportContent','');
 set('manualId',item.id);set('manualTitle',item.title);set('manualCompletionId',item.id);set('manualSaveHint','');
 const guidedEligible=!!item.related_candidates?.length&&item.related_candidates.every(c=>
  ['VALIDATED','INFORMATIONAL','NOT APPLICABLE'].includes(c.status)&&!c.changed_evidence);
 const guidedOption=[...$('manualStatus').options].find(o=>o.value==='ADDRESSED IN GUIDED REVIEW');
 if(guidedOption){guidedOption.hidden=!guidedEligible;guidedOption.disabled=!guidedEligible;}
 $('manualStatus').value=item.status;
 $('manualEvidence').value=item.evidence_reference||'';
 $('manualNotes').value=item.notes||'';$('manualClientNotes').value=item.client_notes||'';
 const pending=item.related_candidates?.filter(c=>!['VALIDATED','INFORMATIONAL','NOT APPLICABLE'].includes(c.status)||c.changed_evidence)||[];
 set('manualChanged',item.changed_evidence?'The test-case procedure changed. Revalidate before recording a new status.':
  pending.length?`${pending.length} linked Guided Review candidate(s) still pending. Completing manual testing will not close this activity until they are dispositioned.`:
  item.related_candidates?.length?'All linked candidates dispositioned. Confirm all test steps before using Addressed in Guided Review.':
  'No linked candidates. Record your manual testing outcome.');
 $('manualSave').disabled=state.status?.framework_version!==bootstrap.version;
 const related=$('manualRelated');related.replaceChildren();
 const inline=$('manualLinkedReview');inline.replaceChildren();inline.hidden=!item.related_candidates?.length;
 if(item.related_candidates?.length){
  const title=el('div',undefined,'linked-wcr-header');
  title.appendChild(el('h3',`Guided Review candidates (${item.related_candidates.length})`));
  title.appendChild(el('p',`${pending.length} pending · All related candidates are shown below. Each saves independently.`, 'hint'));
  related.appendChild(title);
  // Every candidate receives an independent editor. Reviewed candidates start
  // collapsed; pending candidates show their full validation controls immediately.
  for(const candidate of item.related_candidates){
   const card=el('details',undefined,'linked-wcr-card');
   card.open=candidate.status==='PENDING'||!!candidate.changed_evidence;
   const summary=el('summary',undefined,'linked-wcr-summary');
   summary.appendChild(el('span',candidate.id,'linked-wcr-id'));
   summary.appendChild(el('strong',candidate.title,'linked-wcr-title'));
   summary.appendChild(el('span',candidate.changed_evidence?'CHANGED EVIDENCE':candidate.status,'linked-wcr-status'));
   card.appendChild(summary);
   const detailArea=el('div','Loading candidate guidance…','linked-wcr-detail');card.appendChild(detailArea);
   inline.appendChild(card);
   // Independent requests allow every related WCR to be shown, not just the
   // first; the manual editor and its unsaved notes are never reparented.
   loadInlineCandidate(candidate,card,detailArea).catch(e=>{replace(detailArea,el('p','Candidate guidance unavailable: '+e.message,'hint'));});
  }
 }else{
  related.appendChild(el('p','No related Guided Review candidate; record the test result directly.','hint'));
 }
 const guidance=$('manualGuidance');guidance.replaceChildren();
 for(const [label,body] of Object.entries(item.guidance||{})){
  const section=el('details',undefined,'review-guide-section');
  section.open=label==='Procedure'||label==='How to Perform';
  section.appendChild(el('summary',label));section.appendChild(el('pre',body,'manual-guidance-body'));
  guidance.appendChild(section);
 }
 const links=$('manualReportLinks');links.replaceChildren();
 if(!item.reports?.length)links.appendChild(el('p','No supporting report available for inline viewing. Use the procedure in this activity.','hint'));
 else item.reports.forEach(name=>{
  const link=el('button','View '+name+' →','button outline review-guide-link');link.type='button';
  link.addEventListener('click',()=>previewManualReport(name));links.appendChild(link);
 });
 renderManualList();
}
['manualSearch','manualStatusFilter','manualCategoryFilter','manualGuidedFilter'].forEach(id=>$(id).addEventListener(id==='manualSearch'?'input':'change',renderManualList));
$('workflowRefresh').addEventListener('click',loadManualTests);
$('manualSave').addEventListener('click',async()=>{
 if(!state.assessment||!state.selectedManual)return;
 if($('manualLinkedReview').querySelector('.linked-wcr-card[data-unsaved="true"]')){
  set('manualSaveHint','An associated WCR has unsaved changes. Save its decision first so those notes are not lost.');return;
 }
 $('manualSave').disabled=true;
 try{
  const r=await request('/api/manual-tests',{method:'POST',body:{confirmed:true,assessment:state.assessment,
   case_id:state.selectedManual.id,fingerprint:state.selectedManual.fingerprint,
   status:$('manualStatus').value,evidence_reference:$('manualEvidence').value,notes:$('manualNotes').value,client_notes:$('manualClientNotes').value}});
  const savedScroll=window.scrollY;await loadManualTests();await refresh();window.scrollTo(0,savedScroll);
  const fresh=(state.manual?.items||[]).find(x=>x.id===state.selectedManual?.id);
  const outstanding=(fresh?.related_candidates||[]).filter(c=>!['VALIDATED','INFORMATIONAL','NOT APPLICABLE'].includes(c.status)||c.changed_evidence).length;
  set('manualSaveHint',outstanding?`Manual decision saved. ${outstanding} linked Guided Review candidate(s) still require review.`:(r.message||'Manual test status saved.'));
 }catch(e){notice(e,true);}finally{$('manualSave').disabled=state.status?.framework_version!==bootstrap.version;}
});

async function previewWorkspaceEvidence(name){
 if(!state.assessment)return notice('Open an assessment first.',true);
 showWorkspacePane('evidence');$('workspaceEvidencePane').hidden=false;
 set('workspaceEvidenceTitle',name);set('workspaceEvidenceContent','Opening verified report…');
 try{const r=await request('/api/report?'+params({assessment:state.assessment,name}));set('workspaceEvidenceContent',r.content);}
 catch(e){set('workspaceEvidenceContent','Report unavailable: '+e.message);}
}
// Evidence & Guidance is a reference view, never another testing checklist.
// The authoritative trackable procedures and WCR dispositions live in the queue.
const supplementalGuidance=[
 {title:'HTTP / API and authentication',tools:'Burp Suite · Wireshark',
  scope:'The client uses HTTP(S), WebSocket, a localhost service, or authenticated APIs',
  steps:['Identify one in-scope transaction and its authenticating principal.',
   'Replay it with authorized alternate account or object identifiers; check server-side authorization and session handling.',
   'Document only behavior not already covered by network or IPC queue activities.'],
  expected:'The authoritative service rejects unauthorized requests independently of the Windows client.',
  related:['TC-AS-001','TC-NW-002']},
 {title:'Deep code and runtime inspection',tools:'Ghidra · ILSpy · Frida · WinDbg',
  scope:'Evidence identifies a security-sensitive code path that needs deeper inspection',
  steps:['Use static review to locate input parsers, command execution, IPC handling, credential or crypto paths.',
   'Where authorized, observe the specific process/function with a suitable debugger or instrumentation tool.',
   'Validate a real trust-boundary failure rather than reporting API usage or ordinary application behavior.'],
  expected:'Untrusted input cannot trigger unauthorized sensitive operations; memory and authorization boundaries are enforced.',
  related:['TC-AS-001','TC-AR-004']},
 {title:'Application-specific trust boundaries',tools:'Procmon · Process Explorer · protocol-specific tooling',
  scope:'A feature exposes an in-scope trust boundary absent from the other applicable test cases',
  steps:['Identify the lower-trust actor, controllable input, trusted consumer and exact operation.',
   'Use a bounded, non-destructive test action in the authorized VM; correlate with target-scoped evidence.',
   'Record the outcome in the engagement test record rather than reopening completed queue items.'],
  expected:'Sensitive functionality consistently enforces caller identity, permissions and input constraints.',
  related:['TC-AS-001']}
];
const supplement=$('workspaceSupplemental');
for(const group of supplementalGuidance){
 const card=el('section',undefined,'supplemental-card');card.appendChild(el('h3',group.title));
 card.appendChild(el('p','When applicable: '+group.scope));
 card.appendChild(el('p','Tools: '+group.tools,'hint'));
 const detail=el('details');detail.appendChild(el('summary','How to investigate (optional reference)'));
 const steps=el('ol');for(const step of group.steps)steps.appendChild(el('li',step));detail.appendChild(steps);
 detail.appendChild(el('strong','Expected secure behavior'));detail.appendChild(el('p',group.expected));card.appendChild(detail);
 const btn=el('button','Open related Testing Queue activity →','button outline');btn.type='button';
 btn.addEventListener('click',async()=>{
  showWorkspacePane('queue');await loadTestingQueue();
  const target=queueActivities().find(a=>group.related.includes(a.id));
  if(target)await openQueueActivity(target);
  else set('queueProgress','No matching applicable activity in the current assessment. Use engagement-specific testing notes in your formal pentest report.');
 });
 card.appendChild(btn);supplement.appendChild(card);
}
const workspaceReports=[['coverage_summary.txt','Collection coverage'],['module_status.txt','Module execution status'],
 ['collection_provenance.txt','Collection provenance'],['findings_summary.txt','Findings summary']];
for(const [name,label] of workspaceReports){const b=el('button',label+' →','button outline');b.type='button';
 b.addEventListener('click',()=>previewWorkspaceEvidence(name));$('workspaceEvidenceLinks').appendChild(b);}
$('workspaceFullMethodology').addEventListener('click',()=>previewWorkspaceEvidence('attack_surface_test_plan.txt'));
$('workflowCoverage').addEventListener('click',()=>previewWorkspaceEvidence('coverage_summary.txt'));
