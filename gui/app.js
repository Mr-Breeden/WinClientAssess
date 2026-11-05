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
 $('sectionLabel').textContent={dashboard:'Overview',new:'New assessment',workspace:'Tester Workspace',reports:'Reports',tools:'Tool readiness',management:'Assessment Management',compare:'Compare Assessments',help:'Help & About'}[page];
 if(page==='workspace'){
  showWorkspacePane(tab==='review'||tab==='workflow'?'queue':preferredWorkspacePane());
 }
 if(page==='compare')loadComparisonChoices();
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
 if(pane==='final')ensureAppendixPath();
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
// p12: one authoritative export location in Tester Workspace Final Checklist.
function ensureAppendixPath(){
 if(!state.assessment)return;
 const input=$('workspaceAppendixOutput');
 const expected=state.assessment.replace(/[\\/]+$/,'')+'-ClientAppendix.zip';
 // Preserve tester-customized destinations across status refreshes. When the
 // selected assessment changes, replace only the old automatic suggestion.
 if(input.dataset.assessment!==state.assessment||!input.value||input.dataset.autoSuggested==='yes'){
  input.value=expected;input.dataset.autoSuggested='yes';input.dataset.assessment=state.assessment;
 }
}
$('workspaceAppendixOutput').addEventListener('input',()=>{$('workspaceAppendixOutput').dataset.autoSuggested='no';});
const CHECKPOINT_ORDER=[
 'static_analysis','pre_install_snapshot','installation_confirmation','post_install_snapshot',
 'installed_state_analysis','runtime_optional','surface_optional','reporting','complete'
];
const CHECKPOINT_NAMES={
 pre_install_snapshot:'Pre-install snapshot', installation_confirmation:'Installation confirmation',
 post_install_snapshot:'Post-install snapshot',installed_state_analysis:'Installed-state analysis',
 static_analysis:'Static analysis', surface_optional:'Network / IPC surface (optional)',
 runtime_optional:'Runtime capture (optional)', reporting:'Generate reports',complete:'Assessment finalized'
};
function orderedCheckpoints(stages){
 return Object.entries(stages).sort(([a],[b])=>{
  const ai=CHECKPOINT_ORDER.indexOf(a),bi=CHECKPOINT_ORDER.indexOf(b);
  return (ai<0?999:ai)-(bi<0?999:bi)||a.localeCompare(b);
 }).map(([key,value])=>[CHECKPOINT_NAMES[key]||key.replace(/_/g,' '),value]);
}
function setDonut(prefix,completed,total,label){
 const valid=Number.isFinite(completed)&&Number.isFinite(total)&&total>=0;
 const pct=valid&&total>0?Math.round(100*Math.max(0,Math.min(completed,total))/total):0;
 const indicator=$(prefix+'DonutFill');
 const radius=47,circumference=2*Math.PI*radius;
 indicator.style.strokeDasharray=`${(pct/100)*circumference} ${circumference}`;
 set(prefix+'ProgressPercent',valid&&total>0?`${pct}%`:'—');
 $(prefix+'Donut').setAttribute('aria-label',valid&&total>0?`${label}: ${completed} of ${total} complete (${pct} percent)`:`${label}: no applicable results`);
}
function renderTestingProgress(manual,review){
 const statuses=manual?.by_status;
 // A completed applicable manual case is COMPLETED or explicitly addressed
 // through Guided Review. N/A is excluded, not counted as validated work.
 if(manual?.available&&statuses&&Number.isFinite(Number(manual.total))){
  const excluded=Number(statuses['NOT APPLICABLE']||0),blocked=Number(statuses.BLOCKED||0);
  const denominator=Math.max(0,Number(manual.total)-excluded);
  const completed=Number(statuses.COMPLETED||0)+Number(statuses['ADDRESSED IN GUIDED REVIEW']||0);
  setDonut('tc',completed,denominator,'Applicable manual test cases');
  set('tcProgressText',`${completed} of ${denominator} applicable completed`);
  set('progressLimitations',`${blocked} blocked · ${excluded} marked N/A · ${(manual.excluded_cases||[]).length} excluded by evidence applicability · ${Number(manual.historical_saved_decisions||0)} historical saved TC decisions excluded from active progress. Pending WCRs can leave an activity outstanding even when its manual case is completed.`);
 }else{setDonut('tc',NaN,0,'Manual test cases');set('tcProgressText','Manual status not available');set('progressLimitations','Manual testing status unavailable; open Testing Queue for details.');}
 if(review&&Number.isFinite(Number(review.total))&&Number.isFinite(Number(review.pending))){
  const total=Number(review.total),pending=Math.max(0,Number(review.pending));
  const complete=Math.max(0,total-pending);setDonut('wcr',complete,total,'Active Guided Review candidates');
  set('wcrProgressText',`${complete} of ${total} active candidates dispositioned · ${pending} pending`);
 }else{setDonut('wcr',NaN,0,'Guided Review');set('wcrProgressText','Review status not available');}
}
function renderWorkspaceSummary(){
 updateRuntimeStep();
 const status=state.status||{};const manual=state.manual||state.manualOverview||{};const review=state.review||{};
 const queue=manual.testing_queue||{};
 const done=Math.max(0,(review.total||0)-(review.pending||0));
 const cards=[['Evidence collection',status.status==='COMPLETED'?'Completed (review gaps)':status.status||'Not loaded'],
  ['Integrity',status.integrity?.status||'Not verified'],
  ['Guided Review',review.total!==undefined?`${done}/${review.total} dispositioned`:'Open Testing Queue to load'],
  ['Manual / WCR testing',queue.total!==undefined?`${queue.resolved}/${queue.total} addressed`:'Open Testing Queue to load']];
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
  const rows=orderedCheckpoints(d.stages||{});set('checkpointCount',`${rows.length} stages`);
  replace($('checkpointTable'),makeTable(['Checkpoint','Status'],rows));
  $('guidedRuntimeBtn').disabled=state.jobStarting||(state.jobId&&state.jobKind==='runtime'&&!state.jobFinished)||!(d.status==='COMPLETED'&&d.mode==='full'&&d.framework_version===bootstrap.version&&d.integrity?.status==='PASS');
  $('workspaceAppendixBtn').disabled=!(d.available_actions||[]).includes('export_appendix_with_confirmation');
  ensureAppendixPath();
  const manual=result.data.manual||{};state.manualOverview=manual;
  set('workflowCompletion',manual.available&&manual.testing_queue?`${manual.testing_queue.resolved}/${manual.testing_queue.total} addressed`:'Not available');
  const nextAction = d.integrity?.status!=='PASS' ? 'Verify assessment integrity and resolve collection issues first.' : reviewNext(manual,result.data.review,d);
  set('workflowNextAction',nextAction);
  const review=result.data.review;
  set('metricReview',`${review.total-review.pending}/${review.total}`);
  set('metricReviewHint',`${review.pending} pending`);
  renderTestingProgress(manual,review);
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
   const cell=el('div',undefined,'recent-item-actions');cell.appendChild(button);
   const remove=el('button','Remove','button subtle recent-remove');remove.type='button';
   remove.setAttribute('aria-label','Remove '+item.name+' from recent history');
   remove.addEventListener('click',async()=>{
     if(!confirm(`Remove "${item.name}" from Recent Assessments? This does not delete any files.`))return;
     try{await request('/api/recent/remove',{method:'POST',body:{path:item.path,confirmed:true}});await loadRecent();}
     catch(e){notice(e,true);}
   });cell.appendChild(remove);
   return [cell,`${item.target_type||'—'} · ${item.mode||'—'}`,stateText,`TC: ${item.manual?.total ? `${item.manual.completed}/${item.manual.total}` : 'N/A'} · WCR: ${item.review.total ? `${item.review.completed}/${item.review.total}` : 'None'}`,item.last_activity||'—',item.integrity==='NOT VERIFIED'?'Open to verify':item.integrity];
  });
  replace(holder,makeTable(['Assessment','Type / mode','State','Testing Progress','Last activity','Integrity'],rows));
 }catch(e){replace($('recentTable'),el('div','Recent assessments unavailable: '+e.message,'empty-small'));}
}
function renderRuntimeHistory(history){
 const label=history?.state||'NOT RUN';set('runtimeStatus',label);
 const sessions=history?.sessions||[];
 const target=$('runtimeHistory');
 if(!sessions.length){replace(target,el('div','No completed Guided Runtime session recorded for this assessment.','muted'));$('runtimeReportBtn').hidden=true;return;}
 const holder=el('div',undefined,'runtime-session-history');
 holder.appendChild(el('p',`Showing ${sessions.length} most recent session(s) of ${history?.total??sessions.length} retained. Historical observations are NOT current process, ACL, or socket state. Revalidate live identities before drawing conclusions.`,'hint'));
 const rows=sessions.map((x,i)=>{
  const prior=sessions[i+1];
  const changes=prior?`${Number(x.events||0)-Number(prior.events||0)>=0?'+':''}${Number(x.events||0)-Number(prior.events||0)} vs previous session`:'First retained summary';
  const name=x.session_id||`Session ${sessions.length-i} (legacy summary)`;
  const info=el('details',undefined,'runtime-session-detail');
  info.appendChild(el('summary',name));
  info.appendChild(el('p',`Workflow: ${x.workflow_label||'Unspecified'} · Captured: ${x.captured_at||'unknown'} · ${x.capture_status||'unknown'} · ${x.events||0} target events · ${x.target_processes||0} observed process names`));
  info.appendChild(el('p',`New WCR candidates: ${x.new_review_candidates||0}. Event count comparison: ${changes}. Counts compare distinct windows, not a combined security result.`,'hint'));
  info.appendChild(el('p',x.archived_evidence?`Integrity-protected per-session evidence: working/guided_runtime_sessions/${name}`:'No archived trace recorded for this session (legacy summary or unavailable capture).','hint'));
  return info;
 });
 holder.appendChild(makeTable(['Captured (UTC)','Workflow','Capture','Target events','New WCRs','Trace archived'],sessions.map(x=>[
  x.captured_at||'—',x.workflow_label||'Unspecified',x.capture_status||'—',x.events??0,x.new_review_candidates??0,x.archived_evidence?'YES':'NO'])));
 const details=el('div',undefined,'runtime-session-details');rows.forEach(x=>details.appendChild(x));holder.appendChild(details);
 replace(target,holder);
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
// Links are official project/vendor resources, not background installations.
// Keep names synchronized with utils/tool_detection.py (guarded by regression test).
const toolVendorResources=Object.freeze({
 'Python': {url:'https://www.python.org/downloads/windows/', label:'Download'},
 'PowerShell': {url:'https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows', label:'Install guide'},
 '7-Zip': {url:'https://www.7-zip.org/download.html', label:'Download'},
 'Sigcheck': {url:'https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck', label:'Download'},
 'Strings': {url:'https://learn.microsoft.com/en-us/sysinternals/downloads/strings', label:'Download'},
 'AccessChk': {url:'https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk', label:'Download'},
 'Autorunsc': {url:'https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns', label:'Download'},
 'Procmon': {url:'https://learn.microsoft.com/en-us/sysinternals/downloads/procmon', label:'Download'},
 'Process Explorer': {url:'https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer', label:'Download'},
 'Tcpvcon': {url:'https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview', label:'Download'},
 'Handle': {url:'https://learn.microsoft.com/en-us/sysinternals/downloads/handle', label:'Download'},
 'PipeList': {url:'https://learn.microsoft.com/en-us/sysinternals/downloads/pipelist', label:'Download'},
 'ListDLLs': {url:'https://learn.microsoft.com/en-us/sysinternals/downloads/listdlls', label:'Download'},
 'Detect It Easy': {url:'https://github.com/horsicq/DIE-engine/releases', label:'Releases'},
 'lessmsi': {url:'https://github.com/activescott/lessmsi/releases', label:'Releases'},
 'ILSpyCmd': {url:'https://www.nuget.org/packages/ilspycmd', label:'Install guide'},
 'Wireshark': {url:'https://www.wireshark.org/download.html', label:'Download'},
 'Ghidra': {url:'https://github.com/NationalSecurityAgency/ghidra/releases', label:'Releases'},
 'DUMPBIN': {url:'https://visualstudio.microsoft.com/downloads/', label:'Build Tools'},
 'PESecurity': {url:'https://www.powershellgallery.com/packages/PESecurity', label:'PowerShell Gallery'},
 'WinDbg': {url:'https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/', label:'Install guide'},
 'Frida': {url:'https://frida.re/docs/installation/', label:'Install guide'},
 'dotnet-trace': {url:'https://learn.microsoft.com/en-us/dotnet/core/diagnostics/dotnet-trace', label:'Install guide'},
 'dotnet-dump': {url:'https://learn.microsoft.com/en-us/dotnet/core/diagnostics/dotnet-dump', label:'Install guide'},
 'dotnet-counters': {url:'https://learn.microsoft.com/en-us/dotnet/core/diagnostics/dotnet-counters', label:'Install guide'},
});
function vendorDownloadLink(name){
 const resource=toolVendorResources[name];
 if(!resource)return el('span','Not available','hint');
 const link=el('a',resource.label,'tool-download-link');
 link.href=resource.url;link.target='_blank';link.rel='noopener noreferrer';
 link.setAttribute('aria-label',resource.label+' for '+name+' (official site, opens new tab)');
 return link;
}
let toolConfigRows=[];
async function loadTools(){
 try{
  const [result,config]=await Promise.all([backend('tool_readiness'),request('/api/tool-configuration')]);
  const tools=result.data.tools||[];toolConfigRows=config.tools||[];
  set('toolCount',`${tools.filter(t=>t.found).length}/${tools.length}`);
  const required=tools.filter(t=>t.level==='REQUIRED');set('coreTools',`${required.filter(t=>t.found).length}/${required.length}`);
  const selector=$('toolConfigName'),prior=selector.value;selector.replaceChildren();
  toolConfigRows.forEach(t=>{const option=el('option',`${t.name} · ${t.level} · ${t.found?'FOUND':'MISSING'}`);option.value=t.name;selector.appendChild(option);});
  if(toolConfigRows.some(t=>t.name===prior))selector.value=prior;
  showSelectedToolConfig();
  replace($('toolTable'),makeTable(['Tool','Importance','Use','Detected','Method','Download / Install'],tools.map(t=>{
   const row=toolConfigRows.find(x=>x.name===t.name);return [t.name,t.level,t.usage,t.found?'YES':'NO',row?.source||'—',vendorDownloadLink(t.name)];
  })));
 }catch(e){notice(e,true);}
}
function showSelectedToolConfig(){
 const selected=toolConfigRows.find(t=>t.name===$('toolConfigName').value);
 $('toolConfigPath').value=selected?.configured_path||'';
 set('toolConfigStatus',selected?.configured_path?'Using a custom path; Clear restores automatic discovery.':
  'No override set; WCA will discover this tool automatically if available.');
}
$('toolConfigName').addEventListener('change',showSelectedToolConfig);
$('toolConfigClear').addEventListener('click',()=>{$('toolConfigPath').value='';set('toolConfigStatus','Click Save and verify to remove this override.');});
$('toolConfigSave').addEventListener('click',async()=>{
 const button=$('toolConfigSave');button.disabled=true;
 try{
  const name=$('toolConfigName').value, path=value('toolConfigPath');
  const result=await request('/api/tool-configuration',{method:'POST',body:{confirmed:true,name,path}});
  await loadTools();set('toolConfigStatus',result.message);
 }catch(e){set('toolConfigStatus','Configuration not saved: '+e.message);}finally{button.disabled=false;}
});
$('toolsRefresh').addEventListener('click',loadTools);
$('recentRefresh').addEventListener('click',loadRecent);
loadComparisonChoices();
$('managementRefresh').addEventListener('click',loadManagement);
$('runtimeReportBtn').addEventListener('click',async()=>{go('reports');await loadReport('guided_runtime_observation.txt');});
document.querySelectorAll('[data-help]').forEach(b=>b.addEventListener('click',async()=>{
 try{const result=await request('/api/help?'+params({doc:b.dataset.help}));set('helpDocTitle',result.name);set('helpDocBody',result.content);}catch(e){notice('Guide unavailable: '+e.message,true);}
}));
async function loadReview(){
 const assessment=state.assessment,navAtStart=queueNavigationSerial;
 if(!state.assessment)return;
 try{
  const result=await backend('review');if(assessment!==state.assessment)return;state.review=result.data;state.reviewLoadedAt=Date.now();state.reviewCache.clear();
  set('reviewCount',`${result.data.total} conditions · ${result.data.pending} pending`);
  renderReviewList();renderTestingQueue();renderWorkspaceSummary();
  const selected=(result.data.items||[]).find(i=>i.id===state.selectedReview?.id);
  if(navAtStart!==queueNavigationSerial)return;
  if(selected){await editReview(selected,false,()=>navAtStart===queueNavigationSerial&&assessment===state.assessment&&
   (state.workspacePane!=='queue'||state.activeQueue?.type!=='review'||state.activeQueue?.id===selected.id))}else{$('reviewEditor').hidden=true;$('reviewEmpty').hidden=false;state.selectedReview=null;}
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
 const history=(state.review?.retired||[]);
 if(history.length){
  const details=el('details',undefined,'review-guide-section historical-review');
  details.appendChild(el('summary',`Historical observations (${history.length}) · read-only, excluded from active progress`));
  const summary=el('p','Previous candidate decisions are preserved for context. Historical process and ACL observations are not live checks. Revalidate before reuse.','hint');
  details.appendChild(summary);
  history.forEach(item=>{const entry=el('div',undefined,'review-item');
   entry.appendChild(el('strong',`${item.id} · ${item.title}`));
   entry.appendChild(el('div',`${item.previous_status} · ${item.module} · retired ${item.retired_at||'date unknown'}`,'review-item-sub'));
   details.appendChild(entry);});
  list.appendChild(details);
 }
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
 commands.forEach(entry=>{
  const cmd=typeof entry==='string'?entry:String(entry.text||'');
  const kind=typeof entry==='string'?'instruction':entry.kind;
  const line=el('div',undefined,kind==='command'?'review-command':'review-guide-muted');
  if(kind==='command'){
   line.appendChild(el('pre',cmd));
   const button=el('button','Copy command','button subtle');button.type='button';
   button.addEventListener('click',async()=>{try{await navigator.clipboard.writeText(cmd);button.textContent='Copied';}catch(_){notice('Copy unavailable; select the text manually.',true);}});
   line.appendChild(button);
  }else line.appendChild(el('p',cmd));
  box.appendChild(line);
 });return box;
}
function guidePoc(poc){const box=el('div');
 box.appendChild(el('p',poc?.resource||'No bundled PoC resource is applicable to this condition.'));
 for(const key of ['architecture','requires_compilation','expected_output']){if(poc?.[key])box.appendChild(el('p',`${key.replaceAll('_',' ')}: ${poc[key]}`));}
 for(const key of ['build_or_invocation','verification']){if(poc?.[key]?.length){box.appendChild(el('strong',key.replaceAll('_',' ')));poc[key].forEach((step,i)=>box.appendChild(el('p',`${i+1}. ${step}`)));}}
 box.appendChild(el('p','All PoC builds and execution are initiated by the tester, never the web interface.','review-guide-muted'));return box;}
// One verified report viewer for active Testing Queue manual and WCR activities.
// Reparent it directly beneath the clicked link, never to the top of the activity.
let queueReportText='',queueReportLines=[],queueReportMatches=[],queueReportIndex=0,queueReportLoaded=false;
function queueReportPath(){
 if(!state.assessment||!queueReportLoaded)return '';
 const name=$('queueReportName').textContent;
 if(!/^[A-Za-z][A-Za-z0-9_-]{0,110}\.(txt|md|html)$/.test(name))return '';
 return state.assessment.replace(/[\\/]+$/,'')+'\\reports\\'+name;
}
function queuePowerShellCommand(){
 // Require the literal query shown in the read-only report viewer. Empty
 // searches must not unexpectedly open an integrity-protected report in Notepad.
 const path=queueReportPath(),term=$('queueReportSearch').value.trim();
 if(!path||!term)return '';
 const quote=value=>"'"+value.replace(/'/g,"''")+"'";
 return `Select-String -LiteralPath ${quote(path)} -SimpleMatch -Pattern ${quote(term)} | Select-Object LineNumber, Line`;
}
function updateQueueSearchCopy(){
 const available=queueReportLoaded&&!!queueReportPath();
 const hasTerm=!!$('queueReportSearch').value.trim();
 $('queueReportCopySearch').disabled=!available||!hasTerm;
 set('queueReportSearchHint',hasTerm?'Copy PowerShell search will use the current literal search term.':'Enter a search term to enable Copy PowerShell search.');
}

async function queueCopy(content){
 if(!content)return;
 try{await navigator.clipboard.writeText(content);set('queueReportCopyStatus','Copied.');}
 catch(_){set('queueReportCopyStatus','Clipboard unavailable. Select and copy the text manually.');}
}
function renderReportMatches(){
 updateQueueSearchCopy();
 const query=$('queueReportSearch').value.trim().toLowerCase();
 const panel=$('queueReportResults');
 queueReportMatches=query?queueReportLines.flatMap((line,index)=>line.toLowerCase().includes(query)?[index]:[]):[];
 queueReportIndex=0;
 panel.hidden=!query;
 if(!query)return;
 updateReportMatch();
}
function updateReportMatch(){
 const total=queueReportMatches.length,pos=queueReportMatches[queueReportIndex];
 set('queueReportMatchStatus',total?`${total} matching line(s) · ${queueReportIndex+1}/${total} · line ${pos+1}`:'No matching lines in this report.');
 $('queueReportPrevious').disabled=queueReportIndex<=0;
 $('queueReportNext').disabled=queueReportIndex>=total-1;
 if(total){
  const before=Math.max(0,pos-3),after=Math.min(queueReportLines.length,pos+5);
  set('queueReportMatchContext',queueReportLines.slice(before,after).map((line,i)=>`${before+i+1===pos+1?'→':' '} ${before+i+1}: ${line}`).join('\n'));
 }else set('queueReportMatchContext','');
}
async function previewQueueReport(name,anchor,initialSearch=""){
 const pane=$('queueReportPane');
 if(anchor&&anchor.isConnected)anchor.appendChild(pane);
 pane.hidden=false;queueReportLoaded=false;queueReportText='';queueReportLines=[];
 $('queueReportSearch').value='';$('queueReportResults').hidden=true;set('queueReportCopyStatus','');$('queueConfigSources').replaceChildren();
 set('queueReportName',name);set('queueReportContent','Loading verified report…');
 $('queueReportShortcuts').hidden=name.toLowerCase()!=='msi_analysis.txt';
 $('queueReportCopyPath').disabled=true;$('queueReportCopySearch').disabled=true;
 updateQueueSearchCopy();
 try{
  const assessment=state.assessment;
  const result=await request('/api/report?'+params({assessment,name}));
  if(state.assessment!==assessment||$('queueReportName').textContent!==name)return;
  queueReportText=result.content;queueReportLines=queueReportText.split(/\r?\n/);queueReportLoaded=true;
  set('queueReportContent',queueReportText);
  if(name==='configuration_review.txt')renderConfigurationSourceActions(queueReportText);
  else $('queueConfigSources').replaceChildren();
  $('queueReportCopyPath').disabled=false;
  if(name.toLowerCase()==='msi_analysis.txt'){$('queueReportSearch').value='[CUSTOMACTION-';renderReportMatches();}
  else if(initialSearch){$('queueReportSearch').value=initialSearch.slice(0,200);renderReportMatches();}
  else updateQueueSearchCopy();
 }catch(e){set('queueReportContent','Report unavailable: '+e.message);}
}
// Report paths stay sanitized at rest. Resolve only verified assessment-owned
// extracted files when the tester explicitly requests the local location.
function renderConfigurationSourceActions(content){
 const host=$('queueConfigSources');host.replaceChildren();
 const values=[...new Set((content.match(/%SOURCE_DIR%\\[^\r\n|]+/gi)||[]).map(x=>x.trim()).filter(x=>/\\working\\extracted_installer\\/i.test(x)))].slice(0,100);
 if(!values.length)return;
 const title=el('strong','Configuration artifact locations · verified local paths');host.appendChild(title);
 host.appendChild(el('p','Portable report paths are kept unchanged. Use Copy resolved path to locate an extracted artifact on this workstation.','hint'));
 for(const value of values){
  const row=el('div',undefined,'queue-config-source-row');
  const label=el('span',value.split('\\').pop());row.appendChild(label);
  const copy=el('button','Copy resolved path','button outline');copy.type='button';
  copy.addEventListener('click',async()=>{
   try{
    const reply=await request('/api/config-source-path?'+params({assessment:state.assessment,path:value}));
    await queueCopy(reply.path);
   }catch(e){set('queueReportCopyStatus','Cannot resolve source: '+e.message);}
  });row.appendChild(copy);
  const open=el('button','Open file location','button subtle');open.type='button';
  open.addEventListener('click',async()=>{
   try{
    const reply=await request('/api/config-open-location',{method:'POST',body:{assessment:state.assessment,path:value}});
    set('queueReportCopyStatus',reply.message||'Opened artifact location.');
   }catch(e){set('queueReportCopyStatus','Unable to open file location: '+e.message);}
  });row.appendChild(open);host.appendChild(row);
 }
}
function closeQueueReport(){
 const pane=$('queueReportPane');pane.hidden=true;queueReportLoaded=false;set('queueReportContent','');$('queueConfigSources').replaceChildren();
 $('queueReportCopyPath').disabled=true;updateQueueSearchCopy();
 $('queueDetail').prepend(pane);
}
$('queueReportClose').addEventListener('click',closeQueueReport);
$('queueReportCopyPath').addEventListener('click',()=>queueCopy(queueReportPath()));
$('queueReportCopySearch').addEventListener('click',()=>{
 const cmd=queuePowerShellCommand();
 if(!cmd){updateQueueSearchCopy();return;}
 queueCopy(cmd);
});
$('queueReportSearch').addEventListener('input',renderReportMatches);
$('queueReportPrevious').addEventListener('click',()=>{if(queueReportIndex>0){queueReportIndex--;updateReportMatch();}});
$('queueReportNext').addEventListener('click',()=>{if(queueReportIndex<queueReportMatches.length-1){queueReportIndex++;updateReportMatch();}});
document.querySelectorAll('[data-report-term]').forEach(button=>button.addEventListener('click',()=>{
 $('queueReportSearch').value=button.dataset.reportTerm;renderReportMatches();
}));
function guideReports(artifacts){const box=el('div');if(!artifacts?.length)return el('p','No supporting reports linked.');
 artifacts.forEach(name=>{const button=el('button',name,'button outline review-guide-link');button.type='button';button.addEventListener('click',()=>previewQueueReport(name,box));box.appendChild(button);});return box;}
// P17: condition-specific additions to shared TC procedures. These are
// investigation prompts, never vulnerability determinations.
function candidateNextSteps(detail){
 const text=[detail.evidence,detail.description,detail.component,detail.category].filter(Boolean).join(' ').toLowerCase();
 if(/tcp|listener|bind scope|network surface|0\.0\.0\.0|::1/.test(text))return {
   title:'Network endpoint validation',
   why:'A listening socket is exposure evidence, not proof of access control failure.',
   steps:['Correlate the socket with the verified executable, process identity and current collection session.',
     'Compare localhost and remote reachability from an authorized second host; record firewall and network context.',
     'Identify the actual protocol and supported operations using client behavior, vendor documentation or source inspection.',
     'Compare unauthenticated and authorized calls to a harmless protected operation; confirm server-side enforcement.',
     'Report only a demonstrated unintended exposure or unauthorized operation, not the bind address alone.'],
   command:'Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess'
 };
 if(/named.pipe|\\\\.\\pipe|ipc|rpc|alpc/.test(text))return {
   title:'IPC protocol and authorization validation',
   why:'Pipe existence and successful connection do not establish the operations available or their authorization.',
   steps:['Correlate the named endpoint with a verified owner and service account (Handle/Process Explorer).',
     'Inspect access controls and compare opening the pipe under standard-user and elevated identities.',
     'Trace normal application-client requests; find handlers by pipe name, QLocalServer/QLocalSocket, ReadFile or WriteFile.',
     'Determine the message structure before sending controlled, harmless requests; compare allowed and denied operations.',
     'Treat a standard-user connection as informational unless it can trigger an unauthorized security-sensitive action.'],
   command:'Get-ChildItem -Path \\.\\pipe\\ | Select-Object Name'
 };
 if(/dll|search.order|name not found/.test(text))return {
   title:'DLL resolution validation',why:'A missing lookup or heuristic user-writable directory does not prove DLL execution.',
   steps:['Verify process PID, executable, missing DLL name and search sequence from original Procmon evidence.',
     'Identify whether the directory is application-owned or inherited from PATH/tester tooling.',
     'Verify effective write rights as the intended lower-trust user, not from the elevated WCA token.',
     'Confirm actual loadability and privilege boundary in a controlled authorized reproduction.',
     'Do not report isolated NAME NOT FOUND events or hypothetical writable paths.'],command:''
 };
 if(/secret|credential|private.key|token/.test(text))return {
   title:'Sensitive-value validation',why:'Secret-related strings and complete key formats are not proof of a usable credential.',
   steps:['Inspect the verified original source locally without saving raw secret values in notes.',
     'Reject placeholders, PEM parser markers and function declarations; validate actual value syntax.',
     'Determine whether the value is operational, test material, public or inaccessible to unauthorized principals.',
     'Document only sanitized context and a demonstrated unauthorized exposure or misuse.'],command:''
 };
 if(/permission|acl|writable|service|privileg/.test(text))return {
   title:'Effective access and trust boundary',why:'Broad ACEs are potential influence, not independent evidence of exploitation.',
   steps:['Identify the actual security-sensitive file, directory, registry key or service operation.',
     'Verify the effective write permission under a standard-user token.',
     'Identify the privileged component that consumes the controllable artifact.',
     'Use a harmless, reversible test to establish influence where authorized; restore VM state.',
     'Do not report normal user-writable application data without protected consumption.'],command:''
 };
 return null;
}
function renderCandidateSteps(detail){
 const guide=candidateNextSteps(detail);
 if(!guide)return el('p','Follow the shared TC procedure above. If this candidate has a distinct trust boundary, validate that behavior before saving its disposition.','hint');
 const node=el('section',undefined,'p17-candidate-steps');
 node.appendChild(el('h4',guide.title));node.appendChild(el('p',guide.why,'hint'));
 const list=el('ol');for(const step of guide.steps)list.appendChild(el('li',step));node.appendChild(list);
 if(guide.command){const pre=el('pre',guide.command);node.appendChild(pre);const button=el('button','Copy starting check','button outline');button.type='button';button.addEventListener('click',()=>queueCopy(guide.command));node.appendChild(button);}
 return node;
}
function renderGuide(detail,{linkedCase=false}={}){
 // Linked candidates share their parent TC's evidence and procedure. They only
 // present the distinct observation and an independent disposition; the TC is
 // the single authoritative place to inspect reports and perform the test.
 if(linkedCase){
  const holder=el('div',undefined,'linked-wcr-observation');
  holder.appendChild(el('h4','Candidate observation'));
  const evidence=detail.evidence||detail.description||'See the test case evidence above.';
  const observation=el('div',undefined,'p17-observation');
  for(const part of String(evidence).split(/(?=\b(?:Confidence|Bind Scope|Privileged Context|Executable|Why Review|Manual Validation|HTTP\/S-like Port)\s*:)/)){
   const fragment=part.trim();if(fragment)observation.appendChild(el('p',fragment));
  }
  holder.appendChild(observation);
  if(detail.network_bindings?.length){
   holder.appendChild(makeTable(['IP family','Observed endpoint','Source POI'],
    detail.network_bindings.map(e=>[e.family,e.endpoint,e.source_record])));
  }
  if(detail.merged_previous_decisions?.length){
   const history=el('section',undefined,'p18-warning');
   history.appendChild(el('strong','Previous IPv4/IPv6 WCR decisions — historical only'));
   history.appendChild(el('p','The consolidated endpoint requires one new explicit decision. No prior disposition was automatically transferred.'));
   for(const entry of detail.merged_previous_decisions)history.appendChild(el('p',entry.id+' · '+entry.title+' · '+entry.status));
   holder.appendChild(history);
  }
  holder.appendChild(renderCandidateSteps(detail));
  if(detail.component)holder.appendChild(el('p','Affected component: '+detail.component,'hint'));
  holder.appendChild(el('p','Shared reports and generic checks remain in the TC above. These candidate-specific questions supplement them; record the WCR decision independently.','hint'));
  return holder;
 }
 const holder=el('div');holder.appendChild(el('h3','Validation and evidence guide'));
 if(detail.network_bindings?.length){
  holder.appendChild(el('p','Two observed address families share one review. Verify reachability and authorization for each.','hint'));
  holder.appendChild(makeTable(['IP family','Observed endpoint','Source POI'],
   detail.network_bindings.map(e=>[e.family,e.endpoint,e.source_record])));
 }
 if(detail.merged_previous_decisions?.length){
  const warning=el('section',undefined,'p18-warning');
  warning.appendChild(el('strong','Consolidated IPv4/IPv6 review — prior separate decisions retained'));
  warning.appendChild(el('p','Validate both address families; save a new decision for this combined WCR.'));
  for(const entry of detail.merged_previous_decisions)warning.appendChild(el('p',entry.id+' · '+entry.title+' · '+entry.status));
  holder.appendChild(warning);
 }
 holder.appendChild(guideSection(1,'Observed evidence',`${detail.evidence||'See supporting reports.'}

Affected component: ${detail.component||'Not specified'}\nMatching events: ${detail.matching_events||0}`,true,detail.id));
 holder.appendChild(guideSection(2,'Why validate it',detail.description,false,detail.id));
 holder.appendChild(guideSection(3,'Prerequisites',detail.prerequisites,false,detail.id));
 if(linkedCase){
  const note=el('p','Complete the detailed TC procedure above first. WCR Starting Checks are optional follow-ups; use them only when they validate evidence not already covered by the TC.','hint');
  holder.appendChild(note);
 }
 holder.appendChild(guideSection(4,linkedCase?'Optional WCR-specific Starting Checks':'Starting checks',guideCommands(detail.command_steps||detail.commands),!linkedCase,detail.id));
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
async function editReview(item,scroll=true,isCurrent=()=>true){
 if(!isCurrent())return;
 const requested=item.id;state.selectedReview=item;renderReviewList();
 try{
  const key=state.assessment+'|'+requested;
  const cached=state.reviewCache.get(key);
  const response=cached&&Date.now()-cached.saved<30000 ? {detail:cached.detail} : await request('/api/review-detail?'+params({assessment:state.assessment,id:requested}));
  if(!cached || Date.now()-cached.saved>=30000){state.reviewCache.set(key,{detail:response.detail,saved:Date.now()});
   if(state.reviewCache.size>24)state.reviewCache.delete(state.reviewCache.keys().next().value);}
  if(!isCurrent()||state.selectedReview?.id!==requested)return;
  const d=response.detail;
  state.reviewDetail=d;$('reviewEmpty').hidden=true;$('reviewEditor').hidden=false;
  set('reviewTitle',d.title);set('reviewDetails',`${d.module} · ${d.severity} · ${d.id} · Evidence ${d.changed_evidence?'changed — recheck required':'unchanged'} · ${d.artifacts.join(', ')}`);
  replace($('reviewValidation'),renderGuide(d));$('reviewDecision').value=d.status;
  $('reviewNotes').value=d.notes||'';$('reviewClientNotes').value=d.client_notes||'';
  set('reviewSaveHint','Existing notes loaded. Click Save to explicitly record a changed decision or notes.');
  if(scroll&&window.innerWidth<1000)$('reviewEditor').scrollIntoView({behavior:'smooth',block:'start'});
 }catch(e){if(isCurrent()&&state.selectedReview?.id===requested){$('reviewEditor').hidden=true;$('reviewEmpty').hidden=false;notice('Validation guidance unavailable: '+e.message,true);}}
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
function updateStagingAdvice(){
 const target=value('newTarget').replace(/\//g,'\\');
 const insideUserProfile=/^[A-Za-z]:\\Users\\[^\\]+\\/i.test(target);
 $('newStagingAdvice').classList.toggle('staging-location-warning',insideUserProfile);
 $('newStagingAdvice').querySelector('strong').textContent=insideUserProfile?
  'Staging location advisory — user profile detected':'Assessment staging and ACL interpretation';
}
$('newTarget').addEventListener('input',updateStagingAdvice);
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
$('guidedRuntimeBtn').addEventListener('click',()=>startJob('runtime',{assessment:state.assessment,workflow_label:$('runtimeWorkflowLabel').value}));
$('overviewOpenQueue').addEventListener('click',()=>{go('workspace');showWorkspacePane('queue');});
$('workspaceRuntimeStart').addEventListener('click',()=>{
 if(!runtimeCanStart())return;
 startJob('runtime',{assessment:state.assessment,workflow_label:$('workspaceRuntimeWorkflowLabel').value});
});
for(const [source,target] of [['runtimeWorkflowLabel','workspaceRuntimeWorkflowLabel'],['workspaceRuntimeWorkflowLabel','runtimeWorkflowLabel']]){
 $(source).addEventListener('change',()=>{$(target).value=$(source).value;});
}
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
  set('jobProgress',j.progress?`Stage: ${j.progress.stage} · ${j.progress.completed}/${j.progress.total} applicable completed${j.progress.not_applicable?` · ${j.progress.not_applicable} not applicable`:''} · ${j.progress.message}`:'');
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
   if(j.kind==='runtime'&&matchesSelected&&j.state==='COMPLETED'){
    // A runtime session may add or change WCR evidence and applicability links.
    // The Overview refresh alone does not invalidate these cached projections.
    // Re-read both from the verified assessment, never from untrusted job text.
    state.review=null;state.manual=null;state.reviewLoadedAt=0;state.reviewCache.clear();
    await loadReview();await loadManualTests();
    renderTestingQueue();renderWorkspaceSummary();
    const total=state.review?.total,pending=state.review?.pending;
    set('runtimeLive',total===undefined?
     'COMPLETED. Assessment evidence verified; review reload unavailable. Open Tester Workspace and select Refresh review.':
     `COMPLETED. Review lists refreshed: ${total} total WCR candidate(s), ${pending||0} pending. New candidates are reported separately; zero new does not mean zero total. Open Tester Workspace → Testing Queue.`);
   }
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
Array.from(document.querySelectorAll('.browse')).forEach(btn=>btn.addEventListener('click',async()=>{try{const result=await request('/api/pick',{method:'POST',body:{kind:btn.dataset.pick}});if(result.path){$(btn.dataset.target).value=result.path;if(btn.dataset.target==='newTarget')updateStagingAdvice();}}catch(e){notice('Native picker unavailable; enter the full path manually.',true);}}));
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
// Monotonic navigation version: older asynchronous detail requests must never
// replace a newer tester selection in the unified Testing Queue.
let queueNavigationSerial=0;
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
function renderQueueExcludedCases(){
 const excluded=state.manual?.excluded_cases||[];
 const box=$('queueExcludedCases');box.hidden=!excluded.length;
 set('queueExcludedSummary',`Why ${excluded.length} manual test case(s) were excluded`);
 const holder=$('queueExcludedList');holder.replaceChildren();
 for(const item of excluded){
  const div=el('div',undefined,'queue-excluded-item');
  div.appendChild(el('strong',`${item.id} — ${item.title}`));
  div.appendChild(el('p',(item.reasons||[]).join(' · '),'hint'));holder.appendChild(div);
 }
}
function reviewPending(activity){return activity.pending_candidates||0;}
function manualPending(activity){return activity.type==='manual'&&!activity.manual_complete;}
// Reconcile Testing Queue rows in place. Replacing all buttons while a save
// refresh is resolving can remove the target between pointerdown and click;
// preserving the same DOM node prevents a user-visible navigation dead zone.
function renderTestingQueue(){
 const items=queueActivities(), filter=value('queueFilter'), q=value('queueSearch').toLowerCase();
 const resolved=items.filter(x=>x.addressed).length;
 set('queueProgress',`${resolved}/${items.length} activities addressed · ${items.length-resolved} remaining · ${items.reduce((n,a)=>n+reviewPending(a),0)} pending Guided Review candidates. Manual and guided requirements must both be addressed.`);
 const filtered=items.filter(x=>(filter==='all'||(filter==='addressed'?x.addressed:filter==='pending-review'?reviewPending(x)>0:filter==='pending-manual'?manualPending(x):!x.addressed))&&
  (!q||`${x.id} ${x.title} ${x.status} ${(x.related_candidates||[]).map(c=>c.id+' '+c.title).join(' ')}`.toLowerCase().includes(q)));
 const list=$('queueItems');
 if(list.dataset.queueInitialized!=='yes'){list.replaceChildren();list.dataset.queueInitialized='yes';}
 const existing=new Map([...list.querySelectorAll(':scope > button.review-item')].map(b=>[b.dataset.activityId,b]));
 const desired=[];
 for(const a of filtered){
  let button=existing.get(a.id);
  if(!button){
   button=el('button',undefined,'review-item');button.type='button';button.dataset.activityId=a.id;
   button.appendChild(el('div',undefined,'review-item-title'));
   button.appendChild(el('div',undefined,'review-item-sub'));
   // Resolve fresh activity state on click: rows survive background refreshes.
   button.addEventListener('click',()=>{
    const current=queueActivities().find(x=>x.id===button.dataset.activityId);
    if(current)openQueueActivity(current).catch(e=>{
     set('queueEmpty','Unable to open activity: '+e.message);$('queueEmpty').hidden=false;
     notice('Testing Queue navigation error: '+e.message,true);
    });
    else {set('queueEmpty','This activity changed during refresh. Select Refresh and try again.');$('queueEmpty').hidden=false;}
   });
  }
  button.classList.toggle('selected',a.id===state.activeQueue?.id);
  button.querySelector('.review-item-title').textContent=a.title;
  button.querySelector('.review-item-title').title=a.id+' — '+a.title;
  const outstanding=a.type==='manual'&&!a.manual_complete?' · MANUAL TEST PENDING':'';
  button.querySelector('.review-item-sub').textContent=`${a.id} · ${a.addressed?'ADDRESSED':'NEEDS TESTING'} · ${a.status}`+
   outstanding+(reviewPending(a)?` · ${reviewPending(a)} WCR PENDING`:'')+
   (a.changed?' · CHANGED EVIDENCE — REVALIDATE':'')+
   ((a.related_candidates||[]).length?` · ${(a.related_candidates||[]).length} linked WCR(s)`:'');
  desired.push(button);
 }
 if(!desired.length){
  let msg=list.querySelector(':scope > .empty-small');
  if(!msg)msg=el('div','No testing activities match this view.','empty-small');
  desired.push(msg);
 }
 // Move a node only if its position actually changed. Never replace a clicked
 // row simply because a background manual/review snapshot completed.
 desired.forEach((node,i)=>{if(list.children[i]!==node)list.insertBefore(node,list.children[i]||null);});
 while(list.children.length>desired.length)list.lastElementChild.remove();
}

async function openQueueActivity(a){
 // Mark the desired row immediately, before waiting on the backend. When a
 // tester clicks A then B, A's slow response must not reopen A over B.
 const serial=++queueNavigationSerial, assessment=state.assessment;
 const isCurrent=()=>serial===queueNavigationSerial&&assessment===state.assessment&&
  state.activeQueue?.id===a.id&&state.activeQueue?.type===a.type;
 state.activeQueue={id:a.id,type:a.type};
 closeQueueReport();
 const slot=$('queueDetail');
 set('queueEmpty',`Loading ${a.id}…`);$('queueEmpty').hidden=false;
 $('manualEditor').hidden=true;$('reviewEditor').hidden=true;
 $('manualNext').hidden=true;
 renderTestingQueue();
 if(a.type==='manual'){
  const item=(state.manual?.items||[]).find(x=>x.id===a.id);
  if(!item){if(isCurrent())set('queueEmpty','Manual test data is not loaded; refresh the Testing Queue.');return;}
  slot.appendChild($('manualEditor'));
  await editManual(item,isCurrent);
 }else{
  const item=(state.review?.items||[]).find(x=>x.id===a.id);
  if(!item){if(isCurrent())set('queueEmpty','Guided Review data is not loaded; refresh the Testing Queue.');return;}
  slot.appendChild($('reviewEditor'));
  await editReview(item,false,isCurrent);
 }
 if(isCurrent()){
  $('queueEmpty').hidden=!(a.type==='manual'? $('manualEditor').hidden : $('reviewEditor').hidden);
  if($('queueEmpty').hidden===false)set('queueEmpty',`Unable to open ${a.id}. Check notifications or refresh the queue.`);
  renderTestingQueue();
 }
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
async function loadManualTests({restoreSelection=true}={}){
 const assessment=state.assessment, navAtStart=queueNavigationSerial;
 if(!state.assessment){set('workflowHint','Open a verified assessment first.');return;}
 try{
  const response=await request('/api/manual-tests?'+params({assessment:state.assessment}));
  if(assessment!==state.assessment)return;
  state.manual=response.data;
  set('workflowCount',`${state.manual.testing_queue?.resolved??0}/${state.manual.testing_queue?.total??0} activities addressed · ${state.manual.testing_queue?.remaining??0} remaining`);
  set('workflowHint',`${state.manual.changed_evidence||0} case(s) changed since earlier review. Only current-version assessments can be modified; older assessments remain read-only.`);
  const filter=$('manualCategoryFilter'),current=filter.value;
  filter.replaceChildren();const all=el('option','All categories');all.value='';filter.appendChild(all);
  const cats=[...new Set(state.manual.items.map(item=>caseCategory(item.id)))].sort();
  cats.forEach(cat=>{const option=el('option',`${cat} — ${MANUAL_CATEGORIES[cat]||'Other'}`);option.value=cat;filter.appendChild(option);});
  filter.value=cats.includes(current)?current:'';
  renderManualList();renderTestingQueue();renderWorkspaceSummary();renderQueueExcludedCases();
  // Background refreshes must not reopen a previously selected case while
  // the tester has already clicked another queue item (or another tab).
  if(!restoreSelection||navAtStart!==queueNavigationSerial)return;
  const selected=(state.manual.items||[]).find(x=>x.id===state.selectedManual?.id);
  if(selected)await editManual(selected,()=>navAtStart===queueNavigationSerial&&assessment===state.assessment&&
   (state.workspacePane!=='queue'||state.activeQueue?.type!=='manual'||state.activeQueue?.id===selected.id));
  else if(state.workspacePane!=='queue'||!state.activeQueue){$('manualEditor').hidden=true;$('manualEmpty').hidden=false;}
 }catch(e){
  if(assessment!==state.assessment)return;
  set('workflowHint','Manual workflow unavailable: '+e.message);
  if(navAtStart===queueNavigationSerial)$('manualEditor').hidden=true;
 }
}
// An independent WCR editor for each related candidate. Unlike the legacy
// shared reviewEditor this does not move DOM nodes, hide sibling candidates, or
// discard unsaved manual-test input when a candidate disposition is saved.
async function loadInlineCandidate(candidate,card,container){
 const result=await request('/api/review-detail?'+params({assessment:state.assessment,id:candidate.id}));
 const d=result.detail;
 if(!card.isConnected||state.selectedManual?.related_candidates?.every(x=>x.id!==d.id))return;
 const form=el('div',undefined,'linked-wcr-content');
 form.appendChild(el('p',`${d.module} · ${d.severity} · ${d.id} · Evidence ${d.changed_evidence?'changed — revalidation required':'unchanged'}`,'hint'));
 if(d.investigation)form.appendChild(el('p','Shared investigation: '+d.investigation+' · review supporting evidence through the parent TC.','hint'));
 form.appendChild(renderGuide(d,{linkedCase:true}));
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

// Also guards the legacy manual-list editor, where no queue-navigation callback
// is supplied: a slow earlier detail response cannot redraw over a new one.
let manualDetailSerial=0;
async function editManual(item,isCurrent=()=>true){
 const assessment=state.assessment,detailSerial=++manualDetailSerial;
 const stillCurrent=()=>detailSerial===manualDetailSerial&&isCurrent();
 if(!stillCurrent())return;
 state.selectedManual=item;
 try{
  const result=await request('/api/manual-test?'+params({assessment:state.assessment,case_id:item.id}));
  if(!stillCurrent()||state.assessment!==assessment||state.selectedManual?.id!==item.id)return;
  if(result.data.fingerprint!==item.fingerprint)throw new Error('Test case changed; refresh the list.');
  item=result.data;
 }catch(e){if(stillCurrent()&&state.assessment===assessment)notice('Manual test details unavailable: '+e.message,true);return;}
 if(!stillCurrent()||state.assessment!==assessment||state.selectedManual?.id!==item.id)return;
 state.selectedManual=item;
 $('manualNext').hidden=true;
 $('manualEditor').hidden=false;$('manualEmpty').hidden=true;
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
  title.appendChild(el('h3',`Candidate decisions (${item.related_candidates.length})`));
  title.appendChild(el('p','Shared investigation: review the TC evidence once. These candidate dispositions are recorded here; related security checks remain independently testable.','hint'));
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
 // One investigation, two independently saved outcomes. Keep the complete
 // manual completion form directly after the test procedure and put each WCR
 // candidate (with its own decision) after that form. Reparent whole nodes so
 // event listeners, unsaved input values and candidate cards remain intact.
 const editor=$('manualEditor');
 let completion=editor.querySelector('#manualCompletionBlock');
 if(!completion){completion=el('section',undefined,'manual-completion-block');completion.id='manualCompletionBlock';}
 const form=editor.querySelector('.form-grid');
 for(const node of [$('manualCompletionHeading'),form,$('manualChanged'),$('manualSave'),$('manualSaveHint'),$('manualNext')])completion.appendChild(node);
 // The completion block and linked candidates are positioned only after
 // the procedure and its additional evidence references have been built.
 // Appending them to the editor here used to strand both decisions at the
 // bottom of the overall review rather than beside the corresponding work.
 // Return the specialized PE panel to its stable parent before replacing
 // the previous case's step DOM. Otherwise a subsequent case switch could
 // detach it permanently and break all later TC-PE-001 navigation.
 const pePanel=$('peValidationPanel');
 if(pePanel&&$('manualGuidance').contains(pePanel))$('manualGuidance').after(pePanel);
 const guidance=$('manualGuidance');guidance.replaceChildren();
 const intro=el('div',undefined,'tc-workflow-intro');
 intro.appendChild(el('strong','Understand → Inspect evidence → Test → Interpret → Complete'));
 const purpose=el('div',undefined,'tc-security-purpose');
 purpose.appendChild(el('strong','Why this test matters'));
 purpose.appendChild(el('p',item.guidance?.['Procedure']||'Assess the relevant application trust boundary.'));
 guidance.appendChild(purpose);
 intro.appendChild(el('p','Work through the steps below. Open linked reports to identify an observed target; checks run only when explicitly requested. Results are observations, not vulnerability findings or automatic completion.','hint'));
 guidance.appendChild(intro);
 if(item.missing_reports?.length){
  const unavailable=el('div',undefined,'p18-missing-evidence');
  unavailable.appendChild(el('strong','Evidence not produced by this assessment'));
  unavailable.appendChild(el('p',item.missing_reports.join(', ')+'. These references may belong to non-applicable collection modules. They are not verified source links; follow the manual procedure where applicable.','hint'));
  guidance.appendChild(unavailable);
 }
 if(item.id==='TC-PM-001')guidance.appendChild(el('p',
  'GUI runtime capture stops with Stop Guided Runtime Observation, not a console Enter key.','hint'));
 for(const [label,body] of Object.entries(item.guidance||{})){
  const section=el('details',undefined,'review-guide-section');
  section.open=label==='Procedure'||label==='How to Perform';
  section.appendChild(el('summary',label));
  if(label==='How to Perform'){
   const area=el('div',undefined,'tc-procedure-steps');
   const chunks=tcSplitProcedure(body);
   if(chunks.length){
    chunks.forEach((chunk,i)=>{
     const step=el('div',undefined,'tc-procedure-step');step.dataset.step=String(i);
     const header=el('div',undefined,'tc-step-heading');
     header.appendChild(el('span',`STEP ${i+1}`,'tc-step-number'));header.appendChild(el('strong',tcStepLabel(item.id,i,chunk)));step.appendChild(header);
     step.appendChild(el('p',chunk.replace(/^\d+[.)]\s*/,''),'tc-step-instruction'));
     const sources=tcStepReports(chunk,item.reports||[]);
     if(sources.length){
      const ref=el('div',undefined,'tc-step-reports');ref.appendChild(el('span','Evidence: ','hint'));
      for(const name of sources){
       const btn=el('button',name,'button outline tc-evidence-link');btn.type='button';
       const viewer=el('div',undefined,'tc-step-report-view');
       btn.addEventListener('click',()=>{
        if($('queueReportPane').parentElement===viewer&&!$('queueReportPane').hidden){closeQueueReport();return;}
        previewQueueReport(name,viewer);
       });
       const entry=el('div',undefined,'tc-evidence-entry');entry.appendChild(btn);entry.appendChild(viewer);ref.appendChild(entry);
      }
      step.appendChild(ref);
     }
     const actions=el('div',undefined,'tc-step-actions');step.appendChild(actions);
     // Keep optional advanced-analysis help next to the instruction that uses it.
     if(item.id==='TC-AR-003' && i===4)step.appendChild(buildAdvancedModuleToolGuides());
     area.appendChild(step);
    });
   }else{
    area.appendChild(el('p',String(body||''),'tc-step-instruction'));
   }
   const fallback=el('div',undefined,'tc-step-fallback');area.appendChild(fallback);
   const outcome=el('div',undefined,'tc-procedure-outcome');
   outcome.appendChild(el('strong','Interpret and record your review'));
 for(const heading of ['What to Look For','Potentially Vulnerable Behavior','When NOT to Report']){
  if(item.guidance?.[heading]){const line=el('div',undefined,'tc-interpret-line');line.appendChild(el('strong',heading));line.appendChild(el('p',item.guidance[heading]));outcome.appendChild(line);}
 }
   outcome.appendChild(el('p',item.guidance?.['Expected Secure Behavior']||
    'Determine whether observed behavior meets the security objective using the authorized testing context.','hint'));
   outcome.appendChild(el('p','Live metadata is not effective standard-user access or proof of exploitability. Finish any remaining manual steps, then save the manual status and optional notes below.','hint'));
   area.appendChild(outcome);
   section.appendChild(area);
  }else section.appendChild(el('pre',body,'manual-guidance-body'));
  guidance.appendChild(section);
 }
 // Keep interpretation inside the procedure where its evidence is reviewed.
 if(item.id!=='TC-PE-001'){
  const steps=guidance.querySelectorAll('.tc-procedure-step');
  const assigned={'TC-IP-002':2,'TC-FS-001':2,'TC-RG-001':3,
                  'TC-MC-001':0,'TC-PM-001':3,'TC-LS-001':4};
  const target=steps[assigned[item.id]??0];
  if(target)addP18GuidanceExamples(target,item.id);
 }

 // There is deliberately no second runnable checklist detached from the steps.
 $('tcChecksPanel').hidden=true;
  if(item.id==='TC-SV-001')loadUnquotedServiceCallout(item.id,detailSerial);
  if(item.id==='TC-CF-001')loadSecretIndicatorPanel(item.id,detailSerial);
 loadManualChecks(item.id,detailSerial);
 if(item.id==='TC-PE-001'){
  const area=guidance.querySelector('.tc-procedure-steps');
  const step=area?.querySelectorAll('.tc-procedure-step')[2];
  if(step){
   // Place instructions and comparisons at the exact step where testers review
   // DUMPBIN/PE flags, not after the complete procedure and completion controls.
   step.appendChild(buildPeMitigationGuide());
   step.querySelector('.tc-step-actions').appendChild($('peValidationPanel'));
  }else{
   guidance.appendChild($('peValidationPanel'));
   guidance.appendChild(buildPeMitigationGuide());
  }
  loadPeVerification(item.id);
 }else{$('peValidationPanel').hidden=true;peVerificationRows=[];}
  const links=$('manualReportLinks');links.replaceChildren();
  const reportSection=links.closest('.manual-reports');
  // Place additional references immediately after the procedure; completion
  // and linked WCRs are ordered independently below that evidence section.
  const stepLinked=new Set([...guidance.querySelectorAll('.tc-evidence-link')].map(x=>x.textContent.toLowerCase()));
  const extraReports=[...new Set((item.reports||[]).filter(name=>!stepLinked.has(name.toLowerCase())))];
  reportSection.hidden=!extraReports.length;
  if(extraReports.length){
   reportSection.querySelector('h3').textContent='Additional References';
   const help=el('p','These verified reports were not referenced in the procedure steps. They are optional additional context, not another checklist.','hint');
   links.appendChild(help);
  }
  extraReports.forEach(name=>{
   const link=el('button','View '+name,'button outline review-guide-link');link.type='button';
   const anchor=el('div',undefined,'tc-summary-report');
   link.addEventListener('click',()=>{
    if($('queueReportPane').parentElement===anchor&&!$('queueReportPane').hidden){closeQueueReport();return;}
    previewQueueReport(name,anchor);
   });
   const entry=el('div',undefined,'tc-evidence-entry');entry.appendChild(link);entry.appendChild(anchor);
   links.appendChild(entry);
  });
 // Canonical manual editor order: test instructions (including any inline
 // independent/PE checks), optional additional evidence, TC completion, then
 // each linked WCR observation with its own immediately adjacent decision.
 // Reuse existing DOM nodes to preserve registered handlers and current inputs.
 // Inserting after the reports section (even when hidden) also works when a
 // test case has no additional reports or no related WCRs.
 reportSection.after(completion, related, inline);
 renderManualList();
}
// p9: one procedure owns its evidence, target, read-only validation and interpretation.
// Indices are positions in the canonical test-case catalog, *not* search matches
// in prose (which previously mapped network/pipe checks to the wrong step).
const tcStepAssignments={
 'TC-CF-001':{secrets:0},'TC-LS-001':{acl:4},
 'TC-FS-001':{acl:2},'TC-RG-001':{registry:3},
 'TC-SV-001':{service:1,service_acl:1,acl:2},
 'TC-TS-001':{task:1},'TC-PB-001':{acl:2,service:0,service_acl:0},
 'TC-DL-001':{acl:1},'TC-AR-003':{acl:2},
 'TC-NW-001':{network:3},'TC-IP-001':{network:2,pipe:1},
 'TC-IP-002':{pipe:2},'TC-UP-003':{acl:1}
};
const tcStageOverrides={
 'TC-FS-001':['Review collected evidence','Prioritize application locations','Inspect exact permissions','Correlate security impact'],
 'TC-RG-001':['Review registry evidence','Find the current key','Inspect sensitive settings','Validate registry permissions'],
 'TC-SV-001':['Review recorded services','Verify service identity','Inspect file and directory access','Validate privilege-boundary impact'],
 'TC-NW-001':['Review network evidence','Prioritize exposed listeners','Identify localhost services','Validate live process ownership','Confirm protocol','Test access controls'],
 'TC-IP-001':['Start relevant components','Discover named pipes','Discover localhost endpoints','Validate IPC authorization'],
 'TC-CF-001':['Review configuration artifacts','Locate relevant files','Inspect configuration safely','Validate potential secrets'],
 'TC-PE-001':['Review PE evidence','Prioritize mitigation gaps','Run independent DUMPBIN checks','Preserve external evidence','Optional second opinion','Interpret CFG flags','Determine reportability'],
 'TC-LS-001':['Review storage evidence','Inspect text indicators','Inspect database schema','Inspect registry state','Validate storage permissions'],
 'TC-PB-001':['Identify privilege-boundary target','Establish standard-user context','Inspect target permissions','Validate privileged consumption']
};
function tcSplitProcedure(body){
 const value=String(body||'').trim();
 if(!value)return [];
 // Historical application-level guidance has inline numbered instructions.
 // Only split at a number followed by punctuation and a space.
 const pieces=value.split(/(?=(?:^|\s)\d{1,2}[.)]\s+)/m)
  .map(x=>x.trim()).filter(Boolean);
 if(pieces.length>1&&pieces.every(x=>/^\d{1,2}[.)]\s/.test(x)))return pieces;
 const lines=value.split(/(?=^\s*\d{1,2}[.)]\s+)/m).map(x=>x.trim()).filter(Boolean);
 return lines.length&&lines.every(x=>/^\d{1,2}[.)]\s/.test(x))?lines:[value];
}
function tcStepLabel(id,index,wording){
 const override=tcStageOverrides[id]?.[index];if(override)return override;
 const phrase=String(wording||'').replace(/^\d+[.)]\s*/, '').toLowerCase();
 if(/^(open|review|read|identify|prioritize|record)/.test(phrase))return 'Review evidence';
 if(/^(select|locate|navigate|launch|start|confirm)/.test(phrase))return 'Identify or select target';
 if(/^(use|validate|inspect|test|run|reproduce|attach|trigger|exercise)/.test(phrase))return 'Perform validation';
 if(/^(determine|correlate|compare|treat|document|capture|report)/.test(phrase))return 'Interpret and document';
 return 'Manual testing';
}
function tcStepReports(wording,available){
 const wanted=new Set(String(wording||'').match(/[A-Za-z][A-Za-z0-9_-]{0,110}\.(?:txt|md|html)\b/gi)||[]);
 return available.filter(name=>[...wanted].some(x=>x.toLowerCase()===name.toLowerCase()));
}
function tcProcedureStep(check,steps,caseId){
 const index=tcStepAssignments[caseId]?.[check.kind];
 return Number.isInteger(index)&&index>=0&&index<steps.length?index:-1;
}
function tcCheckTarget(check){
 if(!check)return null;
 const target=String(check.target||'');
 const file=check.kind==='acl';
 const slash=Math.max(target.lastIndexOf('\\'),target.lastIndexOf('/'));
 const parent=file&&slash>=2?(slash===2?target.slice(0,3):target.slice(0,slash)):'';
 return {identity:target, parent:parent&&parent!==target?parent:'',source:check.source||'Unavailable'};
}
function tcResultView(data,check){
 const box=el('div',undefined,'tc-inline-result');
 const status=data.status||'INCONCLUSIVE';
 box.appendChild(el('strong',`${status} — ${data.title||check.title}`));
 const recommendation={INCONCLUSIVE:'The live check could not establish a result. Expand Technical Details to inspect the command and error; run manually if necessary.',
  NOT_PRESENT:'The recorded object is absent or its identity has changed; do not assume the old PID or ACL is current.',
  UNAVAILABLE:'The required tool or supporting environment is unavailable. Continue with the manual procedure.',
  OBSERVED:check?.kind==='network'?'Current sockets were observed for a matching live process. Confirm firewall reachability and application authorization separately; a listener alone is not a vulnerability.':'Read-only metadata was collected; this is not a vulnerability verdict and does not prove standard-user access.'}[status];
 if(recommendation)box.appendChild(el('p',recommendation,'hint'));
 if(status==='UNAVAILABLE'){const tools=el('button','Review optional tools →','button subtle');tools.type='button';tools.addEventListener('click',()=>go('tools'));box.appendChild(tools);}
 if(status==='INCONCLUSIVE'||status==='UNAVAILABLE'){
  const diagnostic=String(data.output||'').split(/\r?\n/).find(line=>/error|fail|unavailable|exception|access denied|could not|cannot find|timed out/i.test(line));
  if(diagnostic)box.appendChild(el('p',`Diagnostic: ${diagnostic.slice(0,260)}`,'hint'));
 }
 const info=el('div',undefined,'tc-result-context');
 const target=tcCheckTarget(check);
 for(const [label,value] of [['Observed target',data.target||target?.identity],['Parent directory',data.parent||target?.parent],['Evidence source',data.source||check.source]]){
  if(!value)continue;
  const row=el('div');row.appendChild(el('strong',label+': '));row.appendChild(el('span',value));info.appendChild(row);
 }
 box.appendChild(info);
 box.appendChild(el('p',data.interpretation||'Review these observations using the manual procedure.','hint'));
 box.appendChild(el('p',check?.kind==='network'?'The test case remains unchanged. Network listener ownership does not establish reachability or unauthorized access.':'The selected test case remains unchanged. A read-only check does not establish effective standard-user access or a finding.','hint'));
 const detail=el('details',undefined,'tc-technical');detail.appendChild(el('summary','Raw output and executed command'));
 detail.appendChild(el('pre',data.output||'No output returned.','manual-report-content'));
 if(data.command)detail.appendChild(el('pre',data.command,'manual-report-content'));
 box.appendChild(detail);return box;
}
// Optional, ephemeral deduplication of stable read-only observations across
// related TCs. Never persisted, never treated as a pass, and always rerunnable.
// Network/PID, pipe, and secrets checks are intentionally excluded from reuse.
const tcSessionObservations=new Map();
function tcObservationKey(assessment,check){
 if(!check||!['acl','service','service_acl','registry'].includes(check.kind))return '';
 return JSON.stringify([assessment,check.kind,String(check.target||'').toLowerCase()]);
}
const tcSelectedTargetMemory=new Map();
function renderProcedureChecks(checks,caseId,notice=''){
 const area=$('manualGuidance').querySelector('.tc-procedure-steps');if(!area)return;
 const steps=Array.from(area.querySelectorAll('.tc-procedure-step'));
 // Clear hosts when refreshed, but never create a detached second workflow.
 for(const step of steps){
  const host=step.querySelector('.tc-step-actions');
  if(host&&caseId!=='TC-PE-001')host.replaceChildren();
 }
 const fallback=area.querySelector('.tc-step-fallback');if(fallback)fallback.replaceChildren();
 const groups=new Map();
 for(const check of checks){
  if(caseId==='TC-CF-001'&&check.kind==='secrets')continue;
  const i=tcProcedureStep(check,steps,caseId),key=i>=0?String(i):'other';
  if(!groups.has(key))groups.set(key,[]);groups.get(key).push(check);
 }
 for(const [step,group] of groups){
  const host=step==='other'?fallback:steps[Number(step)]?.querySelector('.tc-step-actions');
  if(!host)continue;
  const wrap=el('div',undefined,'tc-inline-check');
  wrap.appendChild(el('strong',step==='other'?'Additional evidence-backed validation (review placement)':'Select a verified target for this procedure step'));
  const pick=el('select');pick.setAttribute('aria-label',`Select verified target for ${caseId}`);
  for(const check of group){
   const option=el('option',`${check.title} — ${check.target} [${check.source}]`);
   option.value=check.id;pick.appendChild(option);
  }
  const summary=el('div',undefined,'tc-check-context');
  const memoryKey=JSON.stringify([state.assessment,caseId,step]);
  const previousChoice=tcSelectedTargetMemory.get(memoryKey);
  if(group.some(x=>x.id===previousChoice))pick.value=previousChoice;
  const chosen=()=>group.find(x=>x.id===pick.value);
  const showContext=()=>{
   const check=chosen(),target=tcCheckTarget(check);summary.replaceChildren();
   if(!check)return;
   const context=el('div');context.appendChild(el('strong','Selected target: '));context.appendChild(el('span',target.identity));summary.appendChild(context);
   if(target.parent){const row=el('div');row.appendChild(el('strong','Parent: '));row.appendChild(el('span',target.parent));summary.appendChild(row);}
   const source=el('div');source.appendChild(el('strong','Source report: '));source.appendChild(el('span',target.source));summary.appendChild(source);
   summary.appendChild(el('p',check.detail||'Confirm this target belongs to the assessed client before testing.','hint'));
  };
  const evidenceOnly=group.every(x=>x.kind==='secrets');
  const run=el('button',evidenceOnly?'Review Redacted Indicator Locations':'Run Read-Only Check on Selected Target','button outline');run.type='button';
  const result=el('div',undefined,'tc-step-result');
  const showPrior=()=>{
   const key=tcObservationKey(state.assessment,chosen());
   const prior=key&&tcSessionObservations.get(key);
   if(!prior)return;
   const hint=el('p',`Previously inspected in this browser session at ${prior.time}. This is not a fresh verification and does not complete this TC. Re-run if current access may have changed.`,'hint');
   result.replaceChildren(hint,tcResultView(prior.data,chosen()));
  };
  run.addEventListener('click',async()=>{
   const assessment=state.assessment,id=pick.value,check=chosen();
   if(state.selectedManual?.id!==caseId||!check)return;
   run.disabled=true;result.replaceChildren(el('p','Running only the selected check…','hint'));
   try{
    const response=await request('/api/manual-checks/run',{method:'POST',body:{assessment,case_id:caseId,check_id:id,confirmed:true}});
    if(state.assessment!==assessment||state.selectedManual?.id!==caseId||id!==pick.value||!wrap.isConnected)return;
    result.replaceChildren(tcResultView(response.data,check));
    const key=tcObservationKey(assessment,check);
    if(key){
     if(tcSessionObservations.size>=24)tcSessionObservations.delete(tcSessionObservations.keys().next().value);
     tcSessionObservations.set(key,{data:response.data,time:new Date().toLocaleTimeString()});
    }
   }catch(e){if(wrap.isConnected){result.replaceChildren(el('p','Check unavailable: '+e.message+'. Manual testing is still required.','hint'));if(/tool|module|executable|not found|unavailable/i.test(e.message)){const tool=el('button','Open Tool Readiness →','button subtle');tool.type='button';tool.addEventListener('click',()=>go('tools'));result.appendChild(tool);}}}
   finally{if(wrap.isConnected)run.disabled=state.assessment!==assessment||state.selectedManual?.id!==caseId;}
  });
  pick.addEventListener('change',()=>{tcSelectedTargetMemory.set(memoryKey,pick.value);showContext();result.replaceChildren();showPrior();});
  // p18: Evidence-first. Do not require a live privileged check just to view
  // previously collected assessment data. Show a bounded source excerpt and
  // retain an explicit read-only recheck for changed or missing evidence.
  const stored=el('div',undefined,'tc-stored-evidence');
  let evidenceSerial=0;
  const showStored=async()=>{
    const id=++evidenceSerial,check=chosen();stored.replaceChildren();
    if(!check||!/^[a-z0-9_-]+\.(txt|md)$/i.test(String(check.source||''))){
      stored.appendChild(el('p','No directly linked persisted report is available for this selected target. Use the optional read-only check if necessary.','hint'));return;
    }
    stored.appendChild(el('p','Loading collected evidence…','hint'));
    try{
      const response=await request('/api/target-evidence?'+params({assessment:state.assessment,report:check.source,target:check.target}));
      if(id!==evidenceSerial||!wrap.isConnected||state.selectedManual?.id!==caseId)return;
      stored.replaceChildren();
      if(!response.found){stored.appendChild(el('p','No matching collected evidence was located. A live recheck may be useful.','hint'));return;}
      stored.appendChild(el('strong','Collected evidence · '+(response.source||check.source)));
      if(response.storage_acl){
       stored.appendChild(el('p','Selected storage record only. ACL data is historical and does not prove effective standard-user access.','hint'));
       for(const [label,acl] of [['File',response.storage_acl.file],['Parent directory',response.storage_acl.parent]]){
        const section=el('section',undefined,'p18-acl-metadata');
        section.appendChild(el('strong',label+' ACL — '+(acl?.status||'NOT COLLECTED')));
        section.appendChild(el('p','Path: '+(acl?.path||'Unknown')+' · Owner: '+(acl?.owner||'Unknown'),'hint'));
        if(acl?.entries?.length){
         section.appendChild(makeTable(['Principal','Rights','Type','Inherited'],
          acl.entries.map(e=>[e.principal,e.rights,e.type,e.inherited])));
         if(acl.broad_write_indicated){
          const warning=el('section',undefined,'p18-warning');
          warning.appendChild(el('strong','⚠ Potentially Broad Modification Permissions'));
          warning.appendChild(el('p','Verify effective lower-trust access and privileged consumption; this is not a confirmed vulnerability.'));
          section.appendChild(warning);
         }
        }else section.appendChild(el('p','No collected ACE details for this object. Use the optional read-only ACL check; results are live, not the saved assessment snapshot.','hint'));
        stored.appendChild(section);
       }
      }
      if(response.acl?.entries?.length){
       const acl=response.acl;
       const header=el('div',undefined,'p18-acl-metadata');
       header.appendChild(el('p','Owner: '+(acl.owner||'Unknown')+' · '+(acl.component||'Application file / directory')));
       const badge=el('span',acl.status||'COLLECTED','p18-evidence-status');header.appendChild(badge);stored.appendChild(header);
       stored.appendChild(makeTable(['Principal','Rights','Type','Inherited'],
          acl.entries.map(e=>[e.principal||'Unknown',e.rights||'Unknown',e.type||'Unknown',e.inherited||'Unknown'])));
       if(acl.broad_write_indicated){
        const warn=el('section',undefined,'p18-warning');
        warn.appendChild(el('strong','⚠ Potentially Broad Modification Permissions'));
        warn.appendChild(el('p','Broad-write ACEs were identified. Validate effective access from a lower-trust account and whether a privileged component consumes this file or directory. A suspicious ACL is not a confirmed vulnerability.'));
        stored.appendChild(warn);
       }else stored.appendChild(el('p','No broad-write ACE was identified by the stored report. Effective permissions are not established by this heuristic.','hint'));
      }
      if(Array.isArray(response.network_endpoints)&&response.network_endpoints.length){
       stored.appendChild(el('p','Historical collected socket observations — not a live verification. PID and ports may have changed.','hint'));
       stored.appendChild(makeTable(['Protocol','Local endpoint','State','Bind scope','User'],
        response.network_endpoints.map(e=>[e.protocol||'—',e.endpoint||'—',e.state||'—',e.scope||'—',e.user||'—'])));
       if(response.network_endpoints.some(e=>/wildcard|all interfaces/i.test(e.scope||''))){
        const warning=el('section',undefined,'p18-warning');
        warning.appendChild(el('strong','⚠ Wildcard-bound endpoint — review intended exposure'));
        warning.appendChild(el('p','Verify interface/firewall scope, authentication, and authorization from the appropriate network context. A wildcard listener alone is not a vulnerability.'));
        stored.appendChild(warning);
       }
      }else if(!response.storage_acl){
       const excerpt=el('pre',response.excerpt,'tc-collected-excerpt');stored.appendChild(excerpt);
      }
      const detail=el('details');detail.appendChild(el('summary','Evidence provenance and interpretation'));
      detail.appendChild(el('p','Stored report excerpt, not a current effective-access test. Validate lower-trust token permissions and privileged consumption before reporting.','hint'));stored.appendChild(detail);
      if(response.truncated)stored.appendChild(el('p','Excerpt truncated; open the source report for full context.','hint'));
    }catch(e){if(id===evidenceSerial&&wrap.isConnected)stored.replaceChildren(el('p','Stored evidence unavailable: '+e.message,'hint'));}
  };
  pick.addEventListener('change',()=>{
    tcSelectedTargetMemory.set(memoryKey,pick.value);showContext();result.replaceChildren();showPrior();showStored();
  });
  run.textContent=evidenceOnly?'Review Redacted Indicator Locations':'Refresh / Collect ACL or Metadata (read-only)';
  wrap.appendChild(pick);wrap.appendChild(summary);wrap.appendChild(stored);
  const liveSection=el('details',undefined,'tc-live-recheck');
  liveSection.appendChild(el('summary','Optional live read-only recheck'));
  liveSection.appendChild(run);liveSection.appendChild(result);
  wrap.appendChild(liveSection);host.appendChild(wrap);
  showContext();showPrior();showStored();
 }
 if(!checks.length&&fallback&&caseId!=='TC-PE-001'){fallback.appendChild(el('p','No executable read-only checks were derived from verified evidence for this case. Follow the manual procedure; no check was performed or passed.','hint'));}
 if(notice&&checks.length&&fallback)fallback.appendChild(el('p','WCA executes checks with its own security context (typically Administrator). Successful access by WCA does not establish access by a standard user. Validate with an actual standard-user account before reporting unauthorized access.','hint'));
}
let tcAvailableChecks=[];
async function loadManualChecks(caseId,detailSerial){
 const assessment=state.assessment;
 const current=()=>assessment===state.assessment&&state.selectedManual?.id===caseId&&detailSerial===manualDetailSerial;
 const choice=$('tcCheckSelect');choice.replaceChildren();
 $('tcCheckRun').disabled=true;$('tcCheckResults').hidden=true;
 set('tcChecksHint','Loading evidence-backed checks…');
 try{
  const result=await request('/api/manual-checks?'+params({assessment,case_id:caseId}));
  if(!current())return;
  tcAvailableChecks=result.data?.checks||[];
  for(const check of tcAvailableChecks){
   const option=el('option',`${check.title} — ${check.source}`);option.value=check.id;choice.appendChild(option);
  }
  $('tcCheckRun').disabled=!tcAvailableChecks.length;
  renderProcedureChecks(tcAvailableChecks,caseId,result.data?.notice||'');
  set('tcChecksHint',tcAvailableChecks.length?`${tcAvailableChecks.length} evidence-backed validation option(s); none run automatically.`:
    result.data.none||'No eligible read-only check. Continue manually.');
 }catch(e){if(current()){
  $('tcCheckRun').disabled=true;set('tcChecksHint','Read-only checks unavailable: '+e.message);
  renderProcedureChecks([],caseId);
 }}
}
$('tcCheckSelect').addEventListener('change',()=>{$('tcCheckResults').hidden=true;});
$('tcCheckRun').addEventListener('click',async()=>{
 const caseId=state.selectedManual?.id,assessment=state.assessment;
 const id=$('tcCheckSelect').value;
 if(!caseId||!tcAvailableChecks.some(x=>x.id===id))return;
 $('tcCheckRun').disabled=true;set('tcChecksHint','Running explicitly selected read-only check…');
 try{
  const data=(await request('/api/manual-checks/run',{method:'POST',body:{assessment,case_id:caseId,check_id:id,confirmed:true}})).data;
  if(assessment!==state.assessment||caseId!==state.selectedManual?.id||id!==$('tcCheckSelect').value)return;
  $('tcCheckResults').hidden=false;
  set('tcCheckResultStatus',`${data.status} · ${data.title} · Source: ${data.source} · This did not complete the manual test.`);
  set('tcCheckResultText',data.output||'No output was returned.');
  set('tcCheckCommand',data.command||'');
  set('tcCheckInterpretation',data.interpretation||'Review findings in application context.');
  set('tcChecksHint','Check completed. Review the output and finish the manual procedure independently. Results were not saved to assessment evidence.');
 }catch(e){if(assessment===state.assessment&&caseId===state.selectedManual?.id)set('tcChecksHint','Read-only check unavailable: '+e.message);}
 finally{if(assessment===state.assessment&&caseId===state.selectedManual?.id)$('tcCheckRun').disabled=false;}
});
// TC-PE-001: optional, read-only PE verification. All paths come from the
// integrity-verified binary_security_review.txt route, never from the browser
// filesystem or from an arbitrary unverified local path supplied by a page.
let peVerificationRows=[];
const peAbsPath = value => /^(?:[A-Za-z]:\\|\\\\)[^"<>|\r\n]+$/.test(value)&&!/[%!^]/.test(value);
const peCmdQuote = value => '"'+value+'"';
const pePSQuote = value => "'"+value.replace(/'/g,"''")+"'";
function parsePeVerificationReport(content){
 const rows=[];let current=null;
 for(const line of String(content).split(/\r?\n/)){
  const m=line.match(/^\[PE-(\d{4,})\]\s+(.+)$/);
  if(m){current={id:'PE-'+m[1],path:m[2].trim(),aslr:'',dep:'',cfg:'',error:''};rows.push(current);continue;}
  if(!current)continue;
  const field=line.match(/^\s+(ASLR|DEP\/NX|CFG|Error)\s*:\s*(.*)$/);
  if(field){const key={'ASLR':'aslr','DEP/NX':'dep','CFG':'cfg','Error':'error'}[field[1]];current[key]=field[2].trim();}
 }
 const seen=new Set();return rows.filter(row=>{
  if(!peAbsPath(row.path)||seen.has(row.path.toLowerCase()))return false;
  seen.add(row.path.toLowerCase());return true;
 });
}
function peChosen(){return peVerificationRows.filter(row=>$('peFileScope').value!=='flagged'||row.cfg==='False'||row.aslr==='False'||row.dep==='False');}
function peSelected(){return peChosen().find(row=>row.id===$('peSingleTarget').value);}
function peSetMessage(message){set('peVerificationMessage',message);}
function renderPeSelection(){
 const rows=peChosen(),select=$('peSingleTarget'),old=select.value;select.replaceChildren();
 for(const row of rows){const opt=el('option',`${row.id} · ${row.path} · CFG header: ${row.cfg||'unknown'}`);opt.value=row.id;select.appendChild(opt);}
 if(rows.some(row=>row.id===old))select.value=old;
 const ready=rows.length>0;for(const id of ['peDownloadList','peCopyPaths','peCopySingle','peCopyBatch','peCopyPESecurity'])$(id).disabled=!ready;
 const basenames=rows.map(row=>row.path.split('\\').pop().toLowerCase());
 const collisions=basenames.length-new Set(basenames).size;
 if(collisions)$('peCopyBatch').disabled=true;
 set('peVerificationStatus',`${peVerificationRows.length} PE paths available from the verified report · ${rows.length} selected. CFG header flags are NOT independent CFG instrumentation proof.`);
 if(collisions)peSetMessage(`${collisions} duplicate basename(s): batch output would overwrite evidence. Use individual DUMPBIN commands instead.`);
 else if(!ready)peSetMessage('No matching binaries for this filter. Switch to All analyzed PE entries.');
 else peSetMessage('');
}
async function loadPeVerification(caseId){
 const assessment=state.assessment;
 peVerificationRows=[];$('peValidationPanel').hidden=false;peSetMessage('');
 $('peAutoRun').disabled=true;$('peAutoResults').hidden=true;set('peAutoStatus','Preparing current assessment PE paths…');
 set('peVerificationStatus','Reading integrity-verified binary_security_review.txt…');
 for(const id of ['peDownloadList','peCopyPaths','peCopySingle','peCopyBatch','peCopyPESecurity'])$(id).disabled=true;
 try{
  // This local, token-protected route reads the VERIFIED report and resolves
  // WCA's known %USERPROFILE% placeholder for transient manual commands only.
  // Do not persist real tester profile paths in assessment reports or review state.
  const result=await request('/api/pe-verification?'+params({assessment}));
  if(state.assessment!==assessment||state.selectedManual?.id!==caseId)return;
  peVerificationRows=(result.rows||[]).filter(row=>peAbsPath(row.path));
  if(!peVerificationRows.length)throw new Error('No usable local PE paths could be resolved from the verified report. Check PE coverage and the Windows USERPROFILE environment.');
  renderPeSelection();
  peAutoSetup();
  if(result.omitted)peSetMessage(`${result.omitted} PE entries skipped (duplicate, unresolved or unsafe paths). Working paths appear only in this local browser session.`);
  // Display a previously configured LOCAL module path; no module is imported.
  try{
   const config=await request('/api/tool-configuration');
   if(state.assessment===assessment&&state.selectedManual?.id===caseId){
    const module=(config.tools||[]).find(tool=>tool.name==='PESecurity');
    // Use the existing explicit override, otherwise the auto-detected local
    // module. The old C:\Tools example must not overwrite a real installed path.
    if(module?.configured_path||module?.detected_path)$('peModulePath').value=module.configured_path||module.detected_path;
   }
  }catch(_){/* Optional guidance: a missing tool configuration does not block PE review. */}
 }catch(e){if(state.assessment===assessment&&state.selectedManual?.id===caseId){set('peVerificationStatus','Unable to prepare PE verification.');set('peAutoStatus','Unable to load current assessment PE paths.');peSetMessage(e.message);}}
}
function pePathsText(){return peChosen().map(row=>row.path).join('\r\n')+'\r\n';}
async function peCopy(value){
 try{await navigator.clipboard.writeText(value);peSetMessage('Copied. Paste in the appropriate tester-controlled location.');}
 catch(_){peSetMessage('Clipboard unavailable; use the list download or copy the example commands from the documentation.');}
}
function peCommand(single=false){
 const output=$('peOutputFolder').value.trim().replace(/[\\]+$/,'');
 if(!peAbsPath(output))throw new Error('Enter an existing absolute Windows evidence folder without %, ! or ^.');
 if(single){
  const row=peSelected();if(!row||!peAbsPath(row.path))throw new Error('Select a PE with a valid Windows path.');
  const basename=row.path.split('\\').pop();
  const evidence=`${output}\\TC-PE-001-${row.id}-${basename}_dump.txt`;
  return `dumpbin /headers /loadconfig ${peCmdQuote(row.path)} /OUT:${peCmdQuote(evidence)}`;
 }
 const list=$('peFileListPath').value.trim();
 if(!peAbsPath(list)||!list.toLowerCase().endsWith('.txt'))throw new Error('Enter the full Windows path of the saved .txt PE file list.');
 // A CMD prompt uses %I (a .bat file uses %%I). No invocation is automatic.
 return `FOR /F "usebackq delims=" %I IN (${peCmdQuote(list)}) DO dumpbin /headers /loadconfig "%~I" /OUT:${peCmdQuote(output+'\\%~nxI_dump.txt')}`;
}
$('peFileScope').addEventListener('change',renderPeSelection);
$('peDownloadList').addEventListener('click',()=>{
 const rows=peChosen();if(!rows.length)return;
 const blob=new Blob([pePathsText()],{type:'text/plain;charset=utf-8'}),url=URL.createObjectURL(blob);
 const a=document.createElement('a');a.href=url;a.download='TC-PE-001-files.txt';a.hidden=true;document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(url);
 peSetMessage('Downloaded TC-PE-001-files.txt. Enter its actual full saved path above before copying the batch command.');
});
$('peCopyPaths').addEventListener('click',()=>{if(peChosen().length)peCopy(pePathsText());});
$('peCopySingle').addEventListener('click',()=>{try{peCopy(peCommand(true));}catch(e){peSetMessage(e.message);}});
$('peCopyBatch').addEventListener('click',()=>{try{peCopy(peCommand());}catch(e){peSetMessage(e.message);}});
$('peCopyPESecurity').addEventListener('click',()=>{
 const row=peSelected(),module=$('peModulePath').value.trim();
 if(!row||!peAbsPath(row.path)||!peAbsPath(module)||!module.toLowerCase().endsWith('.psm1')){peSetMessage('Choose a Windows PE path and the full PESecurity .psm1 module location.');return;}
 peCopy(`Import-Module -Name ${pePSQuote(module)} -ErrorAction Stop; Get-PESecurity -File ${pePSQuote(row.path)} | Format-List *`);
});

// v2.2.3-p4: one-action, read-only DUMPBIN execution and interpretation.
// Only the authenticated local Python backend can run the configured tool.
let peAutoEvidenceFolder='',peAutoJobId='';
function peAutoSetup(){
 const select=$('peAutoSingleTarget');select.replaceChildren();
 for(const row of peVerificationRows){
  if(row.error && row.error!=='None')continue;
  const base=row.path.split('\\').pop();
  const option=el('option',`${row.id} · ${base}`);option.value=row.id;select.appendChild(option);
 }
 $('peAutoRun').disabled=!peVerificationRows.length;
 set('peAutoStatus',peVerificationRows.length
     ? `${peVerificationRows.length} extracted PE entries loaded. The original installer PE (often PE-0001) is outside this extracted-payload batch. Choose the scope and run independent CFG metadata verification.`
     : 'No PE entries available from this assessment.');
 peAutoScopeChanged();
}
function peAutoScopeChanged(){
 $('peAutoSingleWrap').hidden=$('peAutoScope').value!=='single';
}
function peAutoRender(job){
 const rows=job.rows||[];
 $('peAutoResults').hidden=!rows.length;
 const headers=['PE file','Guard header','CF instrumented','FID table','Metadata result','What it means'];
 const flag=value=>value===true?'PRESENT':value===false?'ABSENT':'UNKNOWN';
 const table=makeTable(headers,rows.map(row=>[`${row.id} · ${row.name}`,flag(row.guard),
  flag(row.instrumented),flag(row.fid),({VERIFIED_METADATA:'METADATA VERIFIED',REVIEW_REQUIRED:'REVIEW REQUIRED',INCONCLUSIVE:'INCONCLUSIVE'}[row.result]||row.result),row.reason]));
 $('peAutoResultsTable').replaceChildren(table);
 const reviewed=rows.filter(x=>x.result==='REVIEW_REQUIRED').length;
 const errors=rows.filter(x=>x.result==='INCONCLUSIVE'||x.error||!x.raw_file).length;
 const verified=rows.filter(x=>x.result==='VERIFIED_METADATA').length;
 set('peAutoEvidence',`${rows.length} PE files analyzed · ${reviewed} require CFG applicability review · ${verified} metadata verified · ${errors} incomplete/failed. Full details and raw output are available using the evidence folder and ZIP controls.`);
 peAutoEvidenceFolder=job.folder||'';peAutoJobId=job.id||'';
 $('peAutoDownload').disabled=!job.rows?.some(x=>x.raw_file)||job.state==='RUNNING';
 $('peAutoCopyFolder').disabled=!peAutoEvidenceFolder;
}
$('peAutoScope').addEventListener('change',peAutoScopeChanged);
$('peAutoDownload').addEventListener('click',async()=>{
 if(!state.assessment||!peAutoJobId)return;
 const btn=$('peAutoDownload');btn.disabled=true;
 try{
  const response=await fetch('/api/pe-dumpbin/download?'+params({assessment:state.assessment,id:peAutoJobId}),
   {headers:{'X-WCA-Token':token},cache:'no-store'});
  if(!response.ok){const err=await response.json();throw new Error(err.message||'Unable to package evidence.');}
  const blob=await response.blob(),url=URL.createObjectURL(blob),a=document.createElement('a');
  a.href=url;a.download=(state.assessment.split(/[\\/]/).filter(Boolean).pop()||'WCA')+'-TC-PE-001-DUMPBIN.zip';
  document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(url);
  set('peAutoStatus','DUMPBIN ZIP packaged by WCA from the completed job. Verify the downloaded archive before sharing.');
 }catch(e){set('peAutoStatus','DUMPBIN package unavailable: '+e.message);}
 finally{btn.disabled=false;}
});
$('peAutoCopyFolder').addEventListener('click',()=>{if(peAutoEvidenceFolder)peCopy(peAutoEvidenceFolder);});
$('peAutoRun').addEventListener('click',async()=>{
 if(!state.assessment||!peVerificationRows.length)return;
 const assessment=state.assessment,caseId=state.selectedManual?.id;
 const scope=$('peAutoScope').value,id=$('peAutoSingleTarget').value;
 $('peAutoRun').disabled=true;$('peAutoResults').hidden=true;peAutoEvidenceFolder='';peAutoJobId='';$('peAutoDownload').disabled=true;
 set('peAutoStatus','Starting tester-requested DUMPBIN verification…');
 try{
  const started=await request('/api/pe-dumpbin/start',{method:'POST',body:{
   assessment,scope,pe_id:id,confirmed:true}});
  let job=started.job;
  for(let i=0;i<1500&&job.state==='RUNNING';i++){
   if(state.assessment!==assessment||state.selectedManual?.id!==caseId)return;
   set('peAutoStatus',`DUMPBIN verification: ${job.done}/${job.total} files processed…`);
   await new Promise(resolve=>setTimeout(resolve,1200));
   const status=await request('/api/pe-dumpbin/status?'+params({assessment,id:job.id}));
   job=status.job;
  }
  if(state.assessment!==assessment||state.selectedManual?.id!==caseId)return;
  peAutoRender(job);
  if(job.state==='COMPLETED')set('peAutoStatus',`Finished: ${job.done}/${job.total} files. Review the table and independent evidence folder; findings are not created automatically.`);
  else set('peAutoStatus',job.error||'Verification was interrupted or could not complete.');
 }catch(err){if(state.assessment===assessment)set('peAutoStatus','Could not run DUMPBIN: '+err.message);}
 finally{if(state.assessment===assessment)$('peAutoRun').disabled=!peVerificationRows.length;}
});

// p14: conditional, evidence-grounded service-path review; no generic root ACL probes.
async function loadUnquotedServiceCallout(caseId,serial){
 const assessment=state.assessment;
 try{
  const resp=await request('/api/report?'+params({assessment,name:'services_review.txt'}));
  if(assessment!==state.assessment||serial!==manualDetailSerial||state.selectedManual?.id!==caseId)return;
  const body=String(resp.content||'');
  const match=body.match(/UNQUOTED SERVICE PATH CANDIDATES\s*[-=]*([\s\S]*?)(?:WHAT TO REVIEW|$)/i);
  if(!match||/Not applicable:\s*command is quoted or executable path contains no spaces/i.test(match[1]))return;
  const callout=el('div',undefined,'service-path-callout');
  callout.appendChild(el('strong','POSSIBLE UNQUOTED SERVICE PATH — validate, not a finding'));
  callout.appendChild(el('p','An installed target service has an ambiguous unquoted executable path. Verify the exact service command, execution account and candidate creation rights from a standard-user context. Protected root-directory candidates are not automatically suspicious.','hint'));
  callout.appendChild(el('pre',match[1].trim().slice(0,4500),'manual-report-content'));
  const guide=$('manualGuidance').querySelector('.tc-procedure-step');
  if(guide)guide.appendChild(callout);
 }catch(_e){/* No supported evidence means no warning; manual procedure remains visible. */}
}

// p15: automatic full original-value inspection from verified local evidence.
async function loadSecretIndicatorPanel(caseId,serial){
 const step=$('manualGuidance').querySelector('.tc-procedure-step');if(!step)return;
 const host=el('div',undefined,'secret-inspector');host.appendChild(el('h3','Potential Secret Indicator Review'));
 host.appendChild(el('p','Selecting an indicator displays its original value and context in this local tester session. Nothing is added to reports or exported artifacts. Treat the panel as sensitive evidence.','hint'));
 const select=el('select');const counter=el('span','Loading indicators…','hint');
 const detail=el('div',undefined,'secret-inspector-detail');
 const actions=el('div',undefined,'secret-inspector-actions');
 const prev=el('button','← Previous','button outline'),next=el('button','Next →','button outline');
 const copyValue=el('button','Copy Value','button subtle'),copyPath=el('button','Copy File Path','button subtle');
 const openFile=el('button','Open File Location','button subtle'),hex=el('button','Copy Hex Inspection Command','button subtle');
 const viewSource=el('button','View Context','button subtle');
 actions.append(prev,next,copyValue,copyPath,openFile,viewSource,hex);
 host.append(select,counter,actions,detail);step.appendChild(host);
 const assessment=state.assessment;let current=null;let activeRequest=0;
 try{
  const response=await request('/api/secret-indicators?'+params({assessment}));
  if(assessment!==state.assessment||serial!==manualDetailSerial||state.selectedManual?.id!==caseId)return;
  const rows=response.indicators||[];select.replaceChildren();
  rows.forEach(row=>{const o=el('option',`${row.id} · ${row.confidence} · ${row.type} · ${row.file.split('\\').pop()}`);o.value=row.id;select.appendChild(o);});
  async function display(){
   const id=select.value,position=rows.findIndex(r=>r.id===id),row=rows[position],requestNumber=++activeRequest;
   current=null;prev.disabled=position<=0;next.disabled=position>=rows.length-1;
   for(const btn of [copyValue,copyPath,openFile,viewSource,hex])btn.disabled=true;
   counter.textContent=row?`${position+1} / ${rows.length} indicators · ${row.type} · ${row.confidence}`:'No indicators recorded.';
   if(!row){replace(detail,el('p','No secret indicators collected. This does not establish that none exist.','hint'));return;}
   replace(detail,el('p','Verifying assessment integrity and retrieving selected original context…','hint'));
   const response=await request('/api/secret-context',{method:'POST',body:{assessment,indicator:id}});
   if(assessment!==state.assessment||serial!==manualDetailSerial||select.value!==id||requestNumber!==activeRequest)return;
   const data=response.data;current=data;detail.replaceChildren();
   detail.appendChild(el('div',`${data.file} · ${data.line?'line '+data.line:data.offset||'offset unavailable'}`,'hint'));
   detail.appendChild(el('p',`Why flagged: ${data.reason||'Match requires manual validation.'}`,'hint'));
   detail.appendChild(el('p',`Validation: ${data.validation||'UNVALIDATED'}${data.algorithm?' · '+data.algorithm:''}${data.key_bits?' · '+data.key_bits+' bits':''}`,'hint'));
   if(data.public_fingerprint)detail.appendChild(el('p','Public key SHA-256: '+data.public_fingerprint,'hint'));
   detail.appendChild(el('h4','Original Value (tester-only)'));
   const original=el('pre',data.original_value||'[Original unavailable for this selected indicator]','manual-report-content secret-original');detail.appendChild(original);
   detail.appendChild(el('h4','Source Context'));
   const context=el('pre',data.context||'No context available','manual-report-content');detail.appendChild(context);
   detail.appendChild(el('p',data.status==='MANUAL'?'The original is outside verified extracted evidence; open it with your approved local tools.':'Displayed from verified assessment-owned evidence; no value is persisted by WCA.','hint'));
   copyValue.disabled=!data.original_value;copyPath.disabled=!data.source_path;openFile.disabled=!data.source_path;
   viewSource.disabled=!data.context;hex.disabled=!data.offset||!data.source_path;
  }
  const copy=async value=>{if(!value)return;try{await navigator.clipboard.writeText(value);notice('Copied to clipboard; handle sensitive evidence appropriately.');}catch(_){notice('Clipboard unavailable; select the value manually.',true);}};
  select.addEventListener('change',()=>display().catch(e=>{current=null;replace(detail,el('p',e.message,'hint'));}));
  prev.addEventListener('click',()=>{select.selectedIndex=Math.max(0,select.selectedIndex-1);select.dispatchEvent(new Event('change'));});
  next.addEventListener('click',()=>{select.selectedIndex=Math.min(rows.length-1,select.selectedIndex+1);select.dispatchEvent(new Event('change'));});
  copyValue.addEventListener('click',()=>copy(current?.original_value));
  copyPath.addEventListener('click',()=>copy(current?.source_path));
  viewSource.addEventListener('click',()=>detail.querySelectorAll('pre')[1]?.scrollIntoView({behavior:'smooth',block:'nearest'}));
  hex.addEventListener('click',()=>{if(!current?.source_path||!current?.offset)return;
   const offset=parseInt(current.offset,16);if(!Number.isFinite(offset))return;
   const source=String(current.source_path).replace(/'/g,"''");
   copy(`Format-Hex -LiteralPath '${source}' -Offset ${Math.max(0,offset-160)} -Count 320`);
  });
  openFile.addEventListener('click',async()=>{if(!current?.source_path)return;
   try{const result=await request('/api/secret-open-location',{method:'POST',body:{assessment,indicator:select.value}});notice(result.message||'Opened file location.');}
   catch(e){notice('Unable to open original file location: '+e.message,true);}
  });
  await display();
 }catch(e){if(assessment===state.assessment&&serial===manualDetailSerial)replace(detail,el('p','Indicator viewer unavailable: '+e.message,'hint'));}
}

// p14: a global comparison, independent of the active single-assessment workspace.
async function loadComparisonChoices(){
 try{
  const result=await request('/api/recent');const mode=$('compareMode').value;
  const options=(result.assessments||[]).filter(x=>x.mode===mode&&x.state==='COMPLETED');
  for(const id of ['compareBaseline','compareTarget']){
   const select=$(id),old=select.value;select.replaceChildren();
   options.forEach(item=>{const option=el('option',`${item.name} · ${item.mode}`);option.value=item.path;select.appendChild(option);});
   if(options.some(item=>item.path===old))select.value=old;
  }
  if(options.length>1&&!$('compareTarget').value)$('compareTarget').selectedIndex=1;
  if(options.length>1&&$('compareTarget').value===$('compareBaseline').value)$('compareTarget').selectedIndex=1;
  set('compareHint',options.length<2?'Open at least two completed assessments of this mode to compare.':'Selections must pass integrity verification before comparison.');
 }catch(e){set('compareHint','Recent assessments unavailable: '+e.message);}
}
$('compareMode').addEventListener('change',loadComparisonChoices);
$('compareRefresh').addEventListener('click',loadComparisonChoices);
$('compareRun').addEventListener('click',async()=>{
 const baseline=$('compareBaseline').value,comparison=$('compareTarget').value;
 if(!baseline||!comparison||baseline===comparison){set('compareHint','Choose two different completed assessments.');return;}
 $('compareRun').disabled=true;set('compareHint','Verifying integrity and comparing…');
 try{
  const result=await request('/api/compare-assessments',{method:'POST',body:{baseline,comparison}});const data=result.data;
  const holder=$('compareSections');holder.replaceChildren();$('compareResults').hidden=false;
  set('compareResultsNote',`${data.baseline} → ${data.comparison} · ${data.mode.toUpperCase()} · ${data.note}`);
  for(const section of data.sections){
   const group=el('details',undefined,'review-guide-section');group.open=section.reports.some(x=>x.new_total||x.removed_total);
   const totalNew=section.reports.reduce((n,r)=>n+(r.new_total||0),0);
   const totalOld=section.reports.reduce((n,r)=>n+(r.removed_total||0),0);
   const totalChanged=section.reports.reduce((n,r)=>n+(r.changed_total||0),0);
   group.appendChild(el('summary',`${section.category} · ${totalNew} new · ${totalChanged} changed · ${totalOld} no longer observed`));
   for(const report of section.reports){
    group.appendChild(el('h4',report.report));
    if(report.status!=='COMPARED'){group.appendChild(el('p',report.reason,'hint'));continue;}
    group.appendChild(el('p',`${report.new_total} new · ${report.changed_total||0} changed · ${report.removed_total} no longer observed · ${report.unchanged} unchanged${report.truncated?' · preview limited':''}`,'hint'));
    if(report.changed?.length)group.appendChild(el('pre',report.changed.map(v=>`~ ${v.before} → ${v.after}`).join('\n'),'manual-report-content'));
    if(report.new.length)group.appendChild(el('pre',report.new.map(v=>'+ '+v).join('\n'),'manual-report-content'));
    if(report.removed.length)group.appendChild(el('pre',report.removed.map(v=>'- '+v).join('\n'),'manual-report-content'));
   }
   holder.appendChild(group);
  }
  set('compareHint','Read-only comparison completed; no assessment evidence was changed.');
 }catch(e){set('compareHint','Comparison unavailable: '+e.message);notice(e,true);}
 finally{$('compareRun').disabled=false;}
});

['manualSearch','manualStatusFilter','manualCategoryFilter','manualGuidedFilter'].forEach(id=>$(id).addEventListener(id==='manualSearch'?'input':'change',renderManualList));
$('workflowRefresh').addEventListener('click',loadManualTests);
function nextOutstandingManualCase(currentId){
 const cases=queueActivities().filter(x=>x.type==='manual'&&!x.addressed&&x.id!==currentId);
 return cases[0]||null;
}
$('manualNext').addEventListener('click',()=>{
 const next=nextOutstandingManualCase(state.selectedManual?.id);
 if(!next){$('manualNext').hidden=true;return;}
 if(state.workspacePane==='queue')openQueueActivity(next).catch(e=>notice('Unable to open next case: '+e.message,true));
 else {const item=(state.manual?.items||[]).find(x=>x.id===next.id);if(item)editManual(item).catch(e=>notice(e,true));}
});
$('manualSave').addEventListener('click',async()=>{
 $('manualNext').hidden=true;
 if(!state.assessment||!state.selectedManual)return;
 const assessment=state.assessment,caseId=state.selectedManual.id;
  const submitted={fingerprint:state.selectedManual.fingerprint,status:$('manualStatus').value,
   evidence_reference:$('manualEvidence').value,notes:$('manualNotes').value,client_notes:$('manualClientNotes').value};
 const isCurrent=()=>assessment===state.assessment&&state.selectedManual?.id===caseId&&
  (state.workspacePane!=='queue'||state.activeQueue?.id===caseId);
 if($('manualLinkedReview').querySelector('.linked-wcr-card[data-unsaved="true"]')){
  set('manualSaveHint','An associated WCR has unsaved changes. Save its decision first so those notes are not lost.');return;
 }
 $('manualSave').disabled=true;
 try{
  const r=await request('/api/manual-tests',{method:'POST',body:{confirmed:true,assessment:state.assessment,
   case_id:caseId,...submitted}});
   // Do not request/rebuild the just-saved editor. Its inputs and procedure
   // remain valid, and rebuilding while the tester clicks another case has
   // caused intermittent Testing Queue navigation failures on Windows.
   if(isCurrent())state.selectedManual={...state.selectedManual,...submitted};
   await loadManualTests({restoreSelection:false});
   await refresh();
  if(isCurrent()){
   const fresh=(state.manual?.items||[]).find(x=>x.id===caseId);
    const outstanding=(fresh?.related_candidates||[]).filter(c=>!['VALIDATED','INFORMATIONAL','NOT APPLICABLE'].includes(c.status)||c.changed_evidence).length;
    set('manualSaveHint',outstanding?`Manual decision saved. ${outstanding} linked Guided Review candidate(s) still require review.`:(r.message||'Manual test status saved.'));
    const next=nextOutstandingManualCase(caseId);
    $('manualNext').hidden=!next;
    if(next)$('manualNext').textContent=`Open Next Outstanding Test Case (${next.id}) →`;
   }
 }catch(e){notice(e,true);}finally{if(isCurrent())$('manualSave').disabled=state.status?.framework_version!==bootstrap.version;}
});

let workspaceActiveEvidence='';
async function previewWorkspaceEvidence(name,anchor){
 if(!state.assessment)return notice('Open an assessment first.',true);
 showWorkspacePane('evidence');
 const pane=$('workspaceEvidencePane');
 if(workspaceActiveEvidence===name&&!pane.hidden){pane.hidden=true;workspaceActiveEvidence='';return;}
 if(anchor?.isConnected)anchor.appendChild(pane);
 workspaceActiveEvidence=name;pane.hidden=false;
 set('workspaceEvidenceTitle',name);set('workspaceEvidenceContent','Opening verified report…');
 const assessment=state.assessment;
 try{const r=await request('/api/report?'+params({assessment,name}));
  if(state.assessment===assessment&&workspaceActiveEvidence===name)set('workspaceEvidenceContent',r.content);}
 catch(e){if(state.assessment===assessment&&workspaceActiveEvidence===name)set('workspaceEvidenceContent','Report unavailable: '+e.message);}
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
for(const [name,label] of workspaceReports){
 const host=el('div',undefined,'workspace-evidence-entry');
 const b=el('button',label+' →','button outline');b.type='button';
 b.addEventListener('click',()=>previewWorkspaceEvidence(name,host));
 host.appendChild(b);$('workspaceEvidenceLinks').appendChild(host);
}
$('workspaceFullMethodology').addEventListener('click',()=>previewWorkspaceEvidence('attack_surface_test_plan.txt',$('workspaceFullMethodology').parentElement));
$('workflowCoverage').addEventListener('click',()=>previewWorkspaceEvidence('coverage_summary.txt',document.querySelector('.workspace-evidence-entry')));

// p18: single glossary source: actual test-case catalog exposed through local backend.
async function loadAbbreviationKey(){
 try{
  const result=await request('/api/abbreviations');
  for(const suffix of ['Queue']){
   const field=$('abbreviationSearch'+suffix),holder=$('abbreviationTable'+suffix);
   if(!field||!holder)continue;
   const draw=()=>{const term=field.value.toLowerCase();const rows=result.items.filter(x=>(x.code+' '+x.meaning+' '+x.type).toLowerCase().includes(term));
    replace(holder,makeTable(['Abbreviation','Meaning','Category'],rows.map(x=>[x.code,x.meaning,x.type])));};
   field.addEventListener('input',draw);draw();
  }
 }catch(_){/* Reference is supplemental: assessment navigation remains usable. */}
}
loadAbbreviationKey();

// Clearly illustrative output; never label examples as collected target evidence.
const p18Examples={
 'TC-IP-002':{title:'Compare named-pipe access permissions',examples:[
 ['Restricted example',String.raw`\\.\pipe\ExampleService
  RW NT AUTHORITY\SYSTEM
      FILE_ALL_ACCESS
  RW BUILTIN\Administrators
      FILE_ALL_ACCESS`],
 ['Potentially broad access (requires review)',String.raw`\\.\pipe\ExampleService
  RW NT AUTHORITY\SYSTEM
      FILE_ALL_ACCESS
  RW BUILTIN\Users
      FILE_GENERIC_READ
      FILE_GENERIC_WRITE
  R Everyone
      FILE_GENERIC_READ`],
 ['Explicit anonymous access (requires review)',String.raw`\\.\pipe\ExampleService
  R NT AUTHORITY\ANONYMOUS LOGON
      FILE_GENERIC_READ
  RW Everyone
      FILE_GENERIC_WRITE`]],
 interpret:'Look at WHO has rights: SYSTEM and Administrators generally indicate restricted access. BUILTIN\\Users, Authenticated Users, Everyone or ANONYMOUS LOGON deserve a caller-context review. RW is NOT a vulnerability by itself. Check actual effective access, the pipe operation protocol and server-side authorization.'},
 'TC-FS-001':{title:'Understanding filesystem modification permissions',examples:[
 ['Potentially broad modification permissions',String.raw`Path: C:\ProgramData\ExampleApp\Plugins
Owner: BUILTIN\Administrators
Identity : BUILTIN\Users
Rights   : Modify
Type     : Allow
Inherited: True`]],
 interpret:'An orange warning is appropriate where a broad principal may modify an application-controlled path. Confirm effective rights with a standard-user token and determine whether a privileged process consumes the files. This is NOT automatically a confirmed vulnerability.'},
 'TC-RG-001':{title:'Understanding registry modification permissions',examples:[
 ['Potentially broad registry modification permissions',String.raw`Key: HKLM\SOFTWARE\ExampleApp
Identity : BUILTIN\Users
Rights   : SetValue
Type     : Allow
Inherited: True`]],
 interpret:'Check whether the key affects privileged behavior and whether a lower-trust token can actually change it. A broadly writable benign setting may be expected.'},
 'TC-LS-001':{title:'File and parent storage permissions',examples:[
 ['Restricted storage example',String.raw`File: C:\ProgramData\ExampleApp\settings.dat
BUILTIN\Users        ReadAndExecute (Allow)
BUILTIN\Administrators FullControl (Allow)`],
 ['Potentially writable storage example',String.raw`Parent: C:\ProgramData\ExampleApp
BUILTIN\Users        Modify (Allow)
SYSTEM               FullControl (Allow)`]],
 interpret:'Review the actual file AND parent ACL for the selected storage object. Check inherited versus explicit entries, deny ACEs and the correct standard-user effective token. Broad read access does not prove modification, and a writable path is not a vulnerability unless a protected trust boundary is crossed.'},
 'TC-PE-001':{title:'CFG, ASLR and DEP — identify, compare and interpret',examples:[],
 interpret:'A missing PE flag is a possible defense-in-depth gap, not a proven vulnerability. Confirm compiler and architecture applicability, inspect DUMPBIN output, and distinguish PE opt-in flags from runtime enforcement.'},
 'TC-MC-001':{title:'Mitigations vs. memory corruption',examples:[['Example investigation',String.raw`ASLR: enabled · DEP: enabled · CFG: missing
Memory corruption: not established`]],interpret:'TC-PE-001 identifies PE hardening properties. TC-MC-001 must determine whether memory corruption exists and its impact. Reuse PE evidence rather than redoing metadata inspection.'},
 'TC-PM-001':{title:'Common Procmon result interpretation',examples:[['Informational filesystem fallback',String.raw`WriteFile | FAST IO DISALLOWED
The fast path was unavailable. Windows may retry using a normal I/O request.`]],interpret:'SUCCESS means the operation completed; ACCESS DENIED signals access restriction, not automatically a flaw; NAME NOT FOUND is common during DLL search; FAST IO DISALLOWED and BUFFER OVERFLOW can be normal operating-system behavior. Correlate subsequent events and target context.'},
};
// p18-p1: Show mitigation examples at TC-PE-001 Step 3, alongside the actual
// PE evidence, rather than in a detached section below the entire test case.
const peMitigationReference=[
 {name:'Control Flow Guard (CFG)',summary:'Restricts certain indirect-call targets to approved destinations, making some memory-corruption exploitation techniques harder.',
  good:'DLL characteristics:\n    Guard CF\nGuard Flags:\n    CF Instrumented\n    FID table present',
  bad:'DLL characteristics:\n    Dynamic base\n    NX compatible\nGuard Flags: (no CFG instrumentation reported)',
  check:'Verify Guard CF in PE characteristics and CF Instrumented / FID table present in load configuration. A marker may be absent for legitimate toolchain or code-layout reasons; check applicability. CFG does not prove the binary is free of memory corruption.'},
 {name:'Address Space Layout Randomization (ASLR)',summary:'Randomizes memory placement to make executable-code addresses less predictable for exploitation.',
  good:'DLL characteristics:\n    Dynamic base\n    High Entropy Virtual Addresses',
  bad:'DLL characteristics:\n    NX compatible\n    (Dynamic base not present)',
  check:'Check Dynamic base; High Entropy VA is an additional applicable 64-bit indicator. Assess relocations, image type and Windows process policy before concluding addresses are fixed. Runtime ASLR is not established by metadata alone.'},
 {name:'Data Execution Prevention (DEP / NX)',summary:'Restricts code execution from non-executable data memory, limiting some injected-code attacks.',
  good:'DLL characteristics:\n    NX compatible',
  bad:'DLL characteristics:\n    Dynamic base\n    (NX compatible not present)',
  check:'Check NX compatible where relevant, architecture and runtime process policy. Missing the flag does not prove DEP is disabled, particularly on modern 64-bit Windows.'}
];
function buildPeMitigationGuide(){
 const wrap=el('details',undefined,'p18-learning p18-pe-step-guide');wrap.open=true;
 wrap.appendChild(el('summary','How to interpret CFG, ASLR and DEP (examples and next checks)'));
 wrap.appendChild(el('p','Illustrative DUMPBIN-style examples, not collected assessment evidence. Compare with the selected PE and its real DUMPBIN output.','hint'));
 for(const mitigation of peMitigationReference){
  const card=el('section',undefined,'p18-pe-mitigation');
  card.appendChild(el('h4',mitigation.name));card.appendChild(el('p',mitigation.summary));
  const good=el('div',undefined,'p18-pe-comparison');good.appendChild(el('strong','✓ Example: Indicators present','p18-pe-present'));
  good.appendChild(el('pre',mitigation.good,'tc-collected-excerpt'));card.appendChild(good);
  const missing=el('div',undefined,'p18-pe-comparison');missing.appendChild(el('strong','Example: Missing or limited metadata'));
  missing.appendChild(el('pre',mitigation.bad,'tc-collected-excerpt'));card.appendChild(missing);
  card.appendChild(el('p',mitigation.check,'hint')); 
  wrap.appendChild(card);
 }
 const sharedWarning=el('div',undefined,'p18-warning');
 sharedWarning.appendChild(el('strong','⚠ Requires applicability review — not a confirmed vulnerability'));
 sharedWarning.appendChild(el('p','CFG, ASLR, and DEP metadata flags indicate build properties, not proven runtime protection or exploitability. Review architecture, toolchain, relocations, Windows policy, and exposure to untrusted inputs before reporting any missing mitigation.'));
 wrap.appendChild(sharedWarning);
 wrap.appendChild(el('p','TC-PE-001 evaluates metadata/hardening; TC-MC-001 separately investigates memory safety and actual exploitability. No mitigation prevents every memory-corruption attack.','hint'));
 return wrap;
}

// TC-AR-003 Step 5: targeted selection guidance, not a duplicate review workflow.
function buildAdvancedModuleToolGuides(){
 const panel=el('div',undefined,'p18-learning tc-ar-step5-guides');
 panel.appendChild(el('strong','Optional advanced module analysis — official getting-started guides'));
 panel.appendChild(el('p','Use these only when collected module evidence cannot establish the loading path. These tools are optional; no tool is launched by opening a guide.','hint'));
 const tools=[
  ['WinDbg','Dynamic debugging: inspect module loads, call stacks, and the caller responsible for a load.','https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/getting-started-with-windbg'],
  ['Ghidra','Static binary analysis: inspect imports and code that chooses or constructs module paths.','https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GettingStarted.md'],
  ['Frida','Runtime instrumentation: observe module-loading APIs and relevant arguments during an authorized workflow.','https://frida.re/docs/quickstart/']
 ];
 for(const [name,why,url] of tools){
  const line=el('div',undefined,'tc-ar-tool-guide');line.appendChild(el('strong',name));
  line.appendChild(el('p',why,'hint'));
  const link=el('a','Official getting-started guide');link.href=url;link.target='_blank';link.rel='noopener noreferrer';line.appendChild(link);panel.appendChild(line);
 }
 return panel;
}
function addP18GuidanceExamples(host,caseId){
 const example=p18Examples[caseId];if(!example)return;
 const details=el('details',undefined,'p18-learning');details.open=caseId==='TC-IP-002';
 details.appendChild(el('summary','Examples & result interpretation · '+example.title));
 details.appendChild(el('p','Illustrative examples — not collected assessment results. Compare with actual evidence before concluding.','hint'));
 for(const [heading,body] of example.examples){
  const block=el('div',undefined,'p18-example');block.appendChild(el('strong',heading));
  if(/broad|anonymous|missing/i.test(heading)){
   const warning=el('div',undefined,'p18-warning');warning.appendChild(el('strong','⚠ Requires Review — Not a Confirmed Vulnerability'));block.appendChild(warning);
  }
  block.appendChild(el('pre',body,'tc-collected-excerpt'));details.appendChild(block);
 }
 details.appendChild(el('p',example.interpret));
 host.appendChild(details);
}
