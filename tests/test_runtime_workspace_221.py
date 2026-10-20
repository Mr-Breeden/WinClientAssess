"""Focused regression for v2.2.1's optional, first-in-workspace runtime step."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from utils.gui_server import runtime_history

ROOT = Path(__file__).resolve().parents[1]


def test_runtime_step_is_first_conditional_workspace_tab():
    html = (ROOT / 'gui/index.html').read_text(encoding='utf-8')
    tabs = html.split('class="workspace-tabs"', 1)[1].split('</div>', 1)[0]
    assert tabs.index('id="workspaceRuntimeTab"') < tabs.index('data-workspace-pane="overview"')
    assert 'id="workspace-pane-runtime"' in html
    assert 'id="workspaceRuntimeStart"' in html
    assert 'id="workspaceRuntimeSkip"' in html
    assert 'id="workspaceRuntimeResume"' in html
    assert 'Skip for this assessment (this browser)' in html
    assert 'Guided Runtime' in (ROOT / 'docs/manual-testing-workflow.md').read_text(encoding='utf-8')


def test_workspace_runtime_entrypoint_is_tester_initiated_and_not_assessment_mutation():
    js = (ROOT / 'gui/app.js').read_text(encoding='utf-8')
    assert "$('workspaceRuntimeStart').addEventListener('click',()=>{" in js
    assert "startJob('runtime',{assessment:state.assessment});" in js
    assert "localStorage.setItem(runtimeSkipKey(),'yes');" in js
    assert "localStorage.removeItem(runtimeSkipKey());" in js
    assert "function preferredWorkspacePane()" in js
    assert "showWorkspacePane(tab==='review'||tab==='workflow'?'queue':preferredWorkspacePane());" in js
    skip_code=js.split("$('workspaceRuntimeSkip').addEventListener", 1)[1].split("$('workspaceRuntimeResume').addEventListener", 1)[0]
    assert 'mutate(' not in skip_code and 'request(' not in skip_code


def test_runtime_history_failed_session_is_not_completed(monkeypatch, tmp_path):
    monkeypatch.setattr('utils.gui_server.verify_assessment', lambda root: {'status':'PASS'})
    root=tmp_path/'assessment'; history=root/'working'/'guided_runtime_observations.json';history.parent.mkdir(parents=True)
    history.write_text(json.dumps({'sessions':[{'capture':{'status':'WARN'},'session':{'capture_duration_seconds':3}}]}),encoding='utf-8')
    result=runtime_history(root)
    assert result['total']==1 and result['sessions'][0]['capture_status']=='WARN'
    # The browser deliberately checks for a PASS session, not just count > 0.
    js=(ROOT/'gui/app.js').read_text(encoding='utf-8')
    assert "session.capture_status==='PASS'" in js
    history.write_text(json.dumps({'sessions':[{'capture':{'status':'WARN'}},{'capture':{'status':'PASS'}}]}), encoding='utf-8')
    result=runtime_history(root)
    assert [x['capture_status'] for x in result['sessions']]==['PASS','WARN']


def test_js_runtime_preflight_eligibility_skip_and_existing_session():
    if not shutil.which('node'):
        pytest.skip('Node is not installed; JavaScript syntax checked separately')
    js = (ROOT / 'gui/app.js').read_text(encoding='utf-8')
    source = js[js.index('// Optional workspace preflight'):js.index('function go(tab){')]
    program = r'''
const assert=require('node:assert/strict');
const bootstrap={version:'2.2.1'};
const storage=new Map();
const localStorage={getItem:k=>storage.get(k)||null,setItem:(k,v)=>storage.set(k,v),removeItem:k=>storage.delete(k)};
const elements={}; const $=id=>(elements[id] ||= {hidden:false,disabled:false,textContent:''});
const set=(id,v)=>$(id).textContent=v;
const state={assessment:'C:/fixture',status:{status:'COMPLETED',mode:'full',framework_version:'2.2.1',integrity:{status:'PASS'}},runtime:{state:'NOT RUN',sessions:[]},runtimeIntroAssessment:null,workspacePane:'overview',jobStarting:false,jobId:null};
let switched='';const showWorkspacePane=p=>{switched=p;state.workspacePane=p};
''' + source + r'''
assert.equal(runtimeStepEligible(),true);
assert.equal(preferredWorkspacePane(),'runtime');
assert.equal(preferredWorkspacePane(),'overview');
updateRuntimeStep();
assert.equal($('workspaceRuntimeTab').hidden,false);
assert.equal($('workspaceRuntimeStart').disabled,false);
localStorage.setItem(runtimeSkipKey(),'yes');
updateRuntimeStep();
assert.equal($('workspaceRuntimeTab').hidden,true);
assert.equal($('workspaceRuntimeReminder').hidden,false);
localStorage.removeItem(runtimeSkipKey());
state.runtime.sessions=[{capture_status:'WARN'}];
assert.equal(runtimeStepEligible(),true);
state.runtime.sessions.push({capture_status:'PASS'});
assert.equal(runtimeStepEligible(),false);
updateRuntimeStep();
assert.equal($('workspaceRuntimeTab').hidden,true);
state.runtime.sessions=[];
state.status.mode='static';assert.equal(runtimeStepEligible(),false);
state.status.mode='full';state.status.framework_version='2.2.0';updateRuntimeStep();
assert.equal(runtimeStepEligible(),true);
assert.equal($('workspaceRuntimeStart').disabled,true);
state.status.framework_version='2.2.1';state.status.integrity.status='FAIL';
assert.equal(runtimeStepEligible(),false);
console.log('Runtime workspace gating PASS');
'''
    result=subprocess.run(['node','-e',program],capture_output=True,text=True,timeout=15)
    assert result.returncode==0, result.stderr
    assert 'gating PASS' in result.stdout
