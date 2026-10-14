from __future__ import annotations
from utils.assessment_layout import artifact_path

import re
from pathlib import Path

from utils.acl import get_acl_summaries, broad_write_aces
from utils.powershell import run_powershell_json
from utils.report_format import header, section, kv, bool_text
from utils.windows_paths import is_user_profile_path, is_temp_path, parent_path
from utils.component_context import launch_contexts_for_candidate, basename as _basename, normalize_path as _norm, is_privileged

UPDATE_WORDS = re.compile(r"(update|updater|upgrade|patch|maintenance|bootstrap|launcher|autoupdate)", re.I)
STAGING_WORDS = re.compile(r"(stage|staging|download|cache|package|payload|patch|update|upgrade|temp)", re.I)
CONFIG_EXTS = {'.json','.xml','.config','.ini','.yaml','.yml','.toml','.conf','.cfg','.properties','.db','.sqlite','.sqlite3'}
PACKAGE_EXTS = {'.exe','.msi','.msp','.msix','.appx','.cab','.zip','.nupkg','.dll','.ps1','.bat','.cmd'}
SIGNABLE_EXTS = {'.exe','.dll','.msi','.msp','.msix','.appx','.cab','.ps1'}
MAX_ARTIFACTS = 300


def _candidate_names(candidates):
    return {_basename(c.get('Path')).lower() for c in candidates or [] if c.get('Path')}


def _signature_batch(paths):
    unique=[]; seen=set()
    for raw in paths or []:
        p=str(raw or '').strip()
        if not p or Path(p).suffix.lower() not in SIGNABLE_EXTS: continue
        key=p.lower()
        if key in seen: continue
        seen.add(key); unique.append(p)
    if not unique:
        return {}
    quoted=','.join("'"+p.replace("'","''")+"'" for p in unique)
    ps=rf'''
    $paths=@({quoted})
    $out=foreach($p in $paths){{
      if(Test-Path -LiteralPath $p -PathType Leaf){{
        try{{
          $s=Get-AuthenticodeSignature -LiteralPath $p
          [PSCustomObject]@{{
            Path=$p;Exists=$true;Status=[string]$s.Status;StatusMessage=$s.StatusMessage;
            SignerSubject=if($s.SignerCertificate){{$s.SignerCertificate.Subject}}else{{$null}};
            Thumbprint=if($s.SignerCertificate){{$s.SignerCertificate.Thumbprint}}else{{$null}};
            NotAfter=if($s.SignerCertificate){{$s.SignerCertificate.NotAfter}}else{{$null}};
            Timestamped=[bool]$s.TimeStamperCertificate
          }}
        }}catch{{[PSCustomObject]@{{Path=$p;Exists=$true;Status='Error';StatusMessage=$_.Exception.Message;SignerSubject=$null;Thumbprint=$null;NotAfter=$null;Timestamped=$false}}}}
      }}else{{[PSCustomObject]@{{Path=$p;Exists=$false;Status='Unavailable';StatusMessage='Path not present at review time';SignerSubject=$null;Thumbprint=$null;NotAfter=$null;Timestamped=$false}}}}
    }}
    $out
    '''
    data,result=run_powershell_json(ps,timeout=240)
    rows=[data] if isinstance(data,dict) else (data if isinstance(data,list) else [])
    out={}
    for row in rows:
        if isinstance(row,dict): out[str(row.get('Path','')).lower()]=row
    for p in unique:
        if p.lower() not in out:
            out[p.lower()]={'Path':p,'Exists':False,'Status':'Unavailable','StatusMessage':result.get('stderr','') or 'No signature result returned','SignerSubject':None,'Thumbprint':None,'NotAfter':None,'Timestamped':False}
    return out


def _launch_contexts(candidate, diff):
    existing = list(candidate.get("LaunchContexts") or [])
    if existing:
        return existing
    return launch_contexts_for_candidate(candidate, diff, include_startup=False)


def _runtime_context(candidate, runtime_processes):
    path_l=_norm(candidate.get('Path')); name=_basename(candidate.get('Path')).lower()
    allow_name_fallback = candidate.get('Source') != 'static/extracted'
    matches=[]
    for proc in runtime_processes or []:
        exact_path = bool(path_l and _norm(proc.get('Exe')) == path_l)
        name_match = bool(allow_name_fallback and name and str(proc.get('Name') or '').lower() == name)
        if exact_path or name_match:
            matches.append(proc)
    return matches


def _artifact_kind(path, is_dir=False):
    if is_dir: return 'Directory'
    ext=Path(path).suffix.lower()
    if ext in PACKAGE_EXTS: return 'Package/Executable'
    if ext in CONFIG_EXTS: return 'Configuration/Data'
    return 'Other'


def _candidate_parent_paths(candidates):
    parents=[]
    for c in candidates or []:
        p=str(c.get('Path') or '')
        parent=parent_path(p)
        if parent: parents.append(parent.lower())
    return parents


def _component_tokens(candidates):
    ignored = {
        'program files', 'program files (x86)', 'windows', 'system32', 'amd64', 'x64', 'x86',
        'bin', 'client', 'application', 'app', 'update', 'updater', 'upgrade',
    }
    tokens=set()
    for candidate in candidates or []:
        path=_norm(candidate.get('Path'))
        for part in re.split(r'[\\/]+', path):
            stem=Path(part).stem.lower()
            if len(stem)>=5 and stem not in ignored and not re.fullmatch(r'v?\d+(?:\.\d+)*',stem):
                tokens.add(stem)
    return tokens


def _discover_artifacts(diff, candidates, procmon_data):
    rows=[]; seen=set(); parent_paths=_candidate_parent_paths(candidates)
    component_tokens=_component_tokens(candidates)
    updater_names=_candidate_names(candidates)

    def add(path, source, is_dir=False, process='', operation='', result='', detail=''):
        path=str(path or '').strip()
        if not path: return
        key=(path.lower(),source,process.lower(),operation.lower())
        if key in seen: return
        seen.add(key)
        rows.append({'Path':path,'Source':source,'IsDirectory':bool(is_dir),'Kind':_artifact_kind(path,bool(is_dir)),'Process':process,'Operation':operation,'Result':result,'Detail':detail})

    fs=(diff or {}).get('Filesystem',{})
    for item in (fs.get('added',[]) or []):
        if not isinstance(item,dict): continue
        path=str(item.get('Path') or '')
        lower=path.lower()
        ext=Path(path).suffix.lower()
        same_component_tree=any(parent and lower.startswith(parent+'\\') for parent in parent_paths)
        component_relevant = same_component_tree and (
            (bool(item.get('IsDirectory')) and bool(UPDATE_WORDS.search(_basename(path))))
            or (not item.get('IsDirectory') and ext in (CONFIG_EXTS | PACKAGE_EXTS))
        )
        component_identity=any(token in lower for token in component_tokens)
        # System-state differentials contain unrelated OS/user activity. Only
        # accept artifacts inside an updater component tree, or paths that carry
        # both product identity and explicit update/upgrade semantics.
        relevant=component_relevant or (component_identity and bool(UPDATE_WORDS.search(path)))
        if relevant:
            add(path,'Filesystem added',item.get('IsDirectory'))
    for change in (fs.get('changed',[]) or []):
        after=change.get('after',{}) if isinstance(change,dict) else {}
        if not isinstance(after,dict): continue
        path=str(after.get('Path') or '')
        lower=path.lower()
        same_component_tree=any(parent and lower.startswith(parent+'\\') for parent in parent_paths)
        component_identity=any(token in lower for token in component_tokens)
        if same_component_tree or (component_identity and UPDATE_WORDS.search(path)):
            add(path,'Filesystem changed',after.get('IsDirectory'))

    pdata=procmon_data or {}
    for event in pdata.get('file_writes',[]) or []:
        process=str(event.get('Process') or '')
        path=str(event.get('Path') or '')
        ext=Path(path).suffix.lower()
        updater_relevant = process.lower() in updater_names and (bool(STAGING_WORDS.search(path)) or ext in (CONFIG_EXTS | PACKAGE_EXTS))
        if updater_relevant:
            add(path,'Procmon file write',False,process,event.get('Operation',''),event.get('Result',''),event.get('Detail',''))

    return rows[:MAX_ARTIFACTS]


def _runtime_events(procmon_data, candidates):
    names=_candidate_names(candidates)
    result={key:[] for key in ('file_writes','registry_writes','network_activity','process_activity')}
    for key in result:
        for event in (procmon_data or {}).get(key,[]) or []:
            if str(event.get('Process') or '').lower() in names:
                result[key].append(event)
    return result


def _endpoint_candidates(runtime_events):
    out=[]; seen=set()
    for event in runtime_events.get('network_activity',[]) or []:
        key=(str(event.get('Process') or '').lower(),str(event.get('Path') or '').lower(),str(event.get('Operation') or '').lower())
        if key in seen: continue
        seen.add(key)
        out.append({'Process':event.get('Process'),'Operation':event.get('Operation'),'Path':event.get('Path'),'Result':event.get('Result'),'Detail':event.get('Detail')})
    return out


def _user_controlled_hint(path):
    p=_norm(path)
    return is_user_profile_path(path) or is_temp_path(path) or '\\users\\public\\' in p or '\\temp\\' in p


def run_updater_security_review(
    assessment_dir: Path,
    updater_candidates=None,
    diff=None,
    post_snapshot=None,
    procmon_data=None,
    runtime_processes=None,
    mode='full',
    filesystem_evidence=True,
    acl_cache=None,
):
    candidates=[dict(x) for x in (updater_candidates or [])]
    diff=diff or {}
    runtime_processes=runtime_processes or []
    width=112

    if not candidates:
        return {
            'status':'SKIPPED',
            'details':'No updater/maintenance candidates available for security correlation',
            'findings':[],
            'updater_security':{},
            'updater_pois':[],
        }

    has_procmon_evidence=bool(procmon_data)
    has_filesystem_evidence=bool(filesystem_evidence)

    # Enrich execution context and runtime correlation.
    for candidate in candidates:
        candidate['LaunchContexts']=_launch_contexts(candidate,diff)
        candidate['RuntimeProcesses']=_runtime_context(candidate,runtime_processes)
        contexts=candidate['LaunchContexts']
        runtime_users=[p.get('Username') for p in candidate['RuntimeProcesses'] if p.get('Username')]
        candidate['Privileged']=any(is_privileged(c.get('Account'),c.get('RunLevel')) for c in contexts) or any(is_privileged(u,'') for u in runtime_users)
        candidate['ExecutionContexts']=contexts

    signatures=_signature_batch([c.get('Path') for c in candidates])
    artifacts=_discover_artifacts(diff if has_filesystem_evidence else {},candidates,procmon_data)
    runtime=_runtime_events(procmon_data,candidates)
    endpoints=_endpoint_candidates(runtime)
    runtime_event_count=sum(len(runtime.get(key,[])) for key in ('file_writes','registry_writes','network_activity','process_activity'))
    runtime_coverage_gap=bool(has_procmon_evidence and runtime_event_count == 0)

    # ACL review only makes sense for installed/runtime filesystem paths. Static extracted content
    # is kept for signature/source review but its extraction-directory ACL is not an application control.
    acl_targets=[]
    for c in candidates:
        if c.get('Source')=='installed differential' or c.get('LaunchContexts'):
            path=str(c.get('Path') or '')
            if path:
                acl_targets.append(path)
                parent=parent_path(path)
                if parent: acl_targets.append(parent)
    for artifact in artifacts:
        path=artifact['Path']
        if artifact['Source'].startswith('Filesystem') or artifact['Source'].startswith('Procmon'):
            acl_targets.append(path)
            if not artifact.get('IsDirectory'):
                parent=parent_path(path)
                if parent: acl_targets.append(parent)
    acl_map=acl_cache.get_many(acl_targets) if acl_cache else get_acl_summaries(acl_targets)

    pois=[]
    def add_poi(candidate, issue, path, evidence, confidence='MEDIUM', category='Privilege / Trust Boundary'):
        pois.append({
            'POI':f"POI-UP-{len(pois)+1:03d}",
            'Candidate':candidate.get('Path') if candidate else '',
            'ProcessName':_basename(candidate.get('Path')) if candidate else '',
            'Privileged':bool(candidate.get('Privileged')) if candidate else False,
            'Category':category,'Issue':issue,'Path':path,'Evidence':evidence,'Confidence':confidence,
        })

    # Candidate path/signature checks.
    for c in candidates:
        path=str(c.get('Path') or '')
        sig=signatures.get(path.lower(),{})
        c['Signature']=sig
        path_acl=acl_map.get(path.lower(),{})
        parent=parent_path(path)
        parent_acl=acl_map.get(str(parent or '').lower(),{})
        c['PathACL']=path_acl
        c['ParentACL']=parent_acl
        c['PathBroadWrite']=broad_write_aces(path_acl)
        c['ParentBroadWrite']=broad_write_aces(parent_acl)

        if c.get('Privileged') and c['PathBroadWrite']:
            add_poi(c,'Privileged updater executable/script is broadly writable',path,c['PathBroadWrite'],'HIGH')
        if c.get('Privileged') and c['ParentBroadWrite']:
            add_poi(c,'Privileged updater parent directory is broadly writable',parent,c['ParentBroadWrite'],'HIGH')
        if c.get('Privileged') and _user_controlled_hint(path):
            add_poi(c,'Privileged updater executes from a user-controlled or temporary location',path,'Path is under a user-profile/public/TEMP location.','HIGH')
        if sig.get('Exists') and str(sig.get('Status') or '') != 'Valid':
            add_poi(c,'Updater code-signing status requires validation',path,f"Authenticode status: {sig.get('Status')} ({sig.get('StatusMessage')})",'MEDIUM','Code Integrity')

    # Artifact/staging checks. Package/executable artifacts are independently
    # checked for Authenticode so the report can distinguish a writable staged
    # object from a writable staged object whose trust state is also non-valid.
    artifact_records=[]
    privileged_any=any(c.get('Privileged') for c in candidates)
    artifact_signatures=_signature_batch([
        a.get('Path') for a in artifacts
        if a.get('Kind') == 'Package/Executable' and not a.get('IsDirectory')
    ])
    for artifact in artifacts:
        path=artifact['Path']
        acl=acl_map.get(path.lower(),{})
        parent=parent_path(path) if not artifact.get('IsDirectory') else path
        parent_acl=acl_map.get(str(parent or '').lower(),{})
        broad=broad_write_aces(acl) or broad_write_aces(parent_acl)
        record=dict(artifact)
        record['ACL']=acl
        record['ParentACL']=parent_acl
        record['BroadWrite']=broad
        record['UserControlledHint']=_user_controlled_hint(path)
        record['Signature']=artifact_signatures.get(path.lower(), {}) if record['Kind'] == 'Package/Executable' else {}
        artifact_records.append(record)
        # Generic logs/caches are navigation evidence, not actionable staging
        # trust boundaries unless a later runtime correlation proves consumption.
        security_relevant_kind = record['Kind'] in {'Package/Executable', 'Configuration/Data'}
        if privileged_any and security_relevant_kind and (broad or record['UserControlledHint']):
            sig_status=str((record.get('Signature') or {}).get('Status') or 'Unavailable')
            confidence='HIGH' if record['Kind']=='Package/Executable' else 'MEDIUM'
            control_evidence=broad or 'Path is under a user-profile/public/TEMP location.'
            evidence=f"Control evidence: {control_evidence}"
            if record['Kind']=='Package/Executable':
                evidence += f"; staged Authenticode status: {sig_status}"
            add_poi(
                next((c for c in candidates if c.get('Privileged')), candidates[0] if candidates else {}),
                f"Privileged update workflow uses a potentially user-influenced {record['Kind'].lower()}",
                path, evidence, confidence, 'Staging / Configuration',
            )
            if record['Kind']=='Package/Executable' and sig_status not in {'Valid','Unavailable'}:
                add_poi(
                    next((c for c in candidates if c.get('Privileged')), candidates[0] if candidates else {}),
                    'Potentially user-influenced staged package/executable has non-valid Authenticode status',
                    path, f"Authenticode status: {sig_status}; {control_evidence}", 'HIGH', 'Package Integrity',
                )

    # Runtime handoff signals: privileged updater writes executable/package into user-controlled area.
    privileged_names={_basename(c.get('Path')).lower() for c in candidates if c.get('Privileged')}
    for event in runtime.get('file_writes',[]):
        path=str(event.get('Path') or '')
        if str(event.get('Process') or '').lower() in privileged_names and Path(path).suffix.lower() in PACKAGE_EXTS and _user_controlled_hint(path):
            candidate=next((c for c in candidates if _basename(c.get('Path')).lower()==str(event.get('Process') or '').lower()), candidates[0] if candidates else {})
            add_poi(candidate,'Privileged updater writes executable/package content to a user-controlled or temporary path',path,event,'MEDIUM','Runtime Staging')

    created_supporting=[]

    # Component index is a primary supporting artifact whenever this correlation phase runs.
    comp_lines=header(
        'Windows Client Assessment - Updater Components',
        ['Concise index of updater/maintenance candidates and their correlated launch/privilege context.'],width
    )
    comp_lines += ['SUMMARY','-'*width,kv('Candidates',len(candidates)),kv('Privileged candidates',sum(1 for c in candidates if c.get('Privileged'))),kv('Runtime-observed candidates',sum(1 for c in candidates if c.get('RuntimeProcesses')))]
    for idx,c in enumerate(candidates,1):
        comp_lines += ['', '='*width, f"[UPD-COMP-{idx:03d}] {_basename(c.get('Path'))}", '='*width,
            kv('Role',c.get('Role') or 'Updater/Update Component'),kv('Source',c.get('Source')),kv('Path',c.get('Path')),
            kv('Privileged',bool_text(c.get('Privileged'))),kv('Launch Contexts',len(c.get('LaunchContexts',[]))),kv('Runtime Processes',len(c.get('RuntimeProcesses',[])))]
        for ctx in c.get('LaunchContexts',[]):
            comp_lines += [f"  {ctx.get('Type')}: {ctx.get('Component')} | Account={ctx.get('Account')} | RunLevel={ctx.get('RunLevel')} | {ctx.get('Command')}"]
    (artifact_path(assessment_dir, 'updater_components.txt')).write_text('\n'.join(comp_lines).rstrip()+'\n',encoding='utf-8')
    created_supporting.append('updater_components.txt')

    # Candidate Authenticode review is applicable whenever candidates exist.
    sig_lines=header(
        'Windows Client Assessment - Updater Signature Review',
        ['Records Authenticode state for updater/maintenance candidates that are present on disk.', 'Unsigned/invalid status is a review point; product context and actual package-integrity behavior still require validation.'],width
    )
    sig_lines += ['SUMMARY','-'*width,kv('Candidate paths',len(candidates)),kv('Valid signatures',sum(1 for c in candidates if c.get('Signature',{}).get('Status')=='Valid')),kv('Non-valid/unavailable',sum(1 for c in candidates if c.get('Signature',{}).get('Status')!='Valid'))]
    for idx,c in enumerate(candidates,1):
        s=c.get('Signature',{})
        sig_lines += ['',f"[UPD-SIG-{idx:03d}] {_basename(c.get('Path'))}",'-'*width,kv('Path',c.get('Path')),kv('Exists',s.get('Exists')),kv('Status',s.get('Status') or 'Unavailable'),kv('Signer',s.get('SignerSubject') or 'Unavailable'),kv('Timestamped',bool_text(s.get('Timestamped'))),kv('Status Message',s.get('StatusMessage') or '')]
    (artifact_path(assessment_dir, 'updater_signature_review.txt')).write_text('\n'.join(sig_lines).rstrip()+'\n',encoding='utf-8')
    created_supporting.append('updater_signature_review.txt')

    # Permissions output is only created if ACL targets were actually queried.
    if acl_targets:
        perm_lines=header(
            'Windows Client Assessment - Updater Permissions Review',
            ['Reviews installed updater binaries, parent directories, and update-related staging/configuration artifacts.', 'Broad-write ACLs require effective-permission and privileged-handoff validation before reporting.'],width
        )
        perm_lines += ['SUMMARY','-'*width,kv('ACL targets queried',len(acl_map)),kv('Candidate broad-write paths',sum(1 for c in candidates if c.get('PathBroadWrite') or c.get('ParentBroadWrite'))),kv('Artifact broad-write paths',sum(1 for a in artifact_records if a.get('BroadWrite')))]
        for idx,c in enumerate(candidates,1):
            if c.get('Source')!='installed differential' and not c.get('LaunchContexts'): continue
            perm_lines += ['', '='*width, f"[UPD-ACL-{idx:03d}] {_basename(c.get('Path'))}", '='*width,kv('Path',c.get('Path')),kv('Privileged',bool_text(c.get('Privileged'))),kv('Binary Broad Write',len(c.get('PathBroadWrite') or [])),kv('Parent Broad Write',len(c.get('ParentBroadWrite') or []))]
            for hit in c.get('PathBroadWrite') or []: perm_lines.append(f"  Binary: {hit}")
            for hit in c.get('ParentBroadWrite') or []: perm_lines.append(f"  Parent: {hit}")
        (artifact_path(assessment_dir, 'updater_permissions.txt')).write_text('\n'.join(perm_lines).rstrip()+'\n',encoding='utf-8')
        created_supporting.append('updater_permissions.txt')

    # Staging/config review requires filesystem differential or Procmon file evidence.
    if has_filesystem_evidence or has_procmon_evidence:
        stage_lines=header(
            'Windows Client Assessment - Updater Staging / Configuration Review',
            ['Inventories update-related files/directories seen during installation or runtime.', 'Prioritize packages/executables and configuration consumed by privileged updater components.'],width
        )
        stage_lines += ['SUMMARY','-'*width,kv('Artifacts',len(artifact_records)),kv('Package/executable artifacts',sum(1 for a in artifact_records if a.get('Kind')=='Package/Executable')),kv('Configuration/data artifacts',sum(1 for a in artifact_records if a.get('Kind')=='Configuration/Data')),kv('Broad-write artifacts',sum(1 for a in artifact_records if a.get('BroadWrite'))),kv('Valid staged signatures',sum(1 for a in artifact_records if (a.get('Signature') or {}).get('Status')=='Valid')),kv('Non-valid staged signatures',sum(1 for a in artifact_records if a.get('Signature') and (a.get('Signature') or {}).get('Status') not in {'Valid','Unavailable'}))]
        if not artifact_records:
            stage_lines += ['', 'No updater staging/configuration artifacts were identified in the available evidence.']
        for idx,a in enumerate(artifact_records,1):
            sig=(a.get('Signature') or {})
            stage_lines += ['',f"[UPD-STAGE-{idx:03d}] {a.get('Kind')}",'-'*width,kv('Path',a.get('Path')),kv('Source',a.get('Source')),kv('Process',a.get('Process') or 'N/A'),kv('Operation',a.get('Operation') or 'N/A'),kv('Broad Write',bool_text(bool(a.get('BroadWrite')))),kv('User-Controlled Hint',bool_text(a.get('UserControlledHint'))),kv('Signature Status',sig.get('Status') or ('N/A' if a.get('Kind')!='Package/Executable' else 'Unavailable'))]
        (artifact_path(assessment_dir, 'updater_staging_review.txt')).write_text('\n'.join(stage_lines).rstrip()+'\n',encoding='utf-8')
        created_supporting.append('updater_staging_review.txt')

    # Runtime-only artifacts exist only when Procmon analysis data was supplied.
    if has_procmon_evidence:
        run_lines=header(
            'Windows Client Assessment - Updater Runtime Activity',
            ['Filters available Procmon data to updater/maintenance process names.', 'Use this as evidence/navigation; exercise the update/check-for-updates workflow during capture for best coverage.'],width
        )
        run_lines += ['SUMMARY','-'*width]
        for key,label in [('file_writes','File writes'),('registry_writes','Registry writes'),('network_activity','Network events'),('process_activity','Process events')]: run_lines.append(kv(label,len(runtime.get(key,[]))))
        for key,label in [('process_activity','PROCESS ACTIVITY'),('file_writes','FILE WRITES'),('registry_writes','REGISTRY WRITES'),('network_activity','NETWORK ACTIVITY')]:
            run_lines += section(label,width,len(runtime.get(key,[])))
            if not runtime.get(key): run_lines.append('None captured.')
            for idx,e in enumerate(runtime.get(key,[]),1):
                run_lines.append(f"[{idx:04d}] {e.get('Process')} | {e.get('Operation')} | {e.get('Result')} | {e.get('Path')}")
        (artifact_path(assessment_dir, 'updater_runtime_activity.txt')).write_text('\n'.join(run_lines).rstrip()+'\n',encoding='utf-8')
        created_supporting.append('updater_runtime_activity.txt')

        ep_lines=header(
            'Windows Client Assessment - Updater Endpoint Candidates',
            ['Lists Procmon network events associated with updater/maintenance processes.', 'Protocol/TLS semantics are not inferred from Procmon alone; validate endpoints with Wireshark/Burp or approved protocol tooling.'],width
        )
        ep_lines += ['SUMMARY','-'*width,kv('Collection State','OBSERVED' if endpoints else 'COLLECTED / NO OBSERVATION'),kv('Endpoint/network events',len(endpoints)),kv('Transport semantics','UNKNOWN_FROM_PROCMON')]
        if not endpoints: ep_lines += ['','No updater-associated network events were captured during the available Procmon evidence.']
        for idx,e in enumerate(endpoints,1):
            ep_lines += ['',f"[UPD-ENDPOINT-{idx:03d}]",'-'*width,kv('Process',e.get('Process')),kv('Operation',e.get('Operation')),kv('Path/Endpoint',e.get('Path')),kv('Result',e.get('Result')),kv('Detail',e.get('Detail'))]
        (artifact_path(assessment_dir, 'updater_endpoint_candidates.txt')).write_text('\n'.join(ep_lines).rstrip()+'\n',encoding='utf-8')
        created_supporting.append('updater_endpoint_candidates.txt')

    # Main correlation report.
    lines=header(
        'Windows Client Assessment - Updater Security Review',
        [
            'Correlates updater/maintenance candidates with privilege, signing, ACLs, staging/configuration, and runtime activity.',
            'POI-UP records are manual validation targets and are NOT automatically confirmed vulnerabilities.',
        ],width
    )
    lines += ['SUMMARY','-'*width,kv('Updater candidates',len(candidates)),kv('Privileged candidates',sum(1 for c in candidates if c.get('Privileged'))),kv('Staging/config artifacts',len(artifact_records)),kv('Updater runtime events',runtime_event_count),kv('Updater network events',len(endpoints)),kv('Runtime workflow observed',not runtime_coverage_gap if has_procmon_evidence else 'No Procmon evidence'),kv('POI-UP review points',len(pois))]
    if runtime_coverage_gap:
        lines += section('Runtime Coverage Gap',width)
        lines += [
            'Procmon evidence was available, but no updater/maintenance process events were captured.',
            'The update/check workflow was therefore not exercised or not observed. Package download, staging,',
            'signature enforcement, privileged handoff, and downgrade behavior remain unvalidated.',
        ]
    lines += section('Recommended Validation Workflow',width)
    lines += [
        '1. Identify how the updater is launched and whether it crosses a user-to-service/SYSTEM boundary.',
        '2. Validate updater binary and parent-directory effective permissions as a standard user.',
        '3. Trigger an authorized update/check workflow while Procmon and network tooling are collecting evidence.',
        '4. Identify download/staging paths and attempt only safe, authorized package/config substitution tests.',
        '5. Determine whether the updater cryptographically authenticates the package before privileged execution/install.',
        '6. Test downgrade/rollback/version-selection behavior using vendor-supported or assessment-approved packages.',
        '7. Report only when a lower-privileged or network-controlled input demonstrably influences trusted privileged update behavior.',
    ]
    lines += section('Points of Interest',width,len(pois))
    if not pois: lines.append('No updater trust-boundary POIs were generated automatically.')
    for poi in pois:
        lines += ['', '='*width, f"[{poi['POI']}] {poi['Issue']}", '='*width,kv('Confidence',poi['Confidence']),kv('Category',poi['Category']),kv('Candidate',poi['Candidate'] or 'N/A'),kv('Privileged',bool_text(poi['Privileged'])),kv('Path',poi['Path']),kv('Evidence',poi['Evidence']), 'Recommended Test:', '  Validate effective access/control from the intended lower-privileged or network context and determine whether the condition changes trusted update behavior.']
    lines += section('Supporting Output Files',width)
    descriptions = {
        'updater_components.txt':'candidate and privilege/launch-context index',
        'updater_signature_review.txt':'Authenticode state for updater components',
        'updater_permissions.txt':'updater binary/parent ACL review',
        'updater_staging_review.txt':'package/config/staging artifacts and ACL context',
        'updater_runtime_activity.txt':'Procmon events filtered to updater processes',
        'updater_endpoint_candidates.txt':'updater-associated network events',
    }
    for filename in created_supporting:
        lines.append(f"{filename:<34} - {descriptions.get(filename,'supporting evidence')}")
    (artifact_path(assessment_dir, 'updater_security_review.txt')).write_text('\n'.join(lines).rstrip()+'\n',encoding='utf-8')

    data={
        'Description':'Updater/maintenance trust-boundary correlation generated by Windows Client Assessment.',
        'Mode':mode,
        'Evidence':{
            'FilesystemDifferential':has_filesystem_evidence,
            'Procmon':has_procmon_evidence,
        },
        'CreatedSupportingArtifacts':created_supporting,
        'Candidates':candidates,'Artifacts':artifact_records,'RuntimeActivity':runtime,'EndpointCandidates':endpoints,'PointsOfInterest':pois,
    }
    findings=[]
    if pois:
        findings.append({
            'title':'Updater / Maintenance Trust Boundaries Require Manual Validation',
            'severity':'Informational',
            'description':'Windows Client Assessment correlated updater/maintenance components with one or more signing, permission, staging, or privilege-boundary conditions that warrant manual validation.',
            'evidence':f"{len(pois)} POI-UP review point(s) generated.",
            'recommendation':'Validate package authenticity enforcement, effective permissions, privileged handoff, staging controls, endpoint behavior, and downgrade/rollback resistance before reporting a vulnerability.',
        })
    if runtime_coverage_gap:
        findings.append({
            'title':'Updater Workflow Was Not Observed During Runtime Capture',
            'severity':'Informational',
            'description':'Procmon evidence was collected, but no events from an updater/maintenance candidate were captured; updater security behavior remains untested.',
            'evidence':f"{len(candidates)} updater candidate(s); 0 correlated updater runtime events.",
            'recommendation':'Trigger an authorized update/check workflow while collecting Procmon and network evidence, then validate staging ACLs, package signature enforcement, privileged handoff, and downgrade resistance.',
        })
    return {'status':'WARN' if pois or runtime_coverage_gap else 'PASS','details':f"{len(candidates)} updater candidate(s); {len(pois)} POI-UP review point(s); {runtime_event_count} runtime event(s)",'findings':findings,'updater_security':data,'updater_pois':pois,'coverage_gap':runtime_coverage_gap}
