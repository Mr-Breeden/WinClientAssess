"""WCA layered, privacy-preserving secret discovery and evidence triage.

A candidate is not a vulnerability. Raw candidate values are never retained in
returned result objects or assessment artifacts; the tester can inspect the
verified original source transiently using TC-CF-001.
"""
from utils.assessment_layout import artifact_path
from pathlib import Path
import re
from collections import Counter, defaultdict
from utils.report_format import header, section, kv
from utils.text_utils import newline_offsets, line_number
from utils.privacy import sanitize_report_text
from utils.credential_classifier import credential_field, evidence_reason
from utils.structured_secret_validator import pem_candidates, MAX_PEM_BYTES
from utils.secret_candidate_scoring import candidate_confidence
from modules.pe_analysis import _has_pe_header

TEXT_EXTS={'.env','.config','.json','.xml','.ini','.yaml','.yml','.toml','.properties','.conf','.cfg','.txt','.ps1','.bat','.cmd','.vbs','.js','.cs','.vb','.pem','.key','.p8'}
ASSIGN=re.compile(r'(?im)(?P<key>[A-Za-z_][\w.-]{0,85})\s*[:=]\s*["\']?(?P<value>[^"\'\s<>\r\n]{4,4096})')
XML=re.compile(r'(?is)<(?P<key>[A-Za-z_][\w.-]{0,80})\s*>\s*(?P<value>[^<\r\n]{4,4096}?)\s*</(?P=key)\s*>')
JSON=re.compile(r'(?i)"(?P<key>[A-Za-z_][\w.-]{0,85})"\s*:\s*"(?P<value>[^"\r\n]{4,4096})"')
BEARER=re.compile(r'(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}')
AWS=re.compile(r'\bAKIA[0-9A-Z]{16}\b')
CONN=re.compile(r'(?i)(?:Server|Data Source)\s*=[^\r\n]{0,200}?(?:Password|Pwd)\s*=\s*[^\r\n;]{4,}')
_ASCII_STRING=re.compile(rb'[\x20-\x7e]{5,}')
_UTF16LE_STRING=re.compile(rb'(?:[\x20-\x7e]\x00){5,}')
MAX_TEXT_BYTES=10*1024*1024
MAX_PE_BYTES=50*1024*1024
MAX_MATCHES=1000
MAX_TEXT_MATCHES=600
MAX_PE_MATCHES=400
MAX_PE_MATCHES_PER_IMAGE=60
MAX_PE_MATCHES_PER_IMAGE_TYPE=18


def _eligible_text(path):
    name=path.name.casefold()
    return (path.suffix.casefold() in TEXT_EXTS or name=='.env'
            or name.startswith('.env.') or name.startswith('.env-'))


def _iter(roots):
    seen=set()
    for root in roots or ():
        p=Path(root)
        items=[p] if p.is_file() else (p.rglob('*') if p.is_dir() else [])
        for item in items:
            try: size=item.stat().st_size
            except OSError: continue
            if item.is_file() and _eligible_text(item) and 0<size<=MAX_TEXT_BYTES:
                key=str(item.resolve())
                if key not in seen:seen.add(key);yield item


def _inventory_paths(roots, file_inventory):
    if file_inventory is not None:
        paths=[Path(row['path']) for row in file_inventory if row.get('path')]
    else:
        paths=[]
        for root in roots or ():
            p=Path(root)
            if p.is_file():paths.append(p)
            elif p.is_dir():paths.extend(item for item in p.rglob('*') if item.is_file())
    out=[];seen=set()
    for path in paths:
        key=str(path).casefold()
        if key not in seen:seen.add(key);out.append(path)
    return out


def _is_credential_field(name,value):
    return credential_field(name,value)


def _candidate(label,path,location_type,location,encoding,*,line=None,meta=None):
    meta=meta or {}
    validation=meta.get('validation','PLAUSIBLE' if label not in ('Private key marker',) else 'MARKER_ONLY')
    return {'type':label,'path':str(path),'location_type':location_type,
            'location':str(location),'line':line,'encoding':encoding,
            'redacted':'[REDACTED]','confidence':candidate_confidence(label,validation),
            'validation':validation,'reason':evidence_reason(label,validation=validation),
            'algorithm':meta.get('algorithm',''),'key_bits':meta.get('key_bits',''),
            'public_fingerprint':meta.get('public_fingerprint',''),
            'block_length':meta.get('block_length',0),'column':meta.get('column',0)}


def _plain_candidates(text, *, format_hint='', metrics=None):
    """Yield validated name/value and syntax matches; no generic HTML matches."""
    if format_hint in ('xml','config','pe','text'):
        for m in XML.finditer(text):
            if credential_field(m['key'],m['value']):
                yield 'XML credential element',m.start(),m.end()
            elif metrics is not None:metrics['noncredential_markup_suppressed']+=1
    if format_hint in ('json','pe','text'):
        for m in JSON.finditer(text):
            if credential_field(m['key'],m['value']):
                yield 'JSON credential property',m.start(),m.end()
            elif metrics is not None:metrics['noncredential_json_suppressed']+=1
    for m in ASSIGN.finditer(text):
        # Avoid matching the second colon in C++ scope operators as an assignment.
        if m.start('value') > 0 and text[m.start('value')-1:m.start('value')] == ':':
            continue
        if credential_field(m['key'],m['value']):
            yield 'Named credential assignment',m.start(),m.end()
        elif metrics is not None and any(word in m['key'].lower() for word in ('secret','password','token','key')):
            metrics['placeholder_or_public_assignment_suppressed']+=1
    for label,pattern in (('Bearer token',BEARER),('AWS access key',AWS),('Connection string',CONN)):
        for m in pattern.finditer(text):yield label,m.start(),m.end()


def _key_blocks(blob,path,location_type,*,text=None):
    for offset,end,label,meta in pem_candidates(blob):
        # A naked PEM marker or invalid block is parser syntax, not an embedded key.
        if label == 'MARKER' or meta.get('validation') in ('INVALID_OR_UNSUPPORTED', 'TOO_LARGE'):
            continue
        typ=('Private key marker' if label=='MARKER' else
             'Encrypted private key' if label=='ENCRYPTED PRIVATE KEY' else 'Structured private key')
        meta={**meta,'block_length':end-offset if label!='MARKER' else 0}
        if location_type=='Text line':
            line_start=blob.rfind(b'\n',0,offset)+1
            meta['column']=offset-line_start+1
        if location_type=='Text line':
            if text is None:continue
            line=text.count('\n',0,len(blob[:offset].decode('utf-8',errors='replace')))+1
            yield _candidate(typ,path,location_type,line,'Text',line=line,meta=meta)
        else:
            yield _candidate(typ,path,location_type,f'0x{offset:X}','ASCII',meta=meta)


def _text_matches(source_files,matches,metrics=None):
    truncated=False
    for path in sorted(source_files,key=lambda p:str(p).casefold()):
        if len(matches)>=MAX_TEXT_MATCHES:return True
        try:
            blob=path.read_bytes()
            utf16=blob.startswith((b'\xff\xfe',b'\xfe\xff')) or (len(blob)>20 and blob[:2048].count(b'\x00')>len(blob[:2048])//5)
            encoding='UTF-16LE' if utf16 else 'Text'
            text=blob.decode('utf-16' if blob.startswith((b'\xff\xfe',b'\xfe\xff')) else 'utf-16le', errors='replace') if utf16 else blob.decode('utf-8',errors='replace')
        except OSError:continue
        starts=newline_offsets(text)
        seen=set()
        # Complete keys are classified first; a bare opening marker is not a verified key.
        for candidate in _key_blocks(text.encode('utf-8') if utf16 else blob,path,'Text line',text=text):
            candidate['encoding']=encoding
            key=(candidate['type'],candidate['location'],candidate['public_fingerprint'])
            if key not in seen:
                matches.append(candidate);seen.add(key)
            if len(matches)>=MAX_TEXT_MATCHES:return True
        suffix=path.suffix.lower()
        hint='xml' if suffix in ('.xml','.config') else 'json' if suffix=='.json' else 'text'
        for label,start,end in _plain_candidates(text,format_hint=hint,metrics=metrics):
            line=line_number(starts,start)
            key=(label,line,start)
            if key in seen:continue
            seen.add(key)
            matches.append(_candidate(label,path,'Text line',line,encoding,line=line,meta={'column':start-starts[line-1]+1}))
            if len(matches)>=MAX_TEXT_MATCHES:return True
    return truncated


def _pe_matches(paths,matches,stats=None,metrics=None):
    scanned=0;binary_matches=0;truncated=False
    for path in paths:
        if binary_matches>=MAX_PE_MATCHES or len(matches)>=MAX_MATCHES:
            truncated=True;break
        try:
            size=path.stat().st_size
            if not 0<size<=MAX_PE_BYTES or not _has_pe_header(path):continue
            blob=path.read_bytes()
        except (OSError,ValueError):continue
        scanned+=1
        file_count=0;file_types=Counter();seen=set()
        # Reserve attention for complete structured keys before noisy printable strings.
        for candidate in _key_blocks(blob,path,'PE file offset'):
            label=candidate['type'];loc=candidate['location']
            if (file_count>=MAX_PE_MATCHES_PER_IMAGE or binary_matches>=MAX_PE_MATCHES
                    or len(matches)>=MAX_MATCHES):truncated=True;break
            if (label,loc) in seen:continue
            matches.append(candidate);seen.add((label,loc));binary_matches+=1
            file_count+=1;file_types[label]+=1
        if file_count>=MAX_PE_MATCHES_PER_IMAGE:continue
        for encoding,regexp in (('ASCII',_ASCII_STRING),('UTF-16LE',_UTF16LE_STRING)):
            for sm in regexp.finditer(blob):
                if file_count>=MAX_PE_MATCHES_PER_IMAGE or binary_matches>=MAX_PE_MATCHES or len(matches)>=MAX_MATCHES:
                    truncated=True;break
                content=sm.group()
                decoded=content.decode('ascii' if encoding=='ASCII' else 'utf-16le',errors='ignore')
                # Each string produces at most one candidate; skip bare key markers
                # already handled by the complete/marker parser above.
                for label,start,end in _plain_candidates(decoded,format_hint='pe',metrics=metrics):
                    if file_types[label]>=MAX_PE_MATCHES_PER_IMAGE_TYPE:continue
                    offset=sm.start() + start*(2 if encoding=='UTF-16LE' else 1)
                    where=f'0x{offset:X}'
                    if (label,where) in seen:continue
                    seen.add((label,where))
                    matches.append(_candidate(label,path,'PE file offset',where,encoding))
                    binary_matches+=1;file_count+=1;file_types[label]+=1
                    break
            if file_count>=MAX_PE_MATCHES_PER_IMAGE:break
    if stats is not None:stats['truncated']=truncated
    return scanned


def run_secrets_review(roots,assessment_dir,file_inventory=None,application_scope=None):
    matches=[]
    all_paths=_inventory_paths(roots,file_inventory)
    if file_inventory is not None:
        sizes={str(row.get('path') or '').casefold():int(row.get('size_bytes') or 0)
               for row in file_inventory if row.get('path')}
        source_files=[p for p in all_paths if _eligible_text(p) and
                      0<sizes.get(str(p).casefold(),MAX_TEXT_BYTES+1)<=MAX_TEXT_BYTES]
    else:source_files=list(_iter(roots))
    suppressions=Counter()
    truncated_text=_text_matches(source_files,matches,metrics=suppressions)
    scope=application_scope or {}
    primary_roots=scope.get('roots') or []
    primary_stem=Path(primary_roots[0]).stem.casefold() if primary_roots else ''
    sidecars={Path(item).stem.casefold() for item in scope.get('sidecars') or []}
    def priority(path):
        name=path.stem.casefold()
        framework=name.startswith(('system.','microsoft.','runtime.','presentation')) or name in {'mscorlib','netstandard','accessibility'}
        first=name in sidecars or bool(primary_stem and (name==primary_stem or name.startswith(primary_stem+'.')))
        return (0 if first else 2 if framework else 1,str(path).casefold())
    scan_stats={}
    pe_scanned=_pe_matches(sorted(all_paths,key=priority),matches,stats=scan_stats,metrics=suppressions) if len(matches)<MAX_MATCHES else 0
    truncated_pe=scan_stats.get('truncated',False) or len(matches)>=MAX_MATCHES
    counts=Counter(m['type'] for m in matches)
    text_count=sum(m['location_type']=='Text line' for m in matches)
    binary_count=len(matches)-text_count
    fingerprints=Counter(m['public_fingerprint'] for m in matches if m['public_fingerprint'])
    width=112
    lines=header('Windows Client Assessment - Secrets / Sensitive String Review',[
        'Layered credential triage: field classification, structured PEM parsing, and PE printable-string analysis.',
        'Original values are NOT persisted. Tester-only TC-CF-001 may retrieve the verified source transiently.',
        'Valid secret format is not proof of a usable credential or a security vulnerability.',
    ],width)
    lines+=['SUMMARY','-'*width,kv('Potential matches',len(matches)),
            kv('Text-file matches',text_count),kv('PE printable-string matches',binary_count),
            kv('PE images string-triaged',pe_scanned),
            kv('Validated private keys',sum(m['validation']=='VALID_KEY' for m in matches)),
            kv('Noncredential markup suppressed',suppressions.get('noncredential_markup_suppressed',0)),
            kv('Public/placeholder assignments suppressed',suppressions.get('placeholder_or_public_assignment_suppressed',0)),
            kv('Repeated public-key fingerprints',sum(n>1 for n in fingerprints.values())),
            kv('Scan budgets',f'text {MAX_TEXT_MATCHES}; PE {MAX_PE_MATCHES}; per image {MAX_PE_MATCHES_PER_IMAGE}'),
            kv('Collection truncated', 'YES - review coverage limitations' if (truncated_pe or truncated_text) else 'NO'),
            'No candidate represents a confirmed vulnerability without tester validation.']
    for name,count in counts.most_common():lines.append(kv(name+' indicators',count))
    lines+=section('Recommended Validation',width)
    lines+=['1. Review structurally validated private keys first; separate key validity from exploitability.',
            '2. Use the tester-only indicator browser to view the complete original value and exact location.',
            '3. Review credential-field assignments and corroborate actual use in application code/configuration.',
            '4. Suppressed HTML/Qt markup, common placeholders, and public identifiers are not secret findings.',
            '5. Record validated impact separately; tester decisions and notes remain optional.',
            '6. If collection was truncated, consider targeted manual inspection of excluded files.']
    by_type=defaultdict(list)
    for m in matches:by_type[m['type']].append(m)
    ids={id(item):idx for idx,item in enumerate(matches,1)}
    for label in sorted(by_type):
        items=by_type[label]
        lines+=section(label,width,len(items))
        for m in items:
            lines.extend([f"[SECRET-{ids[id(m)]:03d}] Confidence={m['confidence']}",
                          kv('File',sanitize_report_text(m['path']),18,'  '),
                          kv('Line' if m['line'] else 'PE file offset',m['location'],18,'  '),
                          kv('String encoding',m['encoding'],18,'  '),
                          kv('Validation',m['validation'],18,'  '),
                          kv('Detection reason',m['reason'],18,'  ')])
            if m['column']:lines.append(kv('Column',m['column'],18,'  '))
            if m['algorithm']:lines.append(kv('Key algorithm',m['algorithm'],18,'  '))
            if m['key_bits']:lines.append(kv('Key bits',m['key_bits'],18,'  '))
            if m['public_fingerprint']:
                lines.append(kv('Public key SHA-256',m['public_fingerprint'],18,'  '))
                if fingerprints[m['public_fingerprint']]>1:
                    lines.append(kv('Public key occurrences',fingerprints[m['public_fingerprint']],18,'  '))
            if m['block_length']:lines.append(kv('PEM block length',m['block_length'],18,'  '))
            lines.extend([kv('Match','[REDACTED]',18,'  '),''])
    artifact_path(assessment_dir,'secrets_review.txt').write_text('\n'.join(lines).rstrip()+'\n',encoding='utf-8')
    actionable=[m for m in matches if m['confidence'] in ('HIGH','MEDIUM')]
    findings=[]
    if actionable:
        findings.append({'title':'Potential Embedded Secrets Require Validation','severity':'Informational',
                         'description':'Credential-like assignments or structured cryptographic material observed; all values redacted.',
                         'evidence':f'{len(actionable)} medium/high-confidence potential secret indicator(s); validation and impact remain distinct.',
                         'recommendation':'Validate candidate relevance, reusability and impact locally before reporting.'})
    return {'status':'WARN' if actionable or truncated_pe or truncated_text else 'PASS',
            'details':f'{len(matches)} candidate(s); {binary_count} PE; {len(actionable)} medium/high; scan truncated={truncated_text or truncated_pe}',
            'findings':findings,'matches':matches,'pe_images_scanned':pe_scanned}
