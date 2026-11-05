"""Integrity-gated, tester-only display of original secret evidence.

Raw values are not persisted or sent in URLs. The browser request loads one
verified assessment-owned source on demand. The original payload is unmodified.
"""
from __future__ import annotations
import re
from pathlib import Path
from utils.assessment_integrity import verify_assessment
from utils.privacy import sanitize_report_text
from utils.structured_secret_validator import pem_candidates, MAX_PEM_BYTES
from modules.secrets_review import _plain_candidates, ASSIGN, XML, JSON

_RE=re.compile(r'^\[(SECRET-\d+)\]\s+Confidence=(\w+)',re.I)
_FIELD=re.compile(r'^\s+(File|PE file offset|Line number|Line|String encoding|Validation|Detection reason|Key algorithm|Key bits|Public key SHA-256|PEM block length|Column)\s*:\s*(.+)$',re.I)
_MAX_INDICATORS=1000


def parse_indicators(text:str)->list[dict]:
    rows=[];group='Other'
    fields={'file':'file','pe file offset':'offset','string encoding':'encoding',
            'validation':'validation','detection reason':'reason','key algorithm':'algorithm',
            'key bits':'key_bits','public key sha-256':'public_fingerprint',
            'pem block length':'block_length','column':'column'}
    for line in text.splitlines():
        m=_RE.match(line.strip())
        if m:
            if len(rows)>=_MAX_INDICATORS:break
            rows.append({'id':m[1],'confidence':m[2].upper(),'type':group,
                         'file':'','offset':'','line':None,'encoding':'','validation':'UNVALIDATED',
                         'reason':'Pattern matched; confirm relevance before reporting.',
                         'algorithm':'','key_bits':'','public_fingerprint':'','block_length':0,'column':0})
            continue
        f=_FIELD.match(line)
        if f and rows:
            key=f[1].lower();value=f[2].strip();row=rows[-1]
            if key in ('line','line number'):
                num=re.search(r'\d+',value)
                if num:row['line']=int(num[0])
            elif key in fields:
                dest=fields[key]
                if dest in ('block_length','column'):
                    row[dest]=int(value) if value.isdecimal() else 0
                else:row[dest]=sanitize_report_text(value)[:650]
        elif line and not line.startswith(' ') and re.search(r'\(\d+\)\s*$',line):
            group=line.rsplit('(',1)[0].strip().title()[:90]
    return rows


def _owned_source(root:Path,redacted_path:str)->Path|None:
    match=re.search(r'(?i)(?:^|\\)working\\extracted_installer\\(.+)$',redacted_path)
    if not match:return None
    parts=match[1].split('\\')
    if not parts or any(x in ('','.','..') or ':' in x or '/' in x for x in parts):return None
    base=root/'working'/'extracted_installer'
    target=base.joinpath(*parts)
    if any(p.is_symlink() for p in (target,*target.parents) if p != root and root in p.parents):
        return None
    if not target.is_file() or base.resolve() not in target.resolve().parents:
        return None
    return target


def _verified_indicator(root:Path,identifier:str):
    rows=indicator_list(root)
    row=next((r for r in rows if r['id']==identifier),None)
    if row is None:raise ValueError('Indicator not found in integrity-verified assessment.')
    return row,_owned_source(root,row['file'])


def indicator_list(root:Path)->list[dict]:
    if verify_assessment(root).get('status')!='PASS':
        raise ValueError('Assessment integrity must be PASS to inspect indicator references.')
    report=root/'reports'/'secrets_review.txt'
    if report.is_symlink() or not report.is_file() or report.stat().st_size>3_000_000:return []
    return parse_indicators(report.read_text(encoding='utf-8',errors='replace'))


def indicator_source_path(root:Path,identifier:str)->Path:
    row,path=_verified_indicator(root,identifier)
    if path is None:raise ValueError('Original source is not a verified assessment-owned extracted file.')
    return path


def _scalar_value(fragment:str,label:str)->str:
    if label in ('Named credential assignment','Generic secret assignment','Generic password assignment'):
        m=ASSIGN.search(fragment)
        if m:return m['value']
    if label=='XML credential element':
        m=XML.search(fragment)
        if m:return m['value']
    if label=='JSON credential property':
        m=JSON.search(fragment)
        if m:return m['value']
    if label=='Bearer token':return fragment.split(None,1)[-1]
    return fragment


def _pem_at(blob:bytes,*,offset:int|None=None,line:int|None=None):
    for start,end,label,meta in pem_candidates(blob):
        if offset is not None and start!=offset:continue
        if line is not None and blob.count(b'\n',0,start)+1!=line:continue
        # Reveal full original key block, not just its opening marker.
        return blob[start:end].decode('utf-8',errors='replace'), meta
    return None


def _string_context(blob:bytes,offset:int,encoding:str)->tuple[str,str]:
    start=max(0,offset-32768)
    end=min(len(blob),offset+MAX_PEM_BYTES)
    window=blob[start:end]
    regexp=(re.compile(rb'(?:[\x20-\x7e]\x00){4,}') if encoding.upper()=='UTF-16LE'
            else re.compile(rb'[\x20-\x7e]{4,}'))
    stride=2 if encoding.upper()=='UTF-16LE' else 1
    strings=[];selected=None
    for match in regexp.finditer(window):
        absolute=start+match.start()
        text=match.group().decode('utf-16le' if stride==2 else 'ascii',errors='replace')
        strings.append((absolute,text))
        if absolute<=offset<start+match.end():selected=len(strings)-1
    if selected is None:
        return f'PE offset 0x{offset:X}: no matching printable string in bounded window.', ''
    excerpt=[]
    for address,value in strings[max(0,selected-10):selected+11]:
        excerpt.append(f'0x{address:X}  {value[:700]}')
    address,text=strings[selected]
    target_index=(offset-address)//stride
    exact=''
    for label,mstart,mend in _plain_candidates(text,format_hint='pe'):
        if mstart==target_index:
            exact=_scalar_value(text[mstart:mend],label)
            break
    return '\n'.join(excerpt),exact or text


def indicator_context(root:Path,identifier:str,*,reveal:bool=True)->dict:
    row,path=_verified_indicator(root,identifier)
    result={k:row[k] for k in ('id','file','offset','line','column','confidence','type','validation','reason','algorithm','key_bits','public_fingerprint')}
    result['revealed']=bool(reveal)
    if path is None:
        result.update(status='MANUAL',context='The source is external or unavailable within verified extracted evidence.',original_value='',source_path='')
        return result
    result['source_path']=str(path)
    if row['line'] is not None:
        if path.stat().st_size>10_000_000:raise ValueError('Text file exceeds bounded inspection limit.')
        blob=path.read_bytes()
        utf16=row['encoding']=='UTF-16LE'
        text=blob.decode('utf-16' if blob.startswith((b'\xff\xfe',b'\xfe\xff')) else 'utf-16le',errors='replace') if utf16 else blob.decode('utf-8',errors='replace')
        lines=text.splitlines()
        number=row['line']
        if not 0<number<=len(lines):
            result.update(status='NOT_PRESENT',context='Recorded source line not found.',original_value='');return result
        value=''
        if 'private key' in row['type'].casefold():
            parsed=_pem_at(text.encode('utf-8') if utf16 else blob,line=number)
            if parsed:
                value,info=parsed
                if result['validation']=='UNVALIDATED':
                    result.update(validation=info['validation'],algorithm=info['algorithm'],
                                  key_bits=info['key_bits'],public_fingerprint=info['public_fingerprint'])
        if not value:
            target=lines[number-1];col=max(0,row['column']-1)
            for label,start,end in _plain_candidates(target,format_hint='text'):
                if (row['column'] and start!=col) or label.casefold()!=row['type'].casefold():continue
                value=_scalar_value(target[start:end],label);break
            if not value:value=target
        begin=max(0,number-11);finish=min(len(lines),number+10)
        context='\n'.join(f'{i+1:>6} {lines[i][:3000]}' for i in range(begin,finish))
        result.update(status='OBSERVED',context=context if reveal else '[REDACTED]',
                      original_value=value[:MAX_PEM_BYTES] if reveal else '')
        return result
    try:offset=int(row['offset'],16)
    except (TypeError,ValueError):
        result.update(status='MANUAL',context='No usable PE offset recorded.',original_value='');return result
    if not 0<=offset<path.stat().st_size:
        result.update(status='NOT_PRESENT',context='Offset outside verified file.',original_value='');return result
    # Bounded read around the precise offset; no whole-binary reanalysis on selection.
    begin=max(0,offset-1024);length=min(MAX_PEM_BYTES+2048,path.stat().st_size-begin)
    with path.open('rb') as handle:
        handle.seek(begin);blob=handle.read(length)
    key=_pem_at(blob,offset=offset-begin) if 'private key' in row['type'].casefold() else None
    if key is not None:
        value,info=key
        if result['validation']=='UNVALIDATED':
            result.update(validation=info['validation'],algorithm=info['algorithm'],
                          key_bits=info['key_bits'],public_fingerprint=info['public_fingerprint'])
        context=f'Complete {row["type"]} block at PE file offset 0x{offset:X}; metadata verified during collection.'
    else:
        context,value=_string_context(blob,offset-begin,row.get('encoding','ASCII'))
        # Relative window must be converted to absolute offset for readability.
        context=re.sub(r'(?m)^0x([0-9A-Fa-f]+)\s+',lambda m:f'0x{int(m[1],16)+begin:X}  ',context)
    result.update(status='OBSERVED',context=context if reveal else '[REDACTED]',
                  original_value=value if reveal else '')
    return result
