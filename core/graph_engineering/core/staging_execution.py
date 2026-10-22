"""Closed, charged stage records and platform-neutral installed projections."""
from __future__ import annotations
import base64
import hashlib
import json
import math
import posixpath
import re
from graph_engineering.core.release_installation import (
    closed,measure,token,digest,integer,ordered,strings,portable_path,version,fail,CODES,
)
from graph_engineering.core.release_staging import stage_digest
from graph_engineering.core.contracts.resources import WorkContext

RECORD_FIELDS={
 'installed-release-manifest':('schema_version','release_id','platform','interpreter_identity','distributions','skills','lock_digest','sbom_digest','security_evidence_digest','policy_digest','installed_manifest_digest'),
 'installation-binding':('schema_version','installation_id','request_id','plan_digest','stage_context_digest','candidate_identity','interpreter_binding','installer_binding','files','binding_digest'),
 'stage-receipt':('schema_version','request_id','plan_digest','release_manifest_digest','stage_context_digest','installed_manifest_digest','binding_digest','execution_binding_digest','status','receipt_digest'),
 'stage-execution-binding':('schema_version','installation_id','request_id','operation','plan_digest','stage_context_digest','envelope_digest','challenge_digest','execution_binding_digest'),
 'stage-generated-template':('schema_version','logical_path','kind','segments','template_digest'),
 'stage-execution-diagnostic':('schema_version','request_id','status','phase','code','checks','refs','capabilities','next_route','diagnostic_digest'),
}
DIGEST_FIELDS={k:v[-1] for k,v in RECORD_FIELDS.items()}
CAPABILITIES={'install-plan':'available','install-apply':'stage-only','stage':'available',
    'reopen-staged':'local-authority-only','release':'unavailable'}

def canonical(value: object) -> bytes:
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()

def seal(kind: str,body: dict[str,object],context: WorkContext) -> dict[str,object]:
    field=DIGEST_FIELDS[kind];value={k:v for k,v in body.items() if k!=field}
    value[field]=stage_digest(kind,value,context)
    return validate_record(kind,value,context)

def _unsigned(value):
    if type(value) is not str or re.fullmatch(r'0|[1-9][0-9]{0,19}',value) is None:fail()

def _raw(value):
    if type(value) is not str or re.fullmatch('[0-9a-f]{64}',value) is None:fail()

def _mode(value):
    integer(value)
    if value>0o777 or value&0o022:fail()

def _ancestor(value):
    closed(value,('device','inode','mode','owner_id'))
    for k in ('device','inode','owner_id'):_unsigned(value[k])
    _mode(value['mode'])

def _physical(value):
    closed(value,('device','inode','owner_id','mtime_ns','ctime_ns','ancestors'))
    for k in ('device','inode','owner_id','mtime_ns','ctime_ns'):_unsigned(value[k])
    if type(value['ancestors']) is not list or not value['ancestors']:fail()
    for a in value['ancestors']:_ancestor(a)

def _file(value,*,executable=False):
    fields=('logical_path','raw_sha256','size_bytes','mode','physical_identity') if executable else ('logical_path','kind','raw_sha256','size_bytes','mode','physical_identity')
    closed(value,fields);portable_path(value['logical_path']);integer(value['size_bytes']);_mode(value['mode']);_physical(value['physical_identity'])
    if executable or value['kind']=='file':
        _raw(value['raw_sha256'])
        if executable and not value['mode']&0o100:fail()
    elif value['kind']!='directory' or value['raw_sha256'] is not None or value['size_bytes']!=0 or value['mode']!=0o700:fail()

def validate_template(value: object,context: WorkContext) -> dict[str,object]:
    measure(value,context);closed(value,RECORD_FIELDS['stage-generated-template'])
    if value['schema_version']!='1.0.0':fail()
    portable_path(value['logical_path'])
    if not value['logical_path'].startswith('payload/tool/') or value['kind'] not in ('launcher','script','RECORD'):fail()
    segments=value['segments']
    if type(segments) is not list:fail()
    if value['kind']=='RECORD':
        if segments or not value['logical_path'].endswith('.dist-info/RECORD'):fail()
    elif not segments:
        if value['kind']!='script' or not value['logical_path'].endswith('.dist-info/REQUESTED'):fail()
    else:
        for s in segments:
            if type(s) is not dict:fail()
            if set(s)=={'literal'}:
                text=s['literal']
                if type(text) is not str or not text or any(ord(x)>126 or ord(x)<32 and x not in '\n\t' for x in text):fail()
            elif set(s)=={'ref'}:
                if s['ref'] not in ('interpreter','tool'):fail()
            else:fail()
    digest(value['template_digest'])
    if stage_digest('stage-generated-template',{k:v for k,v in value.items() if k!='template_digest'},context)!=value['template_digest']:fail('trust_rejected')
    return value

def validate_record(kind: str,value: object,context: WorkContext) -> dict[str,object]:
    if kind=='stage-generated-template':return validate_template(value,context)
    if kind not in RECORD_FIELDS:fail()
    measure(value,context);closed(value,RECORD_FIELDS[kind])
    if value['schema_version']!='1.0.0':fail()
    for k,v in value.items():
        if k.endswith('_digest'):digest(v)
    for k in ('release_id','installation_id','request_id'):
        if k in value:token(value[k])
    if kind=='stage-execution-binding':
        if value['operation']!='install':fail()
    elif kind=='stage-receipt':
        if value['status']!='staged':fail()
    elif kind=='installation-binding':
        _ancestor(value['candidate_identity']);_file(value['interpreter_binding'],executable=True);_file(value['installer_binding'],executable=True)
        ordered(value['files'],lambda r:r['logical_path']);check_paths([r['logical_path'] for r in value['files']],allow_directories=True)
        for row in value['files']:_file(row)
    elif kind=='installed-release-manifest':
        closed(value['platform'],('os','architecture','python_abi'))
        for v in value['platform'].values():token(v)
        closed(value['interpreter_identity'],('artifact_id','implementation','patch','build_id','executable_member'))
        for k in ('artifact_id','implementation','build_id'):token(value['interpreter_identity'][k])
        version(value['interpreter_identity']['patch']);portable_path(value['interpreter_identity']['executable_member'])
        ordered(value['distributions'],lambda r:r['name'])
        for row in value['distributions']:
            closed(row,('name','version','wheel_sha256','installed_record_digest'));token(row['name']);version(row['version']);_raw(row['wheel_sha256']);digest(row['installed_record_digest'])
            if row['name']!=re.sub('[-_.]+','-',row['name']).lower():fail()
        ordered(value['skills'],lambda r:(r['runtime_kind'],r['skill_id']))
        for row in value['skills']:
            closed(row,('runtime_kind','skill_id','version','protocol_range','asset_digest'))
            token(row['runtime_kind']);token(row['skill_id']);version(row['version']);digest(row['asset_digest'])
            if type(row['protocol_range']) is not str or not row['protocol_range']:fail()
    elif kind=='stage-execution-diagnostic':
        if value['phase']!='stage' or value['code'] not in (*CODES,'staged') or value['status'] not in ('staged','rejected','blocked'):fail()
        if (value['code']=='staged')!=(value['status']=='staged'):fail()
        if value['capabilities']!=CAPABILITIES:fail()
        strings(value['refs']);token(value['next_route']);ordered(value['checks'],lambda r:r['id'])
        for row in value['checks']:
            closed(row,('id','status','code','ref'));token(row['id']);token(row['ref'])
            if row['status'] not in ('staged','rejected','blocked') or row['code'] not in (*CODES,'staged'):fail()
    field=DIGEST_FIELDS[kind]
    if stage_digest(kind,{k:v for k,v in value.items() if k!=field},context)!=value[field]:fail('trust_rejected')
    return value

def expand_template(value: object,refs: dict[str,str],context: WorkContext) -> bytes:
    validate_template(value,context)
    if set(refs)!={'interpreter','tool'}:fail()
    for text in refs.values():
        if type(text) is not str or not text.startswith('/') or any(ord(c)<32 for c in text):fail()
    if refs['interpreter'] in refs['tool'] or refs['tool'] in refs['interpreter']:fail()
    if value['kind']=='RECORD':fail()
    size=sum(len((s['literal'] if 'literal' in s else refs[s['ref']]).encode('utf-8')) for s in value['segments'])
    context.check_limit('raw_document_bytes',size,source_id='stage-template')
    body=''.join(s['literal'] if 'literal' in s else refs[s['ref']] for s in value['segments']).encode('utf-8')
    return body

def normalize_template(value: object,actual: bytes,refs: dict[str,str],context: WorkContext) -> bytes:
    if type(actual) is not bytes or actual!=expand_template(value,refs,context):fail('closure_mismatch')
    return canonical(value['segments'])

def record_hash(raw: bytes) -> str:return 'sha256='+base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b'=').decode('ascii')

def check_paths(paths: list[str],*,allow_directories: bool=False) -> None:
    seen=set();spellings={}
    for path in paths:
        portable_path(path);folded=path.casefold();parts=path.split('/')
        # Validate implicit directory prefixes as well as complete file paths.
        # Exactly spelled shared namespace directories remain valid.
        for depth in range(1,len(parts)+1):
            prefix='/'.join(parts[:depth]);key=prefix.casefold()
            if key in spellings and spellings[key]!=prefix:fail('closure_mismatch')
            spellings[key]=prefix
        if folded in seen:fail('closure_mismatch')
        seen.add(folded)
    if not allow_directories:
        for path in seen:
            if any('/'.join(path.split('/')[:i]) in seen for i in range(1,len(path.split('/')))):fail('closure_mismatch')

def map_wheel_members(name: str,ver: str,patch: str,members: list[str],context: WorkContext) -> dict[str,str]:
    measure(members,context);version(ver);version(patch)
    normalized=re.sub('[-_.]+','_',name).lower();prefix=normalized+'-'+ver
    site='payload/tool/lib/python'+'.'.join(patch.split('.')[:2])+'/site-packages'
    result={};dist=prefix+'.dist-info';data=prefix+'.data/'
    check_paths(members)
    for path in members:
        first=path.split('/')[0]
        if first.endswith('.dist-info') and first!=dist:fail('closure_mismatch')
        if first.endswith('.data'):
            if not path.startswith(data):fail('closure_mismatch')
            tail=path[len(data):]
            if tail.startswith('purelib/') and len(tail)>8:dest=site+'/'+tail[8:]
            elif tail.startswith('scripts/') and len(tail)>8 and '/' not in tail[8:]:dest='payload/tool/bin/'+tail[8:]
            else:fail('closure_mismatch')
        else:dest=site+'/'+path
        result[path]=dest
    if dist+'/RECORD' not in result:fail('closure_mismatch')
    check_paths(list(result.values()));return result

def record_path(site: str,path: str) -> str:return posixpath.relpath(path,site)

def process_cutoffs(start: float,grant_deadline: float,maximum: float) -> tuple[float,float,float]:
    for x in (start,grant_deadline,maximum):
        if type(x) not in (int,float) or not math.isfinite(x):fail('resource_limit')
    if maximum<=0:fail('resource_limit')
    final=min(grant_deadline,start+maximum);span=final-start
    if span<=0:fail('authority_required')
    return start+span/2,start+3*span/4,final

def process_deadline_outcome(confirmed: bool,original: str) -> str:
    if type(confirmed) is not bool:fail()
    return original if confirmed else 'recovery_blocked'

class StageBudget:
    def __init__(self,policy):self.maximum_bytes=policy['max_stage_bytes'];self.maximum_files=policy['max_stage_files'];self.bytes=0;self.files=0
    def reserve(self,size: int,entries: int) -> None:
        integer(size);integer(entries)
        if self.bytes+size>self.maximum_bytes or self.files+entries>self.maximum_files:fail('resource_limit')
        self.bytes+=size;self.files+=entries

def diagnostic(code: str,request_id: str,context: WorkContext) -> dict[str,object]:
    body={'schema_version':'1.0.0','request_id':request_id,'status':'staged' if code=='staged' else ('blocked' if code in ('recovery_blocked','platform_unavailable','phase_unavailable') else 'rejected'),
        'phase':'stage','code':code,'checks':[],'refs':[],'capabilities':dict(CAPABILITIES),'next_route':'await-activation' if code=='staged' else 'fresh-owner-decision'}
    value=seal('stage-execution-diagnostic',body,context);context.check_limit('result_bytes',len(canonical(value)),source_id='stage-execution-diagnostic');return value
