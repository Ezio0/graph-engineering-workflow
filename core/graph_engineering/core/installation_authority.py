"""Closed charged local approval data; no identity or terminal authority."""
from __future__ import annotations
import hashlib
import json
import re
from graph_engineering.core.contracts.resources import WorkContext
from graph_engineering.core.release_installation import closed,measure,token,digest,integer,fail
from graph_engineering.core.release_staging import stage_digest,validate_envelope
from graph_engineering.core.contracts.canonical import canonical_byte_length

_POLICY_FIELDS=('max_prompt_bytes','max_input_bytes','max_wait_seconds','max_grant_seconds')
_CODES=('authority_issued','input_invalid','authority_required','currentness','resource_limit','trust_rejected','phase_unavailable')
_CAPS=('local-authority','runtime-authority','install-apply','stage','reopen-staged','release')

def _header(value,fields,context):
    measure(value,context);closed(value,('schema_version',*fields))
    if value['schema_version']!='1.0.0':fail()

def _self(value,kind,field,context):
    digest(value[field])
    if stage_digest(kind,{k:x for k,x in value.items() if k!=field},context)!=value[field]:fail('trust_rejected')

def _owner(value):
    if type(value) is not str or re.fullmatch('0|[1-9][0-9]{0,19}',value) is None:fail()

def validate_policy(value: object,context: WorkContext) -> dict[str,object]:
    _header(value,('policy_id',*_POLICY_FIELDS,'policy_digest'),context);token(value['policy_id'])
    for key in _POLICY_FIELDS:integer(value[key],positive=True)
    _self(value,'installation-approval-policy','policy_digest',context);return value

def validate_challenge(value: object,context: WorkContext) -> dict[str,object]:
    _header(value,('request_id','installation_id','operation','plan_digest','context_digest','envelope_digest','policy_digest','owner_id','invocation_nonce','display_digest','challenge_digest'),context)
    for k in ('request_id','installation_id'):token(value[k])
    if value['operation']!='install':fail('phase_unavailable')
    for k in ('plan_digest','context_digest','envelope_digest','policy_digest'):digest(value[k])
    _owner(value['owner_id'])
    if type(value['invocation_nonce']) is not str or re.fullmatch('[0-9a-f]{32}',value['invocation_nonce']) is None:fail()
    if type(value['display_digest']) is not str or re.fullmatch('sha256:[0-9a-f]{64}',value['display_digest']) is None:fail()
    _self(value,'installation-approval-challenge','challenge_digest',context);return value

def render_display(envelope: object,owner: str,targets: object,policy: object,context: WorkContext) -> bytes:
    validate_envelope(envelope,context);validate_policy(policy,context);_owner(owner);measure(targets,context)
    p=envelope['plan'];s=envelope['stage_context']
    rows=[('operation',p['operation']),('installation_id',p['installation_id']),('request_id',p['request_id'])]
    rows.extend((k,p[k]) for k in ('release_manifest_digest','closure_digest','platform_digest','policy_digest','plan_digest'))
    rows.extend([('context_digest',s['context_digest']),('envelope_digest',envelope['envelope_digest']),('approval_policy_digest',policy['policy_digest']),('preserve_data',True),('owner_id',owner)])
    if type(targets) is not list:fail()
    last=None
    for row in targets:
        closed(row,('ref','role','path'));token(row['ref']);token(row['role'])
        if type(row['path']) is not str or not row['path'].startswith('/') or len(row['path'])>1024:fail()
        if last is not None and row['ref']<=last:fail()
        last=row['ref'];rows.append(('target',row))
    body=('Graph Engineering installation approval\n'+''.join(k+': '+json.dumps(v,sort_keys=True,ensure_ascii=True,separators=(',',':'))+'\n' for k,v in rows)
          +'Staging, activation and release have not happened.\n').encode()
    context.check_limit('result_bytes',len(body),source_id='installation-approval-display')
    if len(body)>policy['max_prompt_bytes']:fail('resource_limit')
    return body

def display_digest(body: bytes) -> str:
    if type(body) is not bytes:fail()
    return 'sha256:'+hashlib.sha256(b'urn:gew:display:installation-approval:1.0.0\x00'+body).hexdigest()

def parse_response(raw: bytes,nonce: str,maximum: int) -> bool:
    integer(maximum,positive=True)
    if type(raw) is not bytes or len(raw)>maximum:fail('resource_limit')
    if type(nonce) is not str or re.fullmatch('[0-9a-f]{32}',nonce) is None:fail()
    if raw!=b'APPROVE '+nonce.encode()+b'\n':fail('authority_required')
    return True

def next_state(state: str,event: str) -> str:
    if state not in ('admitted','displayed','decision','issued','consumed','closed'):fail('currentness')
    if event=='close':return 'closed'
    want={('admitted','display'):'displayed',('displayed','decide'):'decision',('decision','issue'):'issued',('issued','consume'):'consumed'}
    if (state,event) not in want:fail('currentness')
    return want[(state,event)]

def validate_diagnostic(value: object,context: WorkContext) -> dict[str,object]:
    _header(value,('request_id','phase','status','code','refs','capabilities','next_route','diagnostic_digest'),context)
    token(value['request_id']);token(value['next_route'])
    if value['phase']!='authorization' or value['code'] not in _CODES:fail()
    issued=value['code']=='authority_issued'
    status='approved' if issued else ('blocked' if value['code'] in ('authority_required','phase_unavailable') else 'rejected')
    if value['status']!=status or value['refs']!=[]:fail()
    if value['capabilities']!={k:'available' if issued and k=='local-authority' else 'unavailable' for k in _CAPS}:fail()
    _self(value,'installation-approval-diagnostic','diagnostic_digest',context);return value

def diagnostic(code: str,context: WorkContext,*,request_id: str='local-approval',maximum: int|None=None) -> dict[str,object]:
    if maximum is None:maximum=context.profile.limits['result_bytes']
    if code not in _CODES:code='trust_rejected'
    token(request_id);integer(maximum,positive=True);issued=code=='authority_issued'
    v={'schema_version':'1.0.0','request_id':request_id,'phase':'authorization',
       'status':'approved' if issued else ('blocked' if code in ('authority_required','phase_unavailable') else 'rejected'),
       'code':code,'refs':[],'capabilities':{k:'available' if issued and k=='local-authority' else 'unavailable' for k in _CAPS},'next_route':'stage-implementation-required' if issued else 'fresh-owner-decision'}
    v['diagnostic_digest']=stage_digest('installation-approval-diagnostic',v,context)
    context.check_limit('result_bytes',canonical_byte_length(v),source_id='installation-approval-diagnostic')
    if canonical_byte_length(v)>maximum:fail('resource_limit')
    return validate_diagnostic(v,context)
