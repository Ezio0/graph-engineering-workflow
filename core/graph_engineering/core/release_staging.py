"""Closed charged planning records; no filesystem, issuer or execution authority."""
from __future__ import annotations
import re
from dataclasses import dataclass
from graph_engineering.core.contracts import freeze, thaw
from graph_engineering.core.contracts.resources import WorkContext
from graph_engineering.core.contracts.digest import semantic_digest_charged
from graph_engineering.core.contracts.canonical import canonical_byte_length
from graph_engineering.core.release_installation import (
    closed, measure, token, digest, integer, ordered, strings, portable_path,
    version, fail, semantic as release_semantic, CODES,
)


def stage_digest(kind: str, body: object, context: WorkContext) -> str:
    measure(body,context)
    return semantic_digest_charged(body,context,contract_type='urn:gew:contract:release-'+kind+'-v1',
        projection_id='urn:gew:digest-projection:release-'+kind+'-v1:1.0.0',schema_id='urn:gew:schema:'+kind+':1.0.0')


def _header(value,fields,context):
    measure(value,context);closed(value,fields)
    if value['schema_version']!='1.0.0':fail()


def _self(value,kind,field,context):
    digest(value[field])
    if stage_digest(kind,{k:v for k,v in value.items() if k!=field},context)!=value[field]:fail('trust_rejected')


@dataclass(frozen=True,slots=True)
class StageRequest:
    _data: object

    @classmethod
    def from_dict(cls,value: object,context: WorkContext) -> StageRequest:
        _header(value,('schema_version','request_id','operation','installation_id','release_manifest_digest',
            'prior_tuple_digest','target_refs','preserve_data'),context)
        token(value['request_id']);token(value['installation_id']);digest(value['release_manifest_digest'])
        if value['operation'] not in ('install','upgrade') or value['preserve_data'] is not True:fail()
        if value['prior_tuple_digest'] is not None:digest(value['prior_tuple_digest'])
        if value['operation']=='install' and value['prior_tuple_digest'] is not None:fail()
        strings(value['target_refs'])
        if not value['target_refs']:fail()
        return cls(freeze(value))

    def to_dict(self) -> dict[str,object]:return thaw(self._data)


def validate_plan(value: object,context: WorkContext) -> dict[str,object]:
    _header(value,('schema_version','request_id','operation','installation_id','prior_tuple_digest',
        'release_manifest_digest','policy_digest','closure_digest','platform_digest','target_refs','preserve_data','plan_digest'),context)
    token(value['request_id']);token(value['installation_id'])
    if value['operation'] not in ('check','install','init','upgrade','rollback','uninstall') or type(value['preserve_data']) is not bool:fail()
    if value['prior_tuple_digest'] is not None:digest(value['prior_tuple_digest'])
    strings(value['target_refs'])
    for key in ('release_manifest_digest','policy_digest','closure_digest','platform_digest','plan_digest'):digest(value[key])
    if release_semantic('plan',{k:v for k,v in value.items() if k!='plan_digest'},context)!=value['plan_digest']:fail('trust_rejected')
    return value


def validate_stage_policy(value: object,context: WorkContext) -> dict[str,object]:
    _header(value,('schema_version','policy_id','installer_policy_digest','max_stage_bytes','max_stage_files',
        'max_process_seconds','max_output_bytes','max_failed_candidates','max_cleanup_entries','policy_digest'),context)
    token(value['policy_id']);digest(value['installer_policy_digest'])
    for key in ('max_stage_bytes','max_stage_files','max_process_seconds','max_output_bytes','max_failed_candidates','max_cleanup_entries'):integer(value[key],positive=True)
    for key,ceiling in (('max_stage_files','array_items'),('max_failed_candidates','array_items'),('max_cleanup_entries','array_items'),('max_output_bytes','result_bytes')):context.check_limit(ceiling,value[key],source_id='stage-policy')
    _self(value,'stage-policy','policy_digest',context)
    return value


def _argument(value):
    if type(value) is dict:
        closed(value,('ref',))
        if value['ref'] not in ('interpreter','tool','wheelhouse'):fail()
    elif type(value) is str:
        if not 1<=len(value)<=512 or value.startswith('@') or any(c in value for c in ('\x00','\n','\r','`','$',';','|','&')):fail()
    else:fail()


def validate_installer_policy(value: object,context: WorkContext) -> dict[str,object]:
    _header(value,('schema_version','policy_id','recipes','policy_digest'),context);token(value['policy_id'])
    ordered(value['recipes'],lambda r:r['recipe_id'])
    for recipe in value['recipes']:
        closed(recipe,('recipe_id','platform','interpreter_artifact_id','installer_artifact_id',
            'interpreter_version','installer_version','steps','generated_files','recipe_digest'))
        for key in ('recipe_id','interpreter_artifact_id','installer_artifact_id'):token(recipe[key])
        version(recipe['interpreter_version']);version(recipe['installer_version'])
        closed(recipe['platform'],('os','architecture','python_abi'))
        for item in recipe['platform'].values():token(item)
        if type(recipe['steps']) is not list or not recipe['steps']:fail()
        seen=set()
        for step in recipe['steps']:
            closed(step,('step_id','executable_ref','argv','cwd_ref','environment'));token(step['step_id'])
            if step['step_id'] in seen:fail()
            seen.add(step['step_id'])
            if step['executable_ref'] not in ('interpreter','installer') or step['cwd_ref']!='candidate-root':fail()
            if type(step['argv']) is not list:fail()
            for arg in step['argv']:_argument(arg)
            ordered(step['environment'],lambda r:r['name'])
            for row in step['environment']:
                closed(row,('name','value'));name=row['name']
                if type(name) is not str or re.fullmatch('[A-Z][A-Z0-9_]{0,63}',name) is None:fail()
                if name in ('PYTHONPATH','PYTHONHOME','LD_PRELOAD','LD_LIBRARY_PATH') or name.startswith('DYLD_'):fail()
                _argument(row['value'])
        ordered(recipe['generated_files'],lambda r:r['logical_path'])
        for row in recipe['generated_files']:
            closed(row,('logical_path','kind','template_digest'));portable_path(row['logical_path']);digest(row['template_digest'])
            if row['kind'] not in ('launcher','script','RECORD'):fail()
        _self(recipe,'installer-recipe','recipe_digest',context)
    _self(value,'installer-policy','policy_digest',context)
    return value


def select_recipe(policy: object,manifest: dict[str,object],context: WorkContext) -> dict[str,object]:
    validate_installer_policy(policy,context)
    matches=[r for r in policy['recipes'] if r['platform']==manifest['platform']
        and r['interpreter_artifact_id']==manifest['interpreter']['artifact_id'] and r['installer_artifact_id']==manifest['installer']['artifact_id']
        and r['interpreter_version']==manifest['interpreter']['patch'] and r['installer_version']==manifest['installer']['version']]
    if len(matches)!=1:fail('platform_unavailable')
    if matches[0]['recipe_digest']!=manifest['installer']['argv_policy_digest']:fail('trust_rejected')
    return matches[0]


def validate_target_registry(value: object,context: WorkContext) -> dict[str,object]:
    _header(value,('schema_version','registry_id','installation_id','roots','registry_digest'),context)
    token(value['registry_id']);token(value['installation_id']);ordered(value['roots'],lambda r:r['ref']);seen=set()
    for root in value['roots']:
        closed(root,('ref','role','path','owner_id','mode_policy'));token(root['ref'])
        if root['role'] not in ('installation','candidate-parent','skill-bootstrap') or root['mode_policy']!='owner-only':fail()
        p=root['path'];owner=root['owner_id']
        if type(p) is not str or not p.startswith('/') or p=='/' or '\\' in p or len(p)>1024:fail()
        if any(x in ('','.','..') for x in p.split('/')[1:]) or any(ord(c)<32 for c in p):fail()
        if type(owner) is not str or re.fullmatch('0|[1-9][0-9]{0,19}',owner) is None:fail()
        if p in seen:fail()
        seen.add(p)
    _self(value,'stage-target-registry','registry_digest',context)
    return value


def validate_context(value: object,context: WorkContext) -> dict[str,object]:
    _header(value,('schema_version','stage_policy_digest','installer_policy_digest','recipe_digest',
        'target_registry_digest','target_binding_digest','context_digest'),context)
    for key,item in value.items():
        if key!='schema_version':digest(item)
    _self(value,'stage-context','context_digest',context)
    return value


def validate_envelope(value: object,context: WorkContext) -> dict[str,object]:
    _header(value,('schema_version','plan','stage_context','envelope_digest'),context)
    validate_plan(value['plan'],context);validate_context(value['stage_context'],context);_self(value,'stage-plan-envelope','envelope_digest',context)
    return value


def validate_stage_diagnostic(value: object,context: WorkContext) -> dict[str,object]:
    _header(value,('schema_version','request_id','status','phase','code','checks','refs','capabilities','next_route','diagnostic_digest'),context)
    token(value['request_id']);token(value['next_route']);strings(value['refs'])
    if value['phase'] not in ('plan','stage') or value['status'] not in ('blocked','rejected') or value['code'] not in CODES:fail()
    ordered(value['checks'],lambda r:r['id'])
    for row in value['checks']:
        closed(row,('id','status','code','ref'));token(row['id']);token(row['ref'])
        if row['status'] not in ('blocked','rejected') or row['code'] not in CODES:fail()
    if value['capabilities']!={'install-plan':'available','install-apply':'unavailable','stage':'unavailable','reopen-staged':'unavailable','release':'unavailable'}:fail()
    _self(value,'stage-diagnostic','diagnostic_digest',context)
    return value


def stage_diagnostic(code: str,phase: str,context: WorkContext,*,max_bytes: int) -> dict[str,object]:
    value={'schema_version':'1.0.0','request_id':'stage-'+phase,'status':'blocked' if code in ('phase_unavailable','platform_unavailable','clock_unavailable','recovery_blocked') else 'rejected',
        'phase':phase,'code':code,'checks':[],'refs':[],'capabilities':{'install-plan':'available','install-apply':'unavailable','stage':'unavailable','reopen-staged':'unavailable','release':'unavailable'},
        'next_route':'implementation-required' if code=='phase_unavailable' else 'inspect-inputs'}
    value['diagnostic_digest']=stage_digest('stage-diagnostic',value,context)
    integer(max_bytes,positive=True);context.check_limit('result_bytes',canonical_byte_length(value),source_id='stage-diagnostic')
    if canonical_byte_length(value)>max_bytes:fail('resource_limit')
    return validate_stage_diagnostic(value,context)
