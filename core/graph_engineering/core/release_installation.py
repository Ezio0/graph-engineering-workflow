"""Closed, bounded release records and pure comparisons; no installation authority."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable, NoReturn
from graph_engineering.core.contracts import freeze, thaw
from graph_engineering.core.contracts.resources import WorkContext, bounded_measure
from graph_engineering.core.contracts.canonical import canonicalize, canonical_byte_length
from graph_engineering.core.contracts.digest import semantic_digest_charged


class ReleaseInstallationError(ValueError):
    """Only a stable code crosses the diagnostic boundary."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


VERSIONS = frozenset({'core','cli','adapter','skill','repository_contract','repository_bundle','schema_registry','graph','profile','overlay','action'})
KINDS = frozenset({'interpreter','installer','core-wheel','dependency-wheel','build-input','skill','lock','sbom','security-evidence','provenance'})
RESOURCE_FIELDS = frozenset({'schema_version','policy_id','max_manifest_bytes','max_artifacts','max_dependency_edges','max_artifact_bytes','max_bundle_bytes','max_archive_members','max_expanded_bytes','max_expansion_ratio','max_path_segments','max_report_bytes','max_hash_bytes','policy_digest'})
MANIFEST_FIELDS = frozenset({'schema_version','release_id','product','platform','interpreter','installer','artifacts','dependencies','skills','compatibility','lock_artifact_id','sbom_artifact_id','security_evidence_artifact_id','policy_digest','trust_registry_digest','signing_key_id','manifest_digest','signature'})
ARTIFACT_FIELDS = frozenset({'artifact_id','kind','relative_path','distribution_name','version','size_bytes','raw_sha256','source_id','provenance_artifact_id','license_ids'})
EDGE_FIELDS = frozenset({'parent_artifact_id','child_artifact_id','requirement','marker','extras'})
CODES = frozenset({'ok','input_invalid','trust_rejected','closure_mismatch','resource_limit','platform_unavailable','currentness','clock_unavailable','authority_required','quiescence','pmf_export_blocked','recovery_blocked','phase_unavailable'})
_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9:._-]{0,127}\Z')
_DIGEST = re.compile(r'sha256-jcs-v1:[0-9a-f]{64}\Z')
_RAW = re.compile(r'[0-9a-f]{64}\Z')


def fail(code: str='input_invalid') -> NoReturn:
    raise ReleaseInstallationError(code)


def measure(value: object, context: WorkContext) -> None:
    if type(context) is not WorkContext:fail('resource_limit')
    try:bounded_measure(value,context,source_id='release-installation',operation_path=context.child_path(()))
    except (TypeError,ValueError,RuntimeError):fail('resource_limit')


def closed(value: object, fields: Iterable[str]) -> dict[str, object]:
    if type(value) is not dict or set(value)!=set(fields):fail()
    return value


def token(value: object) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:fail()
    return value


def integer(value: object, *, positive: bool=False) -> int:
    if type(value) is not int or not (1 if positive else 0)<=value<=9007199254740991:fail('resource_limit')
    return value


def digest(value: object) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:fail()
    return value


def raw_hash(value: object) -> str:
    if type(value) is not str or _RAW.fullmatch(value) is None:fail()
    return value


def portable_path(value: object) -> str:
    if type(value) is not str or len(value)>1024 or not value or '\\' in value:fail()
    parts=value.split('/')
    for part in parts:
        if (not part or part in ('.','..') or part.endswith('.') or ':' in part
            or re.fullmatch(r'[A-Za-z0-9_.-]+',part) is None
            or re.fullmatch(r'(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?',part)):
            fail()
    return value


def ordered(value: object, key: Callable[[object], object]=lambda x:x) -> list[object]:
    if type(value) is not list:fail()
    try:
        keys=[key(x) for x in value]
        if keys!=sorted(keys) or len(set(keys))!=len(keys):fail()
    except (TypeError,KeyError):fail()
    return value


def strings(value: object) -> list[str]:
    ordered(value)
    for x in value:token(x)
    return value


def version(value: object) -> tuple[int, int, int]:
    if type(value) is not str or re.fullmatch(r'(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*)){1,2}',value) is None:fail()
    parts=tuple(map(int,value.split('.')))
    return parts+(0,)*(3-len(parts))


def version_range(value: object) -> list[tuple[str, tuple[int, int, int]]]:
    if type(value) is not str or not 1<=len(value)<=128:fail()
    result=[]
    for part in value.split(','):
        match=re.fullmatch(r'(>=|<=|==|>|<)([0-9]+\.[0-9]+\.[0-9]+)',part)
        if match is None:fail()
        result.append((match[1],version(match[2])))
    return result


def semantic(kind: str, body: object, context: WorkContext) -> str:
    measure(body,context)
    return semantic_digest_charged(body,context,contract_type='urn:gew:contract:release-install-'+kind,
        projection_id='urn:gew:digest-projection:release-install-'+kind+':1.0.0',schema_id='urn:gew:schema:release-install-'+kind+':1.0.0')


def validate_self(value: dict[str, object], kind: str, field: str, context: WorkContext, *, excluded: tuple[str, ...]=()) -> None:
    digest(value[field]);body={k:v for k,v in value.items() if k not in {field,*excluded}}
    if semantic(kind,body,context)!=value[field]:fail('trust_rejected')


def manifest_signature_preimage(value: dict[str, object], context: WorkContext) -> bytes:
    body={k:v for k,v in value.items() if k not in ('manifest_digest','signature')}
    envelope={'algorithm':'sha-256','body':body,'canonicalizer':'urn:gew:canonicalizer:jcs-input:1.0.0',
        'contract_type':'urn:gew:contract:release-install-manifest','digest_domain':'urn:gew:digest:semantic:1.0.0',
        'projection_id':'urn:gew:digest-projection:release-install-manifest:1.0.0','schema_id':'urn:gew:schema:release-install-manifest:1.0.0'}
    return canonicalize(envelope,context,source_id='release-install-manifest')


@dataclass(frozen=True, slots=True)
class ReleaseInstallManifest:
    _data: object

    @property
    def manifest_digest(self) -> str:return self._data['manifest_digest']

    def to_dict(self) -> dict[str, object]:return thaw(self._data)

    @classmethod
    def from_dict(cls, value: object, guard: WorkContext) -> ReleaseInstallManifest:
        measure(value,guard);closed(value,MANIFEST_FIELDS)
        if value['schema_version']!='1.0.0':fail()
        token(value['release_id']);token(value['signing_key_id'])
        product=closed(value['product'],('name','version','cli_protocol'))
        token(product['name']);version(product['version']);version(product['cli_protocol'])
        platform=closed(value['platform'],('os','architecture','python_abi'))
        for x in platform.values():token(x)
        interpreter=closed(value['interpreter'],('artifact_id','implementation','patch','build_id','executable_member'))
        for k in ('artifact_id','implementation','build_id'):token(interpreter[k])
        version(interpreter['patch']);portable_path(interpreter['executable_member'])
        installer=closed(value['installer'],('artifact_id','version','argv_policy_digest'))
        token(installer['artifact_id']);version(installer['version']);digest(installer['argv_policy_digest'])
        artifacts=ordered(value['artifacts'],lambda r:r['artifact_id']);index={};paths=set();names=set()
        for row in artifacts:
            closed(row,ARTIFACT_FIELDS);ident=token(row['artifact_id']);index[ident]=row
            if row['kind'] not in KINDS:fail()
            path=portable_path(row['relative_path']).casefold()
            if path in paths:fail()
            paths.add(path);integer(row['size_bytes'],positive=True);raw_hash(row['raw_sha256']);token(row['source_id']);strings(row['license_ids'])
            if not row['license_ids']:fail('trust_rejected')
            if row['kind'] in ('core-wheel','dependency-wheel'):
                name=token(row['distribution_name']);version(row['version']);normalized=re.sub(r'[-_.]+','-',name).lower()
                if normalized in names:fail('closure_mismatch')
                names.add(normalized)
            elif row['distribution_name'] is not None or row['version'] is not None:fail()
            if row['provenance_artifact_id'] is not None:token(row['provenance_artifact_id'])
            elif row['kind']!='provenance':fail('trust_rejected')
        def reference(ident: str,kind: str) -> None:
            token(ident)
            if ident not in index or index[ident]['kind']!=kind:fail('closure_mismatch')
        for row in artifacts:
            if row['provenance_artifact_id'] is not None:reference(row['provenance_artifact_id'],'provenance')
        reference(interpreter['artifact_id'],'interpreter');reference(installer['artifact_id'],'installer')
        for k,kind in [('lock_artifact_id','lock'),('sbom_artifact_id','sbom'),('security_evidence_artifact_id','security-evidence')]:reference(value[k],kind)
        roots=[r for r in artifacts if r['kind']=='core-wheel']
        if len(roots)!=1 or roots[0]['distribution_name']!=product['name'] or roots[0]['version']!=product['version']:fail('closure_mismatch')
        edges=ordered(value['dependencies'],lambda r:(r['parent_artifact_id'],r['child_artifact_id'],r['requirement']))
        adjacency={r['artifact_id']:[] for r in artifacts if r['kind'] in ('core-wheel','dependency-wheel')}
        for edge in edges:
            closed(edge,EDGE_FIELDS);strings(edge['extras'])
            if type(edge['requirement']) is not str or not 1<=len(edge['requirement'])<=512:fail()
            if edge['marker'] is not None and (type(edge['marker']) is not str or not 1<=len(edge['marker'])<=512):fail()
            parent=token(edge['parent_artifact_id']);child=token(edge['child_artifact_id'])
            if parent not in adjacency or child not in adjacency:fail('closure_mismatch')
            adjacency[parent].append(child)
        seen=set();active=set();stack=[(roots[0]['artifact_id'],False)]
        while stack:
            ident,leaving=stack.pop()
            if leaving:
                active.remove(ident);seen.add(ident)
            elif ident in active:fail('closure_mismatch')
            elif ident not in seen:
                active.add(ident);stack.append((ident,True))
                stack.extend((child,False) for child in adjacency[ident])
        if seen!=set(adjacency):fail('closure_mismatch')
        skills=ordered(value['skills'],lambda r:(r['runtime_kind'],r['skill_id']))
        for skill in skills:
            closed(skill,('runtime_kind','skill_id','version','artifact_id','entry_member','protocol_range'))
            token(skill['runtime_kind']);token(skill['skill_id']);version(skill['version']);portable_path(skill['entry_member']);version_range(skill['protocol_range']);reference(skill['artifact_id'],'skill')
        compatibility=closed(value['compatibility'],VERSIONS|{'required_capabilities'})
        for k in VERSIONS:version_range(compatibility[k])
        strings(compatibility['required_capabilities'])
        digest(value['policy_digest']);digest(value['trust_registry_digest'])
        if type(value['signature']) is not str or re.fullmatch('[0-9a-f]{128}',value['signature']) is None:fail('trust_rejected')
        validate_self(value,'manifest','manifest_digest',guard,excluded=('signature',))
        return cls(freeze(value))


def compare_release_closure(manifest: ReleaseInstallManifest, observed: object, context: WorkContext) -> str:
    if type(manifest) is not ReleaseInstallManifest:fail()
    measure(observed,context);closed(observed,('artifacts','dependencies'));value=manifest.to_dict()
    facts=[]
    for row in observed['artifacts']:
        closed(row,('artifact_id','raw_sha256','size_bytes'));token(row['artifact_id']);raw_hash(row['raw_sha256']);integer(row['size_bytes'],positive=True);facts.append(row)
    if len({r['artifact_id'] for r in facts})!=len(facts):fail('closure_mismatch')
    expected=[{k:r[k] for k in ('artifact_id','raw_sha256','size_bytes')} for r in value['artifacts']]
    if sorted(facts,key=lambda r:r['artifact_id'])!=expected:fail('closure_mismatch')
    edges=observed['dependencies']
    if type(edges) is not list:fail()
    for row in edges:closed(row,EDGE_FIELDS)
    if sorted(edges,key=lambda r:(r['parent_artifact_id'],r['child_artifact_id'],r['requirement']))!=value['dependencies']:fail('closure_mismatch')
    return semantic('closure',{'artifacts':expected,'dependencies':value['dependencies']},context)


def check_compatibility(manifest: ReleaseInstallManifest, versions: object, capabilities: object, context: WorkContext) -> None:
    measure({'versions':versions,'capabilities':capabilities},context);closed(versions,VERSIONS)
    strings(capabilities);requirements=manifest.to_dict()['compatibility']
    for k in VERSIONS:
        actual=version(versions[k])
        for op,want in version_range(requirements[k]):
            if not {'>':actual>want,'>=':actual>=want,'<':actual<want,'<=':actual<=want,'==':actual==want}[op]:fail('platform_unavailable')
    actual=version(versions['skill'])
    for skill in manifest.to_dict()['skills']:
        for op,want in version_range(skill['protocol_range']):
            if not {'>':actual>want,'>=':actual>=want,'<':actual<want,'<=':actual<=want,'==':actual==want}[op]:fail('platform_unavailable')
    if not set(requirements['required_capabilities']).issubset(capabilities):fail('platform_unavailable')


def validate_resource_policy(value: object, context: WorkContext) -> dict[str, object]:
    measure(value,context);closed(value,RESOURCE_FIELDS)
    if value['schema_version']!='1.0.0':fail()
    token(value['policy_id'])
    for k in RESOURCE_FIELDS-{'schema_version','policy_id','policy_digest'}:integer(value[k],positive=True)
    for k,profile_key in [('max_manifest_bytes','raw_document_bytes'),('max_report_bytes','result_bytes'),('max_artifacts','array_items'),('max_dependency_edges','array_items'),('max_archive_members','array_items'),('max_path_segments','path_tokens')]:
        context.check_limit(profile_key,value[k],source_id='release-install-policy')
    validate_self(value,'resource-policy','policy_digest',context)
    return value


def validate_trust_registry(value: object, context: WorkContext) -> dict[str, object]:
    measure(value,context);closed(value,('schema_version','registry_id','generation','keys','revoked_key_ids','registry_digest'))
    if value['schema_version']!='1.0.0':fail()
    token(value['registry_id']);integer(value['generation'],positive=True);strings(value['revoked_key_ids'])
    ordered(value['keys'],lambda r:r['id'])
    for key in value['keys']:
        closed(key,('id','public_key_hex','purpose','allowed_release_ids'));token(key['id']);raw_hash(key['public_key_hex']);token(key['purpose']);strings(key['allowed_release_ids'])
    validate_self(value,'trust-registry','registry_digest',context)
    return value


def select_release_key(manifest: ReleaseInstallManifest, registry: object, context: WorkContext) -> str:
    validate_trust_registry(registry,context);v=manifest.to_dict()
    for key in registry['keys']:
        if key['id']==v['signing_key_id'] and key['id'] not in registry['revoked_key_ids'] and key['purpose']=='release' and v['release_id'] in key['allowed_release_ids']:return key['public_key_hex']
    fail('trust_rejected')


def validate_release_policy(value: object, context: WorkContext) -> dict[str, object]:
    measure(value,context);closed(value,('schema_version','policy_id','platforms','source_ids','allowed_license_ids','security_rule_digest','required_provenance_kinds','trust_registry_digest','resource_policy_digest','policy_digest'))
    if value['schema_version']!='1.0.0':fail()
    token(value['policy_id']);strings(value['source_ids']);strings(value['allowed_license_ids']);strings(value['required_provenance_kinds'])
    for k in ('security_rule_digest','trust_registry_digest','resource_policy_digest'):digest(value[k])
    ordered(value['platforms'],lambda r:(r['os'],r['architecture'],r['python_abi']))
    for row in value['platforms']:
        closed(row,('os','architecture','python_abi','supported_versions','capabilities'))
        for k in ('os','architecture','python_abi'):token(row[k])
        closed(row['supported_versions'],VERSIONS)
        for x in row['supported_versions'].values():version(x)
        strings(row['capabilities'])
    validate_self(value,'policy','policy_digest',context)
    return value


def validate_diagnostic(value: object, context: WorkContext) -> dict[str, object]:
    measure(value,context);closed(value,('schema_version','request_id','status','phase','code','checks','refs','capabilities','next_route','diagnostic_digest'))
    if value['schema_version']!='1.0.0' or value['status'] not in ('preflight-valid','blocked','rejected') or value['phase'] not in ('check','doctor','plan','stage','migrate','activate','recover') or value['code'] not in CODES:fail()
    token(value['request_id']);token(value['next_route']);strings(value['refs'])
    ordered(value['checks'],lambda r:r['id'])
    for row in value['checks']:
        closed(row,('id','status','code','ref'));token(row['id']);token(row['ref'])
        if row['status'] not in ('preflight-valid','blocked','rejected') or row['code'] not in CODES:fail()
    if value['capabilities']!={'release-check':'available','doctor':'available','install':'unavailable','upgrade':'unavailable','release':'unavailable'}:fail()
    validate_self(value,'diagnostic','diagnostic_digest',context)
    return value


def diagnostic(status: str, phase: str, code: str, checks: list[dict[str, object]], refs: list[str], context: WorkContext, *, max_bytes: int) -> dict[str, object]:
    integer(max_bytes,positive=True);measure({'checks':checks,'refs':refs},context)
    value={'schema_version':'1.0.0','request_id':'release-'+phase,'status':status,'phase':phase,'code':code,
        'checks':checks,'refs':refs,'capabilities':{'release-check':'available','doctor':'available','install':'unavailable','upgrade':'unavailable','release':'unavailable'},
        'next_route':'owner-review' if code=='authority_required' else ('implementation-required' if code=='phase_unavailable' else ('inspect-inputs' if status!='preflight-valid' else 'prepare-install-plan')),
        'diagnostic_digest':'sha256-jcs-v1:'+'0'*64}
    context.check_limit('result_bytes',canonical_byte_length(value),source_id='release-diagnostic')
    if canonical_byte_length(value)>max_bytes:fail('resource_limit')
    value['diagnostic_digest']=semantic('diagnostic',{k:v for k,v in value.items() if k!='diagnostic_digest'},context)
    validate_diagnostic(value,context)
    return value


def bootstrap_diagnostic(phase: str) -> dict[str, object]:
    """Finite fail-closed result when no trustworthy work context can be acquired.

    Only literal enums enter this path. It neither reads configuration nor
    retries the failed provider; it cannot attest any successful capability.
    """
    import hashlib
    import json
    if phase not in ('check','doctor'):
        raise ValueError('unsupported bootstrap diagnostic phase')
    value={'schema_version':'1.0.0','request_id':'release-'+phase,
        'status':'rejected' if phase=='check' else 'blocked','phase':phase,
        'code':'trust_rejected','checks':[],'refs':[],
        'capabilities':{'release-check':'available','doctor':'available',
            'install':'unavailable','upgrade':'unavailable','release':'unavailable'},
        'next_route':'inspect-inputs'}
    envelope={'algorithm':'sha-256','body':value,
        'canonicalizer':'urn:gew:canonicalizer:jcs-input:1.0.0',
        'contract_type':'urn:gew:contract:release-install-diagnostic',
        'digest_domain':'urn:gew:digest:semantic:1.0.0',
        'projection_id':'urn:gew:digest-projection:release-install-diagnostic:1.0.0',
        'schema_id':'urn:gew:schema:release-install-diagnostic:1.0.0'}
    raw=json.dumps(envelope,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
    value['diagnostic_digest']='sha256-jcs-v1:'+hashlib.sha256(raw).hexdigest()
    return value
