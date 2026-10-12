"""Installation-owned inputs and offline physical release observations."""
from __future__ import annotations

import hashlib
import json
import os
import platform as host_platform
import stat
import sys
import zipfile
from pathlib import Path
from typing import Callable

import graph_engineering
from graph_engineering.core.release_installation import (
    ReleaseInstallationError, ReleaseInstallManifest, validate_release_policy,
    validate_resource_policy, validate_trust_registry, semantic, fail,
)
from graph_engineering.core.contracts import parse_json
from graph_engineering.core.contracts.resources import WorkContext, ResourceProfile, CostSchedule
from graph_engineering.core.contracts.schema import SchemaProfilePolicy
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry

_CAPTURE_LOADER = getattr(graph_engineering, '_release_installation_resources', None)
_OWNED_LOADER = graph_engineering._installation_owned_resources
_SEED_LOADER = graph_engineering._security_bootstrap_seed_resources
_PARSER_RESOURCES = graph_engineering._dependency_parser_resources


def _release_backend():
    """Execute only the installation-attested backend, never candidate code."""
    if graph_engineering._dependency_parser_resources is not _PARSER_RESOURCES:fail('currentness')
    backend,provenance,requirement,path=_PARSER_RESOURCES()
    module_path=Path(graph_engineering.__file__).resolve(strict=True)
    source=graph_engineering._source_checkout_root(module_path)
    backend_path=(source/'scripts/build_backend.py' if source else module_path.parent/'build_backend.py')
    scope={'__name__':'gew_release_backend','__file__':str(backend_path)}
    exec(compile(backend,'<installation-attested-release-backend>','exec',dont_inherit=True),scope,scope)
    if _PARSER_RESOURCES()!=(backend,provenance,requirement,path):fail('currentness')
    return scope


def _fresh_context():
    if graph_engineering._security_bootstrap_seed_resources is not _SEED_LOADER:fail('currentness')
    profile,schedule=_SEED_LOADER()
    return WorkContext(ResourceProfile.from_dict(parse_json(profile)),CostSchedule.from_dict(parse_json(schedule)))


def _origin_binding():
    p=Path(graph_engineering.__file__).absolute()
    infos=[]
    for item in (p.parent,p):
        st=os.lstat(item)
        infos.append([hashlib.sha256(os.fsencode(item)).hexdigest(),*[str(x) for x in (st.st_dev,st.st_ino,st.st_uid,st.st_mode,st.st_nlink)]])
    return infos


def _resource_native_binding(paths):
    module_path=Path(graph_engineering.__file__).resolve(strict=True)
    source=graph_engineering._source_checkout_root(module_path)
    root=source if source else module_path.parent
    result=[]
    for relative in paths:
        p=root/relative
        for item in (p.parent,p):
            st=os.lstat(item)
            if stat.S_ISLNK(st.st_mode) or st.st_uid!=os.getuid() or st.st_mode&0o022:fail('currentness')
            result.append([relative,*[str(x) for x in (st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_nlink,st.st_size,st.st_mtime_ns)]])
    return result


def _capture():
    if (not callable(_CAPTURE_LOADER) or graph_engineering._release_installation_resources is not _CAPTURE_LOADER
            or graph_engineering._installation_owned_resources is not _OWNED_LOADER):fail('currentness')
    context=_fresh_context();before=_origin_binding();paths,bodies=_CAPTURE_LOADER(context)
    schema_profile=_OWNED_LOADER(('config/contracts/schema-profile-v1.json',),context=context)[0]
    documents=[parse_json(b,context=context,source_id=p) for p,b in zip(paths,bodies,strict=True)]
    bypath=dict(zip(paths,documents,strict=True));registry_doc=bypath['config/contracts/release-installation-schema-registry-v1.json']
    schema_bodies={d['$id']:b for d,b in zip(documents,bodies,strict=True) if '$id' in d}
    registry=ClosedSchemaRegistry.build(registry_doc,schema_bodies,context.profile,
        SchemaProfilePolicy.from_dict(parse_json(schema_profile,context=context,source_id='release-schema-profile')),context)
    for name,path in [('policy','config/release-installation/release-policy-v1.json'),
                      ('trust-registry','config/release-installation/release-trust-registry-v1.json'),
                      ('resource-policy','config/release-installation/release-resource-policy-v1.json')]:
        if registry.validate('urn:gew:schema:release-install-'+name+':1.0.0',bypath[path],context):fail('trust_rejected')
    p=bypath['config/release-installation/release-policy-v1.json'];t=bypath['config/release-installation/release-trust-registry-v1.json'];r=bypath['config/release-installation/release-resource-policy-v1.json']
    validate_release_policy(p,context);validate_trust_registry(t,context);validate_resource_policy(r,context)
    if p['trust_registry_digest']!=t['registry_digest'] or p['resource_policy_digest']!=r['policy_digest']:fail('trust_rejected')
    if _origin_binding()!=before:fail('currentness')
    native=_resource_native_binding(paths)
    if _resource_native_binding(paths)!=native:fail('currentness')
    binding=semantic('input-binding',{'origin':before,'native':native,'resources':[
        {'path':path,'raw_sha256':hashlib.sha256(body).hexdigest()} for path,body in zip(paths,bodies,strict=True)]},context)
    return paths,bodies,binding


class InstalledReleaseInputs:
    """Only freshly captured real source/wheel resources can be reused."""
    __slots__=('_paths','_bodies','_binding')

    def __init__(self):raise TypeError('installation inputs require open_owned')

    @classmethod
    def open_owned(cls) -> InstalledReleaseInputs:
        try:
            paths,bodies,binding=_capture();result=object.__new__(cls)
            result._paths=paths;result._bodies=bodies;result._binding=binding
            return result
        except ReleaseInstallationError:raise
        except (TypeError,ValueError,RuntimeError,OSError,KeyError,AttributeError):fail('trust_rejected')

    @property
    def resource_paths(self) -> tuple[str, ...]:return self._paths

    @property
    def binding_digest(self) -> str:return self._binding

    def _document(self, path):
        self.require_current()
        return parse_json(self._bodies[self._paths.index(path)],context=_fresh_context(),source_id=path)

    @property
    def policy(self) -> dict[str, object]:return self._document('config/release-installation/release-policy-v1.json')

    @property
    def trust(self) -> dict[str, object]:return self._document('config/release-installation/release-trust-registry-v1.json')

    @property
    def limits(self) -> dict[str, object]:return self._document('config/release-installation/release-resource-policy-v1.json')

    def require_current(self) -> str:
        try:
            paths,bodies,binding=_capture()
            if paths!=self._paths or bodies!=self._bodies or binding!=self._binding:fail('currentness')
            return binding
        except ReleaseInstallationError:raise
        except (TypeError,ValueError,RuntimeError,OSError,KeyError,AttributeError):fail('currentness')


def marker_environment(platform: dict[str, str], patch: str) -> dict[str, str]:
    from graph_engineering.core.release_installation import version, closed
    closed(platform,('os','architecture','python_abi'));version(patch)
    systems={'macos':('darwin','Darwin'),'linux':('linux','Linux')}
    if platform['os'] not in systems:fail('platform_unavailable')
    sys_platform,system=systems[platform['os']]
    return {'implementation_name':'cpython','implementation_version':patch,'os_name':'posix',
        'platform_machine':platform['architecture'],'platform_python_implementation':'CPython',
        'platform_release':'offline','platform_system':system,'platform_version':'offline',
        'python_full_version':patch,'python_version':'.'.join(patch.split('.')[:2]),'sys_platform':sys_platform,'extra':''}


def requirement_active(text: str, environment: dict[str, str], extras: list[str]) -> bool:
    backend=_release_backend()
    before=backend['_package_parser_attestation']()
    req=backend['_parse_requirement'](text,exact_pin=False)
    if req.url is not None:fail('closure_mismatch')
    result=req.marker is None or any(req.marker.evaluate(dict(environment,extra=extra)) for extra in (['']+list(extras)))
    if backend['_package_parser_attestation']()!=before:fail('currentness')
    return result


class _Budget:
    def __init__(self,limits):self.limits=limits;self.used={}

    def charge(self,key: str,amount: int) -> None:
        if type(amount) is not int or amount<0:fail('resource_limit')
        current=self.used.get(key,0)+amount
        if current>self.limits[key]:fail('resource_limit')
        self.used[key]=current

    def ceiling(self,key: str,amount: int) -> None:
        if amount>self.limits[key]:fail('resource_limit')


def _stat_binding(s):
    return (s.st_dev,s.st_ino,s.st_uid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)


class _ReadFile:
    """Descriptor and complete parent chain retained through the operation."""
    def __init__(self,path,maximum,budget,*,account_bundle=True):
        self.path=Path(path).absolute();self.descriptors=[];self.parents=[];self.fd=-1
        try:
            if self.path.resolve(strict=True)!=self.path:fail('currentness')
            # Bind every parent, including ancestors of the explicit input root.
            for parent in reversed(self.path.parents):
                fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
                self.descriptors.append(fd);self.parents.append((parent,_stat_binding(os.fstat(fd))))
            parent_fd=self.descriptors[-1]
            self.fd=os.open(self.path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent_fd)
            s=os.fstat(self.fd);self.binding=_stat_binding(s)
            if (not stat.S_ISREG(s.st_mode) or s.st_uid!=os.getuid() or s.st_nlink!=1 or s.st_mode&0o022):fail('currentness')
            if not 0<s.st_size<=maximum:fail('resource_limit')
            if account_bundle:budget.charge('max_bundle_bytes',s.st_size)
            self.raw=self._read(budget)
            self.raw_sha256=hashlib.sha256(self.raw).hexdigest()
            self._check_stat()
        except BaseException:
            self.close();raise

    def _check_stat(self):
        if _stat_binding(os.fstat(self.fd))!=self.binding:fail('currentness')
        entry=os.stat(self.path.name,dir_fd=self.descriptors[-1],follow_symlinks=False)
        if _stat_binding(entry)!=self.binding:fail('currentness')
        for (path,before),fd in zip(self.parents,self.descriptors,strict=True):
            # Directory entry mtimes can change for unrelated siblings. Native
            # identity/mode/owner, rather than sibling activity, is the binding.
            if _stat_binding(os.fstat(fd))[:4]!=before[:4] or _stat_binding(os.lstat(path))[:4]!=before[:4]:fail('currentness')

    def _read(self,budget):
        budget.charge('max_hash_bytes',self.binding[5]);os.lseek(self.fd,0,os.SEEK_SET)
        data=bytearray();maximum=self.binding[5]
        while len(data)<maximum:
            part=os.read(self.fd,min(65536,maximum-len(data)))
            if not part:fail('currentness')
            data.extend(part)
        if os.read(self.fd,1):fail('currentness')
        return bytes(data)

    def recheck(self,budget: _Budget) -> None:
        self._check_stat()
        if hashlib.sha256(self._read(budget)).hexdigest()!=self.raw_sha256:fail('currentness')
        self._check_stat()

    def snapshot(self) -> tuple[object, ...]:return (str(self.path),self.binding,tuple((str(p),b[:4]) for p,b in self.parents),self.raw_sha256)

    def close(self) -> None:
        if self.fd>=0:os.close(self.fd);self.fd=-1
        for fd in reversed(self.descriptors):os.close(fd)
        self.descriptors=[]


def _member_path(name,limits,seen):
    from graph_engineering.core.release_installation import portable_path
    portable_path(name)
    if len(name.split('/'))>limits['max_path_segments']:fail('resource_limit')
    folded=name.casefold()
    if folded in seen:fail('closure_mismatch')
    seen.add(folded)


def _zip_structure(raw,backend,budget):
    """Validate physical headers and reserve expansion before ZipFile exists."""
    import struct
    limits=budget.limits;offset=raw.rfind(b'PK\x05\x06')
    if offset<0 or len(raw)-offset!=22:fail('input_invalid')
    sig,disk,central_disk,disk_count,count,size,start,comment=struct.unpack_from('<4s4H2LH',raw,offset)
    if disk or central_disk or disk_count!=count or not count or comment or start+size!=offset:fail('input_invalid')
    budget.charge('max_archive_members',count)
    policy=backend['_offline_wheel_policy']();cursor=start;declared=0
    for _ in range(count):
        if cursor+46>offset or raw[cursor:cursor+4]!=b'PK\x01\x02':fail('input_invalid')
        fields=struct.unpack_from('<4s6H3L5H2L',raw,cursor)
        declared+=fields[9];cursor+=46+fields[10]+fields[11]+fields[12]
        if cursor>offset:fail('input_invalid')
    budget.charge('max_expanded_bytes',declared)
    if declared>len(raw)*limits['max_expansion_ratio']:fail('resource_limit')
    names,expanded=backend['_validate_physical_zip'](raw,member_count=count,
        max_member_bytes=min(limits['max_expanded_bytes'],int(policy['max-member-bytes'])),
        max_total_bytes=min(limits['max_expanded_bytes'],int(policy['max-total-bytes'])),
        central_offset=start,central_size=size,eocd_offset=offset)
    if expanded!=declared:fail('input_invalid')
    if expanded>len(raw)*limits['max_expansion_ratio']:fail('resource_limit')
    seen=set();cursor=start
    for name in names:
        _member_path(name,limits,seen)
        fields=struct.unpack_from('<4s6H3L5H2L',raw,cursor);mode=fields[15]>>16
        if stat.S_IFMT(mode) not in (0,stat.S_IFREG):fail('input_invalid')
        cursor+=46+fields[10]+fields[11]+fields[12]
    return names,expanded


def _tar_structure(raw,budget):
    """Closed regular-file ustar subset, no extension records, links or extraction."""
    limits=budget.limits;cursor=0;members={};seen=set()
    def octal(value: bytes) -> int:
        try:
            text=value.rstrip(b'\0 ').lstrip(b' ')
            if not text or any(c not in b'01234567' for c in text):fail('input_invalid')
            return int(text,8)
        except (ValueError,OverflowError):fail('input_invalid')
    while cursor+512<=len(raw):
        header=raw[cursor:cursor+512]
        if header==b'\0'*512:
            if len(raw)-cursor<1024 or any(raw[cursor:]) or len(raw)%512:fail('input_invalid')
            return members
        expected=octal(header[148:156]);computed=sum(header[:148])+8*32+sum(header[156:])
        if expected!=computed or header[156:157] not in (b'0',b'\0') or header[257:263] not in (b'ustar\0',b'ustar '):fail('input_invalid')
        try:
            name=header[:100].split(b'\0',1)[0].decode('ascii',errors='strict')
            prefix=header[345:500].split(b'\0',1)[0].decode('ascii',errors='strict')
        except UnicodeError:fail('input_invalid')
        name=prefix+'/'+name if prefix else name;_member_path(name,limits,seen)
        size=octal(header[124:136]);budget.charge('max_archive_members',1);budget.charge('max_expanded_bytes',size)
        if size>limits['max_expanded_bytes'] or size>len(raw)*limits['max_expansion_ratio']:fail('resource_limit')
        start=cursor+512;end=start+size
        if end>len(raw):fail('input_invalid')
        members[name]=(start,end);cursor=start+((size+511)//512)*512
    fail('input_invalid')


def _bundle_members(root,limits):
    from graph_engineering.core.release_installation import portable_path
    root=Path(root).absolute()
    if root.resolve(strict=True)!=root:fail('currentness')
    s=os.lstat(root)
    if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.getuid() or s.st_mode&0o022:fail('currentness')
    pending=[root];files=set();directories=set();visited=0
    while pending:
        directory=pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                visited+=1
                if visited>limits['max_artifacts']*limits['max_path_segments']+1:fail('resource_limit')
                relative=Path(entry.path).relative_to(root).as_posix();portable_path(relative)
                if len(relative.split('/'))>limits['max_path_segments']:fail('resource_limit')
                st=entry.stat(follow_symlinks=False)
                if st.st_uid!=os.getuid() or st.st_mode&0o022:fail('currentness')
                if stat.S_ISDIR(st.st_mode):pending.append(Path(entry.path));directories.add(relative)
                elif stat.S_ISREG(st.st_mode) and st.st_nlink==1:files.add(relative)
                else:fail('currentness')
    needed={str(Path(f).parent) for f in files}
    needed={str(p) for f in files for p in Path(f).parents if str(p)!='.'}
    if directories!=needed:fail('closure_mismatch')
    return frozenset(files),_stat_binding(s)[:5]


def _json(raw,context):
    try:return parse_json(raw,context=context,source_id='release-input')
    except (TypeError,ValueError,RuntimeError,UnicodeError):fail('input_invalid')


def _verify_signature(public_key_hex,signature,preimage):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    try:Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex)).verify(bytes.fromhex(signature),preimage)
    except (InvalidSignature,TypeError,ValueError):fail('trust_rejected')


def _host_platform():
    operating={'darwin':'macos','linux':'linux'}.get(sys.platform)
    if operating is None:fail('platform_unavailable')
    return {'os':operating,'architecture':host_platform.machine(),'python_abi':'cp'+str(sys.version_info.major)+str(sys.version_info.minor)}


def _security_check(value,manifest,policy,trust,subjects,context):
    import time
    from graph_engineering.core.release_installation import closed,integer,token,manifest_signature_preimage
    closed(value,('schema_version','release_id','policy_digest','security_rule_digest','subjects','issued_at','expires_at','verdict','signing_key_id','signature'))
    if (value['schema_version']!='1.0.0' or value['release_id']!=manifest['release_id'] or value['policy_digest']!=policy['policy_digest']
        or value['security_rule_digest']!=policy['security_rule_digest'] or value['subjects']!=subjects or value['verdict']!='PASS'):fail('trust_rejected')
    integer(value['issued_at']);integer(value['expires_at']);token(value['signing_key_id'])
    rules=_json(_OWNED_LOADER(('config/security/evidence-policies-v1.json',),context=context)[0],context)
    if rules['registry_digest']!=policy['security_rule_digest']:fail('trust_rejected')
    verification=[r for r in rules['policies'] if r['evidence_type']=='verification']
    if len(verification)!=1 or verification[0]['minimum_trust']!='independently-reviewed':fail('trust_rejected')
    now=time.time_ns()//10**9
    if not 0<=value['issued_at']<=now<=value['expires_at'] or now-value['issued_at']>verification[0]['maximum_freshness_seconds']:fail('clock_unavailable')
    key=[k for k in trust['keys'] if k['id']==value['signing_key_id'] and k['purpose']=='security-evidence'
        and k['id'] not in trust['revoked_key_ids'] and manifest['release_id'] in k['allowed_release_ids']]
    if len(key)!=1:fail('trust_rejected')
    body={k:v for k,v in value.items() if k!='signature'}
    # Same charged semantic framing, a purpose distinct from release signatures.
    from graph_engineering.core.contracts.canonical import canonicalize
    envelope={'algorithm':'sha-256','body':body,'canonicalizer':'urn:gew:canonicalizer:jcs-input:1.0.0',
        'contract_type':'urn:gew:contract:release-install-security-evidence','digest_domain':'urn:gew:digest:semantic:1.0.0',
        'projection_id':'urn:gew:digest-projection:release-install-security-evidence:1.0.0','schema_id':'urn:gew:schema:release-install-security-evidence:1.0.0'}
    preimage=canonicalize(envelope,context,source_id='release-security-evidence')
    _verify_signature(key[0]['public_key_hex'],value['signature'],preimage)
    return value['issued_at'],value['expires_at'],verification[0]['maximum_freshness_seconds']


class ReleaseObservation:
    """Process-local verified bytes; JSON never grants installation authority."""
    __slots__=('_inputs','_files','_root','_members','_limits','_diagnostic','_freshness','_parser','_budget','_provider','_provider_current','_provider_close','_backend_binding')
    def __init__(self):raise TypeError('release observation requires verification')

    def require_current(self) -> str:
        try:return self._require_current()
        except BaseException:
            self.close();raise

    def _require_current(self) -> str:
        import time
        current=self._provider_current;provider=current.__self__
        if self._provider is not provider:fail('currentness')
        if 'require_current' in vars(provider) or vars(type(provider)).get('require_current') is not current.__func__:fail('currentness')
        self._inputs.require_current();budget=self._budget
        if _bundle_members(self._root,self._limits)!=self._members:fail('currentness')
        for path,binding,parents,raw_hash in self._files:
            opened=_ReadFile(Path(path),self._limits['max_artifact_bytes'],budget,account_bundle=False)
            try:
                if opened.snapshot()!=(path,binding,parents,raw_hash):fail('currentness')
            finally:opened.close()
        if tuple(_PARSER_RESOURCES())!=self._backend_binding or current()!=self._parser:fail('currentness')
        now=time.time_ns()//10**9;issued,expiry,freshness=self._freshness
        if not issued<=now<=expiry or now-issued>freshness:fail('clock_unavailable')
        self._inputs.require_current()
        return self._diagnostic['diagnostic_digest']

    def close(self) -> None:
        self._provider_close()

    def __del__(self):
        try:self.close()
        except (AttributeError,ValueError,RuntimeError):pass

    def to_dict(self) -> dict[str, object]:
        from graph_engineering.core.contracts import thaw,freeze
        self.require_current();return thaw(freeze(self._diagnostic))


class LocalReleaseVerifier:
    def check(self,bundle_ref: Path,manifest_ref: Path,*,_probe_hook: Callable[[str], None] | None=None) -> ReleaseObservation:
        if _probe_hook is not None and not callable(_probe_hook):fail('input_invalid')
        opened=[];provider=None
        try:
            backend=_release_backend();provider=backend['_owned_constraint_provider']()
            with provider.operation():
                result=self._check(Path(bundle_ref),Path(manifest_ref),opened,_probe_hook,backend,provider)
            provider=None  # Ownership transfers to the returned observation.
            return result
        except ReleaseInstallationError:raise
        except (OSError,ValueError,TypeError,RuntimeError,KeyError,IndexError,OverflowError,zipfile.BadZipFile):fail('closure_mismatch')
        finally:
            for item in reversed(opened):item.close()
            if provider is not None:provider.close()

    def _check(self,bundle,manifest_path,opened,probe,backend,provider):
        from graph_engineering.core.release_installation import (select_release_key,manifest_signature_preimage,
            check_compatibility,compare_release_closure,closed,validate_self,diagnostic)
        import io,zipfile
        inputs=InstalledReleaseInputs.open_owned();policy=inputs.policy;trust=inputs.trust;limits=inputs.limits
        context=_fresh_context();budget=_Budget(limits);parser=backend['_package_parser_attestation']()
        original=tuple(_PARSER_RESOURCES());bundle=bundle.absolute();manifest_path=manifest_path.absolute()
        members=_bundle_members(bundle,limits)
        manifest_file=_ReadFile(manifest_path,limits['max_manifest_bytes'],budget);opened.append(manifest_file)
        raw_manifest=_json(manifest_file.raw,context)
        if type(raw_manifest) is not dict or type(raw_manifest.get('artifacts')) is not list or type(raw_manifest.get('dependencies')) is not list:fail('input_invalid')
        budget.ceiling('max_artifacts',len(raw_manifest['artifacts']));budget.ceiling('max_dependency_edges',len(raw_manifest['dependencies']))
        model=ReleaseInstallManifest.from_dict(raw_manifest,context);value=model.to_dict()
        budget.ceiling('max_artifacts',len(value['artifacts']));budget.ceiling('max_dependency_edges',len(value['dependencies']))
        if value['policy_digest']!=policy['policy_digest'] or value['trust_registry_digest']!=trust['registry_digest']:fail('trust_rejected')
        _verify_signature(select_release_key(model,trust,context),value['signature'],manifest_signature_preimage(value,context))
        platform=_host_platform()
        if platform!=value['platform']:fail('platform_unavailable')
        selected=[p for p in policy['platforms'] if all(p[k]==platform[k] for k in platform)]
        if len(selected)!=1:fail('platform_unavailable')
        check_compatibility(model,selected[0]['supported_versions'],selected[0]['capabilities'],context)
        expected_files={r['relative_path'] for r in value['artifacts']}
        if manifest_path.is_relative_to(bundle):expected_files.add(manifest_path.relative_to(bundle).as_posix())
        if members[0]!=frozenset(expected_files):fail('closure_mismatch')
        if sum(r['size_bytes'] for r in value['artifacts'])+len(manifest_file.raw)>limits['max_bundle_bytes']:fail('resource_limit')
        files={};structures={};facts=[]
        for row in value['artifacts']:
            if row['source_id'] not in policy['source_ids'] or not set(row['license_ids']).issubset(policy['allowed_license_ids']):fail('trust_rejected')
            budget.ceiling('max_artifact_bytes',row['size_bytes'])
            item=_ReadFile(bundle/row['relative_path'],limits['max_artifact_bytes'],budget);opened.append(item);files[row['artifact_id']]=item
            if len(item.raw)!=row['size_bytes'] or item.raw_sha256!=row['raw_sha256']:fail('closure_mismatch')
            facts.append({'artifact_id':row['artifact_id'],'raw_sha256':item.raw_sha256,'size_bytes':len(item.raw)})
        if probe:probe('release.after-open')
        # The entire physical archive closure is bounded before any member parsing.
        for row in value['artifacts']:
            raw=files[row['artifact_id']].raw
            if row['kind'] in ('core-wheel','dependency-wheel','skill'):
                structures[row['artifact_id']]=_zip_structure(raw,backend,budget)
                if row['kind'] in ('core-wheel','dependency-wheel'):
                    # The existing wheel validator materializes members and then
                    # reads METADATA again. Reserve a full second expansion before
                    # either allocation; this conservatively bounds both reads.
                    budget.charge('max_expanded_bytes',structures[row['artifact_id']][1])
            elif row['kind'] in ('interpreter','installer'):
                structures[row['artifact_id']]=_tar_structure(raw,budget)
            elif row['kind']=='build-input':fail('phase_unavailable')
        metadata={};requirements_count=0
        for row in value['artifacts']:
            ident=row['artifact_id'];raw=files[ident].raw
            if row['kind'] in ('core-wheel','dependency-wheel'):
                _,expanded=structures[ident];budget.charge('max_hash_bytes',2*len(raw)+expanded)
                observation=backend['observe_release_wheel'](bundle/row['relative_path'],expected_name=row['distribution_name'],expected_version=row['version'],
                    max_members=limits['max_archive_members'],max_member_bytes=limits['max_expanded_bytes'],max_expanded_bytes=limits['max_expanded_bytes'],max_requirements=limits['max_dependency_edges']-requirements_count,python_patch=value['interpreter']['patch'])
                if observation['raw_sha256']!=row['raw_sha256'] or observation['size_bytes']!=row['size_bytes'] or observation['license_ids']!=row['license_ids'] or observation['parser_attestation_digest']!=parser.attestation_digest:fail('closure_mismatch')
                requirements_count+=len(observation['requirements']);metadata[ident]=observation['requirements']
            elif row['kind'] in ('interpreter','installer'):
                fields=value['interpreter'] if row['kind']=='interpreter' else value['installer'];table=structures[ident]
                executable=fields['executable_member'] if row['kind']=='interpreter' else 'bin/uv'
                if executable not in table or 'release-runtime.json' not in table:fail('closure_mismatch')
                start,end=table['release-runtime.json']
                if _json(raw[start:end],context)!=fields:fail('closure_mismatch')
            elif row['kind']=='skill':
                entries=structures[ident][0]
                for skill in value['skills']:
                    if skill['artifact_id']==ident and skill['entry_member'] not in entries:fail('closure_mismatch')
                # Read every member to check actual CRC and compressed stream integrity.
                with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                    for info in archive.infolist():
                        with archive.open(info) as stream:
                            total=0
                            while chunk:=stream.read(65536):total+=len(chunk)
                            if total!=info.file_size:fail('closure_mismatch')
        environment=marker_environment(value['platform'],value['interpreter']['patch'])
        rows={r['artifact_id']:r for r in value['artifacts']};names={backend['canonicalize_name'](r['distribution_name']):r for r in value['artifacts'] if r['kind'] in ('core-wheel','dependency-wheel')}
        # Compute active extras to a fixed point from actual METADATA, then compare
        # the complete physical edge set. Declared edges cannot suppress a requirement.
        extras={ident:set() for ident in metadata};core_id=next(r['artifact_id'] for r in value['artifacts'] if r['kind']=='core-wheel');reachable={core_id}
        for _ in range(len(metadata)+1):
            changed=False
            for parent in sorted(reachable.copy()):
                for text in metadata[parent]:
                    req=backend['_parse_requirement'](text,exact_pin=False)
                    if req.url is not None:fail('closure_mismatch')
                    active=req.marker is None or any(req.marker.evaluate(dict(environment,extra=e)) for e in ['']+sorted(extras[parent]))
                    if not active:continue
                    child=names.get(backend['canonicalize_name'](req.name))
                    if child is None or backend['Version'](child['version']) not in req.specifier:fail('closure_mismatch')
                    ident=child['artifact_id'];new=set(req.extras)-extras[ident]
                    if ident not in reachable or new:changed=True;reachable.add(ident);extras[ident].update(new)
            if not changed:break
        else:fail('closure_mismatch')
        if reachable!=set(metadata):fail('closure_mismatch')
        edges=[]
        for parent,texts in sorted(metadata.items()):
            seen=set()
            for text in texts:
                req=backend['_parse_requirement'](text,exact_pin=False)
                marker=None if req.marker is None else str(req.marker)
                identity=(backend['canonicalize_name'](req.name),str(req.specifier),marker,tuple(sorted(req.extras)))
                if identity in seen:fail('closure_mismatch')
                seen.add(identity)
                if req.marker is not None and not any(req.marker.evaluate(dict(environment,extra=e)) for e in ['']+sorted(extras[parent])):continue
                child=names[backend['canonicalize_name'](req.name)]
                edges.append({'parent_artifact_id':parent,'child_artifact_id':child['artifact_id'],'requirement':text,'marker':marker,'extras':sorted(req.extras)})
        # Keep current product direct pins exact and sourced from attested pyproject.
        import tomllib
        project=tomllib.loads(original[1].decode())['project']
        if project['name']!=value['product']['name'] or project['version']!=value['product']['version'] or metadata[core_id]!=project['dependencies']:fail('closure_mismatch')
        edges.sort(key=lambda r:(r['parent_artifact_id'],r['child_artifact_id'],r['requirement']))
        closure=compare_release_closure(model,{'artifacts':facts,'dependencies':edges},context)
        components=[{k:r[k] for k in ('artifact_id','distribution_name','version','raw_sha256','size_bytes','source_id','license_ids')} for r in value['artifacts'] if r['kind'] in ('core-wheel','dependency-wheel')]
        for ident,kind,field in [(value['lock_artifact_id'],'lock','export_digest'),(value['sbom_artifact_id'],'sbom','sbom_digest')]:
            document=_json(files[ident].raw,context);fields={'schema_version','release_id','components','dependencies',field}
            if kind=='lock':fields.add('platform')
            closed(document,fields);validate_self(document,kind,field,context)
            if document['schema_version']!='1.0.0' or document['release_id']!=value['release_id'] or document['components']!=components or document['dependencies']!=edges or kind=='lock' and document['platform']!=value['platform']:fail('closure_mismatch')
        subjects=[{k:r[k] for k in ('artifact_id','kind','raw_sha256','size_bytes','source_id','license_ids')} for r in value['artifacts'] if r['kind'] in ('interpreter','installer','core-wheel','dependency-wheel','build-input','skill')]
        provenance_ids={r['provenance_artifact_id'] for r in value['artifacts'] if r['kind'] in policy['required_provenance_kinds']}
        if not provenance_ids or None in provenance_ids:fail('trust_rejected')
        for ident in provenance_ids:
            provenance=_json(files[ident].raw,context);closed(provenance,('schema_version','release_id','subjects','provenance_digest'));validate_self(provenance,'provenance','provenance_digest',context)
            if provenance['schema_version']!='1.0.0' or provenance['release_id']!=value['release_id'] or provenance['subjects']!=subjects:fail('trust_rejected')
        freshness=_security_check(_json(files[value['security_evidence_artifact_id']].raw,context),value,policy,trust,subjects,context)
        if probe:probe('release.before-return')
        for item in opened:item.recheck(budget)
        if _bundle_members(bundle,limits)!=members or tuple(_PARSER_RESOURCES())!=original or backend['_package_parser_attestation']()!=parser:fail('currentness')
        inputs.require_current()
        report=diagnostic('preflight-valid','check','ok',[],sorted([value['manifest_digest'],closure]),context,max_bytes=limits['max_report_bytes'])
        result=object.__new__(ReleaseObservation);result._inputs=inputs;result._files=tuple(i.snapshot() for i in opened)
        result._root=bundle;result._members=members;result._limits=limits;result._diagnostic=report;result._freshness=freshness;result._parser=parser.attestation_digest;result._budget=budget;result._provider=provider;result._provider_current=provider.require_current;result._provider_close=provider.close;result._backend_binding=original
        return result


def _clock_from_snapshot(raw,context):
    """Inspect a bounded SQLite image in memory; never open its source with SQLite."""
    import sqlite3,time
    if not raw.startswith(b'SQLite format 3\x00'):return False
    connection=sqlite3.connect(':memory:')
    try:
        connection.deserialize(raw);connection.execute('PRAGMA query_only=ON');connection.execute('PRAGMA trusted_schema=OFF')
        # Charge execution through the existing deterministic work budget.
        def progress() -> int:
            try:context.emit('schema.instance_visit',1,source_id='release-doctor',operation_path=context.child_path(()));return 0
            except (TypeError,ValueError,RuntimeError):return 1
        connection.set_progress_handler(progress,1)
        now=time.time_ns();rows=[]
        tables={r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('repository_meta','repository_clock_state','clock_state')")}
        if 'repository_meta' in tables:
            rows.extend(r[0] for r in connection.execute("SELECT value FROM repository_meta WHERE key='clock_high_water_ns' LIMIT 2"))
        for table in ('repository_clock_state','clock_state'):
            if table in tables:rows.extend(r[0] for r in connection.execute('SELECT clock_high_water_ns FROM '+table+' LIMIT 2'))
        for value in rows:
            if type(value) is int:observed=value
            elif type(value) is str and value.isascii() and value.isdigit() and len(value)<=20 and (value=='0' or not value.startswith('0')):observed=int(value)
            else:fail('clock_unavailable')
            if observed<0 or observed>now:fail('clock_unavailable')
        return True
    except sqlite3.Error:fail('recovery_blocked')
    finally:connection.close()


class ReadOnlyDoctor:
    def inspect(self,existing_ref: Path | None=None) -> dict[str, object]:
        from graph_engineering.core.release_installation import diagnostic,bootstrap_diagnostic
        opened=[];context=None
        try:
            context=_fresh_context();inputs=InstalledReleaseInputs.open_owned();limits=inputs.limits;budget=_Budget(limits)
            code='phase_unavailable'
            if existing_ref is not None:
                root=Path(existing_ref).absolute()
                # A missing path is a normal blocked result; never initialize it.
                if root.exists():
                    before=_bundle_members(root,limits)
                    for relative in sorted(before[0]):
                        item=_ReadFile(root/relative,limits['max_artifact_bytes'],budget);opened.append(item)
                        if relative.endswith(('-wal','-journal')) and item.raw:code='recovery_blocked'
                        if item.raw.startswith(b'SQLite format 3\x00'):
                            _clock_from_snapshot(item.raw,context)
                    for item in opened:item.recheck(budget)
                    if _bundle_members(root,limits)!=before:fail('currentness')
                elif root.is_symlink():fail('currentness')
            inputs.require_current()
            return diagnostic('blocked','doctor',code,[],[],context,max_bytes=limits['max_report_bytes'])
        except ReleaseInstallationError as error:
            if context is None or error.code == 'trust_rejected':return bootstrap_diagnostic('doctor')
            return diagnostic('blocked','doctor',error.code,[],[],context,max_bytes=context.profile.limits['result_bytes'])
        except (OSError,ValueError,TypeError,RuntimeError,KeyError):
            if context is None:return bootstrap_diagnostic('doctor')
            return diagnostic('blocked','doctor','recovery_blocked',[],[],context,max_bytes=context.profile.limits['result_bytes'])
        finally:
            for item in reversed(opened):item.close()
