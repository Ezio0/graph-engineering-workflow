"""Dependency-free PEP 517 backend for the multi-root installed namespace."""

from __future__ import annotations

import base64
import ast
import abc
import types
import contextlib
import contextvars
import copy
import csv
import functools
import hashlib
import importlib
import importlib.metadata
import importlib.util
import io
import json
import os
import pathlib
import re
import stat
import struct
import sys
import threading
import tomllib
import unicodedata
import zipfile
from collections.abc import Callable, Iterable, Iterator
from email.parser import Parser
from typing import NamedTuple

def _parser_namespace(module: object, expected_name: str | None=None) -> dict[str, object]:
    if type(module) is not types.ModuleType:
        raise ValueError('package parser module is substituted')
    namespace=vars(module)
    if any(type(key) is not str for key in namespace):
        raise ValueError('package parser module namespace is substituted')
    name=namespace.get('__name__')
    if type(name) is not str or (expected_name is not None and name!=expected_name):
        raise ValueError('package parser module name is substituted')
    return namespace


def _validate_loaded_parser_namespaces() -> None:
    # Backend reloading must reject malformed live dictionaries before Python's
    # import machinery or module attribute lookups can consult their keys.
    for name,module in tuple(sys.modules.items()):
        if type(name) is str and (name=='packaging' or name.startswith('packaging.')):
            _parser_namespace(module,name)


_validate_loaded_parser_namespaces()

import packaging
import packaging.requirements
import packaging.specifiers
import packaging._ranges
import packaging.tags
import packaging.utils
import packaging.version
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.tags import parse_tag, sys_tags
from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import InvalidVersion, Version


ROOT = pathlib.Path(__file__).resolve().parents[1]
if pathlib.Path(__file__).name == "build_backend.py" and pathlib.Path(__file__).parent.name == "graph_engineering":
    ROOT = pathlib.Path(__file__).resolve().parent
PYPROJECT = ROOT / "pyproject.toml"
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
ACTION_ADAPTER_PROVENANCE_RESOURCE = "graph_engineering/pyproject.toml"
_RAW_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PARSER_MODULES = (
    packaging,
    packaging.requirements,
    packaging.specifiers,
    packaging.tags,
    packaging.utils,
    packaging.version,
)
_PARSER_RELEASE_INSTALL_PINS = (
    "distribution-metadata-digest",
    "parser-implementation-digest",
    "record-digest",
    "source-artifact-attestation-digest",
    "source-artifact-raw-digest",
    "wheel-attestation-digest",
    "wheel-raw-digest",
)


class PackageParserAttestation(NamedTuple):
    requirement_digest: str
    distribution_name: str
    distribution_version: str
    distribution_root: str
    record_digest: str
    module_digests: tuple[tuple[str, str, str], ...]
    attestation_digest: str


class WheelFileBinding(NamedTuple):
    path: str
    parent_path: str
    parent_device: int
    parent_inode: int
    descriptor_device: int
    descriptor_inode: int
    descriptor_owner: int
    descriptor_mode: int
    descriptor_links: int
    descriptor_size: int
    descriptor_mtime_ns: int
    entry_device: int
    entry_inode: int
    entry_owner: int
    entry_mode: int
    entry_links: int
    entry_size: int
    entry_mtime_ns: int
    raw_digest: str


class OfflineDependencyPlan(NamedTuple):
    parser_attestation: PackageParserAttestation
    candidate_wheel: pathlib.Path | None
    dependency_wheels: tuple[pathlib.Path, ...]
    wheel_bindings: tuple[WheelFileBinding, ...]
    plan_digest: str


_CONFIGURATION_PARSER = tomllib.loads
_CONFIGURATION_OPERATION: contextvars.ContextVar[dict[str, object] | None] = (
    contextvars.ContextVar("configuration_parse_operation", default=None)
)


@contextlib.contextmanager
def _configuration_parse_operation() -> Iterator[None]:
    state: dict[str, object] = {"owner": (os.getpid(), threading.get_ident())}
    token = _CONFIGURATION_OPERATION.set(state)
    try:
        yield
    finally:
        state.clear()
        _CONFIGURATION_OPERATION.reset(token)


def _configuration() -> dict[str, object]:
    # A warm pure parse must never bypass the original read or its failures.
    text = PYPROJECT.read_text(encoding="utf-8")
    parser = tomllib.loads
    state = _CONFIGURATION_OPERATION.get()
    if (
        state is None
        or state.get("owner") != (os.getpid(), threading.get_ident())
        or parser is not _CONFIGURATION_PARSER
    ):
        return parser(text)
    if state.get("parser") is parser and state.get("text") == text:
        return copy.deepcopy(state["value"])
    value = parser(text)
    state.update(parser=parser, text=text, value=copy.deepcopy(value))
    return value


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _regular_descriptor_bytes(path: pathlib.Path) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o022
        ):
            raise ValueError("package parser attestation input is unsafe")
        body = bytearray()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            body.extend(chunk)
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or len(body) != before.st_size
        ):
            raise ValueError("package parser attestation input changed")
        return bytes(body)
    finally:
        os.close(descriptor)


def _normalized_metadata_name(value: object) -> str:
    if type(value) is not str or not value:
        return ""
    return re.sub(r"[-_.]+", "-", value).lower()



def _package_parser_attestation() -> PackageParserAttestation:
    """Attest the configured packaging distribution before any preflight parse."""

    # Module lookups precede parsing too. Inspect exact module dictionaries so
    # a missing export cannot invoke a substituted module __getattr__ hook.
    root_namespace=_parser_namespace(packaging,'packaging')
    if sys.modules.get('packaging') is not packaging:
        raise ValueError('package parser root module is substituted')
    public={}
    for suffix in ('requirements','specifiers','tags','utils','version','_ranges'):
        module=sys.modules.get('packaging.'+suffix)
        namespace=_parser_namespace(module,'packaging.'+suffix)
        if root_namespace.get(suffix) is not module:
            raise ValueError('package parser module link is substituted')
        public[suffix]=namespace
    build = _configuration().get("tool", {}).get("gew", {}).get("build", {})  # type: ignore[union-attr]
    parser_config = build.get("package-parser-requirement") if isinstance(build, dict) else None
    if not isinstance(parser_config, dict) or set(parser_config) != {"path", "sha256"}:
        raise ValueError("package parser requirement configuration is not exact")
    relative_value = parser_config.get("path")
    claimed_requirement_digest = parser_config.get("sha256")
    if (
        type(relative_value) is not str
        or type(claimed_requirement_digest) is not str
        or _RAW_SHA256.fullmatch(claimed_requirement_digest) is None
    ):
        raise ValueError("package parser requirement configuration is malformed")
    relative = pathlib.PurePosixPath(relative_value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("package parser requirement path is invalid")
    requirement_path = ROOT / relative
    if requirement_path.resolve(strict=True) != requirement_path.absolute():
        raise ValueError("package parser requirement path is not canonical")
    requirement_raw = _regular_descriptor_bytes(requirement_path)
    requirement_digest = hashlib.sha256(requirement_raw).hexdigest()
    if requirement_digest != claimed_requirement_digest:
        raise ValueError("package parser requirement digest changed")
    try:
        requirement = json.loads(requirement_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("package parser requirement is malformed") from error
    requirement_fields = {
        "schema_version", "requirement_id", "distribution_name",
        "distribution_version", "python_requires", "import_prefix",
        "parser_boundary", "network_mode", "fallback", "activation_status",
        "required_release_install_pins", "update_authority",
    }
    if (
        type(requirement) is not dict
        or set(requirement) != requirement_fields
        or requirement.get("schema_version") != "1.0.0"
        or requirement.get("requirement_id") != "extension-package-parser-pypa-v1"
        or requirement.get("python_requires") != ">=3.12"
        or requirement.get("parser_boundary") != "build-install-package-verification-only"
        or requirement.get("network_mode") != "offline-only"
        or requirement.get("fallback") != "disabled"
        or requirement.get("activation_status")
        != "blocked-pending-wp10-release-install-manifest"
        or requirement.get("required_release_install_pins")
        != list(_PARSER_RELEASE_INSTALL_PINS)
        or requirement.get("update_authority")
        != "wp10-owner-authorized-supply-chain-install-manifest"
    ):
        raise ValueError("package parser protected requirement is not exact")
    distribution_name = requirement.get("distribution_name")
    distribution_version = requirement.get("distribution_version")
    import_prefix = requirement.get("import_prefix")
    if (
        distribution_name != "packaging"
        or distribution_version != "26.3"
        or import_prefix != "packaging"
    ):
        raise ValueError("package parser requirement identity is unsupported")

    matches = []
    for distribution in importlib.metadata.distributions():
        try:
            name = distribution.metadata["Name"]
        except (KeyError, TypeError):
            continue
        if _normalized_metadata_name(name) == _normalized_metadata_name(distribution_name):
            matches.append(distribution)
    if len(matches) != 1:
        raise ValueError("package parser distribution is missing or shadowed")
    distribution = matches[0]
    if distribution.version != distribution_version:
        raise ValueError("package parser distribution version is wrong")
    distribution_root = pathlib.Path(distribution.locate_file("")).resolve(strict=True)
    if not distribution_root.is_dir() or distribution_root.is_symlink():
        raise ValueError("package parser distribution root is unsafe")
    files = distribution.files
    if files is None:
        raise ValueError("package parser distribution RECORD is unavailable")
    indexed_files = {pathlib.PurePosixPath(str(item)).as_posix(): item for item in files}
    record_names = [name for name in indexed_files if name.endswith(".dist-info/RECORD")]
    if len(record_names) != 1:
        raise ValueError("package parser distribution RECORD is ambiguous")
    record_name = record_names[0]
    record_path = pathlib.Path(distribution.locate_file(record_name)).resolve(strict=True)
    if not record_path.is_relative_to(distribution_root):
        raise ValueError("package parser distribution RECORD escapes its root")
    record_raw = _regular_descriptor_bytes(record_path)
    record_digest = hashlib.sha256(record_raw).hexdigest()
    try:
        record_rows = list(csv.reader(io.StringIO(record_raw.decode("utf-8"), newline="")))
    except (UnicodeDecodeError, csv.Error) as error:
        raise ValueError("package parser distribution RECORD is malformed") from error
    if any(len(row) != 3 for row in record_rows):
        raise ValueError("package parser distribution RECORD shape is invalid")
    record_index = {row[0]: row for row in record_rows}
    if len(record_index) != len(record_rows) or record_name not in record_index:
        raise ValueError("package parser distribution RECORD member set is invalid")

    source_names = tuple(sorted(
        name for name in record_index
        if name.endswith(".py")
        and (name == "packaging/__init__.py" or name.startswith("packaging/"))
    ))
    if not source_names:
        raise ValueError("package parser source closure is unavailable")
    module_digests: list[tuple[str, str, str]] = []
    expected_modules: dict[str, pathlib.Path] = {}
    verified_parser_sources: dict[str, bytes] = {}
    for relative_origin in source_names:
        relative = pathlib.PurePosixPath(relative_origin)
        if (
            relative.is_absolute()
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise ValueError("package parser RECORD source path is invalid")
        origin = pathlib.Path(distribution.locate_file(relative_origin)).resolve(strict=True)
        expected_origin = distribution_root.joinpath(*relative.parts)
        if origin != expected_origin or not origin.is_relative_to(distribution_root) or origin.is_symlink():
            raise ValueError("package parser RECORD source origin is shadowed")
        row = record_index[relative_origin]
        if row[1] == "" or row[2] == "":
            raise ValueError("package parser module RECORD binding is missing")
        module_raw = _regular_descriptor_bytes(origin)
        module_digest = hashlib.sha256(module_raw).digest()
        expected_hash = "sha256=" + base64.urlsafe_b64encode(module_digest).rstrip(b"=").decode()
        if row[1] != expected_hash or row[2] != str(len(module_raw)):
            raise ValueError("package parser module RECORD hash changed")
        parts = list(relative.with_suffix("").parts)
        if parts[-1] == "__init__":
            parts.pop()
        module_name = ".".join(parts)
        if not module_name or module_name in expected_modules:
            raise ValueError("package parser module identity is ambiguous")
        expected_modules[module_name] = origin
        verified_parser_sources[module_name] = module_raw
        module_digests.append((module_name, relative_origin, module_digest.hex()))

    for module_name, module in tuple(sys.modules.items()):
        if module_name != "packaging" and not module_name.startswith("packaging."):
            continue
        namespace=_parser_namespace(module,module_name)
        origin_value = namespace.get("__file__")
        specification = namespace.get("__spec__")
        if type(specification) is not importlib.machinery.ModuleSpec:
            raise ValueError("package parser module specification is substituted")
        specification_namespace=vars(specification)
        if type(specification_namespace) is not dict or any(type(key) is not str for key in specification_namespace):
            raise ValueError('package parser module specification namespace is substituted')
        specification_origin_value=specification_namespace.get('origin')
        found = importlib.util.find_spec(module_name)
        if (
            type(origin_value) is not str
            or type(specification_origin_value) is not str
            or found is not specification
        ):
            raise ValueError("package parser module origin is unavailable")
        origin = pathlib.Path(origin_value).resolve(strict=True)
        specification_origin = pathlib.Path(specification_origin_value).resolve(strict=True)
        expected_origin = expected_modules.get(module_name)
        if (
            expected_origin is None
            or origin != specification_origin
            or origin != expected_origin
            or origin.is_symlink()
        ):
            raise ValueError("package parser module origin is shadowed")
    if any(_parser_namespace(module)['__name__'] not in expected_modules for module in _PARSER_MODULES):
        raise ValueError("package parser public module closure is incomplete")
    if (
        type(vars(packaging).get('__version__')) is not str
        or vars(packaging).get('__version__') != distribution_version
        or Requirement is not public['requirements'].get('Requirement')
        or parse_tag is not public['tags'].get('parse_tag')
        or sys_tags is not public['tags'].get('sys_tags')
        or canonicalize_name is not public['utils'].get('canonicalize_name')
        or parse_wheel_filename is not public['utils'].get('parse_wheel_filename')
        or Version is not public['version'].get('Version')
        or SpecifierSet is not public['specifiers'].get('SpecifierSet')
        or SpecifierSet is not public['requirements'].get('SpecifierSet')
        or InvalidSpecifier is not public['specifiers'].get('InvalidSpecifier')
    ):
        raise ValueError("package parser callable binding is substituted")
    contract_digest = _attest_specifier_callables(verified_parser_sources, expected_modules)
    body = {
        "schema_version": "1.0.0",
        "requirement_digest": requirement_digest,
        "distribution_name": distribution_name,
        "distribution_version": distribution_version,
        "distribution_root": os.fspath(distribution_root),
        "record_digest": record_digest,
        "module_digests": module_digests,
        "constraint_contract_digest": contract_digest,
    }
    attestation_digest = hashlib.sha256(_canonical_json(body)).hexdigest()
    return PackageParserAttestation(
        requirement_digest,
        distribution_name,
        distribution_version,
        os.fspath(distribution_root),
        record_digest,
        tuple(module_digests),
        attestation_digest,
    )



# Source-derived constraint graph. This is owned backend code, not candidate code.
_CONSTRAINT_OPERATION: contextvars.ContextVar[dict[str, object] | None] = contextvars.ContextVar(
    'owned_constraint_operation', default=None)
_CONSTRAINT_METADATA = {
    'packaging.version': frozenset(('LocalType','CmpLocalType','CmpSuffix','CmpKey',
                                    'VersionComparisonMethod','_VersionReplace')),
    'packaging.specifiers': frozenset(('T','UnparsedVersion','UnparsedVersionVar')),
    'packaging._ranges': frozenset(),
}


def _constraint_code(code: types.CodeType) -> types.CodeType:
    return code.replace(co_filename='<verified-parser>', co_consts=tuple(
        _constraint_code(v) if type(v) is types.CodeType else v for v in code.co_consts))


class _ConstraintImage:
    """Finite source image; no registration, ambient parser execution or disk cache."""
    def __init__(self, sources: dict[str, bytes], origins: dict[str, pathlib.Path]):
        import builtins, dis, enum, typing, __future__
        if sys.implementation.name != 'cpython' or sys.version_info[:2] != (3,12):
            raise ValueError('constraint construction recipe is unavailable')
        self.modules: dict[str, types.ModuleType] = {}
        self.sites: list[tuple[object, ...]] = []
        self.links: dict[int, object] = {}
        self.omitted: dict[str, set[str]] = {}
        self.metadata_nodes: dict[str,dict[str,ast.AST]] = {}
        self.annotation_imports: dict[str,dict[str,object]] = {}
        self.key = tuple((name, hashlib.sha256(sources[name]).hexdigest()) for name in
                         ('packaging.version','packaging._ranges','packaging.specifiers','packaging.utils'))
        typing_facade=types.SimpleNamespace(TYPE_CHECKING=False,NamedTuple=typing.NamedTuple)
        def compile_pattern(pattern: str, flags: object=0) -> re.Pattern[str]:
            if type(pattern) is not str or type(flags) not in (int,re.RegexFlag):
                raise ValueError('constraint regex construction is invalid')
            # Same compiler as re._compile, without its process-wide caches.
            return re._compiler.compile(pattern,int(flags))
        regex_facade=types.SimpleNamespace(compile=compile_pattern,VERBOSE=re.VERBOSE,
                                           IGNORECASE=re.IGNORECASE,ASCII=re.ASCII)
        self.links[id(typing_facade)]=typing;self.links[id(regex_facade)]=re
        stdlib={'abc':abc,'re':regex_facade,'sys':sys,'typing':typing_facade,
                'enum':enum,'functools':functools,'warnings':__import__('warnings'),
                '__future__':__future__}
        for name,obj in stdlib.items():
            self.links.setdefault(id(obj),obj)
        self.links[id(typing.NamedTuple)]=typing.NamedTuple
        self.intrinsics=dict(vars(builtins))
        self.bytecode: dict[int, types.CodeType] = {}
        self.instructions: dict[int, tuple[object, ...]] = {}
        def importer(name: str, global_ns: dict[str, object] | None=None, local_ns: dict[str, object] | None=None, fromlist: tuple[str, ...]=(), level: int=0) -> object:
            if level:
                if level!=1 or name not in ('version','_ranges','utils'):
                    raise ValueError('constraint relative import is unavailable')
                target=self.modules.get('packaging.'+name)
                if target is None:raise ValueError('constraint import order is invalid')
                return target
            if name not in stdlib:raise ValueError('constraint stdlib import is unavailable')
            return stdlib[name]
        self.builtins=dict(self.intrinsics,__import__=importer)
        self.overload_sites=0
        def prepare(body: list[ast.stmt], name: str) -> list[ast.stmt]:
            result=[]
            for node in body:
                if isinstance(node,(ast.Import,ast.ImportFrom)):
                    if isinstance(node,ast.ImportFrom) and node.module=='typing':
                        names=[a for a in node.names if a.name in ('NamedTuple','TYPE_CHECKING')]
                        self.annotation_imports.setdefault(name,{}).update({a.asname or a.name:getattr(typing,a.name) for a in node.names if a not in names})
                        if not names:continue
                        node=ast.copy_location(ast.ImportFrom(module='typing',names=names,level=0),node)
                    self.sites.append((name,node.lineno,'import',ast.unparse(node)))
                if isinstance(node,ast.If):
                    # Both branches retain source correspondence. TYPE_CHECKING
                    # never executes and unavailable import routes fail closed.
                    if ast.unparse(node.test) in ('typing.TYPE_CHECKING','TYPE_CHECKING'):
                        self.sites.append((name,node.lineno,'annotation-branch'))
                        result.extend(prepare(node.orelse,name))
                        continue
                    node.body=prepare(node.body,name);node.orelse=prepare(node.orelse,name)
                if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                    overloads=[d for d in node.decorator_list if ast.unparse(d)=='typing.overload']
                    if overloads:
                        if (name!='packaging.specifiers' or node.name!='filter' or len(overloads)!=1
                                or len(node.body)!=1 or not isinstance(node.body[0],ast.Expr)
                                or not isinstance(node.body[0].value,ast.Constant)
                                or node.body[0].value.value is not Ellipsis):
                            raise ValueError('constraint overload projection is invalid')
                        self.overload_sites+=1;self.sites.append((name,node.lineno,'overwritten-overload',hashlib.sha256(ast.dump(node).encode()).hexdigest()));continue
                declared=node.name if isinstance(node,ast.ClassDef) else None
                if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):declared=node.targets[0].id
                if declared in _CONSTRAINT_METADATA.get(name,()):
                    self.omitted.setdefault(name,set()).add(declared)
                    self.metadata_nodes.setdefault(name,{})[declared]=node
                    self.sites.append((name,node.lineno,'unread-metadata',declared,hashlib.sha256(ast.dump(node).encode()).hexdigest()));continue
                if isinstance(node,ast.ClassDef):
                    overloaded=[n for n in node.body if isinstance(n,ast.FunctionDef) and any(ast.unparse(d)=='typing.overload' for d in n.decorator_list)]
                    if overloaded:
                        concrete=[n for n in node.body if isinstance(n,ast.FunctionDef) and n.name=='filter' and not any(ast.unparse(d)=='typing.overload' for d in n.decorator_list)]
                        if len(overloaded)!=2 or len(concrete)!=1 or concrete[0].lineno<=max(n.lineno for n in overloaded):
                            raise ValueError('constraint overload implementation is unavailable')
                    node.body=prepare(node.body,name)
                result.append(node)
            return result
        try:
            for name in ('packaging.version','packaging.utils','packaging._ranges','packaging.specifiers'):
                tree=ast.parse(sources[name],filename=str(origins[name]))
                if name=='packaging.utils':
                    nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='canonicalize_version']
                    if len(nodes)!=1:raise ValueError('constraint utility source is unavailable')
                    tree.body=[ast.ImportFrom(module='__future__',names=[ast.alias(name='annotations')],level=0,lineno=1,col_offset=0,end_lineno=1,end_col_offset=1),*nodes]
                else:tree.body=prepare(tree.body,name)
                ast.fix_missing_locations(tree)
                code=compile(tree,str(origins[name]),'exec',dont_inherit=True)
                def inventory(c: types.CodeType) -> None:
                    self.bytecode[id(c)]=_constraint_code(c)
                    instructions=tuple(dis.get_instructions(c));self.instructions[id(c)]=instructions
                    for i in instructions:
                        if i.opname in ('LOAD_GLOBAL','LOAD_NAME') and i.argval in self.omitted.get(name,set())|set(self.annotation_imports.get(name,{})):
                            raise ValueError('constraint metadata has an executable dependency')
                        if i.opname in ('LOAD_GLOBAL','LOAD_ATTR','LOAD_METHOD','IMPORT_NAME','IMPORT_FROM'):
                            self.sites.append((name,c.co_qualname,i.offset,i.opname,str(i.argval)))
                    for value in c.co_consts:
                        if type(value) is types.CodeType:inventory(value)
                inventory(code)
                module=types.ModuleType(name);namespace=vars(module)
                namespace.update(__builtins__=self.builtins,__file__=str(origins[name]),__package__='packaging')
                if name=='packaging.utils':
                    namespace.update({k:vars(self.modules['packaging.version'])[k] for k in ('Version','InvalidVersion','_TrimmedRelease')})
                exec(code,namespace,namespace)
                self.modules[name]=module
            if self.overload_sites!=6 or any(self.omitted.get(n,set())!=set(v) for n,v in _CONSTRAINT_METADATA.items()):
                raise ValueError('constraint construction inventory is incomplete')
            self.class_pairs={}
            for name in ('packaging.version','packaging._ranges','packaging.specifiers'):
                ambient=sys.modules.get(name)
                if type(ambient) is not types.ModuleType:raise ValueError('constraint module type is substituted')
                for key,value in vars(self.modules[name]).items():
                    if isinstance(value,type) and type.__getattribute__(value,'__module__')==name:
                        self.class_pairs[id(value)]=vars(ambient).get(key)
            self.contract_digest=self.check()
        except BaseException:
            self.close();raise

    def close(self) -> None:
        for module in self.modules.values():vars(module).clear()
        self.modules.clear();self.links.clear();self.builtins.clear();self.intrinsics.clear()
        self.bytecode.clear();self.instructions.clear();self.sites.clear()
        if hasattr(self,'class_pairs'):self.class_pairs.clear()

    def check(self) -> str:
        import builtins,dis,enum,weakref
        pairs={};reverse={};projection=[];checked_namespaces={}
        scalars=(str,bytes,int,bool,float,type(None),type(Ellipsis),type(NotImplemented))
        def refuse() -> None:raise ValueError('package parser constraint graph is substituted')
        def primitive(value: object) -> tuple[object, ...]:
            t=type(value)
            if t not in scalars:refuse()
            return (t.__name__,value.hex() if t is bytes else repr(value) if t in (float,type(Ellipsis),type(NotImplemented)) else value)
        def check_cache(reference: object,live: object) -> None:
            if type(reference) is tuple:
                if type(live) is not tuple or len(reference)!=len(live):refuse()
                for a,b in zip(reference,live,strict=True):check_cache(a,b)
            elif type(reference) not in scalars or type(live) is not type(reference) or primitive(reference)!=primitive(live):refuse()
        def rawclass(cls: type) -> types.MappingProxyType:return type.__getattribute__(cls,'__dict__')
        def key(value: object) -> tuple[object, ...]:
            if type(value) in scalars:return primitive(value)
            if type(value) in (type,abc.ABCMeta,enum.EnumType):
                module=type.__getattribute__(value,'__module__');name=type.__getattribute__(value,'__qualname__')
                if type(module) is not str or type(name) is not str:refuse()
                return ('class',module,name)
            refuse()
        def bind(reference: object,live: object,site: str) -> bool:
            prior=pairs.get(id(reference));other=reverse.get(id(live))
            if prior is not None:
                if prior is not live:refuse()
                return True
            if other is not None and other is not reference:refuse()
            pairs[id(reference)]=live;reverse[id(live)]=reference
            projection.append((site,type(reference).__name__))
            return False
        def effective(function: types.FunctionType,name: str) -> object:
            namespace=function.__globals__
            if name in namespace:return namespace[name]
            intrinsic=function.__builtins__
            if name not in intrinsic:refuse()
            return intrinsic[name]
        def compare(reference: object,live: object,site: str) -> None:
            t=type(reference)
            if t in scalars:
                if type(live) is not t or primitive(reference)!=primitive(live):refuse()
                projection.append((site,*primitive(reference)));return
            linked=self.links.get(id(reference))
            if linked is not None:
                if live is not linked:refuse()
                projection.append((site,'stdlib-link'));return
            if reference is live:
                # Only source-independent shared primitives can have identical
                # identities across the private and ambient object graphs.
                projection.append((site,'shared-intrinsic'));return
            if t in (type,abc.ABCMeta,enum.EnumType):
                if self.class_pairs.get(id(reference)) is not live or type(live) is not t:refuse()
                if bind(reference,live,site):return
                compare(type.__getattribute__(reference,'__bases__'),type.__getattribute__(live,'__bases__'),site+'.bases')
                left=dict(rawclass(reference));right=dict(rawclass(live))
                if any(type(k) is not str for k in right):refuse()
                if set(left)!=set(right):refuse()
                for name in sorted(left):
                    if name=='_abc_impl':
                        if type(left[name]) is not type(right[name]):refuse()
                        registry,positive,negative,_=abc._get_dump(live)
                        if registry:refuse()
                        allowed=tuple(self.class_pairs.values())+(object,str,int,float,bool,bytes,tuple,list,dict,set,frozenset,type(None))
                        for entries,is_positive in ((positive,True),(negative,False)):
                            for entry in entries:
                                if type(entry) is not weakref.ReferenceType:refuse()
                                target=weakref.ReferenceType.__call__(entry)
                                if target is None:continue
                                if not any(target is candidate for candidate in allowed) or type(target) not in (type,abc.ABCMeta,enum.EnumType):refuse()
                                inherited=any(base is live for base in type.__getattribute__(target,'__mro__'))
                                if inherited is not is_positive:refuse()
                        projection.append((site+'.'+name,'owned-abc-cache'));continue
                    compare(left[name],right[name],site+'.'+name)
                return
            mapped=self.class_pairs.get(id(t))
            if mapped is not None:
                if type(live) is not mapped:refuse()
                compare(t,mapped,site+'.class')
                if bind(reference,live,site):return
                slots=[]
                for base in type.__getattribute__(t,'__mro__'):
                    entry=rawclass(base).get('__slots__',())
                    slots.extend((entry,) if type(entry) is str else entry)
                if slots:
                    for slot in slots:
                        if slot in ('__weakref__','__dict__'):continue
                        owner=next(base for base in type.__getattribute__(t,'__mro__') if slot in rawclass(base))
                        descriptor=rawclass(owner)[slot];actual_owner=self.class_pairs.get(id(owner))
                        if type(descriptor) is not types.MemberDescriptorType or actual_owner is None:refuse()
                        actual_descriptor=rawclass(actual_owner)[slot]
                        try:a=types.MemberDescriptorType.__get__(descriptor,reference,t)
                        except AttributeError:a=NotImplemented
                        try:b=types.MemberDescriptorType.__get__(actual_descriptor,live,mapped)
                        except AttributeError:b=NotImplemented
                        if slot in ('_key_cache','_hash_cache') and t is vars(self.modules['packaging.version'])['Version']:
                            if b is not None:
                                derived=reference._key if slot=='_key_cache' else hash(reference._key)
                                check_cache(derived,b)
                            projection.append((site+'.'+slot,'source-derived-cache'));continue
                        compare(a,b,site+'.'+slot)
                else:compare(object.__getattribute__(reference,'__dict__'),object.__getattribute__(live,'__dict__'),site+'.fields')
                return
            if type(live) is not t:refuse()
            if t is re.Pattern:
                compare(reference.pattern,live.pattern,site+'.pattern');compare(reference.flags,live.flags,site+'.flags');return
            if t in (tuple,list):
                if len(reference)!=len(live):refuse()
                if bind(reference,live,site):return
                for index,(a,b) in enumerate(zip(reference,live,strict=True)):compare(a,b,site+'.'+str(index))
                return
            if t in (set,frozenset):
                a=sorted(key(v) for v in reference);b=sorted(key(v) for v in live)
                if a!=b:refuse()
                projection.append((site,'primitive-set',a));return
            if t is dict:
                a={key(k):(k,v) for k,v in dict.items(reference)};b={key(k):(k,v) for k,v in dict.items(live)}
                if a.keys()!=b.keys():refuse()
                if bind(reference,live,site):return
                for k in sorted(a):
                    compare(a[k][0],b[k][0],site+'.key.'+str(k));compare(a[k][1],b[k][1],site+'.value.'+str(k))
                return
            if t is types.FunctionType:
                if type(live.__globals__) is not dict or type(live.__builtins__) is not dict:refuse()
                if bind(reference,live,site):return
                for namespace in (live.__globals__,live.__builtins__):
                    if id(namespace) not in checked_namespaces:
                        if any(type(k) is not str for k in namespace):refuse()
                        checked_namespaces[id(namespace)]=namespace
                expected=self.bytecode.get(id(reference.__code__))
                if expected is None:expected=_constraint_code(reference.__code__)
                if _constraint_code(live.__code__)!=expected:refuse()
                for attr in ('__defaults__','__kwdefaults__','__annotations__','__dict__','__closure__'):
                    compare(object.__getattribute__(reference,attr),object.__getattribute__(live,attr),site+'.'+attr)
                for name,module in self.modules.items():
                    if reference.__globals__ is vars(module):
                        ambient=sys.modules.get(name)
                        if type(ambient) is not types.ModuleType or live.__globals__ is not vars(ambient):refuse()
                        break
                instructions=self.instructions.get(id(reference.__code__))
                if instructions is None:
                    instructions=tuple(dis.get_instructions(reference.__code__));self.instructions[id(reference.__code__)]=instructions
                for instruction in instructions:
                    if instruction.opname=='IMPORT_NAME':
                        # IMPORT_NAME reads __import__ from this function's
                        # captured builtins, independently of its module globals.
                        if live.__builtins__.get('__import__') is not builtins.__import__:refuse()
                        continue
                    if instruction.opname!='LOAD_GLOBAL':continue
                    name=instruction.argval
                    a=effective(reference,name);b=effective(live,name)
                    if name=='__import__' and name not in reference.__globals__:
                        if b is not builtins.__import__:refuse()
                        continue
                    compare(a,b,site+'.global.'+name)
                return
            if t is types.CellType:
                try:a=reference.cell_contents
                except ValueError:a=NotImplemented
                try:b=live.cell_contents
                except ValueError:b=NotImplemented
                compare(a,b,site+'.cell');return
            if t in (staticmethod,classmethod):compare(reference.__func__,live.__func__,site+'.function');return
            if t is property:
                for name in ('fget','fset','fdel','__doc__'):compare(getattr(reference,name),getattr(live,name),site+'.'+name)
                return
            if t in (types.MemberDescriptorType,types.GetSetDescriptorType):
                if reference.__name__!=live.__name__:refuse()
                compare(reference.__objclass__,live.__objclass__,site+'.owner');return
            if t is types.MethodType:
                compare(reference.__func__,live.__func__,site+'.function');compare(reference.__self__,live.__self__,site+'.self');return
            # NamedTuple field descriptors and annotation ForwardRefs are generated
            # by the finite trusted factory, never general object fallbacks.
            if t.__module__=='collections' and t.__name__=='_tuplegetter':
                compare(t.__reduce__(reference),t.__reduce__(live),site+'.tuple-field');return
            if t.__module__=='typing' and t.__name__=='ForwardRef':
                for name in ('__forward_arg__','__forward_module__','__forward_is_argument__','__forward_is_class__'):
                    compare(object.__getattribute__(reference,name),object.__getattribute__(live,name),site+'.'+name)
                if object.__getattribute__(live,'__forward_evaluated__') is not False:refuse()
                return
            refuse()
        def metadata_expr(module: str,node: ast.AST,value: object) -> None:
            import typing
            if isinstance(node,ast.Name):
                declaration=self.metadata_nodes.get(module,{}).get(node.id)
                if declaration is not None:
                    metadata(module,node.id,value);return
                target=vars(builtins).get(node.id)
                if node.id=='Version':target=vars(sys.modules['packaging.version']).get('Version')
                if target is None or value is not target:refuse()
                return
            if isinstance(node,ast.Constant):
                compare(node.value,value,'metadata.literal');return
            if not isinstance(node,ast.Subscript) or not isinstance(node.value,ast.Name):refuse()
            kind=node.value.id;args=list(node.slice.elts) if isinstance(node.slice,ast.Tuple) else [node.slice]
            if kind=='Union':expected_type=typing._UnionGenericAlias;origin=typing.Union
            elif kind=='Callable':
                expected_type=typing._CallableGenericAlias;origin=Callable
                if len(args)!=2 or not isinstance(args[0],ast.List):refuse()
                args=[*args[0].elts,args[1]]
            elif kind=='tuple':expected_type=types.GenericAlias;origin=tuple
            else:refuse()
            if type(value) is not expected_type or object.__getattribute__(value,'__origin__') is not origin:refuse()
            actual_args=object.__getattribute__(value,'__args__')
            if type(actual_args) is not tuple or len(actual_args)!=len(args):refuse()
            for child,actual in zip(args,actual_args,strict=True):metadata_expr(module,child,actual)
        def metadata(module: str,field: str,value: object) -> None:
            import typing
            node=self.metadata_nodes[module][field]
            if isinstance(node,ast.ClassDef):
                if type(value) is not typing._TypedDictMeta:refuse()
                members=type.__getattribute__(value,'__dict__');annotations=members.get('__annotations__')
                declared={n.target.id:ast.unparse(n.annotation) for n in node.body if isinstance(n,ast.AnnAssign) and isinstance(n.target,ast.Name)}
                if type(annotations) is not dict or any(type(k) is not str for k in annotations) or set(annotations)!=set(declared):refuse()
                for key,expected in declared.items():
                    forward=annotations[key]
                    if type(forward) is not typing.ForwardRef or object.__getattribute__(forward,'__forward_evaluated__') is not False:refuse()
                    compare(expected,object.__getattribute__(forward,'__forward_arg__'),'metadata.annotation')
                compare(module,members.get('__module__'),'metadata.module')
                if members.get('__total__') is not False:refuse()
            elif isinstance(node,ast.Assign) and isinstance(node.value,ast.Call):
                if type(value) is not typing.TypeVar:refuse()
                if object.__getattribute__(value,'__name__')!=field or object.__getattribute__(value,'__constraints__')!=():refuse()
                bound=next((k.value for k in node.value.keywords if k.arg=='bound'),None)
                if bound is None:
                    if object.__getattribute__(value,'__bound__') is not None:refuse()
                else:metadata_expr(module,bound,object.__getattribute__(value,'__bound__'))
                if object.__getattribute__(value,'__covariant__') or object.__getattribute__(value,'__contravariant__'):refuse()
            elif isinstance(node,ast.Assign):metadata_expr(module,node.value,value)
            else:refuse()
            projection.append((module+'.'+field,'source-metadata-projection'))
        for name in ('packaging.version','packaging._ranges','packaging.specifiers'):
            module=sys.modules.get(name)
            if type(module) is not types.ModuleType:refuse()
            expected=vars(self.modules[name]);actual=vars(module)
            if any(type(k) is not str for k in actual):refuse()
            loader_metadata={'__builtins__','__cached__','__loader__','__spec__','__file__','__package__'}
            omitted=set(_CONSTRAINT_METADATA.get(name,()))|set(self.annotation_imports.get(name,{}))
            if set(actual)-loader_metadata-omitted!=set(expected)-loader_metadata:refuse()
            for field in sorted(omitted):
                if field not in actual:refuse()
                imported=self.annotation_imports.get(name,{}).get(field)
                if imported is not None:
                    if actual[field] is not imported:refuse()
                else:metadata(name,field,actual[field])
            for field in sorted(set(expected)-loader_metadata):compare(expected[field],actual[field],name+'.'+field)
        compare(vars(self.modules['packaging.utils'])['canonicalize_version'],vars(packaging.utils).get('canonicalize_version'),'packaging.utils.canonicalize_version')
        return hashlib.sha256(_canonical_json({'recipe':'constraint-closure-1','sources':self.key,'sites':self.sites,'structure':projection})).hexdigest()


def _attest_specifier_callables(sources: dict[str, bytes], origins: dict[str, pathlib.Path]) -> str:
    state=_CONSTRAINT_OPERATION.get();image=None;failed=False;result=None
    try:
        key=tuple((name,hashlib.sha256(sources[name]).hexdigest()) for name in
                  ('packaging.version','packaging._ranges','packaging.specifiers','packaging.utils'))
        if state is not None:
            if state.get('owner')!=(os.getpid(),threading.get_ident()):raise ValueError('constraint provider owner changed')
            image=state.get('image')
            if image is None:
                image=_ConstraintImage(sources,origins);state['image']=image
            if type(image) is not _ConstraintImage or image.key!=key:raise ValueError('constraint provider source changed')
            result=image.check()
        else:
            image=_ConstraintImage(sources,origins);result=image.contract_digest
    except Exception as error:
        # Raise the finite refusal outside the handler: no private exception or
        # construction traceback becomes its cause/context or a registry root.
        error.__traceback__=None;failed=True
    finally:
        if state is None and image is not None:image.close()
        image=None
    if failed or type(result) is not str:raise ValueError('package parser constraint attestation refused')
    return str(result)


class _ConstraintProvider:
    def __init__(self):
        self._state={'owner':(os.getpid(),threading.get_ident()),'provider':self};self._closed=False
        try:
            with self.operation():self._binding=_package_parser_attestation()
        except BaseException:self.close();raise

    @contextlib.contextmanager
    def operation(self) -> Iterator[None]:
        if self._closed or self._state.get('owner')!=(os.getpid(),threading.get_ident()):raise ValueError('constraint provider is closed or foreign')
        token=_CONSTRAINT_OPERATION.set(self._state)
        try:yield
        finally:_CONSTRAINT_OPERATION.reset(token)

    def require_current(self) -> str:
        try:
            with self.operation():
                if _package_parser_attestation()!=self._binding:raise ValueError('constraint provider changed')
            return self._binding.attestation_digest
        except BaseException:
            self.close();raise

    def requires_python(self,python_patch: str,constraint: str) -> bool:
        if type(python_patch) is not str or type(constraint) is not str:raise ValueError('constraint inputs are not exact strings')
        self.require_current();failed=False;result=None
        image=self._state['image'];version=vars(image.modules['packaging.version'])['Version'];specifiers=vars(image.modules['packaging.specifiers'])['SpecifierSet']
        try:
            result=version(python_patch) in specifiers(constraint)
            self.require_current()
            if type(result) is not bool:raise ValueError('constraint result is invalid')
        except Exception as error:
            error.__traceback__=None;failed=True
        finally:image=version=specifiers=None
        if failed:
            self.close();raise ValueError('release wheel interpreter constraint refused')
        return result is True

    def close(self) -> None:
        if not self._closed:
            self._closed=True;image=self._state.pop('image',None)
            if image is not None:image.close()
            self._state.clear()


def _owned_constraint_provider() -> _ConstraintProvider:
    return _ConstraintProvider()


@contextlib.contextmanager
def _constraint_provider_operation() -> Iterator[_ConstraintProvider]:
    state=_CONSTRAINT_OPERATION.get();owned=state is None
    provider=_owned_constraint_provider() if owned else state.get('provider')
    if type(provider) is not _ConstraintProvider or (not owned and provider._state is not state):
        raise ValueError('constraint provider binding is substituted')
    try:
        with provider.operation():yield provider
    finally:
        if owned:provider.close()


def _project() -> dict[str, object]:
    return _configuration()["project"]  # type: ignore[return-value]


def _distribution_name() -> str:
    return str(_project()["name"]).replace("-", "_")


def _version() -> str:
    return str(_project()["version"])


def _dist_info() -> str:
    return f"{_distribution_name()}-{_version()}.dist-info"


def _package_roots() -> dict[str, str]:
    build = _configuration()["tool"]["gew"]["build"]  # type: ignore[index]
    return dict(build["package-roots"])  # type: ignore[arg-type,index]


def _owned_root_files() -> dict[str, str]:
    build = _configuration()["tool"]["gew"]["build"]  # type: ignore[index]
    return dict(build["owned-root-files"])  # type: ignore[arg-type,index]


def _validated_relative_path(value: str, *, label: str) -> pathlib.PurePosixPath:
    candidate = pathlib.PurePosixPath(value)
    if candidate.is_absolute() or not candidate.parts or any(part in ("", ".", "..") for part in candidate.parts):
        raise ValueError(f"invalid {label}: {value}")
    return candidate


def _canonical_repository_path(path: pathlib.Path, *, directory: bool) -> pathlib.Path:
    try:
        relative = path.relative_to(ROOT)
    except ValueError as error:
        raise ValueError(f"build input is outside repository: {path}") from error
    current = ROOT
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"symlink component is not a build input: {current}")
    resolved = path.resolve(strict=True)
    if resolved != path.absolute():
        raise ValueError(f"non-canonical build input: {path}")
    if directory and not path.is_dir():
        raise ValueError(f"build input is not a directory: {path}")
    if not directory and not path.is_file():
        raise ValueError(f"build input is not a regular file: {path}")
    return resolved


def _read_regular_file(path: pathlib.Path, source_root: pathlib.Path) -> bytes:
    resolved_root = _canonical_repository_path(source_root, directory=True)
    resolved = _canonical_repository_path(path, directory=False)
    if not resolved.is_relative_to(resolved_root):
        raise ValueError(f"build input escapes package root: {path}")
    return path.read_bytes()


def _add_destination(seen: dict[str, bytes], destination: str, body: bytes) -> None:
    target = _validated_relative_path(destination, label="wheel destination")
    if target.parts[0] != "graph_engineering":
        raise ValueError(f"wheel package must be under graph_engineering/: {destination}")
    normalized = target.as_posix()
    if normalized in seen:
        raise ValueError(f"conflicting wheel destination: {normalized}")
    seen[normalized] = body


def _package_files() -> Iterable[tuple[str, bytes]]:
    seen: dict[str, bytes] = {}
    for source_value, destination_package in sorted(_package_roots().items()):
        source_relative = _validated_relative_path(source_value, label="package source")
        destination = _validated_relative_path(destination_package.replace(".", "/"), label="package destination")
        if destination.parts[:1] != ("graph_engineering",) or len(destination.parts) != 2:
            raise ValueError(f"invalid responsibility package destination: {destination_package}")
        source_root = ROOT / source_relative
        try:
            _canonical_repository_path(source_root, directory=True)
            _canonical_repository_path(source_root / "__init__.py", directory=False)
        except (FileNotFoundError, ValueError) as error:
            raise ValueError(f"invalid responsibility package source: {source_value}") from error
        if not (source_root / "__init__.py").is_file():
            raise ValueError(f"invalid responsibility package source: {source_value}")
        for path in sorted(source_root.rglob("*")):
            if "__pycache__" in path.parts:
                continue
            if path.is_symlink():
                raise ValueError(f"symlink component is not a build input: {path}")
            if path.is_dir():
                continue
            relative = path.relative_to(source_root)
            archive_path = (destination / pathlib.PurePosixPath(relative.as_posix())).as_posix()
            _add_destination(seen, archive_path, _read_regular_file(path, source_root))
    for source_value, destination in sorted(_owned_root_files().items()):
        source_relative = _validated_relative_path(source_value, label="owned source")
        source = ROOT / source_relative
        _add_destination(seen, destination, _read_regular_file(source, ROOT))
    _add_destination(
        seen,
        ACTION_ADAPTER_PROVENANCE_RESOURCE,
        _read_regular_file(PYPROJECT, ROOT),
    )
    profile = _configuration().get("tool", {}).get("gew", {}).get("profile", {})
    category = profile.get("category-execution-policy") if type(profile) is dict else None
    expected_fields = {
        "registry-id", "registry-digest", "registry-raw-sha256",
        "registry-source", "registry-resource", "policy-id", "policy-digest",
        "policy-raw-sha256", "policy-source", "policy-resource",
    }
    if type(category) is not dict or set(category) != expected_fields:
        raise ValueError("category execution policy build authority is not exact")
    for kind in ("registry", "policy"):
        source = _validated_relative_path(
            category[f"{kind}-source"], label=f"category {kind} source",
        )
        destination = category[f"{kind}-resource"]
        body = _read_regular_file(ROOT / source, ROOT)
        if hashlib.sha256(body).hexdigest() != category[f"{kind}-raw-sha256"]:
            raise ValueError(f"category {kind} build bytes changed")
        _add_destination(seen, destination, body)
    dependency = profile.get("dependency-advisory") if type(profile) is dict else None
    dependency_fields = {
        "registry-id", "registry-digest", "registry-generation",
        "registry-raw-sha256", "registry-source", "registry-resource",
        "bootstrap-id", "bootstrap-digest", "bootstrap-raw-sha256",
        "bootstrap-source", "bootstrap-resource", "profile-schema-registry-id",
        "profile-schema-registry-digest", "profile-schema-registry-raw-sha256",
        "profile-schema-registry-source", "profile-schema-registry-resource",
        "source-artifact-id", "source-artifact-digest",
        "source-artifact-raw-sha256", "source-artifact-source",
        "source-artifact-resource", "source-attestation-id",
        "source-attestation-digest", "source-attestation-raw-sha256",
        "source-attestation-source", "source-attestation-resource",
        "source-history-vectors", "bootstrap-history-vectors",
        "schema-vectors", "graph-policy-id", "graph-policy-digest",
        "graph-policy-raw-sha256", "graph-policy-source",
        "graph-policy-resource", "remediation-id", "remediation-digest",
        "remediation-raw-sha256", "remediation-source",
        "remediation-resource", "graph-bootstrap-id",
        "graph-bootstrap-digest", "graph-bootstrap-raw-sha256",
        "graph-bootstrap-source", "graph-bootstrap-resource",
        "build-backend-raw-sha256", "build-backend-source",
        "build-backend-resource", "graph-schema-vectors",
    }
    if type(dependency) is not dict or set(dependency) != dependency_fields:
        raise ValueError("dependency advisory build authority is not exact")
    _add_destination(
        seen,
        "graph_engineering/build_backend.py",
        _read_regular_file(ROOT / "scripts/build_backend.py", ROOT),
    )
    for kind in (
        "registry", "bootstrap", "source-artifact", "source-attestation",
        "profile-schema-registry",
    ):
        source = _validated_relative_path(
            dependency[f"{kind}-source"], label=f"dependency {kind} source",
        )
        destination = dependency[f"{kind}-resource"]
        body = _read_regular_file(ROOT / source, ROOT)
        if hashlib.sha256(body).hexdigest() != dependency[f"{kind}-raw-sha256"]:
            raise ValueError(f"dependency {kind} build bytes changed")
        existing = seen.get(destination)
        if existing is None:
            _add_destination(seen, destination, body)
        elif existing != body:
            raise ValueError(f"dependency {kind} build destination changed")
    source_history_fields = {
        "generation", "registry-id", "registry-digest", "registry-raw-sha256",
        "registry-source", "registry-resource", "source-artifact-id",
        "source-artifact-digest", "source-artifact-raw-sha256",
        "source-artifact-source", "source-artifact-resource",
        "source-attestation-id", "source-attestation-digest",
        "source-attestation-raw-sha256", "source-attestation-source",
        "source-attestation-resource",
    }
    source_history = dependency["source-history-vectors"]
    if (
        type(source_history) is not list or len(source_history) != 2
        or any(
            type(item) is not dict or set(item) != source_history_fields
            for item in source_history
        )
        or [item["generation"] for item in source_history] != [1, 2]
    ):
        raise ValueError("dependency source history build authority is not exact")
    for vector in source_history:
        for kind in ("registry", "source-artifact", "source-attestation"):
            source = _validated_relative_path(
                vector[f"{kind}-source"], label=f"dependency history {kind} source",
            )
            destination = vector[f"{kind}-resource"]
            body = _read_regular_file(ROOT / source, ROOT)
            if hashlib.sha256(body).hexdigest() != vector[f"{kind}-raw-sha256"]:
                raise ValueError(f"dependency history {kind} build bytes changed")
            existing = seen.get(destination)
            if existing is None:
                _add_destination(seen, destination, body)
            elif existing != body:
                raise ValueError(f"dependency history {kind} destination changed")
    bootstrap_history_fields = {
        "schema-version", "bootstrap-id", "bootstrap-digest",
        "bootstrap-raw-sha256", "bootstrap-source", "bootstrap-resource",
    }
    bootstrap_history = dependency["bootstrap-history-vectors"]
    if (
        type(bootstrap_history) is not list or len(bootstrap_history) != 2
        or any(
            type(item) is not dict or set(item) != bootstrap_history_fields
            for item in bootstrap_history
        )
        or [item["schema-version"] for item in bootstrap_history]
        != ["1.0.0", "1.1.0"]
    ):
        raise ValueError("dependency bootstrap history build authority is not exact")
    for vector in bootstrap_history:
        source = _validated_relative_path(
            vector["bootstrap-source"], label="dependency history bootstrap source",
        )
        destination = vector["bootstrap-resource"]
        body = _read_regular_file(ROOT / source, ROOT)
        if hashlib.sha256(body).hexdigest() != vector["bootstrap-raw-sha256"]:
            raise ValueError("dependency history bootstrap build bytes changed")
        existing = seen.get(destination)
        if existing is None:
            _add_destination(seen, destination, body)
        elif existing != body:
            raise ValueError("dependency history bootstrap destination changed")
    dependency_vectors = dependency["schema-vectors"]
    vector_fields = {"schema-id", "raw-sha256", "source", "resource"}
    if (
        type(dependency_vectors) is not list
        or len(dependency_vectors) != 22
        or any(type(item) is not dict or set(item) != vector_fields
               for item in dependency_vectors)
        or tuple(item["schema-id"] for item in dependency_vectors)
        != tuple(sorted({item["schema-id"] for item in dependency_vectors}))
    ):
        raise ValueError("dependency advisory schema vector is not exact")
    for vector in dependency_vectors:
        source = _validated_relative_path(
            vector["source"], label="dependency schema source",
        )
        destination = vector["resource"]
        body = _read_regular_file(ROOT / source, ROOT)
        if hashlib.sha256(body).hexdigest() != vector["raw-sha256"]:
            raise ValueError("dependency advisory schema build bytes changed")
        _add_destination(seen, destination, body)
    dependency_graph = dependency
    if type(dependency_graph) is not dict or set(dependency_graph) != dependency_fields:
        raise ValueError("dependency graph build authority is not exact")
    for kind in (
        "graph-policy", "remediation", "graph-bootstrap", "bootstrap",
        "registry", "profile-schema-registry", "build-backend",
    ):
        source = _validated_relative_path(
            dependency_graph[f"{kind}-source"],
            label=f"dependency graph {kind} source",
        )
        destination = dependency_graph[f"{kind}-resource"]
        body = _read_regular_file(ROOT / source, ROOT)
        if hashlib.sha256(body).hexdigest() != dependency_graph[f"{kind}-raw-sha256"]:
            raise ValueError(f"dependency graph {kind} build bytes changed")
        existing = seen.get(destination)
        if existing is None:
            _add_destination(seen, destination, body)
        elif existing != body:
            raise ValueError(f"dependency graph {kind} destination changed")
    graph_vectors = dependency_graph["graph-schema-vectors"]
    if (
        type(graph_vectors) is not list or len(graph_vectors) != 32
        or any(type(item) is not dict or set(item) != vector_fields
               for item in graph_vectors)
        or tuple(item["schema-id"] for item in graph_vectors)
        != tuple(sorted({item["schema-id"] for item in graph_vectors}))
    ):
        raise ValueError("dependency graph schema vector is not exact")
    for vector in graph_vectors:
        source = _validated_relative_path(
            vector["source"], label="dependency graph schema source",
        )
        destination = vector["resource"]
        body = _read_regular_file(ROOT / source, ROOT)
        if hashlib.sha256(body).hexdigest() != vector["raw-sha256"]:
            raise ValueError("dependency graph schema build bytes changed")
        existing = seen.get(destination)
        if existing is None:
            _add_destination(seen, destination, body)
        elif existing != body:
            raise ValueError("dependency graph schema destination changed")
    migration = profile.get("migration-rehearsal") if type(profile) is dict else None
    migration_fields = {
        "registry-id", "registry-digest", "registry-raw-sha256",
        "registry-source", "registry-resource", "fixture-id", "fixture-digest",
        "fixture-raw-sha256", "fixture-source", "fixture-resource",
        "transform-id", "transform-digest", "transform-raw-sha256",
        "transform-source", "transform-resource", "bootstrap-id",
        "bootstrap-digest", "bootstrap-raw-sha256", "bootstrap-source",
        "bootstrap-resource", "profile-schema-registry-id",
        "profile-schema-registry-digest", "profile-schema-registry-raw-sha256",
        "profile-schema-registry-source", "profile-schema-registry-resource",
        "schema-vectors", "protected-resources", "protected-closure-digest",
        "distribution-name", "distribution-version", "source-attestation-policy-id",
        "build-backend-raw-sha256", "build-backend-source",
        "build-backend-resource",
    }
    if type(migration) is not dict or set(migration) != migration_fields:
        raise ValueError("migration rehearsal build authority is not exact")
    for kind in ("registry", "fixture", "transform", "bootstrap", "profile-schema-registry"):
        source = _validated_relative_path(
            migration[f"{kind}-source"], label=f"migration {kind} source",
        )
        destination = migration[f"{kind}-resource"]
        body = _read_regular_file(ROOT / source, ROOT)
        if hashlib.sha256(body).hexdigest() != migration[f"{kind}-raw-sha256"]:
            raise ValueError(f"migration {kind} build bytes changed")
        existing = seen.get(destination)
        if existing is None:
            _add_destination(seen, destination, body)
        elif existing != body:
            raise ValueError(f"migration {kind} build destination changed")
    migration_vectors = migration["schema-vectors"]
    vector_fields = {"schema-id", "raw-sha256", "source", "resource"}
    if (
        type(migration_vectors) is not list or len(migration_vectors) != 16
        or any(type(item) is not dict or set(item) != vector_fields
               for item in migration_vectors)
        or tuple(item["schema-id"] for item in migration_vectors)
        != tuple(sorted({item["schema-id"] for item in migration_vectors}))
    ):
        raise ValueError("migration rehearsal schema build vector is not exact")
    migration_protected = migration["protected-resources"]
    if (
        type(migration_protected) is not list or not migration_protected
        or any(type(item) is not dict or set(item) != vector_fields - {"schema-id"}
               for item in migration_protected)
        or tuple(item["source"] for item in migration_protected)
        != tuple(sorted({item["source"] for item in migration_protected}))
    ):
        raise ValueError("migration rehearsal protected vector is not exact")
    for vector in (*migration_vectors, *migration_protected):
        source = _validated_relative_path(
            vector["source"], label="migration protected source",
        )
        destination = vector["resource"]
        body = _read_regular_file(ROOT / source, ROOT)
        if hashlib.sha256(body).hexdigest() != vector["raw-sha256"]:
            raise ValueError("migration rehearsal protected build bytes changed")
        existing = seen.get(destination)
        if existing is None:
            _add_destination(seen, destination, body)
        elif existing != body:
            raise ValueError("migration rehearsal protected destination changed")

    performance = profile.get("performance-benchmark") if type(profile) is dict else None
    performance_fields = {
        "registry-id", "registry-digest", "registry-raw-sha256",
        "registry-source", "registry-resource", "bootstrap-id",
        "bootstrap-digest", "bootstrap-raw-sha256", "bootstrap-source",
        "bootstrap-resource", "profile-schema-registry-id",
        "profile-schema-registry-digest", "profile-schema-registry-raw-sha256",
        "profile-schema-registry-source", "profile-schema-registry-resource",
        "fixture-id", "fixture-digest", "fixture-raw-sha256",
        "fixture-source", "fixture-resource", "sample-set-id",
        "sample-set-digest", "sample-raw-sha256", "sample-source",
        "sample-resource", "schema-vectors",
        "command-binding-id", "command-binding-digest", "command-binding-raw-sha256",
        "command-binding-source", "command-binding-resource",
        "command-runtime-policy-id", "command-runtime-policy-digest",
        "command-runtime-policy-raw-sha256", "command-runtime-policy-source",
        "command-runtime-policy-resource", "correctness-policy-id",
        "correctness-oracle-digest", "correctness-oracle-raw-sha256",
        "correctness-oracle-source", "correctness-oracle-resource",
        "source-registry-id", "source-registry-digest", "source-registry-raw-sha256",
        "source-registry-source", "source-registry-resource",
        "child-raw-sha256", "child-source", "child-resource",
        "build-backend-raw-sha256", "build-backend-source", "build-backend-resource",
        "distribution-name", "distribution-version", "source-attestation-policy-id",
        "maximum-warmup-count", "maximum-repetition-count",
        "protected-resources", "protected-closure-digest",
    }
    if type(performance) is not dict or set(performance) != performance_fields:
        raise ValueError("performance benchmark build authority is not exact")
    for kind in (
        "registry", "bootstrap", "profile-schema-registry", "fixture", "sample",
        "command-binding", "command-runtime-policy", "correctness-oracle",
        "source-registry", "child", "build-backend",
    ):
        source = _validated_relative_path(
            performance[f"{kind}-source"], label=f"performance {kind} source",
        )
        destination = performance[f"{kind}-resource"]
        body = _read_regular_file(ROOT / source, ROOT)
        if hashlib.sha256(body).hexdigest() != performance[f"{kind}-raw-sha256"]:
            raise ValueError(f"performance {kind} build bytes changed")
        existing = seen.get(destination)
        if existing is None:
            _add_destination(seen, destination, body)
        elif existing != body:
            raise ValueError(f"performance {kind} build destination changed")
    protected = performance["protected-resources"]
    if (
        type(protected) is not list or not protected
        or any(type(item) is not dict or set(item) != vector_fields - {"schema-id"}
               for item in protected)
        or tuple(item["source"] for item in protected)
        != tuple(sorted({item["source"] for item in protected}))
    ):
        raise ValueError("performance protected resource vector is not exact")
    for vector in protected:
        source = _validated_relative_path(
            vector["source"], label="performance protected source",
        )
        destination = vector["resource"]
        body = _read_regular_file(ROOT / source, ROOT)
        if hashlib.sha256(body).hexdigest() != vector["raw-sha256"]:
            raise ValueError("performance protected build bytes changed")
        existing = seen.get(destination)
        if existing is None:
            _add_destination(seen, destination, body)
        elif existing != body:
            raise ValueError("performance protected destination changed")
    performance_vectors = performance["schema-vectors"]
    if (
        type(performance_vectors) is not list or len(performance_vectors) != 18
        or any(type(item) is not dict or set(item) != vector_fields
               for item in performance_vectors)
        or tuple(item["schema-id"] for item in performance_vectors)
        != tuple(sorted({item["schema-id"] for item in performance_vectors}))
    ):
        raise ValueError("performance benchmark schema vector is not exact")
    for vector in performance_vectors:
        source = _validated_relative_path(
            vector["source"], label="performance schema source",
        )
        destination = vector["resource"]
        body = _read_regular_file(ROOT / source, ROOT)
        if hashlib.sha256(body).hexdigest() != vector["raw-sha256"]:
            raise ValueError("performance benchmark schema build bytes changed")
        existing = seen.get(destination)
        if existing is None:
            _add_destination(seen, destination, body)
        elif existing != body:
            raise ValueError("performance schema build destination changed")
    parser = _configuration()["tool"]["gew"]["build"]["package-parser-requirement"]
    parser_source = _validated_relative_path(
        parser["path"], label="dependency parser requirement source",
    )
    parser_body = _read_regular_file(ROOT / parser_source, ROOT)
    if hashlib.sha256(parser_body).hexdigest() != parser["sha256"]:
        raise ValueError("dependency parser requirement build bytes changed")
    _add_destination(
        seen,
        "graph_engineering/config/supply-chain/extension-package-parser-requirement-v1.json",
        parser_body,
    )
    coverage = profile.get("coverage-execution-plan") if type(profile) is dict else None
    coverage_fields = {
        "plan-id", "plan-digest", "plan-raw-sha256", "plan-source",
        "plan-resource", "oracle-vectors", "runner-raw-sha256",
        "runner-source", "runner-resource", "protected-sources",
        "protected-resources",
    }
    if type(coverage) is not dict or set(coverage) != coverage_fields:
        raise ValueError("Profile coverage build authority is not exact")
    for kind in ("plan",):
        source = _validated_relative_path(
            coverage[f"{kind}-source"], label=f"coverage {kind} source",
        )
        destination = coverage[f"{kind}-resource"]
        body = _read_regular_file(ROOT / source, ROOT)
        if hashlib.sha256(body).hexdigest() != coverage[f"{kind}-raw-sha256"]:
            raise ValueError(f"coverage {kind} build bytes changed")
        try:
            document = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError(f"coverage {kind} build document is malformed") from error
        identity_field = "plan_id" if kind == "plan" else "oracle_id"
        digest_field = "plan_digest" if kind == "plan" else "oracle_digest"
        if (
            type(document) is not dict
            or document.get(identity_field) != coverage[f"{kind}-id"]
            or document.get(digest_field) != coverage[f"{kind}-digest"]
        ):
            raise ValueError(f"coverage {kind} build identity changed")
        _add_destination(seen, destination, body)
    oracle_vectors = coverage["oracle-vectors"]
    oracle_fields = {
        "oracle-id", "profile-id", "selector-kind", "column-id",
        "scenario-id", "category-boundary-case-id", "overlay-id", "oracle-digest",
        "oracle-raw-sha256", "oracle-source", "oracle-resource",
        "pass-task-id", "reject-task-id",
    }
    if (
        type(oracle_vectors) is not list
        or not oracle_vectors
        or any(type(item) is not dict or set(item) != oracle_fields
               for item in oracle_vectors)
    ):
        raise ValueError("Profile coverage oracle build vector is not exact")
    identities: list[tuple[str, str, str, str, str]] = []
    for oracle in oracle_vectors:
        source = _validated_relative_path(
            oracle["oracle-source"], label="coverage oracle source",
        )
        destination = oracle["oracle-resource"]
        body = _read_regular_file(ROOT / source, ROOT)
        if hashlib.sha256(body).hexdigest() != oracle["oracle-raw-sha256"]:
            raise ValueError("coverage oracle build bytes changed")
        try:
            document = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("coverage oracle build document is malformed") from error
        identity = (
            oracle["oracle-id"], oracle["profile-id"],
            oracle["selector-kind"], oracle["column-id"], oracle["scenario-id"],
        )
        if (
            type(document) is not dict
            or tuple(document.get(field) for field in (
                "oracle_id", "profile_id", "selector_kind", "column_id",
            )) != identity[:4]
            or (document.get("scenario_id") or "") != identity[4]
            or (document.get("category_boundary_case_id") or "")
            != oracle["category-boundary-case-id"]
            or document.get("overlay_id") != oracle["overlay-id"]
            or document.get("task_ids") != {
                "P": oracle["pass-task-id"],
                "R": oracle["reject-task-id"],
            }
            or document.get("oracle_digest") != oracle["oracle-digest"]
        ):
            raise ValueError("coverage oracle build identity changed")
        identities.append(identity)
        _add_destination(seen, destination, body)
    if (
        tuple(identities) != tuple(sorted(identities))
        or len(set(identities)) != len(identities)
    ):
        raise ValueError("Profile coverage oracle build vector is not canonical")
    runner_source = _validated_relative_path(
        coverage["runner-source"], label="coverage runner source",
    )
    runner_destination = _validated_relative_path(
        coverage["runner-resource"], label="coverage runner resource",
    ).as_posix()
    runner_body = _read_regular_file(ROOT / runner_source, ROOT)
    if (
        hashlib.sha256(runner_body).hexdigest() != coverage["runner-raw-sha256"]
        or seen.get(runner_destination) != runner_body
    ):
        raise ValueError("coverage runner build bytes or destination changed")
    protected_sources = coverage["protected-sources"]
    protected_resources = coverage["protected-resources"]
    if (
        type(protected_sources) is not list
        or type(protected_resources) is not list
        or not protected_sources
        or len(protected_sources) != len(protected_resources)
        or any(type(item) is not str or not item for item in protected_sources)
        or any(type(item) is not str or not item for item in protected_resources)
        or len(set(protected_sources)) != len(protected_sources)
        or len(set(protected_resources)) != len(protected_resources)
    ):
        raise ValueError("Profile coverage protected-member closure is not exact")
    for source_value, resource_value in zip(
        protected_sources, protected_resources, strict=True,
    ):
        source = _validated_relative_path(
            source_value, label="coverage protected source",
        )
        destination = _validated_relative_path(
            resource_value, label="coverage protected resource",
        ).as_posix()
        body = _read_regular_file(ROOT / source, ROOT)
        existing = seen.get(destination)
        if existing is None:
            _add_destination(seen, destination, body)
        elif existing != body:
            raise ValueError("coverage protected build bytes changed")
    yield from sorted(seen.items())


def _metadata_files() -> list[tuple[str, bytes]]:
    project = _project()
    dependencies = project.get("dependencies", [])
    if type(dependencies) is not list or any(
        type(item) is not str
        or not item
        or item.strip() != item
        or "\n" in item
        or "\r" in item
        or "==" not in item
        for item in dependencies
    ):
        raise ValueError("project dependencies must be exact pinned PEP 508 strings")
    for dependency in dependencies:
        _parse_requirement(dependency, exact_pin=True)
    requirement_lines = tuple(f"Requires-Dist: {item}" for item in dependencies)
    metadata = "\n".join(
        (
            "Metadata-Version: 2.4",
            f"Name: {project['name']}",
            f"Version: {project['version']}",
            f"Summary: {project['description']}",
            f"Requires-Python: {project['requires-python']}",
            *requirement_lines,
            "",
        )
    ).encode()
    wheel = b"Wheel-Version: 1.0\nGenerator: gew-build-backend\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    scripts = project.get("scripts", {})
    _direct_script_configuration()
    if set(scripts) & {"graph-engineering"}:
        raise ValueError("direct script conflicts with console entry point")
    entries = "".join(f"{name} = {target}\n" for name, target in sorted(scripts.items()))
    entry_points = f"[console_scripts]\n{entries}".encode()
    dist_info = _dist_info()
    return [
        (f"{dist_info}/METADATA", metadata),
        (f"{dist_info}/WHEEL", wheel),
        (f"{dist_info}/entry_points.txt", entry_points),
    ]



def _direct_script_configuration() -> None:
    build = _configuration().get('tool', {}).get('gew', {}).get('build', {})
    if build.get('direct-scripts') != {'graph-engineering': 'graph_engineering.cli:main'}:
        raise ValueError('direct script configuration is not exact')
    if 'graph-engineering' in _project().get('scripts', {}):
        raise ValueError('direct script conflicts with console entry point')


def _direct_script_files() -> list[tuple[str, bytes]]:
    _direct_script_configuration()
    # Finite fallback literals are generated here from backend-owned code. They
    # remain available even when the installed product cannot be imported.
    source = """#!python
import sys
_readonly = len(sys.argv) > 1 and sys.argv[1] in ('release-check', 'doctor')
if _readonly:
    sys.dont_write_bytecode = True
try:
    from graph_engineering.cli import main
    _exit = main()
    if _readonly:
        sys.stdout.flush()
except Exception:
    if not _readonly:
        raise
    import hashlib
    import json
    _phase = 'check' if sys.argv[1] == 'release-check' else 'doctor'
    _body = {'schema_version':'1.0.0','request_id':'release-'+_phase,
        'status':'rejected' if _phase=='check' else 'blocked','phase':_phase,
        'code':'trust_rejected','checks':[],'refs':[],
        'capabilities':{'release-check':'available','doctor':'available',
            'install':'unavailable','upgrade':'unavailable','release':'unavailable'},
        'next_route':'inspect-inputs'}
    _envelope = {'algorithm':'sha-256','body':_body,
        'canonicalizer':'urn:gew:canonicalizer:jcs-input:1.0.0',
        'contract_type':'urn:gew:contract:release-install-diagnostic',
        'digest_domain':'urn:gew:digest:semantic:1.0.0',
        'projection_id':'urn:gew:digest-projection:release-install-diagnostic:1.0.0',
        'schema_id':'urn:gew:schema:release-install-diagnostic:1.0.0'}
    _raw = json.dumps(_envelope,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
    _body['diagnostic_digest'] = 'sha256-jcs-v1:'+hashlib.sha256(_raw).hexdigest()
    _exit = 4 if _phase=='check' else 3
    try:
        print(json.dumps(_body,sort_keys=True,separators=(',',':')))
        sys.stdout.flush()
    except OSError:
        sys.stdout = None
raise SystemExit(_exit)
"""
    return [(f'{_distribution_name()}-{_version()}.data/scripts/graph-engineering', source.encode('utf-8'))]


def _offline_dependency_plan(
    parser_attestation: PackageParserAttestation,
    *,
    candidate_wheel: pathlib.Path | None,
    dependency_wheels: tuple[pathlib.Path, ...],
    opened: tuple[_OpenWheel, ...],
) -> OfflineDependencyPlan:
    bindings = tuple(item.binding for item in opened)
    body = {
        "schema_version": "1.0.0",
        "parser_attestation": parser_attestation._asdict(),
        "candidate_wheel": None if candidate_wheel is None else os.fspath(candidate_wheel),
        "dependency_wheels": [os.fspath(item) for item in dependency_wheels],
        "wheel_bindings": [item._asdict() for item in bindings],
    }
    return OfflineDependencyPlan(
        parser_attestation,
        candidate_wheel,
        dependency_wheels,
        bindings,
        hashlib.sha256(_canonical_json(body)).hexdigest(),
    )


def preflight_offline_dependencies(
    wheelhouse: pathlib.Path,
    *,
    _probe_hook: Callable[[str], None] | None = None,
) -> OfflineDependencyPlan:
    """Verify the bounded offline closure without mutating an install target."""

    if _probe_hook is not None and not callable(_probe_hook):
        raise TypeError("offline preflight probe hook must be callable")
    parser_attestation = _package_parser_attestation()
    dependencies = tuple(str(item) for item in _project().get("dependencies", []))
    with _prepare_physical_closure(
        wheelhouse,
        probe_hook=_probe_hook,
    ) as (_initial, physical_candidates, opened):
        ordered = _resolve_offline_closure(
            wheelhouse,
            dependencies,
            physical_candidates=physical_candidates,
        )
        if _probe_hook is not None:
            _probe_hook("preflight.after-traversal")
        for item in opened:
            _recheck_open_wheel(item)
        if _package_parser_attestation() != parser_attestation:
            raise ValueError("package parser attestation changed during preflight")
        plan = _offline_dependency_plan(
            parser_attestation,
            candidate_wheel=None,
            dependency_wheels=ordered,
            opened=opened,
        )
        if _probe_hook is not None:
            _probe_hook("preflight.before-plan-return")
        for item in opened:
            _recheck_open_wheel(item)
        if _package_parser_attestation() != parser_attestation:
            raise ValueError("package parser attestation changed before plan return")
        return plan


def _normalized_distribution(value: str) -> str:
    normalized = canonicalize_name(value)
    if not normalized:
        raise ValueError("wheel distribution name is invalid")
    return normalized.replace("-", "_")


def _parse_requirement(value: str, *, exact_pin: bool) -> Requirement:
    if type(value) is not str or not value or value.strip() != value or "\n" in value or "\r" in value:
        raise ValueError("wheel Requires-Dist entry is malformed")
    try:
        requirement = Requirement(value)
    except InvalidRequirement as error:
        raise ValueError("wheel Requires-Dist entry is malformed") from error
    if requirement.url is not None or requirement.extras:
        raise ValueError("offline dependency URLs and extras are unsupported")
    if exact_pin:
        specifications = tuple(requirement.specifier)
        if (
            requirement.marker is not None
            or len(specifications) != 1
            or specifications[0].operator != "=="
            or "*" in specifications[0].version
        ):
            raise ValueError("offline dependency is not exactly pinned")
    return requirement


def _offline_wheel_policy() -> dict[str, object]:
    value = _configuration()["tool"]["gew"]["build"]["offline-wheel-policy"]  # type: ignore[index]
    if not isinstance(value, dict) or set(value) != {
        "max-members", "max-member-bytes", "max-total-bytes", "compatible-tags",
        "max-closure-wheels", "max-closure-bytes", "max-dependency-edges",
        "max-dependency-depth", "max-requirements",
    }:
        raise ValueError("offline wheel policy is not exact")
    members = value["max-members"]
    member_bytes = value["max-member-bytes"]
    total_bytes = value["max-total-bytes"]
    tags = value["compatible-tags"]
    closure_limits = tuple(
        value[name]
        for name in (
            "max-closure-wheels", "max-closure-bytes", "max-dependency-edges",
            "max-dependency-depth", "max-requirements",
        )
    )
    if (
        type(members) is not int or members < 4
        or type(member_bytes) is not int or member_bytes < 1
        or type(total_bytes) is not int or total_bytes < member_bytes
        or type(tags) is not list or not tags
        or any(type(item) is not str or not item for item in tags)
        or any(type(item) is not int or item < 1 for item in closure_limits)
        or value["max-closure-bytes"] < total_bytes
    ):
        raise ValueError("offline wheel policy values are invalid")
    try:
        compatible = frozenset(tag for value in tags for tag in parse_tag(value))
    except ValueError as error:
        raise ValueError("offline wheel compatible tag policy is malformed") from error
    if not compatible:
        raise ValueError("offline wheel compatible tag policy is empty")
    return {**value, "parsed-compatible-tags": compatible}


def _wheel_filename(path: pathlib.Path) -> tuple[str, Version, frozenset[object]]:
    if path.suffix != ".whl":
        raise ValueError("offline artifact is not a wheel")
    try:
        distribution, version, _build, wheel_tags = parse_wheel_filename(path.name)
    except (InvalidVersion, ValueError) as error:
        raise ValueError("wheel filename is not exact") from error
    return _normalized_distribution(str(distribution)), version, frozenset(wheel_tags)


def _portable_wheel_member(name: str) -> bool:
    if (
        not name
        or "\x00" in name
        or "\\" in name
        or ":" in name
        or any(character in '<>"|?*' for character in name)
    ):
        return False
    if unicodedata.normalize("NFC", name) != name or any(
        unicodedata.category(character).startswith("C") for character in name
    ):
        return False
    candidate = pathlib.PurePosixPath(name)
    reserved = {"con", "prn", "aux", "nul"} | {
        f"{prefix}{number}" for prefix in ("com", "lpt") for number in range(1, 10)
    }
    return (
        not candidate.is_absolute()
        and candidate.as_posix() == name
        and all(
            part not in {"", ".", ".."}
            and not part.endswith((" ", "."))
            and part.split(".", 1)[0].casefold() not in reserved
            for part in candidate.parts
        )
    )


def _decode_zip_name(raw: bytes, flags: int) -> str:
    if not flags & 0x800 and any(value > 0x7f for value in raw):
        raise ValueError("wheel physical member name has ambiguous encoding")
    try:
        name = raw.decode("utf-8" if flags & 0x800 else "ascii")
    except UnicodeDecodeError as error:
        raise ValueError("wheel physical member name is malformed") from error
    if flags & 0x800 and name.encode("utf-8") != raw:
        raise ValueError("wheel physical member name encoding is not canonical")
    return name


def _validate_zip_extra(raw: bytes) -> None:
    cursor = 0
    identifiers: set[int] = set()
    while cursor < len(raw):
        if cursor + 4 > len(raw):
            raise ValueError("wheel physical extra field is malformed")
        identifier, size = struct.unpack_from("<2H", raw, cursor)
        cursor += 4
        if cursor + size > len(raw) or identifier in identifiers:
            raise ValueError("wheel physical extra field is malformed")
        identifiers.add(identifier)
        cursor += size
    if identifiers.intersection({0x0001, 0x6375, 0x7075}):
        raise ValueError("wheel physical extra field has unsupported identity encoding")


def _validate_physical_zip(
    raw: bytes,
    *,
    member_count: int,
    max_member_bytes: int,
    max_total_bytes: int,
    central_offset: int,
    central_size: int,
    eocd_offset: int,
) -> tuple[tuple[str, ...], int]:
    """Require one exact local header and one central record per RECORD member."""

    central_cursor = central_offset
    central_records: list[
        tuple[str, bytes, int, int, int, int, int, int, int, int, int]
    ] = []
    total_size = 0
    portable_names: set[tuple[str, ...]] = set()
    for _index in range(member_count):
        if central_cursor + 46 > eocd_offset or raw[central_cursor:central_cursor + 4] != b"PK\x01\x02":
            raise ValueError("wheel physical central directory is malformed")
        fields = struct.unpack_from("<4s6H3L5H2L", raw, central_cursor)
        required_version, flags, method = fields[2], fields[3], fields[4]
        modified_time, modified_date = fields[5], fields[6]
        crc, compressed, size = fields[7], fields[8], fields[9]
        name_length, extra_length, comment_length = fields[10], fields[11], fields[12]
        disk_start, external_attributes, local_offset = fields[13], fields[15], fields[16]
        end = central_cursor + 46 + name_length + extra_length + comment_length
        name_end = central_cursor + 46 + name_length
        extra_end = name_end + extra_length
        raw_name = raw[central_cursor + 46:name_end]
        extra = raw[name_end:extra_end]
        if (
            end > eocd_offset
            or disk_start != 0
            or required_version > 63
            or flags & ~0x808
            or method not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
            or comment_length != 0
            or 0xFFFFFFFF in {compressed, size, local_offset}
            or size > max_member_bytes
            or stat.S_ISLNK(external_attributes >> 16)
        ):
            raise ValueError("wheel physical central directory is malformed")
        _validate_zip_extra(extra)
        name = _decode_zip_name(raw_name, flags)
        if not _portable_wheel_member(name):
            raise ValueError("wheel physical member path is unsafe")
        portable_key = tuple(part.casefold() for part in pathlib.PurePosixPath(name).parts)
        if portable_key in portable_names:
            raise ValueError("wheel physical member names are not portable and unique")
        portable_names.add(portable_key)
        total_size += size
        if total_size > max_total_bytes:
            raise ValueError("wheel physical member bytes exceed the bounded profile")
        central_records.append(
            (
                name, raw_name, local_offset, required_version, flags, method,
                modified_time, modified_date, crc, compressed, size,
            )
        )
        central_cursor = end
    if central_cursor != central_offset + central_size or central_cursor != eocd_offset:
        raise ValueError("wheel physical central directory is not exact")
    local_records = sorted(central_records, key=lambda item: item[2])
    cursor = 0
    names: list[str] = []
    for index, (
        name, raw_name, offset, required_version, flags, method,
        modified_time, modified_date, crc, compressed, size,
    ) in enumerate(local_records):
        if offset != cursor or offset + 30 > central_offset or raw[offset:offset + 4] != b"PK\x03\x04":
            raise ValueError("wheel physical local member set is not exact")
        local = struct.unpack_from("<4s5H3L2H", raw, offset)
        local_required_version, local_flags, local_method = local[1], local[2], local[3]
        local_crc, local_compressed, local_size = local[6], local[7], local[8]
        name_length, extra_length = local[9], local[10]
        local_name_start = offset + 30
        local_name_end = local_name_start + name_length
        local_extra_end = local_name_end + extra_length
        data_start = local_extra_end
        if data_start > central_offset:
            raise ValueError("wheel physical local header is malformed")
        local_raw_name = raw[local_name_start:local_name_end]
        _validate_zip_extra(raw[local_name_end:local_extra_end])
        local_name = _decode_zip_name(local_raw_name, local_flags)
        if (
            local_required_version > 63
            or local_required_version != required_version
            or local_name != name
            or local_raw_name != raw_name
            or not _portable_wheel_member(local_name)
            or local_flags != flags
            or local_method != method
            or local[4] != modified_time
            or local[5] != modified_date
            or flags & ~0x808
        ):
            raise ValueError("wheel physical local header is substituted")
        data_end = data_start + compressed
        if data_end > central_offset:
            raise ValueError("wheel physical compressed member is truncated")
        next_offset = (
            local_records[index + 1][2]
            if index + 1 < len(local_records)
            else central_offset
        )
        if flags & 0x08:
            descriptor_size = next_offset - data_end
            if descriptor_size == 12:
                descriptor = data_end
            elif descriptor_size == 16 and raw[data_end:data_end + 4] == b"PK\x07\x08":
                descriptor = data_end + 4
            else:
                raise ValueError("wheel physical data descriptor is not exact")
            descriptor_values = struct.unpack_from("<3L", raw, descriptor)
            if descriptor_values != (crc, compressed, size) or (
                local_crc not in {0, crc}
                or local_compressed not in {0, compressed}
                or local_size not in {0, size}
            ):
                raise ValueError("wheel physical data descriptor is substituted")
            cursor = next_offset
        else:
            if (local_crc, local_compressed, local_size) != (crc, compressed, size):
                raise ValueError("wheel physical local sizes are substituted")
            cursor = data_end
        names.append(name)
    if cursor != central_offset or len(names) != len(set(names)):
        raise ValueError("wheel physical local member set is not exact")
    return tuple(item[0] for item in central_records), total_size


class _EnumeratedWheel(NamedTuple):
    path: pathlib.Path
    device: int
    inode: int
    owner: int
    mode: int
    links: int
    size: int
    mtime_ns: int


class _OpenWheel(NamedTuple):
    descriptor: int
    parent_descriptor: int
    binding: WheelFileBinding
    raw: bytes


def _enumerate_wheel(path: pathlib.Path) -> _EnumeratedWheel:
    resolved = path.resolve(strict=True)
    if path.is_symlink() or not resolved.is_file() or resolved != path.absolute():
        raise ValueError("wheel path is not canonical")
    metadata = os.stat(resolved, follow_symlinks=False)
    return _EnumeratedWheel(
        resolved,
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _read_open_wheel(descriptor: int, *, maximum: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    body = bytearray()
    while True:
        chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - len(body)))
        if not chunk:
            break
        body.extend(chunk)
        if len(body) > maximum:
            raise ValueError("wheel archive exceeds the bounded profile")
    return bytes(body)


def _open_wheel(
    enumerated: _EnumeratedWheel,
    *,
    max_total_bytes: int,
) -> _OpenWheel:
    path = enumerated.path
    parent = path.parent.resolve(strict=True)
    if parent != path.parent.absolute() or parent.is_symlink():
        raise ValueError("wheel parent directory is not canonical")
    parent_descriptor = os.open(
        parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    descriptor = -1
    try:
        parent_metadata = os.fstat(parent_descriptor)
        entry = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        descriptor = os.open(
            path.name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
        metadata = os.fstat(descriptor)
        observed = (
            metadata.st_dev, metadata.st_ino, metadata.st_uid,
            stat.S_IMODE(metadata.st_mode), metadata.st_nlink,
            metadata.st_size, metadata.st_mtime_ns,
        )
        expected = tuple(enumerated[1:])
        entry_observed = (
            entry.st_dev, entry.st_ino, entry.st_uid, stat.S_IMODE(entry.st_mode),
            entry.st_nlink, entry.st_size, entry.st_mtime_ns,
        )
        if (
            observed != expected
            or entry_observed != expected
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or metadata.st_nlink != 1
            or metadata.st_size > max_total_bytes
        ):
            raise ValueError("wheel descriptor or parent entry binding changed")
        raw = _read_open_wheel(descriptor, maximum=max_total_bytes)
        after = os.fstat(descriptor)
        if (
            (after.st_dev, after.st_ino, after.st_uid, stat.S_IMODE(after.st_mode),
             after.st_nlink, after.st_size, after.st_mtime_ns)
            != expected
            or len(raw) != metadata.st_size
        ):
            raise ValueError("wheel descriptor changed during read")
        binding = WheelFileBinding(
            os.fspath(path), os.fspath(parent), parent_metadata.st_dev,
            parent_metadata.st_ino, metadata.st_dev, metadata.st_ino,
            metadata.st_uid, stat.S_IMODE(metadata.st_mode), metadata.st_nlink,
            metadata.st_size, metadata.st_mtime_ns, entry.st_dev, entry.st_ino,
            entry.st_uid, stat.S_IMODE(entry.st_mode), entry.st_nlink,
            entry.st_size, entry.st_mtime_ns, hashlib.sha256(raw).hexdigest(),
        )
        return _OpenWheel(descriptor, parent_descriptor, binding, raw)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)
        raise


def _recheck_open_wheel(opened: _OpenWheel) -> None:
    binding = opened.binding
    metadata = os.fstat(opened.descriptor)
    parent_metadata = os.fstat(opened.parent_descriptor)
    try:
        entry = os.stat(
            pathlib.Path(binding.path).name,
            dir_fd=opened.parent_descriptor,
            follow_symlinks=False,
        )
        live_parent = os.stat(binding.parent_path, follow_symlinks=False)
    except OSError as error:
        raise ValueError("wheel parent directory entry was replaced") from error
    if (
        (parent_metadata.st_dev, parent_metadata.st_ino)
        != (binding.parent_device, binding.parent_inode)
        or (live_parent.st_dev, live_parent.st_ino)
        != (binding.parent_device, binding.parent_inode)
        or (
            metadata.st_dev, metadata.st_ino, metadata.st_uid,
            stat.S_IMODE(metadata.st_mode), metadata.st_nlink,
            metadata.st_size, metadata.st_mtime_ns,
        ) != tuple(binding[4:11])
        or (
            entry.st_dev, entry.st_ino, entry.st_uid, stat.S_IMODE(entry.st_mode),
            entry.st_nlink, entry.st_size, entry.st_mtime_ns,
        ) != tuple(binding[11:18])
    ):
        raise ValueError("wheel descriptor or parent directory entry binding was replaced")
    raw = _read_open_wheel(opened.descriptor, maximum=binding.descriptor_size)
    if len(raw) != binding.descriptor_size or hashlib.sha256(raw).hexdigest() != binding.raw_digest:
        raise ValueError("wheel descriptor content changed")


def _close_open_wheel(opened: _OpenWheel) -> None:
    try:
        os.close(opened.descriptor)
    finally:
        os.close(opened.parent_descriptor)


class _PhysicalWheel(NamedTuple):
    path: pathlib.Path
    raw: bytes
    names: tuple[str, ...]
    uncompressed_bytes: int
    binding: WheelFileBinding


def _inspect_physical_wheel(
    opened: _OpenWheel,
    policy: dict[str, object],
) -> _PhysicalWheel:
    max_members = int(policy["max-members"])
    max_member_bytes = int(policy["max-member-bytes"])
    max_total_bytes = int(policy["max-total-bytes"])
    raw_archive = opened.raw
    eocd_offset = raw_archive.rfind(b"PK\x05\x06")
    if eocd_offset < 0 or len(raw_archive) - eocd_offset < 22:
        raise ValueError("wheel ZIP end record is missing")
    try:
        (
            signature, disk_number, central_disk, disk_entries, total_entries,
            central_size, central_offset, comment_size,
        ) = struct.unpack_from("<4s4H2LH", raw_archive, eocd_offset)
    except struct.error as error:
        raise ValueError("wheel ZIP end record is malformed") from error
    if (
        signature != b"PK\x05\x06"
        or disk_number != 0
        or central_disk != 0
        or disk_entries != total_entries
        or total_entries < 4
        or total_entries > max_members
        or central_offset + central_size != eocd_offset
        or comment_size != 0
        or eocd_offset + 22 != len(raw_archive)
    ):
        raise ValueError("wheel ZIP end record or member limit is not exact")
    physical_names, uncompressed_bytes = _validate_physical_zip(
        raw_archive,
        member_count=total_entries,
        max_member_bytes=max_member_bytes,
        max_total_bytes=max_total_bytes,
        central_offset=central_offset,
        central_size=central_size,
        eocd_offset=eocd_offset,
    )
    return _PhysicalWheel(
        pathlib.Path(opened.binding.path), raw_archive, physical_names,
        uncompressed_bytes, opened.binding,
    )


def _validate_wheel(
    path: pathlib.Path,
    *,
    expected_name: str,
    expected_version: str,
    expected_requirements: tuple[str, ...] | None,
    physical: _PhysicalWheel | None = None,
    remaining_requirements: int | None = None,
) -> tuple[pathlib.Path, tuple[str, ...]]:
    if physical is None:
        policy = _offline_wheel_policy()
        opened = _open_wheel(
            _enumerate_wheel(path),
            max_total_bytes=int(policy["max-total-bytes"]),
        )
        try:
            snapshot = _inspect_physical_wheel(opened, policy)
            result = _validate_wheel(
                path,
                expected_name=expected_name,
                expected_version=expected_version,
                expected_requirements=expected_requirements,
                physical=snapshot,
                remaining_requirements=remaining_requirements,
            )
            _recheck_open_wheel(opened)
            return result
        finally:
            _close_open_wheel(opened)
    filename_name, filename_version, filename_tags = _wheel_filename(path)
    expected_normalized = _normalized_distribution(expected_name)
    try:
        requested_version = Version(expected_version)
    except InvalidVersion as error:
        raise ValueError("expected wheel version is invalid") from error
    if filename_name != expected_normalized or filename_version != requested_version:
        raise ValueError("wheel filename identity is substituted")
    policy = _offline_wheel_policy()
    max_members = int(policy["max-members"])
    max_member_bytes = int(policy["max-member-bytes"])
    max_total_bytes = int(policy["max-total-bytes"])
    compatible_tags = policy["parsed-compatible-tags"]
    assert isinstance(compatible_tags, frozenset)
    if not filename_tags or not filename_tags.issubset(compatible_tags) or not filename_tags.intersection(sys_tags()):
        raise ValueError("wheel filename tag is incompatible")
    resolved = path.resolve(strict=True)
    if physical.path != resolved:
        raise ValueError("wheel physical snapshot is substituted")
    raw_archive = physical.raw
    physical_names = physical.names
    try:
        with zipfile.ZipFile(io.BytesIO(raw_archive)) as archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            if (
                tuple(names) != physical_names
                or len(infos) != len(physical_names)
                or len(names) != len(set(names))
                or any(
                    item.is_dir()
                    or item.flag_bits & 0x1
                    or item.file_size > max_member_bytes
                    or not _portable_wheel_member(item.filename)
                    or stat.S_ISLNK(item.external_attr >> 16)
                    for item in infos
                )
                or sum(item.file_size for item in infos) > max_total_bytes
            ):
                raise ValueError("wheel central directory violates the bounded profile")
            bodies = {item.filename: archive.read(item) for item in infos}
    except (OSError, zipfile.BadZipFile, RuntimeError, KeyError) as error:
        raise ValueError("wheel ZIP is malformed") from error

    dist_info = f"{expected_normalized}-{expected_version}.dist-info"
    expected_special = {
        f"{dist_info}/METADATA", f"{dist_info}/WHEEL", f"{dist_info}/RECORD",
    }
    if not expected_special.issubset(bodies) or any(
        ".dist-info/" in name and not name.startswith(dist_info + "/") for name in bodies
    ):
        raise ValueError("wheel distribution metadata identity is invalid")
    try:
        metadata = Parser().parsestr(bodies[f"{dist_info}/METADATA"].decode("utf-8"))
        wheel_metadata = Parser().parsestr(bodies[f"{dist_info}/WHEEL"].decode("utf-8"))
        record_rows = list(csv.reader(
            io.StringIO(bodies[f"{dist_info}/RECORD"].decode("utf-8"), newline="")
        ))
    except (UnicodeDecodeError, csv.Error) as error:
        raise ValueError("wheel metadata is malformed") from error
    if (
        metadata.defects
        or wheel_metadata.defects
        or metadata.get_all("Name") != [expected_name]
        or metadata.get_all("Version") != [expected_version]
        or metadata.get_all("Metadata-Version") not in (["2.1"], ["2.2"], ["2.3"], ["2.4"])
        or len(metadata.get_all("Summary", [])) > 1
        or len(metadata.get_all("Requires-Python", [])) > 1
        or wheel_metadata.get_all("Wheel-Version") != ["1.0"]
        or len(wheel_metadata.get_all("Generator", [])) > 1
        or len(wheel_metadata.get_all("Build", [])) > 1
        or wheel_metadata.get_all("Root-Is-Purelib") != ["true"]
        or wheel_metadata.get_all("Tag") is None
        or len(wheel_metadata.get_all("Tag", [])) != 1
    ):
        raise ValueError("wheel metadata identity or tag is invalid")
    requirement_values = metadata.get_all("Requires-Dist", [])
    requirement_limit = int(policy["max-requirements"])
    if remaining_requirements is not None:
        if type(remaining_requirements) is not int or remaining_requirements < 0:
            raise ValueError("offline dependency closure requirement budget is invalid")
        requirement_limit = min(requirement_limit, remaining_requirements)
    if len(requirement_values) > requirement_limit:
        raise ValueError("offline dependency closure requirement limit is exhausted")
    requirements = tuple(requirement_values)
    if expected_requirements is not None and requirements != expected_requirements:
        raise ValueError("wheel Requires-Dist set is not exact")
    for requirement in requirements:
        _parse_requirement(requirement, exact_pin=False)
    try:
        declared_tags = frozenset(
            tag
            for value in wheel_metadata.get_all("Tag", [])
            for tag in parse_tag(value)
        )
    except ValueError as error:
        raise ValueError("wheel metadata tag is malformed") from error
    if declared_tags != filename_tags or not declared_tags.issubset(compatible_tags):
        raise ValueError("wheel metadata identity or tag is invalid")

    if len(record_rows) != len(bodies) or any(len(row) != 3 for row in record_rows):
        raise ValueError("wheel RECORD shape is invalid")
    indexed = {row[0]: row for row in record_rows}
    if len(indexed) != len(record_rows) or set(indexed) != set(bodies):
        raise ValueError("wheel RECORD member set is not exact")
    record_name = f"{dist_info}/RECORD"
    for name, body in bodies.items():
        row = indexed[name]
        if name == record_name:
            if row[1:] != ["", ""]:
                raise ValueError("wheel RECORD self row is invalid")
            continue
        expected_hash = "sha256=" + base64.urlsafe_b64encode(
            hashlib.sha256(body).digest()
        ).rstrip(b"=").decode()
        if row[1] != expected_hash or row[2] != str(len(body)):
            raise ValueError("wheel RECORD integrity mismatch")
    return resolved, requirements


def _wheelhouse_candidates(
    root: pathlib.Path,
    *,
    initial_wheels: int,
    initial_bytes: int,
) -> tuple[_EnumeratedWheel, ...]:
    resolved = root.resolve(strict=True)
    if root.is_symlink() or not resolved.is_dir() or resolved != root.absolute():
        raise ValueError("offline wheelhouse is not a canonical directory")
    candidates: list[_EnumeratedWheel] = []
    policy = _offline_wheel_policy()
    wheel_count = initial_wheels
    aggregate_bytes = initial_bytes
    before = resolved.stat()
    with os.scandir(resolved) as entries:
        for entry in entries:
            item = pathlib.Path(entry.path)
            if entry.is_symlink() or not entry.is_file(follow_symlinks=False) or item.suffix != ".whl":
                raise ValueError("offline wheelhouse contains a non-wheel artifact")
            metadata = entry.stat(follow_symlinks=False)
            wheel_count += 1
            aggregate_bytes += metadata.st_size
            if (
                wheel_count > policy["max-closure-wheels"]
                or aggregate_bytes > policy["max-closure-bytes"]
            ):
                raise ValueError("offline dependency closure wheel/byte limit is exhausted")
            canonical = item.resolve(strict=True)
            if canonical.parent != resolved:
                raise ValueError("offline wheelhouse artifact escapes its root")
            _wheel_filename(canonical)
            candidates.append(_EnumeratedWheel(
                canonical,
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_uid,
                stat.S_IMODE(metadata.st_mode),
                metadata.st_nlink,
                metadata.st_size,
                metadata.st_mtime_ns,
            ))
    after = resolved.stat()
    if (
        (before.st_dev, before.st_ino, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_mtime_ns)
    ):
        raise ValueError("offline wheelhouse changed during enumeration")
    return tuple(sorted(candidates, key=lambda item: item.path.name))


@contextlib.contextmanager
def _prepare_physical_closure(
    wheelhouse: pathlib.Path,
    *,
    initial: tuple[pathlib.Path, ...] = (),
    probe_hook: Callable[[str], None] | None = None,
) -> Iterator[
    tuple[
        tuple[_PhysicalWheel, ...],
        tuple[_PhysicalWheel, ...],
        tuple[_OpenWheel, ...],
    ]
]:
    """Charge the whole physical closure before metadata allocation or traversal."""

    policy = _offline_wheel_policy()
    initial_enumerated = tuple(_enumerate_wheel(path) for path in initial)
    initial_bytes = 0
    for enumerated in initial_enumerated:
        initial_bytes += enumerated.size
        if initial_bytes > policy["max-closure-bytes"]:
            raise ValueError("offline dependency closure wheel/byte limit is exhausted")
    candidates = _wheelhouse_candidates(
        wheelhouse,
        initial_wheels=len(initial),
        initial_bytes=initial_bytes,
    )
    opened: list[_OpenWheel] = []
    completed = False
    try:
        for enumerated in (*initial_enumerated, *candidates):
            opened.append(_open_wheel(
                enumerated,
                max_total_bytes=int(policy["max-total-bytes"]),
            ))
        if probe_hook is not None:
            probe_hook("preflight.after-open")
        for item in opened:
            _recheck_open_wheel(item)
        initial_physical: list[_PhysicalWheel] = []
        dependency_physical: list[_PhysicalWheel] = []
        aggregate_charge = 0
        for index, item in enumerate(opened):
            physical = _inspect_physical_wheel(item, policy)
            aggregate_charge += max(len(physical.raw), physical.uncompressed_bytes)
            if aggregate_charge > policy["max-closure-bytes"]:
                raise ValueError("offline dependency closure wheel/byte limit is exhausted")
            if index < len(initial):
                initial_physical.append(physical)
            else:
                dependency_physical.append(physical)
        yield tuple(initial_physical), tuple(dependency_physical), tuple(opened)
        completed = True
    finally:
        completion_error: BaseException | None = None
        if completed:
            try:
                if probe_hook is not None:
                    probe_hook("preflight.closure-return")
            except BaseException as error:
                completion_error = error
            for item in opened:
                try:
                    _recheck_open_wheel(item)
                except BaseException as error:
                    if completion_error is None:
                        completion_error = error
        for item in reversed(opened):
            try:
                _close_open_wheel(item)
            except BaseException as error:
                if completed and completion_error is None:
                    completion_error = error
        if completion_error is not None:
            raise completion_error


def _resolve_offline_closure(
    wheelhouse: pathlib.Path,
    root_requirements: tuple[str, ...],
    *,
    initial_wheels: int = 0,
    initial_bytes: int = 0,
    physical_candidates: tuple[_PhysicalWheel, ...] | None = None,
) -> tuple[pathlib.Path, ...]:
    policy = _offline_wheel_policy()
    if (
        len(root_requirements) > policy["max-requirements"]
        or len(root_requirements) > policy["max-dependency-edges"]
        or (root_requirements and policy["max-dependency-depth"] < 1)
    ):
        raise ValueError("offline dependency closure root limit is exhausted")
    if physical_candidates is None:
        raise ValueError("offline physical closure binding is required")
    candidates = tuple(item.path for item in physical_candidates)
    physical_by_path = {item.path: item for item in physical_candidates}
    pending = [
        (_parse_requirement(value, exact_pin=True), 1, ())
        for value in root_requirements
    ]
    selected: dict[str, tuple[Version, pathlib.Path]] = {}
    ordered: list[pathlib.Path] = []
    requirement_count = len(pending)
    edge_count = len(pending)
    if edge_count > policy["max-dependency-edges"]:
        raise ValueError("offline dependency closure edge limit is exhausted")
    while pending:
        requirement, depth, ancestry = pending.pop(0)
        if depth > policy["max-dependency-depth"]:
            raise ValueError("offline dependency closure depth limit is exhausted")
        if requirement.marker is not None and not requirement.marker.evaluate():
            continue
        name = canonicalize_name(requirement.name)
        if name in ancestry:
            raise ValueError("offline dependency closure contains a cycle")
        existing = selected.get(name)
        if existing is not None:
            if existing[0] not in requirement.specifier:
                raise ValueError(f"offline dependency closure conflicts: {requirement}")
            continue
        matches: list[tuple[Version, pathlib.Path]] = []
        for candidate in candidates:
            candidate_name, candidate_version, _tags = _wheel_filename(candidate)
            if canonicalize_name(candidate_name) == name and candidate_version in requirement.specifier:
                matches.append((candidate_version, candidate))
        if len(matches) != 1:
            raise ValueError(f"offline dependency is unavailable or ambiguous: {requirement}")
        version, path = matches[0]
        remaining_requirements = int(policy["max-requirements"]) - requirement_count
        _verified, child_requirements = _validate_wheel(
            path,
            expected_name=requirement.name,
            expected_version=str(version),
            expected_requirements=None,
            physical=physical_by_path[path],
            remaining_requirements=remaining_requirements,
        )
        selected[name] = (version, path)
        ordered.append(path)
        edge_count += len(child_requirements)
        requirement_count += len(child_requirements)
        if (
            edge_count > policy["max-dependency-edges"]
            or requirement_count > policy["max-requirements"]
        ):
            raise ValueError("offline dependency closure edge/requirement limit is exhausted")
        if child_requirements and depth + 1 > policy["max-dependency-depth"]:
            raise ValueError("offline dependency closure depth limit is exhausted")
        pending.extend(
            (_parse_requirement(value, exact_pin=False), depth + 1, (*ancestry, name))
            for value in child_requirements
        )
    if set(ordered) != set(candidates):
        raise ValueError("offline wheelhouse contains an unreferenced dependency")
    return tuple(ordered)


def preflight_offline_candidate(
    candidate_wheel: pathlib.Path,
    wheelhouse: pathlib.Path,
    *,
    _probe_hook: Callable[[str], None] | None = None,
) -> OfflineDependencyPlan:
    """Verify the candidate and its exact direct dependency wheels before mutation."""

    if _probe_hook is not None and not callable(_probe_hook):
        raise TypeError("offline preflight probe hook must be callable")
    with _configuration_parse_operation():
        return _preflight_offline_candidate(candidate_wheel, wheelhouse, _probe_hook=_probe_hook)


def _preflight_offline_candidate(
    candidate_wheel: pathlib.Path,
    wheelhouse: pathlib.Path,
    *,
    _probe_hook: Callable[[str], None] | None,
) -> OfflineDependencyPlan:
    parser_attestation = _package_parser_attestation()
    project = _project()
    dependencies = tuple(str(item) for item in project.get("dependencies", []))
    policy = _offline_wheel_policy()
    if (
        len(dependencies) > policy["max-requirements"]
        or len(dependencies) > policy["max-dependency-edges"]
    ):
        raise ValueError("offline dependency closure root limit is exhausted")
    candidate = candidate_wheel.resolve(strict=True)
    with _prepare_physical_closure(
        wheelhouse,
        initial=(candidate,),
        probe_hook=_probe_hook,
    ) as (initial_physical, dependency_physical, opened):
        _validate_wheel(
            candidate_wheel,
            expected_name=str(project["name"]),
            expected_version=str(project["version"]),
            expected_requirements=dependencies,
            physical=initial_physical[0],
            remaining_requirements=int(policy["max-requirements"]),
        )
        ordered = _resolve_offline_closure(
            wheelhouse,
            dependencies,
            physical_candidates=dependency_physical,
        )
        if _probe_hook is not None:
            _probe_hook("preflight.after-traversal")
        for item in opened:
            _recheck_open_wheel(item)
        if _package_parser_attestation() != parser_attestation:
            raise ValueError("package parser attestation changed during preflight")
        plan = _offline_dependency_plan(
            parser_attestation,
            candidate_wheel=candidate,
            dependency_wheels=ordered,
            opened=opened,
        )
        if _probe_hook is not None:
            _probe_hook("preflight.before-plan-return")
        for item in opened:
            _recheck_open_wheel(item)
        if _package_parser_attestation() != parser_attestation:
            raise ValueError("package parser attestation changed before plan return")
        return plan


def _record(files: list[tuple[str, bytes]]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for path, body in files:
        digest = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode()
        writer.writerow((path, f"sha256={digest}", len(body)))
    writer.writerow((f"{_dist_info()}/RECORD", "", ""))
    return output.getvalue().encode()


def _write_zip_member(archive: zipfile.ZipFile, path: str, body: bytes, *, executable: bool = False) -> None:
    info = zipfile.ZipInfo(path, date_time=ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (0o100755 if executable else 0o100644) << 16
    archive.writestr(info, body)


def get_requires_for_build_wheel(config_settings: dict[str, object] | None = None) -> list[str]:
    del config_settings
    return []


def prepare_metadata_for_build_wheel(
    metadata_directory: str,
    config_settings: dict[str, object] | None = None,
) -> str:
    del config_settings
    target = pathlib.Path(metadata_directory) / _dist_info()
    target.mkdir(parents=True, exist_ok=False)
    for archive_path, body in _metadata_files():
        (target / pathlib.Path(archive_path).name).write_bytes(body)
    return target.name


def build_wheel(
    wheel_directory: str,
    config_settings: dict[str, object] | None = None,
    metadata_directory: str | None = None,
) -> str:
    del config_settings, metadata_directory
    filename = f"{_distribution_name()}-{_version()}-py3-none-any.whl"
    destination = pathlib.Path(wheel_directory)
    destination.mkdir(parents=True, exist_ok=True)
    direct_scripts = _direct_script_files()
    files = list(_package_files()) + _metadata_files() + direct_scripts
    files.sort(key=lambda item: item[0])
    record = _record(files)
    with zipfile.ZipFile(destination / filename, "w") as archive:
        for path, body in files:
            _write_zip_member(archive, path, body, executable=path == direct_scripts[0][0])
        _write_zip_member(archive, f"{_dist_info()}/RECORD", record)
    return filename


def observe_release_wheel(
    path: pathlib.Path, *, expected_name: str, expected_version: str,
    max_members: int, max_member_bytes: int, max_expanded_bytes: int,
    max_requirements: int, python_patch: str,
) -> dict[str, object]:
    """Read a real wheel through the existing physical/parser boundary, never install it."""
    with _configuration_parse_operation(), _constraint_provider_operation() as provider:
        before = _package_parser_attestation()
        policy = dict(_offline_wheel_policy())
        for key, ceiling in (("max-members", max_members), ("max-member-bytes", max_member_bytes),
                             ("max-total-bytes", max_expanded_bytes)):
            if type(ceiling) is not int or ceiling <= 0:
                raise ValueError("release wheel resource ceiling is invalid")
            policy[key] = min(int(policy[key]), ceiling)
        opened = _open_wheel(_enumerate_wheel(path), max_total_bytes=int(policy["max-total-bytes"]))
        try:
            physical = _inspect_physical_wheel(opened, policy)
            _, requirements = _validate_wheel(path, expected_name=expected_name,
                expected_version=expected_version, expected_requirements=None,
                physical=physical, remaining_requirements=max_requirements)
            with zipfile.ZipFile(io.BytesIO(physical.raw)) as archive:
                metadata = Parser().parsestr(archive.read(
                    f"{_normalized_distribution(expected_name)}-{expected_version}.dist-info/METADATA"
                ).decode("utf-8", errors="strict"))
            # Actual METADATA is RECORD-bound above; manifest text is not a
            # substitute for checking its full interpreter patch constraint.
            if _package_parser_attestation() != before:
                raise ValueError("release wheel parser changed before constraint parse")
            python_constraints = metadata.get_all("Requires-Python", [])
            if len(python_constraints) > 1:
                raise ValueError("release wheel interpreter constraint is duplicated")
            if python_constraints:
                constraint = python_constraints[0]
                if not constraint or not constraint.strip():
                    raise ValueError("release wheel interpreter constraint is empty")
                try:
                    compatible = provider.requires_python(python_patch,constraint)
                except (InvalidVersion, InvalidSpecifier) as error:
                    raise ValueError("release wheel interpreter constraint is invalid") from error
                if not compatible:
                    raise ValueError("release wheel interpreter constraint is incompatible")
            licenses = metadata.get_all("License-Expression", [])
            if len(licenses) != 1 or not licenses[0] or any(x in licenses[0] for x in (" ", "\n", "\r")):
                raise ValueError("release wheel license identity is unavailable")
            _recheck_open_wheel(opened)
            if _package_parser_attestation() != before:
                raise ValueError("release wheel parser changed")
            return {"requirements": list(requirements), "license_ids": licenses,
                    "raw_sha256": opened.binding.raw_digest,
                    "size_bytes": opened.binding.descriptor_size,
                    "parser_attestation_digest": before.attestation_digest}
        finally:
            _close_open_wheel(opened)
