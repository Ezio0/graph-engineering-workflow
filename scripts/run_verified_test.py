"""Execute one exact unittest module delivered by the verified-byte parent protocol."""

from __future__ import annotations

import ast
import base64
import hashlib
import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import CodeType


def _raw_digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _code_fingerprint(code: CodeType) -> str:
    def value_projection(value: object) -> object:
        if value is None or type(value) in (bool, int, float, str):
            return value
        if type(value) is bytes:
            return {"bytes": base64.b64encode(value).decode("ascii")}
        if type(value) is tuple:
            return {"tuple": [value_projection(item) for item in value]}
        if type(value) is frozenset:
            projected = [value_projection(item) for item in value]
            return {
                "frozenset": sorted(
                    projected,
                    key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
                )
            }
        if type(value) is CodeType:
            return code_projection(value)
        return {"constant_type": type(value).__name__, "representation": repr(value)}

    def code_projection(current: CodeType) -> dict[str, object]:
        return {
            "argcount": current.co_argcount,
            "posonlyargcount": current.co_posonlyargcount,
            "kwonlyargcount": current.co_kwonlyargcount,
            "nlocals": current.co_nlocals,
            "stacksize": current.co_stacksize,
            "flags": current.co_flags,
            "code": base64.b64encode(current.co_code).decode("ascii"),
            "consts": [value_projection(value) for value in current.co_consts],
            "names": list(current.co_names),
            "varnames": list(current.co_varnames),
            "freevars": list(current.co_freevars),
            "cellvars": list(current.co_cellvars),
            "name": current.co_name,
            "qualname": current.co_qualname,
            "firstlineno": current.co_firstlineno,
            "linetable": base64.b64encode(current.co_linetable).decode("ascii"),
            "exceptiontable": base64.b64encode(current.co_exceptiontable).decode("ascii"),
        }

    body = json.dumps(code_projection(code), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(body).hexdigest()


def _bound_callable(module_source: bytes, qualified_test: str) -> tuple[str, str, CodeType]:
    parts = qualified_test.split(".")
    if len(parts) < 5:
        raise RuntimeError("verified test identity is malformed")
    source = module_source.decode("utf-8")
    tree = ast.parse(source, filename="<verified-test-module>")
    class_node = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == parts[-2]
    )
    callable_node = next(
        node for node in class_node.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == parts[-1]
    )
    segment = ast.get_source_segment(source, callable_node)
    if segment is None:
        raise RuntimeError("verified callable source is unavailable")
    module_code = compile(source, "<verified-test-module>", "exec", dont_inherit=True)
    class_code = next(
        value for value in module_code.co_consts
        if type(value) is CodeType and value.co_name == parts[-2]
    )
    callable_code = next(
        value for value in class_code.co_consts
        if type(value) is CodeType and value.co_name == parts[-1]
    )
    return _raw_digest(segment.encode("utf-8")), _code_fingerprint(callable_code), module_code


def _load_attestation_issuer(root: pathlib.Path):  # type: ignore[no-untyped-def]
    path = root / "tests/support/source_checkout_attestation.py"
    specification = importlib.util.spec_from_file_location("gew_source_checkout_issuer", path)
    if specification is None or specification.loader is None:
        raise RuntimeError("Candidate source checkout issuer is unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def protocol_main(payload: object, runner_source: bytes) -> int:
    fields = {
        "schema_version", "source_root", "qualified_test", "module_name",
        "module_source_b64", "callable_source_b64", "runner_digest", "module_digest",
        "callable_source_digest", "callable_code_digest",
    }
    if not isinstance(payload, dict) or set(payload) != fields or payload.get("schema_version") != "1.0.0":
        raise RuntimeError("verified byte protocol payload is not exact")
    root = pathlib.Path(str(payload["source_root"]))
    if not root.is_absolute() or root.is_symlink() or root.resolve(strict=True) != root:
        raise RuntimeError("Candidate source root is not canonical")
    qualified_test = str(payload["qualified_test"])
    module_name = str(payload["module_name"])
    if module_name != ".".join(qualified_test.split(".")[:3]):
        raise RuntimeError("verified module identity is substituted")
    try:
        module_source = base64.b64decode(str(payload["module_source_b64"]), validate=True)
        callable_source = base64.b64decode(
            str(payload["callable_source_b64"]), validate=True
        )
    except ValueError as error:
        raise RuntimeError("verified module bytes are malformed") from error
    source_digest, code_digest, module_code = _bound_callable(module_source, qualified_test)
    if (
        _raw_digest(runner_source) != payload["runner_digest"]
        or _raw_digest(module_source) != payload["module_digest"]
        or _raw_digest(callable_source) != payload["callable_source_digest"]
        or source_digest != payload["callable_source_digest"]
        or code_digest != payload["callable_code_digest"]
    ):
        raise RuntimeError("verified byte protocol digest mismatch")

    with tempfile.TemporaryDirectory(prefix="gew-coverage-control-") as directory:
        control_root = pathlib.Path(directory).resolve(strict=True)
        issuer = _load_attestation_issuer(root)
        issuer.issue_source_checkout_attestation(root, control_root)
        sys._xoptions[issuer.CONTROL_OPTION] = str(control_root)
        for source_root in ("adapters", "application", "storage", "core"):
            sys.path.insert(0, str(root / source_root))
        sys.path.insert(0, str(root))

        module = types.ModuleType(module_name)
        module.__file__ = "<verified-test-module>"
        module.__package__ = module_name.rpartition(".")[0]
        sys.modules[module_name] = module
        exec(module_code, module.__dict__)
        test_class = getattr(module, qualified_test.split(".")[-2], None)
        test_method_name = qualified_test.split(".")[-1]
        if not isinstance(test_class, type) or not issubclass(test_class, unittest.TestCase):
            raise RuntimeError("verified test class does not resolve exactly")
        test_method = getattr(test_class, test_method_name, None)
        if not callable(test_method) or _code_fingerprint(test_method.__code__) != code_digest:
            raise RuntimeError("verified callable code changed after load")
        suite = unittest.TestSuite((test_class(test_method_name),))
        observed = unittest.TestResult()
        captured_stdout = io.StringIO()
        captured_stderr = io.StringIO()
        with redirect_stdout(captured_stdout), redirect_stderr(captured_stderr):
            suite.run(observed)
        post_source_digest, post_code_digest, _post_module_code = _bound_callable(
            module_source, qualified_test
        )
        if (
            _raw_digest(runner_source) != payload["runner_digest"]
            or _raw_digest(module_source) != payload["module_digest"]
            or post_source_digest != source_digest
            or post_code_digest != code_digest
            or _code_fingerprint(test_method.__code__) != code_digest
        ):
            raise RuntimeError("verified byte protocol changed during execution")
        body = {
            "schema_version": "1.0.0",
            "qualified_test": qualified_test,
            "tests_run": observed.testsRun,
            "successful": observed.wasSuccessful(),
            "failures": len(observed.failures),
            "errors": len(observed.errors),
            "captured_stdout_empty": not captured_stdout.getvalue(),
            "captured_stderr_empty": not captured_stderr.getvalue(),
            "runner_digest": payload["runner_digest"],
            "module_digest": payload["module_digest"],
            "callable_source_digest": payload["callable_source_digest"],
            "callable_code_digest": payload["callable_code_digest"],
        }
        result = {
            **body,
            "observed_result_digest": _raw_digest(
                json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ),
        }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0 if observed.testsRun == 1 and observed.wasSuccessful() else 1


if "_GEW_PROTOCOL_PAYLOAD" in globals():
    raise SystemExit(protocol_main(_GEW_PROTOCOL_PAYLOAD, _GEW_RUNNER_SOURCE))
