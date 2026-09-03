"""Mechanical WP-00 architecture and runtime-dependency checks."""

from __future__ import annotations

import ast
import json
import pathlib
import re
import sys
import tomllib


ROOT = pathlib.Path(__file__).resolve().parents[1]
REFERENCE_PROJECT_NAME = "agent-engineering-workflow"
REQUIRED_CORE_FORBIDDEN = (
    "graph_engineering.application",
    "graph_engineering.storage",
    "graph_engineering.adapters",
)
REQUIRED_VENDOR_FORBIDDEN = ("codex", "hermes", "openclaw")
REQUIRED_RUNTIME_ROOTS = ("core", "application", "storage", "adapters", "config", "skills")
REQUIRED_ENVIRONMENT_PATTERNS = (
    r'''(?i)[a-z][a-z0-9+.-]*://[^\s'"]+''',
    r"(?i)(?:^|\s)(?:/Users/|/home/|[A-Z]:\\Users\\)",
    r"(?i)\b(?:sqlite|postgres(?:ql)?|mysql|mariadb|mongodb)\+?[a-z0-9+.-]*://",
)
DATA_NAME_PATTERN = re.compile(
    r"(?i)(weight|score|threshold|timeout|limit|port|url|uri|path|command|connection|dsn|"
    r"interest|preference|behavior|profile)"
)


def _configured_values(architecture: dict[str, object], key: str) -> tuple[str, ...]:
    value = architecture.get(key, [])
    return tuple(item for item in value if isinstance(item, str)) if isinstance(value, list) else ()


def validate_policy(architecture: dict[str, object]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    minimums = {
        "core-forbidden-imports": REQUIRED_CORE_FORBIDDEN,
        "forbidden-runtime-import-prefixes": REQUIRED_VENDOR_FORBIDDEN,
        "runtime-roots": REQUIRED_RUNTIME_ROOTS,
        "forbidden-environment-patterns": REQUIRED_ENVIRONMENT_PATTERNS,
    }
    for key, required in minimums.items():
        configured = _configured_values(architecture, key)
        missing = sorted(set(required) - set(configured))
        if missing:
            findings.append({"code": "ARCHITECTURE_POLICY_WEAKENED", "path": "pyproject.toml", "value": f"{key}:{','.join(missing)}"})
    return findings


def _is_static_data_value(node: ast.expr) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, (str, int, float, bool, bytes))
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_is_static_data_value(element) for element in node.elts)
    if isinstance(node, ast.Dict):
        return all(key is not None and _is_static_data_value(key) for key in node.keys) and all(
            _is_static_data_value(value) for value in node.values
        )
    if isinstance(node, ast.UnaryOp):
        return _is_static_data_value(node.operand)
    if isinstance(node, ast.BinOp):
        return _is_static_data_value(node.left) and _is_static_data_value(node.right)
    return False


def _static_data_keys(node: ast.expr) -> list[str]:
    found: list[str] = []
    if isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values, strict=True):
            if isinstance(key, ast.Constant) and isinstance(key.value, str) and DATA_NAME_PATTERN.search(key.value) and _is_static_data_value(value):
                found.append(key.value)
            found.extend(_static_data_keys(value))
    elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for child in node.elts:
            found.extend(_static_data_keys(child))
    return found


def _attribute_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _attribute_name(node.value)
        return f"{parent}.{node.attr}" if parent else None
    return None


def _resolve_alias(name: str | None, aliases: dict[str, str]) -> str | None:
    if not name:
        return None
    root, separator, remainder = name.partition(".")
    resolved = aliases.get(root, root)
    return f"{resolved}.{remainder}" if separator else resolved


def inspect_python(path: pathlib.Path, layer: str, architecture: dict[str, object]) -> list[dict[str, str]]:
    text = path.read_text(encoding="utf-8")
    tree = ast.parse(text, filename=str(path))
    findings: list[dict[str, str]] = []
    core_forbidden = tuple(sorted(set(REQUIRED_CORE_FORBIDDEN) | set(_configured_values(architecture, "core-forbidden-imports"))))
    vendor_forbidden = tuple(sorted(set(REQUIRED_VENDOR_FORBIDDEN) | set(_configured_values(architecture, "forbidden-runtime-import-prefixes"))))
    external_allowed = set(_configured_values(architecture, "declared-external-imports"))
    pattern_values = tuple(sorted(set(REQUIRED_ENVIRONMENT_PATTERNS) | set(_configured_values(architecture, "forbidden-environment-patterns"))))
    try:
        environment_patterns = [re.compile(pattern) for pattern in pattern_values]
    except re.error as error:
        return [{"code": "INVALID_ARCHITECTURE_POLICY", "path": str(path), "value": str(error)}]
    imports: list[str] = []
    aliases: dict[str, str] = {}
    class_fields = {
        id(statement)
        for class_node in ast.walk(tree)
        if isinstance(class_node, ast.ClassDef)
        for statement in class_node.body
        if isinstance(statement, (ast.Assign, ast.AnnAssign))
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
                aliases[alias.asname or alias.name.split(".", 1)[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imports.append(node.module)
            for alias in node.names:
                if alias.name != "*":
                    aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            for pattern in environment_patterns:
                if pattern.search(node.value):
                    findings.append({"code": "ENVIRONMENT_VALUE_IN_LOGIC", "path": str(path), "value": node.value})
        elif isinstance(node, ast.Call):
            called = _resolve_alias(_attribute_name(node.func), aliases)
            if called in {"os.getenv", "os.environ.get"}:
                findings.append({"code": "DIRECT_ENVIRONMENT_READ", "path": str(path), "value": called})
            if called and called.startswith("subprocess.") and node.args and _is_static_data_value(node.args[0]):
                findings.append({"code": "HARDCODED_COMMAND_IN_LOGIC", "path": str(path), "value": called})
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            if id(node) in class_fields:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            if value is not None and _is_static_data_value(value):
                for data_key in _static_data_keys(value):
                    findings.append({"code": "DATA_VALUE_IN_LOGIC", "path": str(path), "value": data_key})
                for target in targets:
                    target_name = target.id if isinstance(target, ast.Name) else target.attr if isinstance(target, ast.Attribute) else ""
                    scalar_value = isinstance(value, ast.Constant) or isinstance(value, ast.UnaryOp)
                    if target_name and DATA_NAME_PATTERN.search(target_name) and (scalar_value or target_name.isupper()):
                        findings.append({"code": "DATA_VALUE_IN_LOGIC", "path": str(path), "value": target_name})
    for imported in imports:
        if layer == "core" and imported.startswith(core_forbidden):
            findings.append({"code": "CORE_IMPORT_BOUNDARY", "path": str(path), "value": imported})
        top_level = imported.split(".", 1)[0]
        if imported.startswith(vendor_forbidden):
            findings.append({"code": "VENDOR_RUNTIME_IMPORT", "path": str(path), "value": imported})
        elif top_level not in sys.stdlib_module_names and top_level != "graph_engineering" and top_level not in external_allowed:
            findings.append({"code": "UNDECLARED_EXTERNAL_IMPORT", "path": str(path), "value": imported})
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript):
            resolved = _resolve_alias(_attribute_name(node.value), aliases)
            if resolved == "os.environ":
                findings.append({"code": "DIRECT_ENVIRONMENT_READ", "path": str(path), "value": resolved})
    return findings


def inspect() -> list[dict[str, str]]:
    configuration = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    architecture = configuration["tool"]["gew"]["architecture"]
    findings: list[dict[str, str]] = validate_policy(architecture)
    for layer in ("core", "application", "storage", "adapters"):
        for path in sorted((ROOT / layer).rglob("*.py")):
            findings.extend(inspect_python(path, layer, architecture))
    for root_name in architecture["runtime-roots"]:
        for path in sorted((ROOT / root_name).rglob("*")):
            if (
                path.is_file()
                and "__pycache__" not in path.parts
                and path.suffix != ".pyc"
                and REFERENCE_PROJECT_NAME in path.read_text(encoding="utf-8")
            ):
                findings.append({"code": "REFERENCE_RUNTIME_DEPENDENCY", "path": str(path), "value": REFERENCE_PROJECT_NAME})
    return findings


def main() -> int:
    findings = inspect()
    print(json.dumps({"status": "PASS" if not findings else "FAIL", "findings": findings}, sort_keys=True))
    return 0 if not findings else 1


if __name__ == "__main__":
    sys.exit(main())
