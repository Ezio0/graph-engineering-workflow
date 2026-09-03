"""Dependency-free source lint and annotation checks."""

from __future__ import annotations

import argparse
import ast
import json
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE_ROOTS = ("core", "application", "storage", "adapters", "scripts", "tests")
SIMPLE_TYPES = {"str", "int", "float", "bool", "bytes", "None"}


def _python_files() -> list[pathlib.Path]:
    return [
        path
        for root in SOURCE_ROOTS
        for path in sorted((ROOT / root).rglob("*.py"))
        if "__pycache__" not in path.parts
    ]


def _annotation(node: ast.expr | None) -> object | None:
    if node is None:
        return None
    if isinstance(node, ast.Name) and node.id in SIMPLE_TYPES:
        return node.id
    if isinstance(node, ast.Constant) and node.value is None:
        return "None"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left = _annotation(node.left)
        right = _annotation(node.right)
        if left is not None and right is not None:
            left_members = left[1] if isinstance(left, tuple) and left[0] == "union" else (left,)
            right_members = right[1] if isinstance(right, tuple) and right[0] == "union" else (right,)
            return ("union", (*left_members, *right_members))
    if isinstance(node, ast.Subscript):
        base = node.value.id if isinstance(node.value, ast.Name) else None
        if base in {"list", "set", "tuple", "dict"}:
            if isinstance(node.slice, ast.Tuple):
                arguments = tuple(_annotation(element) for element in node.slice.elts)
            else:
                arguments = (_annotation(node.slice),)
            if all(argument is not None for argument in arguments):
                return (base, arguments)
    return None


def _literal_type(node: ast.expr | None) -> object | None:
    if node is None:
        return None
    if isinstance(node, ast.Constant):
        if node.value is None:
            return "None"
        if type(node.value) is bool:
            return "bool"
        if type(node.value) is int:
            return "int"
        if type(node.value) is float:
            return "float"
        if isinstance(node.value, str):
            return "str"
        if isinstance(node.value, bytes):
            return "bytes"
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        return _literal_type(node.operand)
    collection_kinds = {ast.List: "list", ast.Set: "set", ast.Tuple: "tuple"}
    for node_type, name in collection_kinds.items():
        if isinstance(node, node_type):
            elements = tuple(_literal_type(element) for element in node.elts)
            if any(element is None for element in elements):
                return None
            if name in {"list", "set"}:
                unique = tuple(dict.fromkeys(elements))
                return (name, (unique[0] if len(unique) == 1 else ("union", unique),)) if unique else (name, ("never",))
            return (name, elements)
    if isinstance(node, ast.Dict):
        keys = tuple(_literal_type(key) for key in node.keys)
        values = tuple(_literal_type(value) for value in node.values)
        if any(item is None for item in (*keys, *values)):
            return None
        key_types = tuple(dict.fromkeys(keys))
        value_types = tuple(dict.fromkeys(values))
        key_type: object = key_types[0] if len(key_types) == 1 else ("union", key_types)
        value_type: object = value_types[0] if len(value_types) == 1 else ("union", value_types)
        return ("dict", (key_type, value_type))
    return None


def _compatible(expected: object, actual: object) -> bool:
    if actual == "never":
        return True
    if isinstance(expected, tuple) and expected[0] == "union" and isinstance(actual, tuple) and actual[0] == "union":
        return all(any(_compatible(expected_member, actual_member) for expected_member in expected[1]) for actual_member in actual[1])
    if isinstance(expected, tuple) and expected[0] == "union":
        return any(_compatible(member, actual) for member in expected[1])
    if isinstance(actual, tuple) and actual[0] == "union":
        return all(_compatible(expected, member) for member in actual[1])
    if expected == "float" and actual == "int":
        return True
    if isinstance(expected, tuple) and isinstance(actual, tuple) and expected[0] == actual[0]:
        expected_arguments = expected[1]
        actual_arguments = actual[1]
        if expected[0] == "tuple" and len(expected_arguments) == 2 and expected_arguments[1] == "...":
            return all(_compatible(expected_arguments[0], argument) for argument in actual_arguments)
        return len(expected_arguments) == len(actual_arguments) and all(
            _compatible(expected_argument, actual_argument)
            for expected_argument, actual_argument in zip(expected_arguments, actual_arguments, strict=True)
        )
    return expected == actual


def _expression_type(
    node: ast.expr | None,
    variables: dict[str, object],
    functions: dict[str, object],
) -> object | None:
    literal = _literal_type(node)
    if literal is not None:
        return literal
    if isinstance(node, ast.Name):
        return variables.get(node.id)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        return functions.get(node.func.id)
    if isinstance(node, ast.IfExp):
        body_type = _expression_type(node.body, variables, functions)
        else_type = _expression_type(node.orelse, variables, functions)
        if body_type is not None and else_type is not None:
            return body_type if body_type == else_type else ("union", (body_type, else_type))
    return None


def _assignment_names(target: ast.expr) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [name for child in target.elts for name in _assignment_names(child)]
    return []


def _record_mismatch(
    findings: list[dict[str, object]],
    *,
    code: str,
    shown: str,
    line: int,
    expected: object | None,
    actual: object | None,
    name: str | None = None,
) -> None:
    if expected is None or actual is None or _compatible(expected, actual):
        return
    finding: dict[str, object] = {
        "code": code,
        "path": shown,
        "line": line,
        "expected": repr(expected),
        "actual": repr(actual),
    }
    if name is not None:
        finding["name"] = name
    findings.append(finding)


def _check_statements(
    statements: list[ast.stmt],
    variables: dict[str, object],
    functions: dict[str, object],
    expected_return: object | None,
    findings: list[dict[str, object]],
    shown: str,
) -> None:
    for statement in statements:
        if isinstance(statement, ast.AnnAssign):
            expected = _annotation(statement.annotation)
            actual = _expression_type(statement.value, variables, functions)
            _record_mismatch(
                findings,
                code="ANNOTATED_ASSIGNMENT_TYPE_MISMATCH",
                shown=shown,
                line=statement.lineno,
                expected=expected,
                actual=actual,
            )
            for name in _assignment_names(statement.target):
                if expected is not None:
                    variables[name] = expected
        elif isinstance(statement, ast.Assign):
            actual = _expression_type(statement.value, variables, functions)
            for target in statement.targets:
                for name in _assignment_names(target):
                    expected = variables.get(name)
                    _record_mismatch(
                        findings,
                        code="ASSIGNMENT_TYPE_MISMATCH",
                        shown=shown,
                        line=statement.lineno,
                        expected=expected,
                        actual=actual,
                        name=name,
                    )
                    if expected is None and actual is not None:
                        variables[name] = actual
        elif isinstance(statement, ast.Return):
            actual = _expression_type(statement.value, variables, functions)
            _record_mismatch(
                findings,
                code="RETURN_TYPE_MISMATCH",
                shown=shown,
                line=statement.lineno,
                expected=expected_return,
                actual=actual,
            )
        elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _check_function(statement, functions, findings, shown)
        elif isinstance(statement, ast.ClassDef):
            _check_statements(statement.body, {}, functions, None, findings, shown)
        elif isinstance(statement, ast.If):
            _check_statements(statement.body, dict(variables), functions, expected_return, findings, shown)
            _check_statements(statement.orelse, dict(variables), functions, expected_return, findings, shown)
        elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
            _check_statements(statement.body, dict(variables), functions, expected_return, findings, shown)
            _check_statements(statement.orelse, dict(variables), functions, expected_return, findings, shown)
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            _check_statements(statement.body, dict(variables), functions, expected_return, findings, shown)
        elif isinstance(statement, ast.Try):
            _check_statements(statement.body, dict(variables), functions, expected_return, findings, shown)
            for handler in statement.handlers:
                _check_statements(handler.body, dict(variables), functions, expected_return, findings, shown)
            _check_statements(statement.orelse, dict(variables), functions, expected_return, findings, shown)
            _check_statements(statement.finalbody, dict(variables), functions, expected_return, findings, shown)


def _check_function(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    functions: dict[str, object],
    findings: list[dict[str, object]],
    shown: str,
) -> None:
    arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    if not node.name.startswith("_"):
        missing = [
            argument.arg
            for argument in arguments
            if argument.annotation is None and argument.arg not in ("self", "cls")
        ]
        if node.returns is None or missing:
            findings.append({
                "code": "PUBLIC_ANNOTATION_MISSING",
                "path": shown,
                "line": node.lineno,
                "arguments": missing,
                "return_missing": node.returns is None,
            })
    positional = [*node.args.posonlyargs, *node.args.args]
    positional_defaults = [None] * (len(positional) - len(node.args.defaults)) + list(node.args.defaults)
    default_pairs = [*zip(positional, positional_defaults, strict=True), *zip(node.args.kwonlyargs, node.args.kw_defaults, strict=True)]
    for argument, default in default_pairs:
        _record_mismatch(
            findings,
            code="DEFAULT_ARGUMENT_TYPE_MISMATCH",
            shown=shown,
            line=node.lineno,
            expected=_annotation(argument.annotation),
            actual=_literal_type(default),
            name=argument.arg,
        )
    variables = {
        argument.arg: annotation
        for argument in arguments
        if (annotation := _annotation(argument.annotation)) is not None
    }
    _check_statements(node.body, variables, functions, _annotation(node.returns), findings, shown)


def inspect_path(path: pathlib.Path, mode: str, *, display_path: str | None = None) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    shown = display_path or str(path)
    text = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(text, filename=str(path))
        compile(tree, str(path), "exec", dont_inherit=True)
    except (SyntaxError, ValueError) as error:
        return [{"code": "INVALID_PYTHON", "path": shown, "detail": str(error)}]
    if mode == "lint":
        for line_number, line in enumerate(text.splitlines(), start=1):
            if line.rstrip() != line:
                findings.append({"code": "TRAILING_WHITESPACE", "path": shown, "line": line_number})
            if "\t" in line:
                findings.append({"code": "TAB_INDENT", "path": shown, "line": line_number})
        return findings
    functions = {
        node.name: annotation
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and (annotation := _annotation(node.returns)) is not None
    }
    _check_statements(tree.body, {}, functions, None, findings, shown)
    return findings


def inspect(mode: str) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for path in _python_files():
        if mode == "type" and "tests" in path.relative_to(ROOT).parts:
            continue
        text = path.read_text(encoding="utf-8")
        del text
        findings.extend(inspect_path(path, mode, display_path=str(path.relative_to(ROOT))))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("lint", "type"))
    arguments = parser.parse_args(argv)
    findings = inspect(arguments.mode)
    print(json.dumps({"mode": arguments.mode, "status": "PASS" if not findings else "FAIL", "findings": findings}, sort_keys=True))
    return 0 if not findings else 1


if __name__ == "__main__":
    sys.exit(main())
