"""
tools/reserved_attr_guard.py — ShadowPort Scanner v2.3.0

Static guard against the exact bug class fixed in main.py: a custom App or
Screen subclass assigning to one of Textual's reserved internal attribute
names, silently shadowing framework state (e.g. `App._registry`, the
`set[Widget]` Textual uses for shutdown cleanup).

Scope decision: this guard flags reserved-name assignments ONLY on classes
that are, or transitively inherit from, Textual's `App` or `Screen` — because
those are the concrete classes that own the reserved attributes in question
(confirmed by static audit: `_registry` etc. live on App, not on every
Widget). Plain widget subclasses (Vertical, Static, Container, ...) are not
flagged for using the same *names*, since there is no actual attribute to
shadow there — e.g. `PluginView(Vertical)`'s own `self._registry` (its plugin
lookup table) is unrelated and safe. Flagging it anyway would just train
people to ignore the guard. If a future class inherits from App or Screen and
reuses one of these names, the guard fails immediately and loudly.

Usage:
    python3 tools/reserved_attr_guard.py main.py [other_app_files.py ...]
    # exit code 0 = clean, 1 = violation(s) found, prints details to stderr

Also exposed as `find_violations(path) -> list[Violation]` for a pytest test
(see tests/test_reserved_attr_guard.py) or a pre-commit hook.
"""

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass

RESERVED_NAMES = {
    "_registry", "_nodes", "_timers", "_running", "_closing",
    "_exit", "_animator", "_workers", "screen_stack",
}

# Names that mark a class as Textual-managed and therefore in-scope.
# (App and Screen are the two base classes confirmed to own these
# reserved attributes; extend this set if Textual's internals or this
# app's class hierarchy change.)
TEXTUAL_ROOTS = {"App", "Screen"}


@dataclass
class Violation:
    cls: str
    attr: str
    lineno: int
    kind: str  # "class-body" or "self-assign"

    def __str__(self) -> str:
        return f"{self.kind}: class '{self.cls}' assigns reserved attr '{self.attr}' at line {self.lineno}"


def _base_names(node: ast.ClassDef) -> list[str]:
    names = []
    for b in node.bases:
        if isinstance(b, ast.Name):
            names.append(b.id)
        elif isinstance(b, ast.Attribute):
            names.append(b.attr)
    return names


def _is_textual_derived(node: ast.ClassDef, derived: dict[str, bool]) -> bool:
    for base in _base_names(node):
        if base in TEXTUAL_ROOTS:
            return True
        if derived.get(base):
            return True
    return False


def find_violations(path: str) -> list[Violation]:
    with open(path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=path)

    class_nodes = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]

    # Resolve transitive in-scope status (handles local subclassing chains).
    derived: dict[str, bool] = {}
    changed = True
    while changed:
        changed = False
        for node in class_nodes:
            if derived.get(node.name):
                continue
            if _is_textual_derived(node, derived):
                derived[node.name] = True
                changed = True

    violations: list[Violation] = []

    for node in class_nodes:
        if not derived.get(node.name):
            continue

        # Class-body level: `_registry: dict = {}` or `_registry = {}`
        for stmt in node.body:
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                if stmt.target.id in RESERVED_NAMES:
                    violations.append(Violation(node.name, stmt.target.id, stmt.lineno, "class-body"))
            elif isinstance(stmt, ast.Assign):
                for t in stmt.targets:
                    if isinstance(t, ast.Name) and t.id in RESERVED_NAMES:
                        violations.append(Violation(node.name, t.id, stmt.lineno, "class-body"))

        # Method bodies: `self._registry = ...` anywhere inside the class
        for sub in ast.walk(node):
            if isinstance(sub, ast.Assign):
                for t in sub.targets:
                    if (isinstance(t, ast.Attribute)
                            and isinstance(t.value, ast.Name)
                            and t.value.id == "self"
                            and t.attr in RESERVED_NAMES):
                        violations.append(Violation(node.name, t.attr, sub.lineno, "self-assign"))

    return violations


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: reserved_attr_guard.py <file.py> [file.py ...]", file=sys.stderr)
        return 2

    total = 0
    for path in argv:
        violations = find_violations(path)
        if violations:
            print(f"\n✗ {path}: {len(violations)} reserved-attribute violation(s)", file=sys.stderr)
            for v in violations:
                print(f"    {v}", file=sys.stderr)
            total += len(violations)
        else:
            print(f"✓ {path}: clean — no reserved Textual attribute names shadowed on App/Screen subclasses")

    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
