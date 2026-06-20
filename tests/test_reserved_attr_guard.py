"""tests/test_reserved_attr_guard.py — ShadowPort Scanner v2.3.0

Folds tools/reserved_attr_guard.py into the regular `pytest tests/` run, so
CI catches any future App/Screen subclass that shadows one of Textual's
reserved internal attribute names (the exact bug class fixed in main.py).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from tools.reserved_attr_guard import find_violations

MAIN_PY = os.path.join(os.path.dirname(os.path.dirname(__file__)), "main.py")


def test_main_has_no_reserved_attribute_shadowing():
    violations = find_violations(MAIN_PY)
    assert not violations, "\n" + "\n".join(str(v) for v in violations)
