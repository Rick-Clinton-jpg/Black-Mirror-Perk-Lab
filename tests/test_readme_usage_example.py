"""Runs the "How to use Black Mirror" example from README.md exactly as written.

The code block is read from README.md at test time, not copied here, so any
edit to the README example is tested automatically. If the documented usage
stops working, this test fails.
"""
from __future__ import annotations

import os
import re

import pytest

from mirror_world.sandbox.kernel_containment import available as containment_available

pytestmark = pytest.mark.skipif(
    not containment_available(), reason="requires working Linux namespaces and seccomp"
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _readme_usage_block() -> str:
    with open(os.path.join(REPO_ROOT, "docs", "BLACK-MIRROR-BASELINE.md"), encoding="utf-8") as f:
        readme = f.read()
    start = readme.index("## How to use Black Mirror")
    end = readme.index("\n## ", start + 1)
    blocks = re.findall(r"```python\n(.*?)```", readme[start:end], re.S)
    assert len(blocks) == 1, "expected exactly one python example in the usage section"
    return blocks[0]


def test_readme_usage_example_runs_as_documented(monkeypatch, capsys):
    # The example uses a path relative to the repository root.
    monkeypatch.chdir(REPO_ROOT)
    namespace: dict = {"__name__": "readme_example"}

    exec(compile(_readme_usage_block(), "README.md:How to use Black Mirror", "exec"), namespace)

    gov = namespace["gov"]
    log = namespace["log"]

    # The example agent entered the mirror, and its actions were logged,
    # starting with the request that put it there.
    obs = log.observations_for("agent-1")
    assert obs, "no observations were recorded"
    assert obs[0].entered_mirror is True
    # Step 4's re-entry actually moved the session back to real access.
    assert gov._session_mode.get("agent-1") == "real"
