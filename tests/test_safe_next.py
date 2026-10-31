"""The frontend's safeNext() must never hand an off-site address to the router.

There is no JavaScript test runner in this project, so the cases live in a plain
Node script and this test runs it (Node 22.6+ strips the TypeScript types).
"""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_safe_next_cases():
    result = subprocess.run(
        ["node", "--experimental-strip-types", "--no-warnings", "tests/frontend/safe_next_cases.mjs"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr or result.stdout
