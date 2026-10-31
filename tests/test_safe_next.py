"""Frontend URL guards: safeNext() (login redirect) and safeHttpUrl() (external links).

safeNext() must never hand an off-site address to the router; safeHttpUrl()
must never let a javascript:/data: link reach an href.

There is no JavaScript test runner in this project, so the cases live in a plain
Node script and this test runs it (Node 22.6+ strips the TypeScript types).
"""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
@pytest.mark.parametrize("script", ["safe_next_cases.mjs", "safe_url_cases.mjs"])
def test_frontend_url_guards(script):
    result = subprocess.run(
        ["node", "--experimental-strip-types", "--no-warnings", f"tests/frontend/{script}"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr or result.stdout
