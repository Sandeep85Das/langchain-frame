"""End-to-end tests that run Frame itself on a small vulnerable app.

Frame runs locally and offline; no API key is needed.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from langchain_tests.integration_tests import ToolsIntegrationTests

from langchain_frame import FrameScanTool, FrameVerifyTool

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture
def app(tmp_path: Path) -> Path:
    dest = tmp_path / "app"
    shutil.copytree(FIXTURE, dest)
    return dest


def test_scan_then_fix_then_verify(app: Path, tmp_path: Path) -> None:
    scan = FrameScanTool(root_dir=str(app), report_dir=str(tmp_path / "reports"))
    out = json.loads(scan.invoke({"path": "."}))
    sqli = [f for f in out["findings"] if f["cwe_id"] == "CWE-89"]
    assert len(sqli) == 1
    assert sqli[0]["path"] == "shop/services/orders.py"
    assert sqli[0]["evidence"] == "solver-verified"

    verify = FrameVerifyTool()
    before = json.loads(verify.invoke({"report": out["report"]}))
    assert before["all_fixed"] is False

    orders = app / "shop" / "services" / "orders.py"
    orders.write_text(
        orders.read_text().replace(
            '"SELECT * FROM orders WHERE customer = \'" + name.strip() + "\'"',
            '"SELECT * FROM orders WHERE customer = ?", (name.strip(),)',
        )
    )
    after = json.loads(
        verify.invoke({"report": out["report"], "fingerprints": [sqli[0]["fingerprint"]]})
    )
    assert after["all_fixed"] is True
    assert after["results"][0]["status"] == "fixed"


def test_clean_scan(app: Path, tmp_path: Path) -> None:
    out = json.loads(
        FrameScanTool(report_dir=str(tmp_path)).invoke({"path": str(app / "shop" / "app.py")})
    )
    assert "summary" in out


class TestFrameScanToolIntegration(ToolsIntegrationTests):
    @property
    def tool_constructor(self) -> type[FrameScanTool]:
        return FrameScanTool

    @property
    def tool_constructor_params(self) -> dict[str, Any]:
        return {"root_dir": str(FIXTURE)}

    @property
    def tool_invoke_params_example(self) -> dict[str, Any]:
        return {"path": "shop"}
