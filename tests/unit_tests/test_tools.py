"""Unit tests for the Frame tools, with the Frame process replaced."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from langchain_frame import FrameScanTool, FrameVerifyTool, summarize_scan

REPORT = {
    "schema_version": 1,
    "files": [
        {"filename": "/repo/shop/app.py", "vulnerabilities": [], "errors": []},
        {
            "filename": "/repo/shop/services/orders.py",
            "vulnerabilities": [
                {
                    "type": "sql_injection",
                    "severity": "critical",
                    "location": "/repo/shop/services/orders.py",
                    "line": 7,
                    "column": 4,
                    "description": "Tainted data from 'request.args' flows to sql sink",
                    "witness": None,
                    "cwe_id": "CWE-89",
                    "category": "taint",
                    "evidence": "solver-verified",
                    "data_flow": ["shop/app.py:11 -> shop/services/orders.py::for_customer(name)"],
                    "path": "shop/services/orders.py",
                    "fingerprint": "d8cf913f624855bd",
                }
            ],
            "errors": [],
        },
    ],
    "summary": {"files_scanned": 2, "total_vulnerabilities": 1, "critical": 1, "high": 0},
}


class FakeRun:
    def __init__(self, returncode: int = 0, stdout: str = "", report: dict | None = None) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.report = report
        self.calls: list[list[str]] = []

    def __call__(self, cmd: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(cmd)
        if self.report is not None and "-o" in cmd:
            Path(cmd[cmd.index("-o") + 1]).write_text(json.dumps(self.report))
        return subprocess.CompletedProcess(cmd, self.returncode, self.stdout, "boom")


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> Any:
    def install(**kw: Any) -> FakeRun:
        run = FakeRun(**kw)
        monkeypatch.setattr(subprocess, "run", run)
        return run

    return install


def test_scan_command_and_output(fake: Any, tmp_path: Path) -> None:
    run = fake(report=REPORT)
    (tmp_path / "src").mkdir()
    tool = FrameScanTool(root_dir=str(tmp_path), report_dir=str(tmp_path / "reports"))
    out = json.loads(tool.invoke({"path": "src", "min_severity": "high"}))
    cmd = run.calls[0]
    assert cmd[1:3] == ["-m", "frame"]
    assert cmd[3:5] == ["scan", str((tmp_path / "src").resolve())]
    assert cmd[5:7] == ["-f", "json"]
    assert cmd[-4:] == ["--fail-on", "none", "--min-severity", "high"]
    assert out["summary"]["critical"] == 1
    assert out["findings"] == [
        {
            "type": "sql_injection",
            "severity": "critical",
            "cwe_id": "CWE-89",
            "path": "shop/services/orders.py",
            "line": 7,
            "description": "Tainted data from 'request.args' flows to sql sink",
            "category": "taint",
            "evidence": "solver-verified",
            "data_flow": ["shop/app.py:11 -> shop/services/orders.py::for_customer(name)"],
            "fingerprint": "d8cf913f624855bd",
        }
    ]
    assert Path(out["report"]).parent == tmp_path / "reports"


def test_scan_extra_args(fake: Any, tmp_path: Path) -> None:
    run = fake(report=REPORT)
    FrameScanTool(extra_args=["--sca"], report_dir=str(tmp_path)).invoke({"path": str(tmp_path)})
    assert run.calls[0][-1] == "--sca"


def test_scan_custom_command(fake: Any, tmp_path: Path) -> None:
    run = fake(report=REPORT)
    FrameScanTool(frame_command=["frame"], report_dir=str(tmp_path)).invoke({"path": str(tmp_path)})
    assert run.calls[0][:2] == ["frame", "scan"]


def test_scan_refuses_path_outside_root(fake: Any, tmp_path: Path) -> None:
    run = fake(report=REPORT)
    tool = FrameScanTool(root_dir=str(tmp_path))
    out = tool.invoke({"path": "../../etc"})
    assert "outside the allowed directory" in out
    assert run.calls == []


def test_scan_missing_path(fake: Any, tmp_path: Path) -> None:
    fake(report=REPORT)
    out = FrameScanTool(root_dir=str(tmp_path)).invoke({"path": "nope"})
    assert "does not exist" in out


def test_scan_path_is_never_a_flag(fake: Any, tmp_path: Path) -> None:
    run = fake(report=REPORT)
    (tmp_path / "--ai").mkdir()
    FrameScanTool(root_dir=str(tmp_path), report_dir=str(tmp_path)).invoke({"path": "--ai"})
    assert run.calls[0][4].startswith("/")


def test_scan_could_not_run(fake: Any, tmp_path: Path) -> None:
    fake(returncode=2)
    out = FrameScanTool(report_dir=str(tmp_path)).invoke({"path": str(tmp_path)})
    assert "Frame could not run (exit 2)" in out


def test_frame_not_installed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def missing(*a: Any, **kw: Any) -> None:
        raise FileNotFoundError("frame")

    monkeypatch.setattr(subprocess, "run", missing)
    out = FrameScanTool(report_dir=str(tmp_path)).invoke({"path": str(tmp_path)})
    assert "pip install 'frame-security[scan]'" in out


def test_summarize_truncates() -> None:
    many = {"files": [{"vulnerabilities": [{"type": f"t{i}"} for i in range(5)]}], "summary": {}}
    out = summarize_scan(many, "r.json", max_findings=2)
    assert [f["type"] for f in out["findings"]] == ["t0", "t1"]
    assert out["findings_not_shown"] == 3


def test_summarize_keeps_file_errors() -> None:
    data = {"files": [{"filename": "a.py", "vulnerabilities": [], "errors": ["parse"]}]}
    assert summarize_scan(data, "r.json")["errors"] == [{"file": "a.py", "errors": ["parse"]}]


VERIFY = {
    "schema_version": 1,
    "results": [{"fingerprint": "d8cf913f624855bd", "status": "fixed"}],
    "summary": {"fixed": 1},
}


def test_verify_all_fixed(fake: Any, tmp_path: Path) -> None:
    report = tmp_path / "r.json"
    report.write_text("{}")
    run = fake(returncode=0, stdout=json.dumps(VERIFY))
    out = json.loads(
        FrameVerifyTool().invoke({"report": str(report), "fingerprints": ["d8cf913f624855bd"]})
    )
    assert run.calls[0][3:] == ["verify", str(report), "-f", "json", "--id", "d8cf913f624855bd"]
    assert out["all_fixed"] is True
    assert out["results"][0]["status"] == "fixed"


def test_verify_still_present(fake: Any, tmp_path: Path) -> None:
    report = tmp_path / "r.json"
    report.write_text("{}")
    present = {**VERIFY, "results": [{"status": "present"}], "summary": {"present": 1}}
    fake(returncode=1, stdout=json.dumps(present))
    out = json.loads(FrameVerifyTool().invoke({"report": str(report)}))
    assert out["all_fixed"] is False


def test_verify_rejects_bad_fingerprint(fake: Any, tmp_path: Path) -> None:
    report = tmp_path / "r.json"
    report.write_text("{}")
    run = fake(returncode=0, stdout="{}")
    out = FrameVerifyTool().invoke({"report": str(report), "fingerprints": ["--ai"]})
    assert "not a Frame fingerprint" in out
    assert run.calls == []


def test_verify_missing_report(fake: Any, tmp_path: Path) -> None:
    fake(returncode=0, stdout="{}")
    out = FrameVerifyTool().invoke({"report": str(tmp_path / "none.json")})
    assert "not a report file" in out


def test_verify_could_not_run(fake: Any, tmp_path: Path) -> None:
    report = tmp_path / "r.json"
    report.write_text("{}")
    fake(returncode=2, stdout="")
    assert "could not run" in FrameVerifyTool().invoke({"report": str(report)})
