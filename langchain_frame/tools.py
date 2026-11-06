"""LangChain tools for Frame, the static analysis security scanner.

Both tools run Frame's command line (https://github.com/lambdasec/frame):

- `FrameScanTool` runs `frame scan <path> -f json` and returns the findings.
- `FrameVerifyTool` runs `frame verify <report> -f json` after a change, to check
  whether each earlier finding is fixed, still present, suppressed or uncertain.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any, Literal

from langchain_core.callbacks import CallbackManagerForToolRun
from langchain_core.tools import BaseTool, ToolException
from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]

FINDING_FIELDS = (
    "type",
    "severity",
    "cwe_id",
    "path",
    "line",
    "description",
    "category",
    "evidence",
    "data_flow",
    "fingerprint",
)
_FINGERPRINT = re.compile(r"^[0-9a-fA-F]{8,64}$")


def _default_command() -> list[str]:
    return [sys.executable, "-m", "frame"]


class _FrameToolBase(BaseTool):
    frame_command: list[str] = Field(default_factory=_default_command)
    """How to start Frame. Defaults to `python -m frame` with the current interpreter,
    which is where `frame-security` is installed alongside this package."""
    root_dir: str | None = None
    """If set, relative paths are resolved against this directory and any path
    outside it is refused."""
    timeout: float = 900.0
    """Seconds before the Frame process is stopped."""
    handle_tool_error: bool | str | Any = True

    def _resolve(self, path: str, *, must_exist: bool = True) -> Path:
        base = Path(self.root_dir).resolve() if self.root_dir else Path.cwd()
        target = (base / os.path.expanduser(path)).resolve()
        if self.root_dir and target != base and base not in target.parents:
            raise ToolException(f"{path} is outside the allowed directory {base}")
        if must_exist and not target.exists():
            raise ToolException(f"{path} does not exist")
        return target

    def _run_frame(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                [*self.frame_command, *args],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except FileNotFoundError as e:
            raise ToolException(
                "Frame is not installed. Install it with: pip install 'frame-security[scan]'"
            ) from e
        except subprocess.TimeoutExpired as e:
            raise ToolException(f"Frame did not finish within {self.timeout:.0f} seconds") from e

    @staticmethod
    def _failure(proc: subprocess.CompletedProcess[str]) -> ToolException:
        detail = (proc.stderr or proc.stdout or "").strip()[-2000:]
        return ToolException(f"Frame could not run (exit {proc.returncode}): {detail}")


class FrameScanInput(BaseModel):
    """Input for `FrameScanTool`."""

    path: str = Field(description="File or directory to scan.")
    min_severity: Severity | None = Field(
        default=None,
        description="Report only findings at or above this severity. Default: low.",
    )


class FrameScanTool(_FrameToolBase):
    """Scan code for vulnerabilities with Frame.

    Runs `frame scan <path> -f json` and returns a JSON string with the scan
    summary, the findings (type, severity, CWE, file, line, description, evidence
    level, data flow and fingerprint) and `report`, the path of the full JSON
    report. Pass `report` to `FrameVerifyTool` after a fix.

    Setup:
        ```bash
        pip install -U langchain-frame
        ```

    Instantiate:
        ```python
        from langchain_frame import FrameScanTool

        tool = FrameScanTool(root_dir="/path/to/repo")
        ```

    Invoke:
        ```python
        tool.invoke({"path": "src/", "min_severity": "high"})
        ```
    """

    name: str = "frame_scan"
    description: str = (
        "Scan a file or directory for security vulnerabilities with Frame, a static "
        "analyzer that follows attacker-controlled data through the code. Input: a "
        "path, and optionally min_severity (critical, high, medium, low or info). "
        "Returns JSON with a summary, the findings, and `report`, a file path to pass "
        "to frame_verify after fixing the code."
    )
    args_schema: type[BaseModel] = FrameScanInput

    extra_args: list[str] = Field(default_factory=list)
    """Extra `frame scan` flags set by the developer, for example `["--sca"]` or
    `["--iac"]`. See `frame scan --help`."""
    report_dir: str | None = None
    """Where full JSON reports are written. Default: a temporary directory."""
    max_findings: int = 50
    """Most findings returned to the model. The full list stays in the report."""

    def _report_path(self) -> Path:
        directory = Path(self.report_dir or Path(tempfile.gettempdir()) / "langchain-frame")
        directory.mkdir(parents=True, exist_ok=True)
        return directory / f"frame-scan-{uuid.uuid4().hex[:12]}.json"

    def _run(
        self,
        path: str,
        min_severity: Severity | None = None,
        run_manager: CallbackManagerForToolRun | None = None,
    ) -> str:
        target = self._resolve(path)
        report = self._report_path()
        args = ["scan", str(target), "-f", "json", "-o", str(report), "--fail-on", "none"]
        if min_severity:
            args += ["--min-severity", min_severity]
        args += self.extra_args
        proc = self._run_frame(args)
        if proc.returncode not in (0, 1) or not report.exists():
            raise self._failure(proc)
        data = json.loads(report.read_text())
        return json.dumps(summarize_scan(data, str(report), self.max_findings))


def summarize_scan(data: dict[str, Any], report: str, max_findings: int = 50) -> dict[str, Any]:
    """Reduce a `frame scan -f json` report to what an agent needs."""
    findings = [
        {k: v for k, v in finding.items() if k in FINDING_FIELDS and v not in (None, [], "")}
        for file in data.get("files", [])
        for finding in file.get("vulnerabilities", [])
    ]
    errors = [
        {"file": file.get("filename"), "errors": file["errors"]}
        for file in data.get("files", [])
        if file.get("errors")
    ]
    out: dict[str, Any] = {
        "report": report,
        "summary": data.get("summary", {}),
        "findings": findings[:max_findings],
    }
    if len(findings) > max_findings:
        out["findings_not_shown"] = len(findings) - max_findings
    if errors:
        out["errors"] = errors
    return out


class FrameVerifyInput(BaseModel):
    """Input for `FrameVerifyTool`."""

    report: str = Field(description="Path of the JSON report returned by frame_scan.")
    fingerprints: list[str] | None = Field(
        default=None,
        description="Check only these findings, by fingerprint. Default: all findings.",
    )


class FrameVerifyTool(_FrameToolBase):
    """Check whether earlier Frame findings are fixed.

    Runs `frame verify <report> -f json`, which re-scans the files behind each
    finding in a `FrameScanTool` report. Each finding comes back as `fixed`,
    `file_removed`, `present`, `suppressed`, `uncertain` or `unverifiable`, and
    `all_fixed` is true only when every checked finding is fixed or its file
    removed. Moving or silencing a finding does not count as fixing it.

    Instantiate:
        ```python
        from langchain_frame import FrameVerifyTool

        verify = FrameVerifyTool()
        ```

    Invoke:
        ```python
        verify.invoke({"report": "/tmp/langchain-frame/frame-scan-....json"})
        ```
    """

    name: str = "frame_verify"
    description: str = (
        "After changing code, check whether the findings from an earlier frame_scan "
        "are fixed. Input: `report`, the report path frame_scan returned, and "
        "optionally `fingerprints` to check only some findings. Returns each "
        "finding's status (fixed, file_removed, present, suppressed, uncertain or "
        "unverifiable) and `all_fixed`."
    )
    args_schema: type[BaseModel] = FrameVerifyInput

    def _run(
        self,
        report: str,
        fingerprints: list[str] | None = None,
        run_manager: CallbackManagerForToolRun | None = None,
    ) -> str:
        report_path = Path(os.path.expanduser(report)).resolve()
        if not report_path.is_file():
            raise ToolException(f"{report} is not a report file")
        args = ["verify", str(report_path), "-f", "json"]
        for fp in fingerprints or []:
            if not _FINGERPRINT.match(fp):
                raise ToolException(f"{fp!r} is not a Frame fingerprint")
            args += ["--id", fp]
        proc = self._run_frame(args)
        if proc.returncode not in (0, 1):
            raise self._failure(proc)
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as e:
            raise self._failure(proc) from e
        data["all_fixed"] = proc.returncode == 0
        return json.dumps(data)
