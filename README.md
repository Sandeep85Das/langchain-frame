# langchain-frame

LangChain tools for [Frame](https://github.com/lambdasec/frame), a static analysis
security scanner. Frame follows attacker-controlled data through code, across functions
and files, and checks each finding with a solver. It runs locally and needs no API key.

| tool | runs | returns |
|---|---|---|
| `FrameScanTool` (`frame_scan`) | `frame scan <path> -f json` | the findings, a summary, and the path of the full report |
| `FrameVerifyTool` (`frame_verify`) | `frame verify <report> -f json` | each earlier finding's status after a change, and `all_fixed` |

Together they let an agent scan code, change it, and check that the change removed the
finding rather than moving or hiding it.

## Installation

```bash
pip install -U langchain-frame
```

This installs `frame-security[scan]`, which provides the `frame` command. Frame scans
Python, JavaScript/TypeScript, Java, C# and C/C++.

## Scan

```python
import json

from langchain_frame import FrameScanTool

scan = FrameScanTool(root_dir="/path/to/repo")
result = json.loads(scan.invoke({"path": "src/", "min_severity": "high"}))

result["summary"]   # {"files_scanned": 4, "total_vulnerabilities": 1, "critical": 1, ...}
result["findings"]  # [{"type": "sql_injection", "severity": "critical", "cwe_id": "CWE-89",
                    #   "path": "shop/services/orders.py", "line": 7,
                    #   "description": "Tainted data from 'request.args' flows to sql sink",
                    #   "evidence": "solver-verified",
                    #   "data_flow": ["shop/app.py:11 -> shop/services/orders.py::for_customer(name)"],
                    #   "fingerprint": "..."}]
result["report"]    # path of the full JSON report, for frame_verify
```

`evidence` is Frame's own measure of how strongly a finding is shown, weakest first:
`matched`, `llm-detected`, `llm-verified`, `data-flow`, `solver-verified`,
`exploit-confirmed`.

## Check a fix

```python
from langchain_frame import FrameVerifyTool

verify = FrameVerifyTool()
status = json.loads(verify.invoke({"report": result["report"]}))

status["results"]    # [{"fingerprint": "...", "status": "fixed", ...}]
status["all_fixed"]  # True only when every checked finding is fixed or its file removed
```

A status is one of `fixed`, `file_removed`, `present`, `suppressed`, `uncertain` or
`unverifiable`. Pass `fingerprints=[...]` to check only some findings.

## In an agent

```python
from langchain.agents import create_agent
from langchain_frame import FrameScanTool, FrameVerifyTool

root = "/path/to/repo"
agent = create_agent(
    "anthropic:claude-opus-5-5",
    tools=[FrameScanTool(root_dir=root), FrameVerifyTool(root_dir=root), *file_editing_tools],
    system_prompt=(
        "Scan the repository with frame_scan, fix the critical findings, "
        "then confirm each fix with frame_verify."
    ),
)
```

## Options

Both tools take:

| argument | default | |
|---|---|---|
| `root_dir` | none | resolve relative paths against this directory and refuse paths outside it |
| `frame_command` | `[sys.executable, "-m", "frame"]` | how to start Frame, for example `["frame"]` |
| `timeout` | `900` | seconds before the Frame process is stopped |

`FrameScanTool` also takes:

| argument | default | |
|---|---|---|
| `extra_args` | `[]` | more `frame scan` flags, for example `["--sca"]` for vulnerable dependencies or `["--iac"]` for infrastructure files |
| `report_dir` | a temporary directory | where full JSON reports are written |
| `max_findings` | `50` | most findings returned to the model; the report keeps them all |

The model only chooses the path and the minimum severity. Flags such as `--ai`, which
sends code to a model you configure for Frame, can only be turned on by the developer
through `extra_args`. Frame's settings in `.frame.toml` or `[tool.frame]` in
`pyproject.toml` apply as usual; see the
[Frame usage docs](https://github.com/lambdasec/frame/blob/main/docs/usage.md).

Errors, such as a missing path or a scan Frame could not run, are returned to the
model as the tool result instead of raising.

## Development

```bash
uv sync --all-groups
make test               # unit tests, Frame process mocked
make integration_tests  # runs Frame on tests/fixtures, offline
make lint
```

`tests/fixtures` is a two-file Flask app with a deliberate SQL injection, used by the
integration tests.

## License

Apache-2.0, the same as Frame.
