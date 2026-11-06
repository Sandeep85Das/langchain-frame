"""LangChain standard unit tests for the Frame tools."""

from __future__ import annotations

from typing import Any

from langchain_tests.unit_tests import ToolsUnitTests

from langchain_frame import FrameScanTool, FrameVerifyTool


class TestFrameScanToolUnit(ToolsUnitTests):
    @property
    def tool_constructor(self) -> type[FrameScanTool]:
        return FrameScanTool

    @property
    def tool_constructor_params(self) -> dict[str, Any]:
        return {}

    @property
    def tool_invoke_params_example(self) -> dict[str, Any]:
        return {"path": "src/", "min_severity": "high"}


class TestFrameVerifyToolUnit(ToolsUnitTests):
    @property
    def tool_constructor(self) -> type[FrameVerifyTool]:
        return FrameVerifyTool

    @property
    def tool_constructor_params(self) -> dict[str, Any]:
        return {}

    @property
    def tool_invoke_params_example(self) -> dict[str, Any]:
        return {"report": "/tmp/langchain-frame/frame-scan-0.json"}
