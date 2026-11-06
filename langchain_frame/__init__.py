"""LangChain tools for Frame, the static analysis security scanner."""

from importlib import metadata

from langchain_frame.tools import FrameScanTool, FrameVerifyTool, summarize_scan

try:
    __version__ = metadata.version(__package__)
except metadata.PackageNotFoundError:
    __version__ = ""
del metadata

__all__ = ["FrameScanTool", "FrameVerifyTool", "summarize_scan", "__version__"]
