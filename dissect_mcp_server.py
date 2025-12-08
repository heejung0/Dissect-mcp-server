import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("dissect-MCP")

TARGET_QUERY_BIN = os.getenv("DISSECT_TARGET_QUERY")
RDUMP_BIN = os.getenv("DISSECT_RDUMP")
TARGET_FS_BIN = os.getenv("DISSECT_TARGET_FS")
ACQUIRE_BIN = os.getenv("DISSECT_ACQUIRE_BIN")

ACQUIRE_OUTPUT_DIR = os.getenv("DISSECT_ACQUIRE_DIR")
DEFAULT_EXTRACT_DIR = os.getenv("DISSECT_EXTRACT_DIR")

class DissectError(RuntimeError):
    """Dissect 관련 외부 명령 실패 시 사용하는 예외."""

