import os
import json
import time
import shutil
import subprocess
import re
import tarfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

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

def _run(
    cmd: List[str],
    cwd: Optional[Path] = None,
    timeout: int = 0,
    check: bool = True,
) -> subprocess.CompletedProcess:
    """
    공통 subprocess.run 래퍼.

    - stdout/stderr 를 텍스트(str)로 반환
    - cwd 지정 가능
    - timeout=0 이면 제한 없음
    - check=True 이면 returncode != 0 일 때 DissectError 발생
    """
    cp = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=str(cwd) if cwd else None,
        timeout=timeout or None,
    )
    if check and cp.returncode != 0:
        raise DissectError(
            f"Command failed: {' '.join(cmd)}\n"
            f"Return code: {cp.returncode}\n"
            f"STDERR:\n{cp.stderr}"
        )
    return cp


def _resolve_image(image_path: str) -> Dict[str, Any]:
    """
    디스크 이미지 경로 정규화 및 분할(raw) 이미지 병합 처리.

    - 입력: image_path (예: SCHARDT.001, 2023_KDFS.E01 등)
    - raw 분할 이미지(.001, .002 ...) 이면서 EWF(.E01, .EX01 등)가 아닌 경우:
      * 디렉터리 내 동일 prefix + .[0-9][0-9][0-9] 패턴을 모두 찾고
      * <stem>.raw 로 병합(SCHARDT.001 → SCHARDT.raw)
    - EWF 계열(.E01, .EX01 등)은 병합 없이 그대로 사용
    - 반환:
      {
        "original": 원본 경로(str),
        "target": 실제 사용될 경로(str),  (병합된 .raw 또는 원본)
        "segments": 세그먼트 목록(str 리스트),
        "merged": 병합 여부(bool)
      }
    """
    p = Path(image_path).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(f"Image not found: {p}")

    segments: List[Path] = []
    merged = False
    merged_path: Optional[Path] = None

    m = re.search(r"\.([0-9]{3})$", p.name)
    if m and p.suffix.lower() not in {".e01", ".e02", ".ex01"}:
        stem = p.name[:-4]
        segs = sorted(p.parent.glob(stem + ".[0-9][0-9][0-9]"))
        if len(segs) > 1:
            segments = list(segs)
            merged_path = p.parent / f"{stem}.raw"
            if not merged_path.exists():
                merged_path.parent.mkdir(parents=True, exist_ok=True)
                with merged_path.open("wb") as out:
                    for seg in segments:
                        with seg.open("rb") as f:
                            shutil.copyfileobj(f, out)
            merged = True

    if not segments:
        segments = [p]

    return {
        "original": str(p),
        "target": str(merged_path or p),
        "segments": [str(s) for s in segments],
        "merged": merged,
    }

def _parse_plugin_listing(text: str) -> List[Dict[str, Any]]:
    """
    `target-query <image> -l -q` 출력 파싱 → 평탄화된 플러그인 리스트 생성.

    Dissect의 plugin tree 구조 예:
        os:
          windows:
            prefetch:
              prefetch - Windows Prefetch files (output: records)
    """
    plugins: List[Dict[str, Any]] = []
    stack: Dict[int, str] = {}

    for line in text.splitlines():
        if not line.strip():
            continue
        if line.strip().startswith("Available plugins"):
            continue
        if line.strip().startswith("Failed to load"):
            continue

        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()

        if stripped.endswith(":") and " - " not in stripped:
            name = stripped[:-1]
            stack[indent] = name
            for k in list(stack.keys()):
                if k > indent:
                    del stack[k]
            continue

        if " - " in stripped:
            plugin_name, rest = stripped.split(" - ", 1)

            output_type = None
            m_out = re.search(r"\(output:\s*([^)]*)\)", rest)
            if m_out:
                output_type = m_out.group(1).strip()
                description = rest[: m_out.start()].strip()
            else:
                description = rest.strip()

            namespaces = [v for k, v in sorted(stack.items())]

            base = ".".join(namespaces)
            last_ns = namespaces[-1] if namespaces else ""

            plugin_name = plugin_name.strip()

            if last_ns:
                if plugin_name == last_ns:
                    full_name = base
                elif plugin_name.startswith(last_ns):
                    full_name = base + plugin_name[len(last_ns):]
                else:
                    full_name = base + "." + plugin_name
            else:
                full_name = plugin_name

            plugins.append(
                {
                    "name": plugin_name,
                    "namespaces": namespaces,
                    "description": description,
                    "output": output_type,
                    "full_name": full_name,
                }
            )

    return plugins

def _parse_query_output(raw: str) -> Any:
    """
    target-query / rdump 출력 → JSON-friendly 구조 변환.

    1. json.loads 시도
    2. 실패 시, non-empty line 리스트로 반환
    """
    s = raw.strip()
    if not s:
        return []

    try:
        return json.loads(s)
    except Exception:
        pass

    return [ln for ln in s.splitlines() if ln.strip()]

@mcp.tool()
def disk_image_info(image_path: str) -> Dict[str, Any]:
    """
    디스크 이미지 기본 정보 확인 (분할 이미지 병합 여부 포함).

    - _resolve_image 로 raw 스플릿 병합 여부 계산
    - 병합/세그먼트 목록, 파일 크기, 확장자 등 메타 정보 반환
    """
    resolved = _resolve_image(image_path)
    target = Path(resolved["target"])
    stat = target.stat()

    return {
        "original_path": resolved["original"],
        "resolved_path": str(target),
        "merged": resolved["merged"],
        "segments": resolved["segments"],
        "size_bytes": stat.st_size,
        "extension": target.suffix.lower(),
    }

@mcp.tool()
def list_plugins(image_path: str) -> Dict[str, Any]:
    """
    디스크 이미지에서 사용 가능한 Dissect 플러그인 목록 조회.

    내부적으로:
      target-query <image> -l -q

    를 실행하여 계층형 플러그인 리스트를 가져온 뒤,
    _parse_plugin_listing 으로 평탄화된 구조로 변환.
    """
    resolved = _resolve_image(image_path)

    cmd = [TARGET_QUERY_BIN, resolved["target"], "-l", "-q"]
    cp = _run(cmd)
    plugins = _parse_plugin_listing(cp.stdout)

    return {
        "image": resolved["original"],
        "target": resolved["target"],
        "merged": resolved["merged"],
        "segments": resolved["segments"],
        "plugins": plugins,
    }

@mcp.tool()
def run_single_plugin(
    image_path: str,
    plugin: str,
    max_rows: int = 0,
) -> Dict[str, Any]:
    """
    단일 Dissect 플러그인 실행(target-query).

    - plugin: full name (예: "os.windows.prefetch")
      * list_plugins 의 full_name 사용 권장
    - 시도 순서:
      1) target-query <image> -f <plugin> --json
      2) 실패하면 --json 없이 다시 실행 후 일반 텍스트 파싱

    - max_rows > 0 이면 리스트형 결과를 상위 max_rows 개까지만 자름
    """
    resolved = _resolve_image(image_path)

    cmd = [TARGET_QUERY_BIN, resolved["target"], "-f", plugin, "--json"]
    cp = _run(cmd, check=False)

    if cp.returncode != 0:
        cmd_nojson = [TARGET_QUERY_BIN, resolved["target"], "-f", plugin]
        cp = _run(cmd_nojson)

    parsed = _parse_query_output(cp.stdout)

    if isinstance(parsed, list) and max_rows and len(parsed) > max_rows:
        parsed = parsed[:max_rows]

    return {
        "image": resolved["original"],
        "target": resolved["target"],
        "plugin": plugin,
        "max_rows": max_rows,
        "raw_stdout": cp.stdout,
        "parsed": parsed,
    }