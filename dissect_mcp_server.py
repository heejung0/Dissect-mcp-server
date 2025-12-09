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

TARGET_QUERY_BIN = os.getenv("DISSECT_TARGET_QUERY", "/path/to/Dissect-mcp-server/.venv/bin/target-query")
RDUMP_BIN = os.getenv("DISSECT_RDUMP", "/path/to/Dissect-mcp-server/.venv/bin/rdump")
TARGET_FS_BIN = os.getenv("DISSECT_TARGET_FS", "/path/to/Dissect-mcp-server/.venv/bin/target-fs")
ACQUIRE_BIN = os.getenv("DISSECT_ACQUIRE_BIN", "/path/to/Dissect-mcp-server/.venv/bin/acquire")

ACQUIRE_OUTPUT_DIR = os.getenv("DISSECT_ACQUIRE_DIR", "/path/to/Dissect-mcp-server/acquire_output")
DEFAULT_EXTRACT_DIR = os.getenv("DISSECT_EXTRACT_DIR", "/path/to/Dissect-mcp-server/dissect_extracts")

_SYSTEM_PLUGINS = {
    "hostname": "os.windows._os.hostname",
    "os_version": "os.windows._os.version",
    "os_slug": "os.windows._os.os",
    "users": "os.windows._os.users",
    "timezone": "os.windows.locale.timezone",
    "language": "os.windows.locale.language",
    "install_date": "os.windows.generic.install_date",
    "domain": "os.windows.generic.domain",
    "network_interfaces": "os.windows.network.interfaces",
    "network_ips": "os.windows.network.ips",
    "network_macs": "os.windows.network.macs",
}

_ARTIFACT_PLUGINS = {
    "browser": ("browser.history", "Return history for: firefox, chromium, edge, brave, iexplore, chrome (output: records)"),
    "webserver": ("webserver.logs", "Returns log file records from installed webservers. (output: records)"),
    "amcache": ("os.windows.amcache", "Return Amcache"),
    "jumplist": ("os.windows.jumplist", "Return Jumplist"),
    "evtx": ("os.windows.log.evtx.evtx", "Parse Windows Eventlog files (``*.evt``). (output: records)"),
    "prefetch": ("os.windows.prefetch", "Return the content of all prefetch files. (output: records)"),
    "bam": ("os.windows.regf.bam", "Parse bam and dam registry keys. (output: records)"),
    "mru.mstsc": ("os.windows.regf.mru.mstsc", "Return Terminal Server Client MRU data. (output: records)"),
    "mru.opensave": ("os.windows.regf.mru.opensave", "Return the OpenSaveMRU data. (output: records)"),
    "mru.recentdocs": ("os.windows.regf.mru.recentdocs", "Return the RecentDocs data. (output: records)"),
    "regf": ("os.windows.regf.regf", "Return all registry keys and values. (output: records)"),
    "shellbags": ("os.windows.regf.shellbags", "Yields Windows Shellbags. (output: records)"),
    "shimcache": ("os.windows.regf.shimcache", "Return the shimcache. (output: records)"),
    "userassist": ("os.windows.regf.userassist", "Return the UserAssist information for each user. (output: records)"),
    "tasks": ("os.windows.tasks", "Return all scheduled tasks on a Windows system. (output: records)")
}

_TIMELINE_PLUGINS = {
    "mft": "filesystem.ntfs.mft.records",
    "prefetch": "os.windows.prefetch",
    "amcache": "os.windows.amcache.files",
    "jumplist_auto": "os.windows.jumplist.automatic_destination",
    "jumplist_custom": "os.windows.jumplist.custom_destination",
    "evtx": "os.windows.log.evtx.evtx",
}

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

def _filter_plugins(
    plugins: List[Dict[str, Any]],
    keywords: Optional[List[str]],
) -> List[Dict[str, Any]]:
    """
    플러그인 메타데이터를 키워드로 필터링.

    - 검색 대상 필드:
      * name
      * full_name (os.windows.prefetch 등)
      * namespaces (os/windows/prefetch)
      * description
      * output 타입
    - keywords 가 None/빈 리스트면 전체 반환
    """
    if not keywords:
        return plugins

    lowered = [k.lower() for k in keywords]

    def matches(p: Dict[str, Any]) -> bool:
        hay = " ".join(
            [
                p.get("name", ""),
                p.get("full_name", ""),
                " ".join(p.get("namespaces", [])),
                p.get("description", ""),
                (p.get("output") or ""),
            ]
        ).lower()
        return any(k in hay for k in lowered)

    return [p for p in plugins if matches(p)]

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

def _ensure_extract_dir(base: Union[str, Path]) -> Path:
    """
    추출용 기본 디렉터리 생성/보장.

    - base를 절대경로로 변환 후, 존재하지 않으면 mkdir -p
    """
    p = Path(base).expanduser().resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p

def _extract_timestamp(record: Dict[str, Any]) -> Optional[str]:
    """
    각 레코드(dict)에서 timestamp 후보 필드를 휴리스틱으로 추출.

    - 우선순위 키:
      ["timestamp", "time", "datetime", "created", "modified",
       "mtime", "atime", "ctime", "last_write_time", "start_time", "end_time"]
    - 위 키가 없으면, *_time 으로 끝나는 키 중 첫 번째 truthy 값 사용
    - 아무것도 없으면 None
    """
    if not isinstance(record, dict):
        return None

    candidate_keys = [
        "timestamp",
        "time",
        "datetime",
        "created",
        "modified",
        "mtime",
        "atime",
        "ctime",
        "last_write_time",
        "start_time",
        "end_time",
    ]

    for k in candidate_keys:
        if k in record and record[k]:
            return str(record[k])

    for k, v in record.items():
        if k.endswith("_time") and v:
            return str(v)

    return None

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

@mcp.tool()
def run_multiple_plugins(
    image_path: str,
    plugin_keywords: Optional[List[str]] = None,
    max_plugins: int = 0,
    max_rows_per_plugin: int = 0,
) -> Dict[str, Any]:
    """
    키워드 기반 플러그인 일괄 실행 래퍼.

    - list_plugins 결과에서 plugin_keywords 로 필터링
      * 예: ["prefetch", "amcache", "jumplist"]
    - max_plugins > 0 이면 앞에서부터 해당 개수까지만 실행
    - 각 플러그인 실행은 run_single_plugin(...) 사용
    - 결과는 full_name 기준 딕셔너리로 반환
    """
    resolved = _resolve_image(image_path)

    inventory = list_plugins(image_path)
    plugins: List[Dict[str, Any]] = inventory["plugins"]
    plugins = _filter_plugins(plugins, plugin_keywords)

    if max_plugins and len(plugins) > max_plugins:
        plugins = plugins[:max_plugins]

    results: Dict[str, Any] = {
        "image": resolved["original"],
        "target": resolved["target"],
        "merged": resolved["merged"],
        "segments": resolved["segments"],
        "count": len(plugins),
        "filters": {
            "plugin_keywords": plugin_keywords,
            "max_plugins": max_plugins,
            "max_rows_per_plugin": max_rows_per_plugin,
        },
        "results": {},
    }

    for p in plugins:
        full_name = p.get("full_name") or p.get("name")
        try:
            r = run_single_plugin(
                image_path=image_path,
                plugin=full_name,
                max_rows=max_rows_per_plugin,
            )
            results["results"][full_name] = r
        except Exception as e:
            results["results"][full_name] = {
                "error": str(e),
                "meta": p,
            }

    return results

@mcp.tool()
def extract_system_profile(image_path: str) -> Dict[str, Any]:
    """
    OS / Host 기본 프로파일 생성.

    - hostname, OS 버전, 설치 일자, 사용자 목록
    - 도메인, 타임존, 언어
    - 네트워크 인터페이스 / IP / MAC 등
    을 각각의 Dissect 플러그인(_SYSTEM_PLUGINS) 호출로 수집.
    """
    resolved = _resolve_image(image_path)
    profile: Dict[str, Any] = {
        "image": resolved["original"],
        "target": resolved["target"],
        "fields": {},
        "errors": {},
    }

    for field, plugin in _SYSTEM_PLUGINS.items():
        try:
            r = run_single_plugin(image_path=image_path, plugin=plugin, max_rows=100)
            parsed = r.get("parsed")
            profile["fields"][field] = parsed
        except Exception as e:
            profile["errors"][field] = str(e)

    return profile

@mcp.tool()
def search_keyword(
    image_path: str,
    plugin: str,
    search: str,
    max_rows: int = 0,
) -> Dict[str, Any]:
    """
    target-query 출력에 rdump -s 표현식을 적용해 필터링된 결과를 JSON으로 반환.

    쉘에서 사용하던 명령을 그대로 MCP로 감싼 형태:

      - 전체 exe 검색:
          target-query <image> -f walkfs | rdump -s "r.path.suffix=='.exe'" --json

      - 특정 파일명 검색:
          target-query <image> -f walkfs | rdump -s "r.path.name == 'ransom.exe'" --json

    - plugin: target-query 에 사용할 플러그인 이름 (예: "walkfs")
    - search: rdump -s 에 들어갈 표현식 (r.path.* 기반)
    """
    resolved = _resolve_image(image_path)

    p1 = subprocess.Popen(
        [TARGET_QUERY_BIN, resolved["target"], "-f", plugin],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    p2 = subprocess.Popen(
        [RDUMP_BIN, "-s", search, "--json"],
        stdin=p1.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    if p1.stdout is not None:
        p1.stdout.close()

    out, err2 = p2.communicate()
    _, err1 = p1.communicate()

    if p2.returncode != 0:
        return {
            "image": resolved["original"],
            "target": resolved["target"],
            "plugin": plugin,
            "search": search,
            "error": {
                "returncode": p2.returncode,
                "stderr": (err1 or "") + "\n" + (err2 or ""),
            },
        }

    parsed = _parse_query_output(out)
    if isinstance(parsed, list) and max_rows and len(parsed) > max_rows:
        parsed = parsed[:max_rows]

    return {
        "image": resolved["original"],
        "target": resolved["target"],
        "plugin": plugin,
        "search": search,
        "max_rows": max_rows,
        "raw_stdout": out,
        "parsed": parsed,
    }

@mcp.tool()
def list_artifact_plugins() -> Dict[str, Any]:
    """
    _ARTIFACT_PLUGINS에 등록된 아티팩트 플러그인 목록 반환.

    - key: 내부 식별자 (예: "prefetch")
    - plugin: target-query에서 사용할 full plugin name (예: "os.windows.prefetch")
    - description: 사람이 보기 좋은 설명
    """
    artifacts = []
    for key, (plugin, desc) in _ARTIFACT_PLUGINS.items():
        artifacts.append(
            {
                "key": key,
                "plugin": plugin,
                "description": desc,
            }
        )
    return {"artifacts": artifacts}

@mcp.tool()
def run_all_artifact_plugins(
    image_path: str,
    max_rows_per_plugin: int = 0,
) -> Dict[str, Any]:
    """
    _ARTIFACT_PLUGINS에 정의된 모든 플러그인을 실행하고,
    각 플러그인의 parsed 결과를 그대로 반환하는 래퍼.

    - image_path: 디스크 이미지 경로
    - max_rows_per_plugin: 각 플러그인 결과에서 상위 N개까지만 사용 (0이면 제한 없음)
    """
    resolved = _resolve_image(image_path)

    results: Dict[str, Any] = {
        "image": resolved["original"],
        "target": resolved["target"],
        "merged": resolved["merged"],
        "segments": resolved["segments"],
        "max_rows_per_plugin": max_rows_per_plugin,
        "artifacts": {},
    }

    for key, (plugin, desc) in _ARTIFACT_PLUGINS.items():
        entry: Dict[str, Any] = {
            "plugin": plugin,
            "description": desc,
            "count": 0,
            "parsed": None,
            "error": None,
        }
        try:
            r = run_single_plugin(
                image_path=image_path,
                plugin=plugin,
                max_rows=max_rows_per_plugin,
            )
            parsed = r.get("parsed")

            if isinstance(parsed, list):
                entry["count"] = len(parsed)
            elif parsed:
                entry["count"] = 1
            else:
                entry["count"] = 0

            entry["parsed"] = parsed
        except Exception as e:
            entry["error"] = str(e)

        results["artifacts"][key] = entry

    return results

@mcp.tool()
def detect_artifacts_existence(
    image_path: str,
    max_rows_per_artifact: int = 5,
) -> Dict[str, Any]:
    """
    주요 윈도우 아티팩트 존재 여부 빠른 스캐닝.

    - _ARTIFACT_PLUGINS 에 정의된 플러그인들을 각각 max_rows_per_artifact 개수만큼 실행
    - parsed 결과가 비어있지 않으면 exists=True 로 표시
    - 디스크 이미지에 어떤 아티팩트가 실제로 존재하는지 "존재 여부 체크" 용으로 사용
    """
    resolved = _resolve_image(image_path)
    summary: Dict[str, Any] = {
        "image": resolved["original"],
        "target": resolved["target"],
        "artifacts": {},
    }

    for key, (plugin, desc) in _ARTIFACT_PLUGINS.items():
        result: Dict[str, Any] = {
            "plugin": plugin,
            "description": desc,
            "exists": False,
            "count": 0,
            "error": None,
        }
        try:
            r = run_single_plugin(image_path=image_path, plugin=plugin, max_rows=max_rows_per_artifact)
            parsed = r.get("parsed")
            if isinstance(parsed, list):
                result["count"] = len(parsed)
                result["exists"] = len(parsed) > 0
            else:
                if parsed:
                    result["count"] = 1
                    result["exists"] = True
        except Exception as e:
            result["error"] = str(e)
        summary["artifacts"][key] = result

    return summary

@mcp.tool()
def extract_file_or_directory(
    image_path: str,
    fs_path: str,
    output_dir: Optional[str] = None,
    max_list: int = 200,
) -> Dict[str, Any]:
    """
    디스크 이미지 내부 파일/디렉터리 추출(target-fs 래퍼).

    내부적으로 실행되는 명령:
        target-fs <image> cp "<fs_path>" -o <output_dir>

    예시:
        target-fs image.E01 cp "C:/Windows/System32/config" -o ./config_dump

    - image_path: 디스크 이미지 경로 (분할 이미지 가능)
    - fs_path: 이미지 내부 절대 경로 (예: "C:/Windows/System32/config/SAM")
    - output_dir:
        * 지정 시: 해당 디렉터리에 바로 cp
        * 미지정 시: DEFAULT_EXTRACT_DIR/<sanitized_fs_path>_<timestamp>/ 으로 생성
    - max_list: 반환 시 샘플로 보여줄 파일 목록 최대 개수
    """
    resolved = _resolve_image(image_path)
    base_dir = _ensure_extract_dir(output_dir or DEFAULT_EXTRACT_DIR)

    if output_dir is None:
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", fs_path)
        subdir = f"{safe_name}_{int(time.time())}"
        out_dir = base_dir / subdir
        out_dir.mkdir(parents=True, exist_ok=True)
    else:
        out_dir = base_dir

    cmd = [
        TARGET_FS_BIN,
        resolved["target"],
        "cp",
        fs_path,
        "-o",
        str(out_dir),
    ]

    cp = _run(cmd, check=False)
    if cp.returncode != 0:
        return {
            "image": resolved["original"],
            "target": resolved["target"],
            "fs_path": fs_path,
            "output_dir": str(out_dir),
            "error": {
                "returncode": cp.returncode,
                "stdout": cp.stdout,
                "stderr": cp.stderr,
            },
        }

    created_files: List[str] = []
    created_dirs: List[str] = []

    for root, dirs, files in os.walk(out_dir):
        for d in dirs:
            created_dirs.append(str(Path(root) / d))
        for f in files:
            created_files.append(str(Path(root) / f))
            if len(created_files) >= max_list:
                break
        if len(created_files) >= max_list:
            break

    return {
        "image": resolved["original"],
        "target": resolved["target"],
        "fs_path": fs_path,
        "output_dir": str(out_dir),
        "created_files_sample": created_files,
        "created_dirs_sample": created_dirs,
        "note": (
            "Files/directories are copied using target-fs cp. "
            "created_*_sample는 최대 max_list까지만 보여줌"
        ),
    }

@mcp.tool()
def acquire_minimal_artifacts(
    image_path: str,
    output_dir: Optional[str] = None,
    profile: str = "minimal",
    output_type: str = "tar",
) -> Dict[str, Any]:
    """
    acquire를 이용해 기본 아티팩트 컨테이너를 생성하는 래퍼.

    내부적으로 실행되는 명령어:
        acquire -p minimal [image 파일 이름]
        acquire -p <profile> -ot <output_type> -of <OUT_FILE> <resolved_image>

    - image_path:
        * E01, raw, 분할(raw .001/.002...) 모두 지원
        * _resolve_image 로 병합/정규화 후 target 경로 사용
    - output_dir:
        * None 이면 ACQUIRE_OUTPUT_DIR/<이미지이름_타임스탬프>/ 에 결과 생성
        * 지정 시, 해당 디렉터리 하위에 서브디렉터리 없이 바로 파일 생성 기준 디렉터리로 사용
    - profile:
        * acquire --profile(-p)에 해당 (기본: "minimal")
    - output_type:
        * acquire --output-type(-ot)에 해당 (기본: "tar")
    """
    resolved = _resolve_image(image_path)

    base_dir = _ensure_extract_dir(output_dir or ACQUIRE_OUTPUT_DIR)

    img_name = Path(resolved["original"]).name
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", img_name)

    ts = int(time.time())

    out_subdir = base_dir / f"{safe_name}_{ts}"
    out_subdir.mkdir(parents=True, exist_ok=True)

    ext = ".tar" if output_type == "tar" else f".{output_type}"
    out_file = out_subdir / f"{safe_name}{ext}"

    cmd = [
        ACQUIRE_BIN,
        "-p",
        profile,
        "-ot",
        output_type,
        "-of",
        str(out_file),
        resolved["target"],
    ]

    cp = _run(cmd, check=False)

    extracted_dir: Optional[Path] = None
    extract_error: Optional[str] = None
    extracted_files_sample: List[str] = []

    if cp.returncode == 0 and output_type == "tar" and out_file.exists():
        try:
            extracted_dir = out_subdir / "extracted"
            extracted_dir.mkdir(parents=True, exist_ok=True)

            with tarfile.open(out_file, "r") as tf:
                tf.extractall(path=extracted_dir)

            for root, dirs, files in os.walk(extracted_dir):
                for f in files:
                    extracted_files_sample.append(str(Path(root) / f))
                    if len(extracted_files_sample) >= 100:
                        break
                if len(extracted_files_sample) >= 100:
                    break

        except Exception as e:
            extract_error = str(e)

    return {
        "ok": cp.returncode == 0,
        "image": resolved["original"],
        "target": resolved["target"],
        "merged": resolved["merged"],
        "segments": resolved["segments"],
        "profile": profile,
        "output_type": output_type,
        "output_dir": str(out_subdir),
        "output_file": str(out_file),
        "returncode": cp.returncode,
        "stdout_head": "\n".join(cp.stdout.splitlines()[:50]),
        "stderr": cp.stderr,
        "cmd": cmd,
        "extracted_dir": str(extracted_dir) if extracted_dir else None,
        "extracted_files_sample": extracted_files_sample,
        "extract_error": extract_error,
        "note": (
            "acquire -p minimal 로 tar 생성 후, 성공 시 out_dir/extracted/ 에 자동으로 압축 해제"
            "extracted_files_sample 은 최대 100개까지만 표시"
        ),
    }

@mcp.tool()
def build_timeline(
    image_path: str,
    plugins: Optional[List[str]] = None,
    max_rows_per_plugin: int = 5000,
) -> Dict[str, Any]:
    """
    여러 Dissect 타임라인 아티팩트를 묶어서 단일 정렬 타임라인 생성.

    - plugins: 사용할 타임라인 키 리스트
      * None 이면 _TIMELINE_PLUGINS 전체 사용
      * 예: ["mft", "prefetch", "evtx"]
    - 각 플러그인을 run_single_plugin 으로 실행 후, 레코드에서 timestamp 필드 추출
    - timestamp 기준으로 전체 타임라인 정렬
    """
    resolved = _resolve_image(image_path)
    selected = plugins or list(_TIMELINE_PLUGINS.keys())

    timeline: List[Dict[str, Any]] = []
    errors: Dict[str, str] = {}

    for key in selected:
        plugin = _TIMELINE_PLUGINS.get(key)
        if not plugin:
            errors[key] = f"Unknown timeline plugin key: {key}"
            continue

        try:
            r = run_single_plugin(image_path=image_path, plugin=plugin, max_rows=max_rows_per_plugin)
            parsed = r.get("parsed")
            if not isinstance(parsed, list):
                continue

            for rec in parsed:
                if not isinstance(rec, dict):
                    continue
                ts = _extract_timestamp(rec)
                if not ts:
                    continue
                timeline.append(
                    {
                        "source": key,
                        "plugin": plugin,
                        "timestamp": ts,
                        "record": rec,
                    }
                )
        except Exception as e:
            errors[key] = str(e)

    timeline.sort(key=lambda x: x.get("timestamp", ""))

    return {
        "image": resolved["original"],
        "target": resolved["target"],
        "plugins_used": selected,
        "timeline_length": len(timeline),
        "timeline": timeline,
        "errors": errors,
    }

if __name__ == "__main__":
    mcp.run()