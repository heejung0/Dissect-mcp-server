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
    "amcache": "os.windows.amcache",
    "jumplist_auto": "os.windows.jumplist.automatic_destination",
    "jumplist_custom": "os.windows.jumplist.custom_destination",
    "shellbags": "os.windows.regf.shellbags",
    "userassist": "os.windows.regf.userassist",
    "bam": "os.windows.regf.bam",
    "mru_recentdocs": "os.windows.regf.mru.recentdocs",
    "mru_opensave": "os.windows.regf.mru.opensave",
    "evtx": "os.windows.log.evtx.evtx",
    "browser_history": "browser.history",
}

_DROP_ALWAYS = {
    "_source",
    "_classification",
    "_generated",
    "_version",
    "_type",
    "_recorddescriptor",
}

_EVTX_NOISE_SOURCES = {
    "LoadPerf",
    "EAPOL",
    "WmdmPmSp",
}

_MFT_SYSTEM_PREFIXES = (
    r"c:\\$mft",
    r"c:\\$mftmirr",
    r"c:\\$logfile",
    r"c:\\$bitmap",
)

_MFT_USE_TS_TYPES = {"B", "M"}

_SUSPICIOUS_PS_KEYWORDS = [
    "-enc",
    "-encodedcommand",
    "frombase64string",
    "invoke-webrequest",
    "invoke-expression",
    " iwr ",
    " iex ",
    "new-object net.webclient",
    "downloadstring(",
    "add-mppreference",
    "set-mppreference",
    "bypass",
    "unrestricted",
    "-executionpolicy",
    "netsh advfirewall",
    "schtasks ",
    "reg add ",
    "invoke-command",
    "enter-pssession",
    "windowstyle hidden",
    "-w hidden",
    "-nop",
    "-noni",
    "bitsadmin",
    "certutil",
    "http:",
    "https:",
    "import-module",
]

_SUSPICIOUS_CHILD_PROCESSES = (
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "powershell.exe",
    "pwsh.exe"
)

_KNOWN_GOOD_CHILD_REGEX = (
    r"\\winlogbeat\.exe$",
)

_PS_CORE_EVENT_IDS = { 4103, 4104, 4105, 4106, 400, 403, 600, 800 }

def _get_lower(rec: dict, *keys: str) -> str:
    for k in keys:
        v = rec.get(k)
        if v:
            return str(v).lower()
    return ""

def _get_int(rec: dict, *keys: str) -> int:
    for k in keys:
        v = rec.get(k)
        if v is None:
            continue
        try:
            return int(v)
        except Exception:
            pass
    return 0

def _is_interesting_powershell(rec: dict) -> bool:
    provider = _get_lower(rec, "Provider_Name", "ProviderName", "Provider")
    event_id = _get_int(rec, "EventID", "EventId", "event_id")

    if provider in ("microsoft-windows-powershell", "windows powershell"):
        if event_id in _PS_CORE_EVENT_IDS:
            return True
        return False

    if provider not in ("microsoft-windows-sysmon", "microsoft-windows-security-auditing"):
        return False

    if event_id not in (1, 4688):
        return False

    image = _get_lower(rec, "Image", "Process_Name", "NewProcessName", "NewProcess_Name", "ProcessName", "ApplicationName")
    parent_image = _get_lower(rec, "ParentImage", "ParentProcessName", "CreatorProcessName", "ParentProcess", "ParentProcessPath")
    cmdline = _get_lower(rec, "CommandLine", "ProcessCommandLine", "NewProcessCommandLine", "ParentCommandLine", "CommandLineText", "Process_Command_Line")

    parent_is_ps = ("powershell.exe" in parent_image) or ("pwsh.exe" in parent_image)
    image_is_ps  = ("powershell.exe" in image) or ("pwsh.exe" in image)

    parent_is_cmd = "cmd.exe" in parent_image
    image_is_cmd  = "cmd.exe" in image

    has_shell = (
        parent_is_ps or image_is_ps or ("powershell.exe" in cmdline) or ("pwsh.exe" in cmdline) or
        parent_is_cmd or image_is_cmd or ("cmd.exe" in cmdline)
    )

    if not has_shell:
        if image.endswith(("iexplore.exe", "msedge.exe", "chrome.exe", "firefox.exe")) and re.search(r"https?://", cmdline):
            return True

        writable_markers = ("\\appdata\\local\\temp\\","\\appdata\\roaming\\","\\users\\public\\","\\downloads\\")
        in_writable = any(m in image for m in writable_markers)

        parent_base = parent_image.split("\\")[-1] if parent_image else ""
        doc_openers = {"excel.exe","winword.exe","powerpnt.exe","outlook.exe","acrord32.exe","acrord64.exe","chrome.exe","msedge.exe","iexplore.exe","firefox.exe"}

        image_base = image.split("\\")[-1] if image else ""
        lolbins = {"cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","schtasks.exe","at.exe"}

        if parent_base in doc_openers and (image_base in lolbins or in_writable):
            return True

        if in_writable and image_base in lolbins:
            return True

        return False

    if any(k in cmdline for k in _SUSPICIOUS_PS_KEYWORDS):
        return True

    parent_is_shell = parent_is_ps or parent_is_cmd

    if parent_is_shell:
        for good in _KNOWN_GOOD_CHILD_REGEX:
            if image and re.search(good, image):
                return False

        for bad_child in _SUSPICIOUS_CHILD_PROCESSES:
            if image.endswith(bad_child):
                return True

        if image.endswith("cmd.exe") and re.search(r"(^|[\s\"\\])/c([\s\"\\]|$)", cmdline):
            return True

    return True

def _cleanup_common(rec: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in rec.items() if k not in _DROP_ALWAYS}

def _cleanup_parsed(parsed: Any) -> Any:
    if isinstance(parsed, list):
        cleaned: list[Any] = []
        for item in parsed:
            if isinstance(item, dict):
                cleaned.append(_cleanup_common(item))
            else:
                cleaned.append(item)
        return cleaned
    elif isinstance(parsed, dict):
        return _cleanup_common(parsed)
    else:
        return parsed

class DissectError(RuntimeError):
    """Dissect 관련 외부 명령 실패 시 사용하는 예외."""

def _run(
    cmd: List[str],
    cwd: Optional[Path] = None,
    timeout: int = 0,
    check: bool = True,
) -> subprocess.CompletedProcess:
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
    s = raw.strip()
    if not s:
        return []

    data: Any = None
    try:
        data = json.loads(s)
    except Exception:
        data = None

    if data is not None:
        if isinstance(data, (list, dict)):
            return data
        if isinstance(data, str):
            s = data.strip()
        else:
            return data

    objs: list[Any] = []
    for ln in s.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            obj = json.loads(ln)
        except Exception:
            continue

        if isinstance(obj, dict) and obj.get("_type") == "recorddescriptor":
            continue

        objs.append(obj)

    if objs:
        return objs

    return [ln for ln in s.splitlines() if ln.strip()]

def _ensure_extract_dir(base: Union[str, Path]) -> Path:
    p = Path(base).expanduser().resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p

def _extract_timestamp(record: Dict[str, Any]) -> Optional[str]:
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
        "ts"
    ]

    for k in candidate_keys:
        if k in record and record[k]:
            return str(record[k])

    for k, v in record.items():
        if k.endswith("_time") and v:
            return str(v)

    return None

def _normalize_evtx_record(rec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    src = rec.get("SourceName")
    if src in _EVTX_NOISE_SOURCES:
        return None

    ts = rec.get("TimeGenerated") or rec.get("ts") or rec.get("TimeWritten")

    out = _cleanup_common(rec)

    if ts:
        out["timestamp"] = ts

    for k in ("ts", "TimeGenerated", "TimeWritten"):
        if k != "timestamp":
            out.pop(k, None)

    return out

def _is_useful_mft(rec: Dict[str, Any]) -> bool:
    path = (rec.get("path") or "").lower()
    if any(path.startswith(p.lower()) for p in _MFT_SYSTEM_PREFIXES):
        return False

    ts_type = rec.get("ts_type")
    if ts_type and ts_type not in _MFT_USE_TS_TYPES:
        return False

    return True

def _normalize_mft_record(rec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not _is_useful_mft(rec):
        return None

    out = _cleanup_common(rec)

    return out

def _normalize_shellbag_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    out = _cleanup_common(rec)

    ts = (
        rec.get("ts_mtime")
        or rec.get("ts_btime")
        or rec.get("ts_atime")
        or rec.get("regf_mtime")
    )
    if ts:
        out["timestamp"] = ts

    out.pop("regf_hive_path", None)
    out.pop("regf_key_path", None)

    return out

@mcp.tool()
def disk_image_info(image_path: str) -> Dict[str, Any]:
    """
    디스크 이미지 기본 정보 확인 (분할 이미지 병합 여부 포함)
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
    디스크 이미지에서 사용 가능한 Dissect 플러그인 목록 조회
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
    단일 Dissect 플러그인 실행
    """
    resolved = _resolve_image(image_path)

    cmd = [TARGET_QUERY_BIN, resolved["target"], "-f", plugin, "--json"]
    cp = _run(cmd, check=False)

    if cp.returncode != 0:
        cmd_nojson = [TARGET_QUERY_BIN, resolved["target"], "-f", plugin]
        cp = _run(cmd_nojson)

    parsed = _parse_query_output(cp.stdout)
    parsed = _cleanup_parsed(parsed)

    if isinstance(parsed, list) and max_rows and len(parsed) > max_rows:
        parsed = parsed[:max_rows]

    return {
        "plugin": plugin,
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
    키워드로 여러 플러그인을 골라서 run_single_plugin으로 실행
    """
    resolved = _resolve_image(image_path)

    inventory = list_plugins(image_path)
    plugins: List[Dict[str, Any]] = inventory["plugins"]
    plugins = _filter_plugins(plugins, plugin_keywords)

    if max_plugins and len(plugins) > max_plugins:
        plugins = plugins[:max_plugins]

    results: Dict[str, Any] = {
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
    OS / Host 기본 프로파일 생성
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
    target-query 출력에 rdump -s 표현식을 적용해 필터링된 결과를 JSON으로 반환
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
    parsed = _cleanup_parsed(parsed)

    if isinstance(parsed, list) and max_rows and len(parsed) > max_rows:
        parsed = parsed[:max_rows]

    return {
        "plugin": plugin,
        "search": search,
        "parsed": parsed,
    }

@mcp.tool()
def extract_powershell_activity(
    image_path: str,
    max_rows: int = 0,
) -> Dict[str, Any]:
    """
    Event Log에서 PowerShell 관련 핵심 이벤트만 추출.
    """
    resolved = _resolve_image(image_path)

    cmd = [
        TARGET_QUERY_BIN,
        resolved["target"],
        "-f",
        "os.windows.log.evtx.evtx",
        "--json",
    ]
    cp = _run(cmd, check=False)

    if cp.returncode != 0:
        return {
            "plugin": "os.windows.log.evtx.evtx",
            "kind": "powershell_activity",
            "error": {
                "returncode": cp.returncode,
                "stdout_head": "\n".join(cp.stdout.splitlines()[:50]),
                "stderr": cp.stderr,
            },
        }

    parsed = _parse_query_output(cp.stdout)
    parsed = _cleanup_parsed(parsed)

    if not isinstance(parsed, list):
        parsed_list: list[Any] = []
    else:
        parsed_list = parsed

    filtered: list[Dict[str, Any]] = []
    for rec in parsed_list:
        if not isinstance(rec, dict):
            continue

        if _is_interesting_powershell(rec):
            filtered.append(rec)
            if max_rows > 0 and len(filtered) >= max_rows:
                break

    return {
        "plugin": "os.windows.log.evtx.evtx",
        "kind": "powershell_activity",
        "count": len(filtered),
        "records": filtered,
    }

@mcp.tool()
def list_artifact_plugins() -> Dict[str, Any]:
    """
    _ARTIFACT_PLUGINS에 등록된 아티팩트 플러그인 목록 반환.
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
    max_rows_per_plugin: int = 500,
) -> Dict[str, Any]:
    """
    _ARTIFACT_PLUGINS에 정의된 모든 플러그인을 실행하고, 각 플러그인의 parsed 결과 반환
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
def extract_file_or_directory(
    image_path: str,
    fs_path: str,
    output_dir: Optional[str] = None,
    max_list: int = 0,
) -> Dict[str, Any]:
    """
    절대 경로 기반으로 파일 또는 폴더 추출
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

    unlimited = max_list == 0

    for root, dirs, files in os.walk(out_dir):
        for d in dirs:
            created_dirs.append(str(Path(root) / d))
        for f in files:
            created_files.append(str(Path(root) / f))
            if not unlimited and len(created_files) >= max_list:
                break

        if not unlimited and len(created_files) >= max_list:
            break

    return {
        "image": resolved["original"],
        "target": resolved["target"],
        "fs_path": fs_path,
        "output_dir": str(out_dir),
        "created_files_sample": created_files,
        "created_dirs_sample": created_dirs
    }

@mcp.tool()
def extract_downloads_folder(
    image_path: str,
    username: str = "winbg",
    output_dir: Optional[str] = None,
    max_list: int = 0,
) -> Dict[str, Any]:
    """
    지정한 사용자 프로필의 Downloads 폴더 전체 추출
    """
    fs_path = f"C:\\Users\\{username}\\Downloads"

    base_result = extract_file_or_directory(
        image_path=image_path,
        fs_path=fs_path,
        output_dir=output_dir,
        max_list=max_list,
    )

    base_result["downloads_fs_path"] = fs_path
    base_result["username"] = username
    base_result["kind"] = "downloads_folder"

    return base_result

@mcp.tool()
def acquire_minimal_artifacts(
    image_path: str,
    output_dir: Optional[str] = None,
    profile: str = "minimal",
    output_type: str = "tar",
) -> Dict[str, Any]:
    """
    acquire를 이용해 기본 아티팩트 컨테이너 생성
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
        "extract_error": extract_error
    }

@mcp.tool()
def build_timeline(
    image_path: str,
    plugins: Optional[List[str]] = None,
    max_rows_per_plugin: int = 500,
) -> Dict[str, Any]:
    """
    여러 Dissect 타임라인 아티팩트를 묶어서 단일 정렬 타임라인 생성
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
            r = run_single_plugin(
                image_path=image_path,
                plugin=plugin,
                max_rows=max_rows_per_plugin,
            )
            parsed = r.get("parsed")
            if not isinstance(parsed, list):
                continue

            for rec in parsed:
                if not isinstance(rec, dict):
                    continue

                if "evt" in plugin:
                    norm = _normalize_evtx_record(rec)
                    if norm is None:
                        continue
                elif "mft" in plugin:
                    norm = _normalize_mft_record(rec)
                    if norm is None:
                        continue
                elif "shellbag" in plugin:
                    norm = _normalize_shellbag_record(rec)
                else:
                    norm = _cleanup_common(rec)

                ts = _extract_timestamp(norm)
                if not ts:
                    continue

                timeline.append(
                    {
                        "source": key,
                        "plugin": plugin,
                        "timestamp": ts,
                        "record": norm,
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
