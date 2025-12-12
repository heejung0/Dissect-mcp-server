# Dissect-mcp-server

Dissect MCP Server는 [Dissect](https://docs.dissect.tools/en/stable/index.html) 라이브러리를 [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) 서버 형태로 노출합니다. 이를 통해 Cursor, Claude Desktop 등 MCP 클라이언트에서 **디스크 이미지(E01, RAW, VMDK 등)** 에서 전반적인 아티팩트를 추출하고 분석할 수 있습니다.

## Tools

- `disk_image_info` : 디스크 이미지의 기본 메타데이터와 분할 이미지 병합 정보 확인
- `list_plugins` : 해당 디스크 이미지에서 사용 가능한 Dissect 플러그인 목록 조회
- `run_single_plugin` : 단일 Dissect 플러그인 실행
- `run_multiple_plugins` : 여러 개의 Dissect 플러그인 실행  
- `extract_system_profile` : 기본 프로파일 정보 수집
- `search_keyword` : 파일명, 확장자, 경로 등으로 필터링
- `extract_powershell_activity` : Event Log에서 PowerShell 관련 핵심 이벤트만 추출
- `list_artifact_plugins` : 사용자가 정의한 아티팩트 플러그인 목록 조회
- `run_all_artifact_plugins` : 사용자가 정의한 아티팩트 플러그인 일괄 실행
- `extract_file_or_directory` : 절대 경로 기반으로 디스크 이미지 내의 특정 파일 또는 디렉토리 추출
- `extract_downloads_folder` : 지정한 사용자명의 Downloads 폴더 추출
- `acquire_minimal_artifacts` : 최소한의 아티팩트를 tar파일로 추출하여 압축 해제
- `build_timeline` : 사용자가 정의한 타임라인 관련 아티팩트를 추출해 하나의 타임라인으로 통합

## Installation

### 1. Python 환경 준비
```bash
git clone https://github.com/heejung0/Dissect-mcp-server.git
cd Dissect-mcp-server
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. MCP Client 연결
```json
{
  "dissect-MCP": {
    "command": "/path/to/.venv/bin/python",
    "args": [
    "/path/to/dissect_mcp_server.py"
    ],
    "env": {
    "DISSECT_TARGET_QUERY": "/path/to/Dissect-mcp-server/.venv/bin/target-query",
    "DISSECT_RDUMP": "/path/to/Dissect-mcp-server/.venv/bin/rdump",
    "DISSECT_TARGET_FS": "/path/to/Dissect-mcp-server/.venv/bin/target-fs",
    "DISSECT_ACQUIRE_BIN": "/path/to/Dissect-mcp-server/.venv/bin/acquire",
    "DISSECT_ACQUIRE_DIR": "/path/to/acquire_output",
    "DISSECT_EXTRACT_DIR": "/path/to/dissect_extracts",
    "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
    }
  }
}
```
