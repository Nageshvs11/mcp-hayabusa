# mcp-hayabusa

An MCP server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) to expose Windows Event Log (EVTX) threat detection as a tool callable by Claude and other MCP clients.

## What it does

Exposes a single `scan_evtx` tool that:
- Accepts a path to an `.evtx` file or a directory of `.evtx` files
- Runs Hayabusa's sigma-based detection rules against them
- Returns structured JSON findings, filtered by severity

## Setup

**1. Install dependencies**
```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

**2. Download Hayabusa**
```bash
.venv/bin/python download_hayabusa.py
```
This fetches the latest Hayabusa release for your platform and installs it to `./hayabusa/`.

## Usage

### With Claude Desktop

Add to your `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "hayabusa": {
      "command": "/path/to/mcp-hayabusa/.venv/bin/python",
      "args": ["/path/to/mcp-hayabusa/server.py"]
    }
  }
}
```

Then ask Claude things like:
> "Scan `/path/to/Security.evtx` for high and critical findings"

### Direct invocation

```bash
.venv/bin/python server.py
```

The server communicates over stdio using the MCP protocol.

## Tool reference

### `scan_evtx`

| Parameter | Type | Default | Description |
|---|---|---|---|
| `evtx_path` | string | required | Path to `.evtx` file or directory |
| `min_severity` | string | `"low"` | Minimum severity: `informational`, `low`, `medium`, `high`, `critical` |

**Example response:**
```json
{
  "evtx_path": "/logs/Security.evtx",
  "min_severity": "high",
  "total_findings": 3,
  "findings": [
    {
      "Timestamp": "2019-05-08T02:10:43.487217Z",
      "RuleTitle": "Mimikatz DC Sync",
      "Level": "high",
      "Computer": "DC1.corp.local",
      "Channel": "Sec",
      "EventID": 4662,
      "Details": { ... }
    }
  ]
}
```

## Running tests

```bash
.venv/bin/pytest test_server.py -v
```

Tests require sample EVTX files in `./samples/`. A few attack samples from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) are used:
- `CA_DCSync_4662.evtx` — DCSync / Mimikatz credential access
- `DE_RDP_Tunneling_4624.evtx` — RDP tunneling C2
- `rundll32_cmd_schtask.evtx` — rundll32 malware execution

Download them with:
```bash
mkdir -p samples
gh api repos/sbousseaden/EVTX-ATTACK-SAMPLES/contents/Credential%20Access/CA_DCSync_4662.evtx --jq '.download_url' | xargs curl -sL -o samples/CA_DCSync_4662.evtx
gh api "repos/sbousseaden/EVTX-ATTACK-SAMPLES/contents/Command and Control/DE_RDP_Tunneling_4624.evtx" --jq '.download_url' | xargs curl -sL -o samples/DE_RDP_Tunneling_4624.evtx
gh api repos/sbousseaden/EVTX-ATTACK-SAMPLES/contents/AutomatedTestingTools/Malware/rundll32_cmd_schtask.evtx --jq '.download_url' | xargs curl -sL -o samples/rundll32_cmd_schtask.evtx
```
