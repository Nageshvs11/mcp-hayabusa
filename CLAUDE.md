# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an MCP server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) for EVTX (Windows Event Log) analysis **and** provides a detection engineering knowledge base.

**Goals:**
- Expose a `scan_evtx` tool that runs Hayabusa against EVTX files
- Return results as structured JSON
- Support filtering by severity level
- Handle errors gracefully
- Expose Sigma rules as browsable MCP resources
- Expose ATT&CK technique mappings
- Allow Claude to query detection coverage
- Combine detection knowledge base with Hayabusa scanning

## Stack

- **Python** with the [`mcp`](https://github.com/modelcontextprotocol/python-sdk) library
- **Hayabusa CLI** installed locally (invoked as a subprocess)

## Repository Structure

```
rules/       - Sigma detection rules (YAML)
mappings/    - ATT&CK technique to rule mappings
server.py    - MCP server with resources and tools
```

## Key Architecture

- The MCP server defines a `scan_evtx` tool that accepts an EVTX file path and optional severity filter
- Tool handler shells out to the Hayabusa CLI with appropriate flags and parses stdout as JSON
- Results are returned to the MCP client as structured JSON content
- Sigma rules under `rules/` are exposed as browsable MCP resources
- ATT&CK technique mappings under `mappings/` link techniques to detection rules
- A coverage query tool allows Claude to assess detection coverage for a given technique or tactic

## Development Commands

```bash
# Create virtual environment (first time)
python3 -m venv .venv

# Install dependencies
.venv/bin/pip install -r requirements.txt

# Run the MCP server (stdio transport)
.venv/bin/python server.py

# Run tests
.venv/bin/pytest

# Run a single test
.venv/bin/pytest tests/test_server.py::test_name -v
```

> Kali's Python is externally managed — always use the `.venv` rather than system `pip`/`python`.

## MCP Resources

Always use MCP resources (via `ReadMcpResourceTool`) instead of raw filesystem commands when answering questions about detection content:

| Resource URI | What it returns |
|---|---|
| `detection://rules` | All 2,396 Sigma rules with title, level, status, ATT&CK techniques, and path |
| `detection://rules/{rule_name}` | Full YAML content of a single rule by file stem |
| `detection://rules/by-technique/{technique_id}` | All rules covering a specific ATT&CK technique |
| `detection://attack/techniques/{technique_id}` | ATT&CK technique details + coverage status |

**Tools:**
- `analyze_coverage(query)` — pass a technique ID (e.g. `T1003`, `T1059.001`) or tactic name (e.g. `credential-access`) to get a full coverage report: covered techniques with rule counts, partial coverage, and gaps.
- `suggest_rule(technique_id, create_file=False)` — for a given technique ID, checks existing coverage then generates a Sigma rule YAML template with the correct log source, ATT&CK tags, and detection skeleton. Set `create_file=True` to write it to `rules/<category>/`.

Example: when asked "what rules do we have?", call `ReadMcpResourceTool` with server `hayabusa` and uri `detection://rules` — do **not** use `find`/`grep` on the `rules/` directory.

## Hayabusa Integration

Hayabusa is invoked via subprocess. The expected CLI invocation pattern:

```bash
hayabusa json-timeline -f <evtx_path> --no-color --no-summary
```

Severity levels follow Hayabusa's built-in levels: `critical`, `high`, `medium`, `low`, `informational`.
