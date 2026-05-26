# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an MCP server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) for EVTX (Windows Event Log) analysis.

**Goals:**
- Expose a `scan_evtx` tool that runs Hayabusa against EVTX files
- Return results as structured JSON
- Support filtering by severity level
- Handle errors gracefully

## Stack

- **Python** with the [`mcp`](https://github.com/modelcontextprotocol/python-sdk) library
- **Hayabusa CLI** installed locally (invoked as a subprocess)

## Key Architecture

- The MCP server defines a single tool (`scan_evtx`) that accepts an EVTX file path and optional severity filter
- Tool handler shells out to the Hayabusa CLI with appropriate flags and parses stdout as JSON
- Results are returned to the MCP client as structured JSON content

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

## Hayabusa Integration

Hayabusa is invoked via subprocess. The expected CLI invocation pattern:

```bash
hayabusa json-timeline -f <evtx_path> --no-color --no-summary
```

Severity levels follow Hayabusa's built-in levels: `critical`, `high`, `medium`, `low`, `informational`.
