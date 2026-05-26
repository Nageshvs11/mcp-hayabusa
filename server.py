import json
import platform
import subprocess
import tempfile
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("hayabusa")

SEVERITY_LEVELS = ["informational", "low", "medium", "high", "critical"]

_BINARY_NAME = "hayabusa.exe" if platform.system() == "Windows" else "hayabusa"
_BINARY_PATH = Path(__file__).parent / "hayabusa" / _BINARY_NAME


def _require_binary() -> Path:
    if not _BINARY_PATH.exists():
        raise FileNotFoundError(
            f"Hayabusa binary not found at {_BINARY_PATH}. "
            "Run download_hayabusa.py to install it."
        )
    return _BINARY_PATH


@mcp.tool()
def scan_evtx(evtx_path: str, min_severity: str = "low") -> dict:
    """Scan an EVTX file or directory with Hayabusa and return structured results.

    Args:
        evtx_path: Path to the EVTX file or directory to scan.
        min_severity: Minimum severity level to include in results.
                      One of: informational, low, medium, high, critical.
    """
    min_severity = min_severity.lower()
    if min_severity not in SEVERITY_LEVELS:
        raise ValueError(
            f"Invalid severity '{min_severity}'. "
            f"Must be one of: {', '.join(SEVERITY_LEVELS)}"
        )

    target = Path(evtx_path)
    if not target.exists():
        raise FileNotFoundError(f"EVTX path not found: {evtx_path}")

    binary = _require_binary()

    tmp = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
    tmp_path = Path(tmp.name)
    tmp.close()

    try:
        input_flag = "-d" if target.is_dir() else "-f"
        cmd = [
            str(binary),
            "json-timeline",
            input_flag, str(target),
            "--output", str(tmp_path),
            "--JSONL-output",
            "--min-level", min_severity,
            "--no-wizard",
            "--no-summary",
            "--quiet",
            "--UTC",
            "--ISO-8601",
            "--clobber",
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"Hayabusa scan failed (exit {result.returncode}).\n"
                + (result.stderr.strip() or result.stdout.strip())
            )

        findings = []
        if tmp_path.exists():
            for line in tmp_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    findings.append(json.loads(line))

        return {
            "evtx_path": str(target.resolve()),
            "min_severity": min_severity,
            "total_findings": len(findings),
            "findings": findings,
        }

    finally:
        tmp_path.unlink(missing_ok=True)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
