import base64
import hashlib
import html
import json
import platform
import re
import subprocess
import tempfile
import urllib.parse
import zlib
from pathlib import Path

import yaml

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


_SUMMARY_KEYS = ("Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID", "Details")


@mcp.tool()
def scan_evtx(
    evtx_path: str,
    min_severity: str = "low",
    rule_filter: str = "",
    output_format: str = "summary",
    max_results: int = 0,
) -> dict:
    """Scan an EVTX file or directory with Hayabusa and return structured results.

    Args:
        evtx_path: Path to the EVTX file or directory to scan.
        min_severity: Minimum severity level to include in results.
                      One of: informational, low, medium, high, critical.
        rule_filter: Case-insensitive substring matched against RuleTitle.
                     Empty string returns all rules.
        output_format: "summary" (default) returns key fields only;
                       "full" returns all fields including ExtraFieldInfo.
        max_results: Maximum number of findings to return. 0 means no limit.
    """
    min_severity = min_severity.lower()
    if min_severity not in SEVERITY_LEVELS:
        raise ValueError(
            f"Invalid severity '{min_severity}'. "
            f"Must be one of: {', '.join(SEVERITY_LEVELS)}"
        )

    output_format = output_format.lower()
    if output_format not in ("summary", "full"):
        raise ValueError("output_format must be 'summary' or 'full'")

    if max_results < 0:
        raise ValueError("max_results must be 0 (no limit) or a positive integer")

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

    finally:
        tmp_path.unlink(missing_ok=True)

    if rule_filter:
        needle = rule_filter.lower()
        findings = [f for f in findings if needle in f.get("RuleTitle", "").lower()]

    total = len(findings)

    if max_results > 0:
        findings = findings[:max_results]

    if output_format == "summary":
        findings = [{k: f[k] for k in _SUMMARY_KEYS if k in f} for f in findings]

    return {
        "evtx_path": str(target.resolve()),
        "min_severity": min_severity,
        "rule_filter": rule_filter,
        "output_format": output_format,
        "total_findings": total,
        "returned_findings": len(findings),
        "findings": findings,
    }


_RULES_DIR = Path(__file__).parent / "hayabusa" / "rules"

_RULE_FIELDS = ("title", "id", "level", "status", "description", "tags", "author")


def _parse_rule(path: Path) -> dict | None:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
        if not isinstance(data, dict) or "title" not in data:
            return None
        rule = {k: data[k] for k in _RULE_FIELDS if k in data}
        rule["path"] = str(path.relative_to(_RULES_DIR))
        return rule
    except Exception:
        return None


@mcp.tool()
def get_hayabusa_rules(
    keyword: str = "",
    level: str = "",
    max_results: int = 100,
) -> dict:
    """List available Hayabusa detection rules, optionally filtered.

    Args:
        keyword: Case-insensitive substring matched against rule title and description.
                 Empty string returns all rules (subject to max_results).
        level: Filter by exact severity level: informational, low, medium, high, critical.
               Empty string returns all levels.
        max_results: Maximum number of rules to return. 0 means no limit. Default 100.
    """
    if not _RULES_DIR.exists():
        raise FileNotFoundError(f"Rules directory not found: {_RULES_DIR}")

    if level and level.lower() not in SEVERITY_LEVELS:
        raise ValueError(
            f"Invalid level '{level}'. Must be one of: {', '.join(SEVERITY_LEVELS)}"
        )

    needle = (keyword or "").lower()
    level_filter = (level or "").lower()

    rules = []
    for yml in sorted(_RULES_DIR.rglob("*.yml")):
        rule = _parse_rule(yml)
        if rule is None:
            continue
        if level_filter and (rule.get("level") or "").lower() != level_filter:
            continue
        if needle:
            title = (rule.get("title") or "").lower()
            desc = (rule.get("description") or "").lower()
            if needle not in title and needle not in desc:
                continue
        rules.append(rule)

    total = len(rules)
    if max_results > 0:
        rules = rules[:max_results]

    return {
        "rules_dir": str(_RULES_DIR),
        "keyword": keyword,
        "level": level,
        "total_matches": total,
        "returned": len(rules),
        "rules": rules,
    }


# ── CyberChef helpers ──────────────────────────────────────────────────────

_HASH_LENGTHS: dict[int, str] = {
    32:  "MD5",
    40:  "SHA-1",
    56:  "SHA-224",
    64:  "SHA-256 / SHA3-256",
    96:  "SHA-384",
    128: "SHA-512 / SHA3-512",
}


def _cc_identify(value: str) -> str:
    s = value.strip()
    hits: list[str] = []

    if re.fullmatch(r"[0-9a-fA-F]+", s):
        label = _HASH_LENGTHS.get(len(s))
        hits.append(f"Hash ({label})" if label else f"Hex string ({len(s)} chars)")

    b64_clean = re.sub(r"[\r\n]", "", s)
    if len(b64_clean) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/]+=*", b64_clean):
        hits.append("Base64 (standard)")
    elif len(b64_clean) > 4 and re.fullmatch(r"[A-Za-z0-9\-_]+=*", b64_clean):
        hits.append("Base64 (URL-safe)")

    if re.fullmatch(r"[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*", s):
        hits.append("JWT token")

    if "%" in s and re.search(r"%[0-9a-fA-F]{2}", s):
        hits.append("URL-encoded")

    if re.search(r"&[a-zA-Z#0-9]+;", s):
        hits.append("HTML entity-encoded")

    if re.fullmatch(r"[01 \n]+", s) and " " in s:
        hits.append("Binary string")

    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", s):
        hits.append("IPv4 address")

    if re.fullmatch(r"(\d+[\s,;]+)+\d+", s):
        hits.append("Decimal char codes")

    ratio = sum(1 for c in s if 32 <= ord(c) <= 126) / max(len(s), 1)
    if ratio > 0.95 and not hits:
        hits.append("Plain ASCII text")

    return "Detected: " + (", ".join(hits) if hits else "Unknown / binary / non-standard")


def _cc_identify_hash(value: str) -> str:
    s = value.strip()
    if re.fullmatch(r"[0-9a-fA-F]+", s):
        label = _HASH_LENGTHS.get(len(s))
        return f"{label} ({len(s)} hex chars)" if label else f"Unknown hash length ({len(s)} hex chars)"
    return "Not a recognised hash format"


def _cc_extract_iocs(text: str) -> dict:
    out: dict[str, list] = {}

    ips = sorted(set(re.findall(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", text)))
    if ips:
        out["ipv4"] = ips

    urls = sorted(set(re.findall(r"https?://[^\s<>\"'`\]]+", text)))
    if urls:
        out["urls"] = urls

    emails = sorted(set(re.findall(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", text)))
    if emails:
        out["emails"] = emails

    sha256 = sorted(set(re.findall(r"\b[0-9a-fA-F]{64}\b", text)))
    if sha256:
        out["sha256"] = sha256
    sha1 = sorted(set(re.findall(r"\b[0-9a-fA-F]{40}\b", text)))
    if sha1:
        out["sha1"] = sha1
    md5 = sorted(set(re.findall(r"\b[0-9a-fA-F]{32}\b", text)))
    if md5:
        out["md5"] = md5

    paths = sorted(set(re.findall(
        r"[A-Za-z]:\\(?:[^\s<>\"/\\|?*\x00-\x1f]+\\)*[^\s<>\"/\\|?*\x00-\x1f]*", text)))
    if paths:
        out["file_paths"] = paths

    reg_keys = sorted(set(re.findall(r"HKEY_[A-Z_]+(?:\\[^\s<>\"]+)+", text)))
    if reg_keys:
        out["registry_keys"] = reg_keys

    return out


def _cc_apply(current: str, op: str, args: dict) -> str:
    key = op.lower().replace("-", "_").replace(" ", "_")

    if key == "from_base64":
        s = re.sub(r"[\r\n]", "", current.strip())
        s += "=" * ((-len(s)) % 4)
        try:
            return base64.b64decode(s).decode("utf-8", errors="replace")
        except Exception:
            return base64.urlsafe_b64decode(s).decode("utf-8", errors="replace")

    if key == "to_base64":
        return base64.b64encode(current.encode()).decode()

    if key == "from_base32":
        s = current.strip().upper()
        s += "=" * ((-len(s)) % 8)
        return base64.b32decode(s).decode("utf-8", errors="replace")

    if key == "to_base32":
        return base64.b32encode(current.encode()).decode()

    if key == "from_base85":
        return base64.b85decode(current.strip()).decode("utf-8", errors="replace")

    if key == "to_base85":
        return base64.b85encode(current.encode()).decode()

    if key == "from_hex":
        cleaned = re.sub(r"[\s:\-]", "", current).lstrip("0x").lstrip("0X")
        return bytes.fromhex(cleaned).decode("utf-8", errors="replace")

    if key == "to_hex":
        delim = args.get("delimiter", " ")
        return delim.join(f"{b:02x}" for b in current.encode())

    if key == "from_url_encode":
        return urllib.parse.unquote(current)

    if key == "to_url_encode":
        return urllib.parse.quote(current)

    if key == "from_html_entity":
        return html.unescape(current)

    if key == "to_html_entity":
        return html.escape(current)

    if key == "rot13":
        return current.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
        ))

    if key == "from_charcode":
        delim = args.get("delimiter", None)
        base = int(args.get("base", 10))
        parts = re.split(re.escape(delim), current.strip()) if delim else re.split(r"[\s,;]+", current.strip())
        return "".join(chr(int(p, base)) for p in parts if p.strip())

    if key == "to_charcode":
        delim = args.get("delimiter", " ")
        return delim.join(str(ord(c)) for c in current)

    if key == "from_binary":
        bits = re.sub(r"\s", "", current)
        return "".join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8) if len(bits[i:i+8]) == 8)

    if key == "to_binary":
        return " ".join(f"{ord(c):08b}" for c in current)

    if key in ("md5", "sha1", "sha224", "sha256", "sha384", "sha512"):
        return hashlib.new(key, current.encode()).hexdigest()

    if key == "xor":
        raw_key = bytes.fromhex(args.get("key", "00"))
        data = current.encode("latin-1")
        return bytes(b ^ raw_key[i % len(raw_key)] for i, b in enumerate(data)).decode("latin-1")

    if key == "xor_hex":
        raw_key = bytes.fromhex(args.get("key", "00"))
        data = bytes.fromhex(re.sub(r"\s", "", current))
        return bytes(b ^ raw_key[i % len(raw_key)] for i, b in enumerate(data)).hex()

    if key == "gunzip":
        import gzip
        return gzip.decompress(base64.b64decode(current.strip())).decode("utf-8", errors="replace")

    if key == "zlib_inflate":
        return zlib.decompress(base64.b64decode(current.strip())).decode("utf-8", errors="replace")

    if key == "reverse":
        return current[::-1]

    if key == "to_upper":
        return current.upper()

    if key == "to_lower":
        return current.lower()

    if key == "extract_strings":
        min_len = int(args.get("min_length", 4))
        return "\n".join(re.findall(rf"[\x20-\x7e]{{{min_len},}}", current))

    if key == "identify":
        return _cc_identify(current)

    if key == "identify_hash":
        return _cc_identify_hash(current)

    if key == "extract_iocs":
        return json.dumps(_cc_extract_iocs(current), indent=2)

    raise ValueError(f"Unknown operation: '{op}'. See the tool docstring for the full list.")


@mcp.tool()
def cyberchef(
    input_data: str,
    recipe: list[dict],
) -> dict:
    """Apply CyberChef-style operations to analyse payloads, decode obfuscation, or extract IOCs.

    Designed for security analysts investigating malicious payloads, binaries, or links.
    Operations are applied as a sequential pipeline — each step's output feeds the next,
    matching CyberChef's recipe model.

    Args:
        input_data: Raw input string (plaintext, base64, hex, binary, char codes, etc.).
        recipe: Ordered list of operations. Each entry is a dict with:
                  "op"   (required) — operation name (case-insensitive, spaces/hyphens OK)
                  "args" (optional) — dict of named arguments for that operation

    Available operations
    ────────────────────
    Encoding / Decoding
      from_base64 / to_base64
      from_base32 / to_base32
      from_base85 / to_base85
      from_hex    / to_hex        args: delimiter (default " ")
      from_url_encode / to_url_encode
      from_html_entity / to_html_entity
      rot13
      from_charcode / to_charcode  args: delimiter (default whitespace/comma), base (default 10)
      from_binary / to_binary
      reverse / to_upper / to_lower

    Hashing
      md5 / sha1 / sha224 / sha256 / sha384 / sha512

    Crypto
      xor      args: key=<hex string>  (e.g. "1a2b3c") — XOR against string input
      xor_hex  args: key=<hex string>  — XOR against hex-encoded input, returns hex

    Compression  (input must be base64-encoded compressed bytes)
      gunzip / zlib_inflate

    Analysis
      identify         — detect encoding / format of current data
      identify_hash    — identify hash algorithm by length and charset
      extract_iocs     — extract IPs, URLs, emails, MD5/SHA1/SHA256, file paths, registry keys
      extract_strings  — args: min_length (default 4) printable-ASCII extraction

    Example recipes
    ───────────────
    Decode a Base64 payload then compute its SHA-256:
      [{"op": "from_base64"}, {"op": "sha256"}]

    Identify then URL-decode a suspicious link parameter:
      [{"op": "identify"}, {"op": "from_url_encode"}]

    XOR-decrypt a hex payload with key 0x41:
      [{"op": "xor_hex", "args": {"key": "41"}}]

    Decode JS char-code array (comma-separated decimals):
      [{"op": "from_charcode", "args": {"delimiter": ","}}]

    Extract all IOCs from a threat-intel blob:
      [{"op": "extract_iocs"}]

    Chain: base64 → hex → identify:
      [{"op": "from_base64"}, {"op": "to_hex"}, {"op": "identify"}]
    """
    steps: list[dict] = []
    current = input_data

    for i, step in enumerate(recipe):
        if not isinstance(step, dict) or "op" not in step:
            return {
                "success": False,
                "input": input_data,
                "failed_at_step": i,
                "error": f"Step {i} must be a dict with an 'op' key, got: {step!r}",
                "steps": steps,
            }
        op = step["op"]
        args: dict = step.get("args") or {}
        try:
            result = _cc_apply(current, op, args)
        except Exception as exc:
            return {
                "success": False,
                "input": input_data,
                "failed_at_step": i,
                "failed_op": op,
                "error": str(exc),
                "steps": steps,
            }
        steps.append({"step": i, "op": op, "args": args, "output": result})
        current = result

    return {
        "success": True,
        "input": input_data,
        "output": current,
        "steps": steps,
    }


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
