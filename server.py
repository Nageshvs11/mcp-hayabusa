import base64
import hashlib
import html
import json
import platform
import re
import subprocess
import sys
import tempfile
import urllib.parse
import uuid
import zlib
from datetime import date as _date
from pathlib import Path

import yaml

from mcp.server.fastmcp import FastMCP

_sse_mode = "--sse" in sys.argv
_http_mode = "--streamable-http" in sys.argv
_remote_mode = _sse_mode or _http_mode
_sse_port = next((int(a.split("=")[1]) for a in sys.argv if a.startswith("--port=")), 8001)
mcp = FastMCP("hayabusa", host="0.0.0.0" if _remote_mode else "127.0.0.1", port=_sse_port)

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


# ── Sigma rule resources ───────────────────────────────────────────────────

_SIGMA_RULES_DIR = Path(__file__).parent / "rules"


def _load_sigma_rules() -> list[tuple[Path, dict]]:
    if not _SIGMA_RULES_DIR.exists():
        return []
    results = []
    for yml in sorted(_SIGMA_RULES_DIR.rglob("*.yml")):
        try:
            data = yaml.safe_load(yml.read_text(encoding="utf-8", errors="replace"))
            if isinstance(data, dict) and "title" in data:
                results.append((yml, data))
        except Exception:
            continue
    return results


def _extract_techniques(data: dict) -> list[str]:
    techniques = []
    for tag in data.get("tags") or []:
        m = re.match(r"attack\.(t\d+(?:\.\d+)?)", tag, re.IGNORECASE)
        if m:
            techniques.append(m.group(1).upper())
    return techniques


def _rule_summary(path: Path, data: dict) -> dict:
    return {
        "name": path.stem,
        "title": data.get("title", ""),
        "id": data.get("id", ""),
        "level": data.get("level", ""),
        "status": data.get("status", ""),
        "techniques": _extract_techniques(data),
        "path": str(path.relative_to(_SIGMA_RULES_DIR)),
    }


@mcp.resource(
    "detection://rules",
    description="List all available Sigma detection rules with metadata and ATT&CK technique mappings.",
    mime_type="application/json",
)
def list_sigma_rules() -> str:
    rules = [_rule_summary(p, d) for p, d in _load_sigma_rules()]
    return json.dumps({"total": len(rules), "rules": rules}, indent=2)


@mcp.resource(
    "detection://rules/{rule_name}",
    description="Get the full YAML content of a specific Sigma rule by its file stem (e.g. proc_creation_win_whoami).",
    mime_type="text/plain",
)
def get_sigma_rule(rule_name: str) -> str:
    if not _SIGMA_RULES_DIR.exists():
        return json.dumps({"error": f"Rules directory not found: {_SIGMA_RULES_DIR}"})
    for path in sorted(_SIGMA_RULES_DIR.rglob("*.yml")):
        if path.stem == rule_name:
            return path.read_text(encoding="utf-8", errors="replace")
    return json.dumps({"error": f"Rule '{rule_name}' not found"})


@mcp.resource(
    "detection://rules/by-technique/{technique_id}",
    description="List all Sigma rules that cover a specific ATT&CK technique (e.g. T1059, T1059.001).",
    mime_type="application/json",
)
def get_rules_by_technique(technique_id: str) -> str:
    needle = technique_id.upper()
    matches = [
        _rule_summary(p, d)
        for p, d in _load_sigma_rules()
        if needle in _extract_techniques(d)
    ]
    return json.dumps(
        {"technique_id": needle, "total": len(matches), "rules": matches},
        indent=2,
    )


# ── ATT&CK technique resource ──────────────────────────────────────────────

_ATTACK_DATA_PATH = Path(__file__).parent / "mappings" / "enterprise-attack.json"

# Lazily populated on first use: technique_id (e.g. "T1059.001") -> {name, description, is_subtechnique}
_attack_index: dict[str, dict] | None = None


def _get_attack_index() -> dict[str, dict]:
    global _attack_index
    if _attack_index is not None:
        return _attack_index

    if not _ATTACK_DATA_PATH.exists():
        _attack_index = {}
        return _attack_index

    with _ATTACK_DATA_PATH.open(encoding="utf-8") as fh:
        stix = json.load(fh)

    index: dict[str, dict] = {}
    for obj in stix.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext_id = next(
            (ref["external_id"] for ref in obj.get("external_references", [])
             if ref.get("source_name") == "mitre-attack"),
            None,
        )
        if not ext_id:
            continue
        tactics = [
            phase["phase_name"].replace("-", " ").title()
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]
        index[ext_id.upper()] = {
            "technique_id": ext_id.upper(),
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "tactics": tactics,
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            "platforms": obj.get("x_mitre_platforms", []),
            "data_sources": obj.get("x_mitre_data_sources", []),
            "detection": obj.get("x_mitre_detection", ""),
        }

    _attack_index = index
    return _attack_index


def _assess_coverage(
    technique_id: str,
    direct_rules: list[dict],
    attack_index: dict[str, dict],
) -> dict:
    """Return coverage assessment for a technique.

    - covered  : ≥1 rule maps directly to this technique ID
    - partial  : parent technique has no direct rules but ≥1 sub-technique is covered
    - gap      : no rules found at all
    """
    if direct_rules:
        return {"status": "covered", "rule_count": len(direct_rules)}

    # For parent techniques (no dot), check whether any sub-techniques are covered
    if "." not in technique_id:
        sigma_rules = _load_sigma_rules()
        all_techniques_in_rules: set[str] = set()
        for _, d in sigma_rules:
            all_techniques_in_rules.update(_extract_techniques(d))

        subtechs_in_attack = [
            tid for tid in attack_index
            if tid.startswith(technique_id + ".")
        ]
        covered_subtechs = [t for t in subtechs_in_attack if t in all_techniques_in_rules]

        if covered_subtechs:
            return {
                "status": "partial",
                "rule_count": 0,
                "note": (
                    f"{len(covered_subtechs)}/{len(subtechs_in_attack)} sub-techniques covered: "
                    + ", ".join(sorted(covered_subtechs))
                ),
            }

    return {"status": "gap", "rule_count": 0}


@mcp.resource(
    "detection://attack/techniques/{technique_id}",
    description=(
        "ATT&CK technique details plus Sigma rule coverage. "
        "technique_id examples: T1059, T1059.001. "
        "Coverage is 'covered' (direct rules exist), "
        "'partial' (parent technique with sub-technique coverage), or 'gap' (no rules)."
    ),
    mime_type="application/json",
)
def get_attack_technique(technique_id: str) -> str:
    tid = technique_id.upper()
    attack_index = _get_attack_index()

    technique = attack_index.get(tid)
    if technique is None:
        if not _ATTACK_DATA_PATH.exists():
            return json.dumps({
                "error": (
                    f"ATT&CK data not found at {_ATTACK_DATA_PATH}. "
                    "Download enterprise-attack.json into the mappings/ directory."
                )
            })
        return json.dumps({"error": f"Technique '{tid}' not found in ATT&CK data"})

    sigma_rules = _load_sigma_rules()
    direct_rules = [
        _rule_summary(p, d)
        for p, d in sigma_rules
        if tid in _extract_techniques(d)
    ]

    coverage = _assess_coverage(tid, direct_rules, attack_index)

    return json.dumps({
        "technique_id": technique["technique_id"],
        "name": technique["name"],
        "description": technique["description"],
        "tactics": technique["tactics"],
        "is_subtechnique": technique["is_subtechnique"],
        "platforms": technique["platforms"],
        "coverage": coverage,
        "rules": direct_rules,
    }, indent=2)


# ── Coverage analysis tool ────────────────────────────────────────────────


@mcp.tool()
def analyze_coverage(query: str) -> dict:
    """Analyze detection coverage for an ATT&CK technique ID or tactic name.

    Reads Sigma rules from the detection://rules resource and cross-references
    them against the ATT&CK knowledge base to identify covered techniques,
    partial coverage, and detection gaps.

    Args:
        query: An ATT&CK technique ID  (e.g. "T1003", "T1059.001")
               or a tactic name       (e.g. "credential-access", "Lateral Movement").
               Technique IDs are matched exactly; tactic names are matched
               case-insensitively with hyphens/underscores treated as spaces.

    Returns a coverage report with:
      - summary: counts and percentage of covered / partial / gap techniques
      - covered: techniques with ≥1 direct Sigma rule
      - partial: parent techniques where sub-techniques are covered but not the parent itself
      - gaps:    techniques with no Sigma rules at all
    """
    attack_index = _get_attack_index()

    # Build technique -> rules mapping from Sigma rules
    sigma_rules = _load_sigma_rules()
    technique_to_rules: dict[str, list[dict]] = {}
    for path, data in sigma_rules:
        summary = _rule_summary(path, data)
        for tid in summary["techniques"]:
            technique_to_rules.setdefault(tid, []).append(summary)

    covered_set = set(technique_to_rules.keys())

    # Determine query type: technique ID vs tactic name
    technique_id_match = re.match(r"^(T\d{4}(?:\.\d{3})?)$", query.strip(), re.IGNORECASE)

    if technique_id_match:
        # ── Technique / sub-technique ID ──────────────────────────────────
        tid = technique_id_match.group(1).upper()
        is_subtechnique = "." in tid

        in_scope: list[str] = []
        if tid in attack_index:
            in_scope.append(tid)
        if not is_subtechnique:
            in_scope += sorted(t for t in attack_index if t.startswith(tid + "."))

        if not in_scope:
            return {
                "error": f"Technique '{tid}' not found in ATT&CK data.",
                "note": "Ensure mappings/enterprise-attack.json is present.",
            }

        query_type = "subtechnique" if is_subtechnique else "technique"
        scope_label = (
            f"{tid} and its sub-techniques"
            if not is_subtechnique and len(in_scope) > 1
            else tid
        )

    else:
        # ── Tactic name ───────────────────────────────────────────────────
        tactic_key = query.strip().lower().replace("-", " ").replace("_", " ")

        in_scope = [
            t for t, info in attack_index.items()
            if any(tac.lower().replace("-", " ") == tactic_key for tac in info["tactics"])
        ]

        if not in_scope:
            # Fallback: partial match
            in_scope = [
                t for t, info in attack_index.items()
                if any(tactic_key in tac.lower().replace("-", " ") for tac in info["tactics"])
            ]

        if not in_scope:
            available = sorted({
                tac for info in attack_index.values() for tac in info["tactics"]
            })
            return {
                "error": f"Tactic '{query}' not found in ATT&CK data.",
                "available_tactics": available,
            }

        query_type = "tactic"
        scope_label = query.strip()
        in_scope = sorted(in_scope)

    # ── Categorise each in-scope technique ────────────────────────────────
    covered_items: list[dict] = []
    partial_items: list[dict] = []
    gap_items: list[dict] = []

    for t in sorted(in_scope):
        info = attack_index.get(t, {})
        base = {
            "technique_id": t,
            "name": info.get("name", ""),
            "tactics": info.get("tactics", []),
            "is_subtechnique": info.get("is_subtechnique", False),
        }
        direct_rules = technique_to_rules.get(t, [])

        if direct_rules:
            severity_breakdown = {
                lvl: sum(1 for r in direct_rules if r["level"] == lvl)
                for lvl in SEVERITY_LEVELS
                if any(r["level"] == lvl for r in direct_rules)
            }
            covered_items.append({
                **base,
                "rule_count": len(direct_rules),
                "severity_breakdown": severity_breakdown,
                "rules": direct_rules,
            })
        elif not info.get("is_subtechnique", True):
            # Parent technique: check whether any sub-techniques are covered
            subtechs = [s for s in attack_index if s.startswith(t + ".")]
            covered_subtechs = sorted(s for s in subtechs if s in covered_set)
            if covered_subtechs:
                partial_items.append({
                    **base,
                    "rule_count": 0,
                    "covered_subtechniques": covered_subtechs,
                    "total_subtechniques": len(subtechs),
                })
            else:
                gap_items.append({**base, "rule_count": 0})
        else:
            gap_items.append({**base, "rule_count": 0})

    total = len(in_scope)
    n_covered = len(covered_items)
    n_partial = len(partial_items)
    n_gap = len(gap_items)
    # Partial counts as half-covered in the percentage
    coverage_pct = round((n_covered + n_partial * 0.5) / total * 100, 1) if total else 0.0

    return {
        "query": query,
        "query_type": query_type,
        "scope": scope_label,
        "summary": {
            "total_techniques": total,
            "covered": n_covered,
            "partial": n_partial,
            "gaps": n_gap,
            "coverage_pct": coverage_pct,
        },
        "covered": covered_items,
        "partial": partial_items,
        "gaps": gap_items,
    }


# ── Rule suggestion tool ──────────────────────────────────────────────────

# ATT&CK data source label -> Sigma logsource dict, in match-priority order
_DS_TO_LOGSOURCE: list[tuple[str, dict]] = [
    ("Process: Process Creation",                       {"category": "process_creation", "product": "windows"}),
    ("Command: Command Execution",                      {"category": "process_creation", "product": "windows"}),
    ("Process: Process Access",                         {"category": "process_access",   "product": "windows"}),
    ("Process: OS API Execution",                       {"category": "process_access",   "product": "windows"}),
    ("Module: Module Load",                             {"category": "image_load",        "product": "windows"}),
    ("Driver: Driver Load",                             {"category": "driver_load",       "product": "windows"}),
    ("Named Pipe: Named Pipe Metadata",                 {"category": "pipe_created",      "product": "windows"}),
    ("File: File Creation",                             {"category": "file_event",        "product": "windows"}),
    ("File: File Access",                               {"category": "file_access",       "product": "windows"}),
    ("File: File Modification",                         {"category": "file_change",       "product": "windows"}),
    ("File: File Deletion",                             {"category": "file_delete",       "product": "windows"}),
    ("Windows Registry: Registry Key Modification",     {"category": "registry_set",      "product": "windows"}),
    ("Windows Registry: Registry Key Creation",         {"category": "registry_add",      "product": "windows"}),
    ("Windows Registry: Registry Key Deletion",         {"category": "registry_delete",   "product": "windows"}),
    ("Script: Script Execution",                        {"category": "ps_script",         "product": "windows"}),
    ("Network Traffic: Network Connection Creation",    {"category": "network_connection","product": "windows"}),
    ("Network Traffic: Network Traffic Content",        {"category": "network_connection","product": "windows"}),
    ("Active Directory: Active Directory Object Access",{"product": "windows", "service": "security"}),
    ("User Account: User Account Authentication",       {"product": "windows", "service": "security"}),
    ("Logon Session: Logon Session Creation",           {"product": "windows", "service": "security"}),
    ("Application Log: Application Log Content",        {"product": "windows", "service": "application"}),
]


def _suggest_logsource(data_sources: list[str]) -> dict:
    for ds_label, logsource in _DS_TO_LOGSOURCE:
        if any(ds_label.lower() in src.lower() for src in data_sources):
            return logsource
    return {"category": "process_creation", "product": "windows"}


def _build_rule_template(tid: str, info: dict) -> str:
    logsource = _suggest_logsource(info.get("data_sources", []))
    tactics = info.get("tactics", [])

    tactic_tags = ["attack." + t.lower().replace(" ", "-") for t in tactics]
    technique_tag = "attack." + tid.lower()
    tags_yaml = "\n".join(f"    - {tag}" for tag in tactic_tags + [technique_tag])
    logsource_yaml = "\n".join(f"    {k}: {v}" for k, v in logsource.items())

    cat = logsource.get("category", "")
    svc = logsource.get("service", "")

    if cat == "process_creation":
        detection_block = (
            "detection:\n"
            "    selection:\n"
            "        Image|endswith:\n"
            "            - '\\\\TODO.exe'  # tool or process name(s)\n"
            "        CommandLine|contains:\n"
            "            - 'TODO'  # suspicious argument patterns\n"
            "    condition: selection\n"
        )
    elif cat in ("registry_set", "registry_add", "registry_event", "registry_delete"):
        detection_block = (
            "detection:\n"
            "    selection:\n"
            "        TargetObject|contains:\n"
            "            - 'TODO'  # registry key path\n"
            "    condition: selection\n"
        )
    elif cat in ("file_event", "file_access", "file_change", "file_delete"):
        detection_block = (
            "detection:\n"
            "    selection:\n"
            "        TargetFilename|contains:\n"
            "            - 'TODO'  # file path or name pattern\n"
            "    condition: selection\n"
        )
    elif cat == "network_connection":
        detection_block = (
            "detection:\n"
            "    selection:\n"
            "        Initiated: 'true'\n"
            "        DestinationPort:\n"
            "            - 0  # TODO: target port(s)\n"
            "    condition: selection\n"
        )
    elif cat == "process_access":
        detection_block = (
            "detection:\n"
            "    selection:\n"
            "        TargetImage|endswith:\n"
            "            - '\\\\TODO.exe'  # target process\n"
            "        GrantedAccess|contains:\n"
            "            - '0x0'  # TODO: access mask(s)\n"
            "    condition: selection\n"
        )
    elif cat == "image_load":
        detection_block = (
            "detection:\n"
            "    selection:\n"
            "        ImageLoaded|endswith:\n"
            "            - '\\\\TODO.dll'\n"
            "    filter_signed:\n"
            "        Signed: 'true'\n"
            "    condition: selection and not filter_signed\n"
        )
    elif cat == "ps_script":
        detection_block = (
            "detection:\n"
            "    selection:\n"
            "        ScriptBlockText|contains:\n"
            "            - 'TODO'  # PowerShell pattern\n"
            "    condition: selection\n"
        )
    elif svc == "security":
        detection_block = (
            "detection:\n"
            "    selection:\n"
            "        EventID:\n"
            "            - 0  # TODO: relevant EventID(s)\n"
            "    filter_machine_accounts:\n"
            "        SubjectUserName|endswith: '$'\n"
            "    condition: selection and not filter_machine_accounts\n"
        )
    else:
        detection_block = (
            "detection:\n"
            "    selection:\n"
            "        # TODO: add detection conditions\n"
            "    condition: selection\n"
        )

    # Short description: first sentence of ATT&CK description, citations/links stripped
    full_desc = re.sub(r"\(Citation:[^)]+\)", "", info.get("description", "")).strip()
    full_desc = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", full_desc)  # strip markdown links
    m = re.search(r"\.(\s|$)", full_desc)
    short_desc = (full_desc[: m.end()].strip()) if m else (full_desc or f"Detects {info.get('name', tid)} ({tid}).")

    att_url = "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"

    return (
        f"title: Potential {info.get('name', tid)} Activity\n"
        f"id: {uuid.uuid4()}\n"
        f"status: experimental\n"
        f"description: |\n"
        f"    {short_desc}\n"
        f"references:\n"
        f"    - {att_url}\n"
        f"author: TODO\n"
        f"date: {_date.today().isoformat()}\n"
        f"tags:\n"
        f"{tags_yaml}\n"
        f"logsource:\n"
        f"{logsource_yaml}\n"
        f"{detection_block}"
        f"falsepositives:\n"
        f"    - Legitimate administrative activity\n"
        f"    - TODO: enumerate known false positives\n"
        f"level: medium\n"
    )


@mcp.tool()
def suggest_rule(technique_id: str, create_file: bool = False) -> dict:
    """Suggest a Sigma detection rule template for an ATT&CK technique.

    Checks existing coverage first. If the technique is a gap, generates a
    Sigma rule skeleton guided by ATT&CK data sources and detection guidance.
    Optionally writes the template to the rules/ directory.

    Args:
        technique_id: ATT&CK technique ID, e.g. "T1558.004" or "T1110.003".
        create_file:  If True, write the template to rules/<logsource_category>/
                      so it can be refined and committed. Defaults to False.

    Returns:
        coverage_status:    "covered", "partial", or "gap"
        existing_rules:     list of existing rule summaries covering this technique
        data_sources:       ATT&CK data sources for the technique
        detection_guidance: ATT&CK detection notes (truncated)
        suggested_logsource: recommended Sigma log source
        template:           Sigma YAML template string
        file_path:          path written (only present when create_file=True)
    """
    tid = technique_id.strip().upper()
    if not re.match(r"^T\d{4}(\.\d{3})?$", tid):
        return {"error": f"'{technique_id}' is not a valid ATT&CK technique ID (expected T1234 or T1234.001)."}

    attack_index = _get_attack_index()
    info = attack_index.get(tid)
    if info is None:
        return {
            "error": f"Technique '{tid}' not found in ATT&CK data.",
            "note": "Ensure mappings/enterprise-attack.json is present.",
        }

    # Check existing coverage
    sigma_rules = _load_sigma_rules()
    technique_to_rules: dict[str, list[dict]] = {}
    for path, data in sigma_rules:
        summary = _rule_summary(path, data)
        for t in summary["techniques"]:
            technique_to_rules.setdefault(t, []).append(summary)

    existing = technique_to_rules.get(tid, [])

    if existing:
        coverage_status = "covered"
    elif not info.get("is_subtechnique"):
        subtechs = [t for t in attack_index if t.startswith(tid + ".")]
        covered_subs = [t for t in subtechs if t in technique_to_rules]
        coverage_status = "partial" if covered_subs else "gap"
    else:
        coverage_status = "gap"

    data_sources = info.get("data_sources", [])
    logsource = _suggest_logsource(data_sources)

    detection_notes = re.sub(r"\(Citation:[^)]+\)", "", info.get("detection", "")).strip()

    template = _build_rule_template(tid, info)

    result: dict = {
        "technique_id": tid,
        "name": info.get("name"),
        "tactics": info.get("tactics"),
        "coverage_status": coverage_status,
        "existing_rule_count": len(existing),
        "existing_rules": existing,
        "data_sources": data_sources,
        "detection_guidance": detection_notes[:600] if detection_notes else "",
        "suggested_logsource": logsource,
        "template": template,
    }

    if create_file:
        cat = logsource.get("category") or logsource.get("service", "other")
        out_dir = _SIGMA_RULES_DIR / cat
        out_dir.mkdir(parents=True, exist_ok=True)
        name_slug = re.sub(r"[^a-z0-9]+", "_", info.get("name", tid).lower()).strip("_")[:35]
        filename = f"attack_{tid.lower().replace('.', '_')}_{name_slug}.yml"
        out_path = out_dir / filename
        out_path.write_text(template, encoding="utf-8")
        result["file_path"] = str(out_path)

    return result


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
        cleaned = re.sub(r"(?i)^0x", "", re.sub(r"[\s:\-]", "", current))
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
    print("hayabusa MCP server starting", file=sys.stderr, flush=True)
    if _http_mode:
        mcp.run(transport="streamable-http")
    elif _sse_mode:
        mcp.run(transport="sse")
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
