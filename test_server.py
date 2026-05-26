"""
Direct tests for the scan_evtx tool in server.py.
Run with: .venv/bin/pytest test_server.py -v
"""

import pytest
from pathlib import Path
from server import scan_evtx

SAMPLES = Path(__file__).parent / "samples"
DCSYNC = SAMPLES / "CA_DCSync_4662.evtx"
RDP = SAMPLES / "DE_RDP_Tunneling_4624.evtx"
RUNDLL32 = SAMPLES / "rundll32_cmd_schtask.evtx"


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

def test_invalid_severity_raises():
    with pytest.raises(ValueError, match="Invalid severity"):
        scan_evtx(str(DCSYNC), min_severity="banana")

def test_missing_file_raises():
    with pytest.raises(FileNotFoundError, match="EVTX path not found"):
        scan_evtx("/tmp/does_not_exist.evtx")

def test_severity_case_insensitive():
    result = scan_evtx(str(DCSYNC), min_severity="HIGH")
    assert result["min_severity"] == "high"


# ---------------------------------------------------------------------------
# Return structure
# ---------------------------------------------------------------------------

def test_result_has_required_keys():
    result = scan_evtx(str(DCSYNC), min_severity="informational")
    assert set(result.keys()) == {"evtx_path", "min_severity", "total_findings", "findings"}

def test_total_findings_matches_list_length():
    result = scan_evtx(str(RUNDLL32), min_severity="informational")
    assert result["total_findings"] == len(result["findings"])

def test_finding_fields_present():
    result = scan_evtx(str(DCSYNC), min_severity="informational")
    finding = result["findings"][0]
    for key in ("Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID"):
        assert key in finding, f"Missing field: {key}"


# ---------------------------------------------------------------------------
# Known content
# ---------------------------------------------------------------------------

def test_dcsync_detects_mimikatz():
    result = scan_evtx(str(DCSYNC), min_severity="informational")
    titles = [f["RuleTitle"] for f in result["findings"]]
    assert any("DCSync" in t or "Mimikatz" in t for t in titles)

def test_dcsync_finding_count():
    result = scan_evtx(str(DCSYNC), min_severity="informational")
    assert result["total_findings"] == 6

def test_rdp_tunneling_findings():
    result = scan_evtx(str(RDP), min_severity="informational")
    assert result["total_findings"] == 8


# ---------------------------------------------------------------------------
# Severity filtering
# ---------------------------------------------------------------------------

def test_higher_min_severity_returns_fewer_results():
    all_results = scan_evtx(str(RDP), min_severity="informational")
    high_only = scan_evtx(str(RDP), min_severity="high")
    assert high_only["total_findings"] < all_results["total_findings"]

def test_severity_filter_excludes_lower_levels():
    result = scan_evtx(str(RDP), min_severity="high")
    low_levels = {"info", "low", "med"}
    for finding in result["findings"]:
        assert finding["Level"] not in low_levels, (
            f"Found level '{finding['Level']}' below 'high'"
        )

def test_critical_filter_on_dcsync():
    result = scan_evtx(str(DCSYNC), min_severity="critical")
    assert result["total_findings"] == 3
    assert all(f["Level"] == "crit" for f in result["findings"])


# ---------------------------------------------------------------------------
# Directory scan
# ---------------------------------------------------------------------------

def test_directory_scan():
    result = scan_evtx(str(SAMPLES), min_severity="high")
    assert result["total_findings"] > 0

def test_directory_scan_path_in_result():
    result = scan_evtx(str(SAMPLES), min_severity="high")
    assert Path(result["evtx_path"]) == SAMPLES.resolve()
