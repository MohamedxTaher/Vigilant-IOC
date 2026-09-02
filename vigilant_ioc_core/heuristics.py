"""Risk scoring for extracted IOCs and document findings."""

from __future__ import annotations

from enum import Enum
from typing import Dict, List

from logger import get_logger
from settings import RISK_WEIGHTS, VT_THRESHOLD, ABUSE_CONFIDENCE_CUTOFF

log = get_logger(__name__)


class ThreatLevel(str, Enum):
    """Severity label for the final score."""

    BENIGN = "benign"
    LOW = "low"
    MEDIUM = "medium"
    SUSPICIOUS = "suspicious"
    HIGH = "high"
    CRITICAL = "critical"


def score_to_threat_level(score: int) -> ThreatLevel:
    """Convert a 0-100 risk score to a severity level."""
    if score < 10:
        return ThreatLevel.BENIGN
    if score < 25:
        return ThreatLevel.LOW
    if score < 50:
        return ThreatLevel.MEDIUM
    if score < 75:
        return ThreatLevel.HIGH
    return ThreatLevel.CRITICAL


# --------------------------------------------------------------------------- #
# Core scoring
# --------------------------------------------------------------------------- #
def score(findings: Dict) -> Dict:
    """
    Score document findings with heuristic weights and threat intelligence.

    Mutates *findings* dict in-place, adding:
    - score: 0-100 risk score
    - verdict: threat level (benign/low/medium/high/critical)
    - threat_level: ThreatLevel enum
    - summary: human-readable reason string

    Parameters
    ----------
    findings : Dict
        Document analysis findings dict from parsers

    Returns
    -------
    Dict
        Same dict with score, verdict, threat_level, and summary added
    """
    total: int = 0
    reasons: List[str] = []

    # 1) Macro present
    if findings.get("macro"):
        total += RISK_WEIGHTS["macro"]
        reasons.append("macro detected")

    # 2) Suspicious VBA keywords
    kw: List[str] = findings.get("suspicious_keywords", [])
    if kw:
        total += min(len(kw) * 2, 15)
        reasons.append("suspicious VBA keywords")

    # 3) Auto-exec functions (critical macro behavior)
    if findings.get("autoexec_funcs"):
        total += RISK_WEIGHTS["autoexec"]
        reasons.append("auto-exec macro")

    # 4) String obfuscation (encoding/hiding)
    if findings.get("string_obfuscation", 0):
        total += RISK_WEIGHTS["obfuscation"]
        reasons.append("obfuscation detected")

    # 5) Suspicious API calls
    if findings.get("suspicious_calls"):
        total += min(len(findings["suspicious_calls"]) * RISK_WEIGHTS["susp_call"], 15)
        reasons.append("suspicious API calls")

    # 6) URL reputation - VirusTotal lookups
    for info in findings.get("url_rep", {}).values():
        if info.get("vendors", 0) >= VT_THRESHOLD:
            total += RISK_WEIGHTS["malicious_url"]
            reasons.append("malicious URL (VirusTotal consensus)")

    # 7) IP reputation - AbuseIPDB lookups
    for info in findings.get("ip_rep", {}).values():
        if info.get("abuse_confidence", 0) >= ABUSE_CONFIDENCE_CUTOFF:
            total += RISK_WEIGHTS["malicious_ip"]
            reasons.append("malicious IP (AbuseIPDB high confidence)")

    # 8) PDF-specific heuristics
    if findings.get("embedded_files", 0) > 0:
        total += 10
        reasons.append("embedded file(s) detected")

    if findings.get("js_count", 0) > 0:
        total += 10
        reasons.append("JavaScript in PDF")

    # Clamp to 0-100
    total = max(0, min(total, 100))

    # Map the score to a threat label. Keep the historical public verdict
    # "suspicious" for the 25-49 range used by the project tests and callers.
    threat_level: ThreatLevel = score_to_threat_level(total)
    verdict: str = "suspicious" if 25 <= total < 50 else threat_level.value

    # Build summary
    summary: str = ", ".join(reasons) if reasons else "No significant issues detected"

    # Update findings dict
    findings.update(
        score=total,
        verdict=verdict,
        threat_level=threat_level.value,
        summary=summary,
    )

    log.debug(
        "Scored %s → %s (%d) | Threat: %s | Reasons: %s",
        findings.get("name") or findings.get("type", "unknown"),
        verdict,
        total,
        threat_level.name,
        "; ".join(reasons) or "none",
    )
    return findings
