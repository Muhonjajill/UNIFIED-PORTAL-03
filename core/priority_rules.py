# priority_rules.py

import re
import logging

logger = logging.getLogger(__name__)

# Mapping of categories → issue → priority
PRIORITY_MATRIX = {
    "Hardware Related": {
        "Note rejects": "high",
        "Hardware Error": "high",
        "Broken part": "high",
        "Note jams pathway": "medium",
        "Note jams Escrow": "medium",
    },
    "Software Related": {
        "Out of Service": "critical",
        "Account validation failing": "high",
        "Application offline": "critical",
        "Application Unresponsive": "critical",
        "Application Update": "medium",
        "Front screen unavailable": "high",
        "Failed Transactions on terminal": "high",
        "Server Update": "medium",
        "E journal not uploading": "medium",
        "Template Update": "high",
        "Firmware update": "medium",
    },
    "Cash Reconciliation": {
        "Excess cash": "high",
        "Cash shortage": "high",
    },
    "Power and Network": {
        "System off": "critical",
        "System Offline": "critical",
        "Faulty UPS/No clean Power": "high",
    },
    "De-/Installation /Maintenance": {
        "Relocation": "medium",
        "Configuration": "medium",
        "Quarterly PM": "low",
        "Re-imaging of the terminal": "medium",
    },
    "Safe": {
        "Lock/Key jam": "high",
        "Door jam": "high",
    },
    "SLA Related": {
        "General Complaint": "high",
    },
}

# Keywords that force a critical escalation
ESCALATION_KEYWORDS = {
    "urgent": ["urgent", "urgently", "emergency", "crisis", "immediate", "immediately"],
    "outage": ["outage", "down", "offline", "disconnected", "unresponsive"],
    "breach": ["breach", "violation", "failure"],
    "critical": ["critical", "severe", "disaster", "major", "critically"],
    "failure": ["failure", "breakdown", "fault", "malfunction", "error"],
    "emergency": ["emergency", "urgent", "crisis", "imminent"],
}

def determine_priority(problem_category: str, issue: str, description: str = "") -> str:
    """
    Determine ticket priority by:
      1. Scanning issue+description for escalation keywords → 'critical'
      2. Looking up exact issue in PRIORITY_MATRIX
      3. Falling back to 'medium'
    """
    text = f"{issue} {description}".lower()
    # Normalize to words only
    words = re.findall(r"\w+", text)
    logger.debug(f"Priority check text tokens: {words}")

    # 1) Check for any escalation keyword (with synonyms)
    for main_kw, variations in ESCALATION_KEYWORDS.items():
        if any(kw in words for kw in variations):  # If any variation of the keyword is found
            logger.debug(f"Escalation keyword set for '{main_kw}' found → critical")
            return "critical"

    # 2) Category-issue lookup
    issues_map = PRIORITY_MATRIX.get(problem_category, {})
    logger.debug(f"Looking up in matrix for '{problem_category}': {issues_map}")
    return issues_map.get(issue, "medium")

def get_issues_for_category(problem_category: str) -> list:
    """
    Return the list of valid issues (keys) for a given category.
    """
    return list(PRIORITY_MATRIX.get(problem_category, {}).keys())