"""
RiskScorer – computes a 0-100 wallet risk score.

Starts at 100 and subtracts deductions based on detected signals.
Final score is clamped to [0, 100].

Deduction table:
  Suspicious token detected       -20 (max once per wallet)
  Unlimited approval found        -20 (max once per wallet)
  Risky wallet interaction        -15 (max once per wallet)
  Clone impersonator detected     -15 (max once per wallet)
  Phishing signature detected     -10 (max once per wallet)
  
  Additional per-finding penalty  -5  (for each extra critical finding)
"""

import logging

logger = logging.getLogger("walletguard.services.risk_scoring")

# Base deductions (applied at most once per category)
DEDUCTIONS = {
    "suspicious_token": 20,
    "unlimited_approval": 20,
    "risky_wallet_interaction": 15,
    "clone_impersonator": 15,
    "phishing_signature": 10,
}

# Extra deduction per additional critical finding beyond the first
EXTRA_CRITICAL_DEDUCTION = 5


class RiskScorer:
    def __init__(self, scan_data: dict):
        self.scan_data = scan_data

    def compute(self) -> int:
        score = 100
        applied: set[str] = set()
        extra_critical = 0

        risk_signals: list[dict] = self.scan_data.get("risk_signals", [])
        scam_tokens: list[dict] = self.scan_data.get("scam_tokens", [])
        approvals: list[dict] = self.scan_data.get("approvals", [])
        clone_wallets: list[dict] = self.scan_data.get("clone_wallets", [])

        # --- Suspicious tokens ---
        if scam_tokens:
            score -= DEDUCTIONS["suspicious_token"]
            applied.add("suspicious_token")
            critical_count = sum(1 for t in scam_tokens if t.get("riskLevel") == "critical")
            extra_critical += max(0, critical_count - 1)

        # --- Unlimited approvals ---
        unlimited = [a for a in approvals if a.get("isUnlimited")]
        if unlimited:
            score -= DEDUCTIONS["unlimited_approval"]
            applied.add("unlimited_approval")
            critical_count = sum(1 for a in unlimited if a.get("riskLevel") == "critical")
            extra_critical += max(0, critical_count - 1)

        # --- Risky interactions ---
        risky = [s for s in risk_signals if s["type"] == "risky_wallet_interaction"]
        if risky:
            score -= DEDUCTIONS["risky_wallet_interaction"]
            applied.add("risky_wallet_interaction")
            critical_count = sum(1 for s in risky if s.get("severity") == "critical")
            extra_critical += max(0, critical_count - 1)

        # --- Clone wallets ---
        if clone_wallets:
            score -= DEDUCTIONS["clone_impersonator"]
            applied.add("clone_impersonator")

        # --- Phishing signatures ---
        phishing = [s for s in risk_signals if s["type"] == "phishing_signature"]
        if phishing:
            score -= DEDUCTIONS["phishing_signature"]
            applied.add("phishing_signature")
            critical_count = sum(1 for s in phishing if s.get("severity") == "critical")
            extra_critical += max(0, critical_count - 1)

        # Extra critical penalty
        score -= extra_critical * EXTRA_CRITICAL_DEDUCTION

        final_score = max(0, min(100, score))
        logger.info(
            "Risk score: %d (deductions=%s, extra_critical=%d)",
            final_score,
            applied,
            extra_critical,
        )
        return final_score
