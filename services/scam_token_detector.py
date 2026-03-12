"""
ScamTokenDetector – detects scam, spam and honeypot tokens in a wallet's
token transfer history using on-chain heuristics.
"""

import logging
import re

logger = logging.getLogger("walletguard.services.scam_token_detector")

# ---------------------------------------------------------------------------
# Heuristic rule sets
# ---------------------------------------------------------------------------

# Known scam / airdrop token name patterns (regex, case-insensitive)
SCAM_NAME_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"free\s*(airdrop|drop|claim)",
        r"(airdrop|drop)\s*\d+",
        r"\$\d+[\.,]\d*\s*(usd|usdt|usdc|eth)",
        r"visit\s*http",
        r"claim\s*(now|your|reward)",
        r"(reward|bonus|gift)\s*(token|coin)",
        r"(scam|spam|phishing|hack)",
        r"(\d{4,}x\s*return)",
        r"(safe|legit|trust)\s*(moon|inu|shib)",
        r"elon|musk.*coin",
        r"(v[23456]|v\s*[23456])\s*$",   # fake "v2" upgrades
    ]
]

# Addresses known to deploy mass airdrop scams (illustrative list)
KNOWN_SCAM_DEPLOYERS: set[str] = {
    "0x0000000000000000000000000000000000000000",
    # Add real flagged addresses from threat-intelligence feeds here
}

# Tokens whose supply is astronomically large (common honeypot pattern)
HONEYPOT_SUPPLY_THRESHOLD = 10 ** 30  # >1 nonillion tokens = red flag


class ScamTokenDetector:
    def __init__(self, wallet_address: str, token_transfers: list[dict]):
        self.wallet_address = wallet_address
        self.token_transfers = token_transfers

    async def detect(self) -> list[dict]:
        """
        Returns a list of detected scam tokens with risk metadata.
        """
        findings: list[dict] = []
        seen: set[str] = set()

        for tx in self.token_transfers:
            contract = tx.get("contractAddress", "").lower()
            token_name = tx.get("tokenName", "")
            token_symbol = tx.get("tokenSymbol", "")
            token_decimal = tx.get("tokenDecimal", "18")
            value = int(tx.get("value", "0"))
            to_addr = tx.get("to", "").lower()
            from_addr = tx.get("from", "").lower()

            # Only inspect tokens received by our wallet
            if to_addr != self.wallet_address.lower():
                continue

            if contract in seen:
                continue
            seen.add(contract)

            risk_level, reasons = self._evaluate_token(
                token_name, token_symbol, contract, from_addr, value, token_decimal
            )

            if risk_level != "safe":
                findings.append({
                    "tokenName": token_name or token_symbol or "Unknown Token",
                    "contractAddress": contract,
                    "riskLevel": risk_level,
                    "reasons": reasons,
                })
                logger.info(
                    "Scam token detected: %s (%s) – %s",
                    token_name,
                    contract,
                    risk_level,
                )

        return findings

    # ------------------------------------------------------------------
    # Internal heuristics
    # ------------------------------------------------------------------

    def _evaluate_token(
        self,
        name: str,
        symbol: str,
        contract: str,
        from_addr: str,
        value: int,
        decimal: str,
    ) -> tuple[str, list[str]]:
        reasons: list[str] = []

        # 1. Name-based heuristics
        for pattern in SCAM_NAME_PATTERNS:
            if pattern.search(name) or pattern.search(symbol):
                reasons.append(f"Suspicious name/symbol pattern: '{name} ({symbol})'")
                break

        # 2. Known scam deployer
        if from_addr in KNOWN_SCAM_DEPLOYERS:
            reasons.append("Token deployed/sent by known scam address")

        # 3. Zero-value transfer (phishing bait)
        if value == 0:
            reasons.append("Zero-value token transfer (common phishing bait)")

        # 4. Honeypot supply heuristic (very large value sent)
        try:
            decimals = int(decimal)
            normalised_value = value / (10 ** decimals)
            if normalised_value > 1e15:
                reasons.append("Absurdly large token amount – likely honeypot lure")
        except (ValueError, ZeroDivisionError):
            pass

        # 5. Empty / very short symbol
        if len(symbol.strip()) <= 1:
            reasons.append("Missing or single-character token symbol")

        # Map number of reasons → risk level
        if not reasons:
            return "safe", []
        if len(reasons) == 1:
            return "medium", reasons
        if len(reasons) == 2:
            return "high", reasons
        return "critical", reasons
