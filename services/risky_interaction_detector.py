"""
RiskyInteractionDetector – detects wallet interactions with addresses
listed in publicly known scam / exploit / sanctions databases.

In production, integrate real threat-intel feeds such as:
  • Forta Network threat database
  • Chainalysis sanctions API
  • MistTrack flagged addresses
  • De.Fi / Revoke.cash blacklist feeds
"""

import logging

logger = logging.getLogger("walletguard.services.risky_interaction_detector")

# ---------------------------------------------------------------------------
# Static threat database (illustrative – replace with live feeds in prod)
# ---------------------------------------------------------------------------
KNOWN_RISKY_ADDRESSES: dict[str, dict] = {
    # address_lower → {label, category, severity}
    "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b": {
        "label": "Lazarus Group (OFAC sanctioned)",
        "category": "sanctions",
        "severity": "critical",
    },
    "0x098b716b8aaf21512996dc57eb0615e2383e2f96": {
        "label": "Ronin Bridge Exploit (Lazarus)",
        "category": "exploit",
        "severity": "critical",
    },
    "0xa7efae728d2936e78bda97dc267687568dd593f3": {
        "label": "Tornado Cash (OFAC sanctioned)",
        "category": "sanctions",
        "severity": "critical",
    },
    "0x8576acc5c05d6ce88f4e49bf65bdf0c62f91353c": {
        "label": "FTX Hack Drainer",
        "category": "exploit",
        "severity": "critical",
    },
    "0x6f1ca141a28907f78ebaa64fb83a9088b02a8352": {
        "label": "Alphapo Hot Wallet (Lazarus)",
        "category": "sanctions",
        "severity": "critical",
    },
    # Add thousands more from live threat-intel in production
}


class RiskyInteractionDetector:
    def __init__(self, wallet_address: str, transactions: list[dict]):
        self.wallet_address = wallet_address.lower()
        self.transactions = transactions

    async def detect(self) -> list[dict]:
        """
        Returns list of risk signals for interactions with flagged addresses.
        """
        signals: list[dict] = []
        seen: set[str] = set()

        for tx in self.transactions:
            counterparty = self._get_counterparty(tx)
            if not counterparty or counterparty in seen:
                continue

            threat = KNOWN_RISKY_ADDRESSES.get(counterparty)
            if threat is None:
                continue

            seen.add(counterparty)

            direction = (
                "sent to" if tx.get("from", "").lower() == self.wallet_address else "received from"
            )
            signals.append({
                "type": "risky_wallet_interaction",
                "description": (
                    f"Wallet {direction} {threat['label']} "
                    f"({counterparty[:10]}…) — category: {threat['category']}"
                ),
                "severity": threat["severity"],
                "flaggedAddress": counterparty,
                "label": threat["label"],
                "txHash": tx.get("hash", ""),
            })
            logger.warning(
                "Risky interaction detected: %s (%s)",
                counterparty,
                threat["label"],
            )

        return signals

    def _get_counterparty(self, tx: dict) -> str | None:
        from_addr = tx.get("from", "").lower()
        to_addr = tx.get("to", "").lower()

        if from_addr == self.wallet_address:
            return to_addr if to_addr else None
        if to_addr == self.wallet_address:
            return from_addr if from_addr else None
        return None
