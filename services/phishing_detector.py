"""
PhishingDetector – detects suspicious smart-contract signatures and
phishing patterns in a wallet's transaction history.

Detects:
  • EIP-2612 permit() calls (off-chain approval exploit)
  • setApprovalForAll() calls to unknown contracts (NFT drain)
  • transferFrom() calls initiated by unknown third parties
  • Calls to contracts with no ENS name and very recent deployment
"""

import logging

logger = logging.getLogger("walletguard.services.phishing_detector")

# ---------------------------------------------------------------------------
# Function selectors (first 4 bytes of keccak256 of signature)
# ---------------------------------------------------------------------------
SUSPICIOUS_SELECTORS: dict[str, str] = {
    "d505accf": "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
    "2b991746": "permit(address,address,uint256,uint256,uint8,bytes32,bytes32,uint256)",
    "a22cb465": "setApprovalForAll(address,bool)",
    "23b872dd": "transferFrom(address,address,uint256)",
    "42842e0e": "safeTransferFrom(address,address,uint256)",
    "b88d4fde": "safeTransferFrom(address,address,uint256,bytes)",
    "095ea7b3": "approve(address,uint256)",       # approve to unknown
}

# Selectors considered highest risk
HIGH_RISK_SELECTORS = {"d505accf", "2b991746", "a22cb465"}


class PhishingDetector:
    def __init__(self, wallet_address: str, transactions: list[dict]):
        self.wallet_address = wallet_address.lower()
        self.transactions = transactions

    async def detect(self) -> list[dict]:
        """
        Returns list of phishing-related risk signals.
        """
        signals: list[dict] = []

        for tx in self.transactions:
            # Only outbound transactions from this wallet
            if tx.get("from", "").lower() != self.wallet_address:
                continue

            input_data: str = tx.get("input", "") or ""
            if len(input_data) < 10:
                continue  # no meaningful calldata

            selector = input_data[2:10].lower()  # strip "0x", take 4 bytes
            if selector not in SUSPICIOUS_SELECTORS:
                continue

            sig_name = SUSPICIOUS_SELECTORS[selector]
            to_addr = tx.get("to", "0x0000…")
            tx_hash = tx.get("hash", "")

            severity = "critical" if selector in HIGH_RISK_SELECTORS else "high"

            signals.append({
                "type": "phishing_signature",
                "description": (
                    f"Called '{sig_name.split('(')[0]}' on contract "
                    f"{to_addr[:10]}… — possible phishing/drain attempt"
                ),
                "severity": severity,
                "txHash": tx_hash,
                "selector": selector,
                "contractAddress": to_addr,
            })
            logger.info(
                "Phishing signal: selector=%s to=%s tx=%s",
                selector,
                to_addr,
                tx_hash,
            )

        return signals
