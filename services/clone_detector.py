"""
CloneDetector – detects visually similar (impersonator) wallet addresses
by comparing prefix and suffix similarity.

Algorithm:
  1. Extract all addresses from transaction history.
  2. Compare PREFIX (first N chars after 0x) and SUFFIX (last N chars).
  3. Flag addresses that share both a significant prefix AND suffix with
     the target wallet but differ in the middle – classic clone pattern.

Example:
  Target:  0x9A1B...cd34...8F12
  Clone:   0x9A1B...ef56...8F1A  ← same 4-char prefix AND near-identical 3-char suffix
"""

import logging
from difflib import SequenceMatcher

logger = logging.getLogger("walletguard.services.clone_detector")

# Tuning parameters
PREFIX_LEN = 6   # chars after "0x" to compare
SUFFIX_LEN = 6   # tail chars to compare
PREFIX_MATCH_REQUIRED = 4   # minimum matching prefix chars to trigger
SUFFIX_MATCH_REQUIRED = 4   # minimum matching suffix chars to trigger
OVERALL_SIMILARITY_FLOOR = 0.30  # overall must differ enough to avoid self-match


class CloneDetector:
    def __init__(self, wallet_address: str, transactions: list[dict]):
        self.wallet_address = wallet_address.lower()
        self.transactions = transactions

    async def detect(self) -> list[dict]:
        """
        Returns list of suspected clone wallet findings.
        """
        candidates = self._collect_unique_addresses()
        clones: list[dict] = []

        target_hex = self.wallet_address[2:]  # strip 0x
        target_prefix = target_hex[:PREFIX_LEN]
        target_suffix = target_hex[-SUFFIX_LEN:]

        for addr in candidates:
            addr_hex = addr[2:]
            prefix = addr_hex[:PREFIX_LEN]
            suffix = addr_hex[-SUFFIX_LEN:]

            prefix_match = self._common_prefix_len(target_prefix, prefix)
            suffix_match = self._common_suffix_len(target_suffix, suffix)

            if prefix_match < PREFIX_MATCH_REQUIRED and suffix_match < SUFFIX_MATCH_REQUIRED:
                continue

            overall_sim = SequenceMatcher(None, target_hex, addr_hex).ratio()
            # Must be similar enough to be a clone but NOT the same address
            if overall_sim >= 0.99:
                continue

            match_type = self._determine_match_type(prefix_match, suffix_match)
            similarity_score = round(
                (prefix_match / PREFIX_LEN * 0.5 + suffix_match / SUFFIX_LEN * 0.5) * 100, 1
            )

            clones.append({
                "suspectedAddress": addr,
                "similarityScore": similarity_score,
                "matchType": match_type,
                "prefixMatch": prefix_match,
                "suffixMatch": suffix_match,
            })
            logger.info(
                "Clone detected: %s (type=%s, score=%.1f)",
                addr,
                match_type,
                similarity_score,
            )

        # Sort by similarity descending
        clones.sort(key=lambda c: c["similarityScore"], reverse=True)
        return clones[:10]  # cap at 10 results

    # ------------------------------------------------------------------

    def _collect_unique_addresses(self) -> set[str]:
        """Extract every unique address that interacted with the wallet."""
        addresses: set[str] = set()
        for tx in self.transactions:
            for field in ("from", "to", "contractAddress"):
                addr = tx.get(field, "").lower()
                if addr and addr != self.wallet_address and addr.startswith("0x") and len(addr) == 42:
                    addresses.add(addr)
        return addresses

    @staticmethod
    def _common_prefix_len(a: str, b: str) -> int:
        count = 0
        for ca, cb in zip(a, b):
            if ca == cb:
                count += 1
            else:
                break
        return count

    @staticmethod
    def _common_suffix_len(a: str, b: str) -> int:
        count = 0
        for ca, cb in zip(reversed(a), reversed(b)):
            if ca == cb:
                count += 1
            else:
                break
        return count

    @staticmethod
    def _determine_match_type(prefix_match: int, suffix_match: int) -> str:
        has_prefix = prefix_match >= PREFIX_MATCH_REQUIRED
        has_suffix = suffix_match >= SUFFIX_MATCH_REQUIRED
        if has_prefix and has_suffix:
            return "both"
        if has_prefix:
            return "prefix"
        return "suffix"
