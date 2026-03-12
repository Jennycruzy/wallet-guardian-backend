"""
WalletScanner – orchestrates all individual scanning services using
the provided ChainConfig, making every check chain-aware.
"""

import asyncio
import logging
import ssl
from typing import Any

import aiohttp
import certifi
from web3 import AsyncWeb3
from web3.providers import AsyncHTTPProvider

from chains import ChainConfig
from services.scam_token_detector import ScamTokenDetector
from services.approval_checker import ApprovalChecker
from services.clone_detector import CloneDetector
from services.phishing_detector import PhishingDetector
from services.risky_interaction_detector import RiskyInteractionDetector

logger = logging.getLogger("walletguard.services.wallet_scanner")

# SSL context using certifi — fixes macOS certificate verification errors
SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())


def _make_connector() -> aiohttp.TCPConnector:
    return aiohttp.TCPConnector(ssl=SSL_CONTEXT)


class WalletScanner:
    def __init__(self, address: str, chain: ChainConfig):
        self.address = address
        self.chain = chain
        self.w3 = AsyncWeb3(AsyncHTTPProvider(chain.rpc_url))

    async def run_all_checks(self) -> dict[str, Any]:
        logger.info(
            "Fetching on-chain data for %s on %s", self.address, self.chain.name
        )
        transactions, token_transfers = await asyncio.gather(
            self._fetch_transactions(),
            self._fetch_token_transfers(),
        )

        (
            scam_tokens,
            approvals,
            clone_wallets,
            phishing_signals,
            risky_interactions,
        ) = await asyncio.gather(
            ScamTokenDetector(self.address, token_transfers).detect(),
            ApprovalChecker(self.address, self.w3, self.chain).detect(),
            CloneDetector(self.address, transactions).detect(),
            PhishingDetector(self.address, transactions).detect(),
            RiskyInteractionDetector(self.address, transactions).detect(),
        )

        risk_signals: list[dict] = []
        risk_signals.extend(phishing_signals)
        risk_signals.extend(risky_interactions)

        for token in scam_tokens:
            if token["riskLevel"] in ("high", "critical"):
                risk_signals.append({
                    "type": "suspicious_token",
                    "description": f"Scam/spam token detected: {token['tokenName']}",
                    "severity": token["riskLevel"],
                })

        for approval in approvals:
            if approval["riskLevel"] in ("high", "critical"):
                risk_signals.append({
                    "type": "unlimited_approval",
                    "description": (
                        f"Unlimited approval granted to {approval['spenderAddress'][:10]}…"
                    ),
                    "severity": approval["riskLevel"],
                })

        timeline = self._build_timeline(
            transactions, scam_tokens, approvals, risky_interactions
        )

        return {
            "transactions": transactions,
            "scam_tokens": scam_tokens,
            "approvals": approvals,
            "clone_wallets": clone_wallets,
            "risk_signals": risk_signals,
            "timeline": timeline,
        }

    async def _fetch_transactions(self) -> list[dict]:
        url = (
            f"{self.chain.explorer_api}"
            f"?module=account&action=txlist"
            f"&address={self.address}"
            f"&startblock=0&endblock=99999999"
            f"&sort=desc&offset=50&page=1"
            f"&apikey={self.chain.explorer_key}"
        )
        return await self._explorer_get(url, "transactions")

    async def _fetch_token_transfers(self) -> list[dict]:
        url = (
            f"{self.chain.explorer_api}"
            f"?module=account&action=tokentx"
            f"&address={self.address}"
            f"&startblock=0&endblock=99999999"
            f"&sort=desc&offset=100&page=1"
            f"&apikey={self.chain.explorer_key}"
        )
        return await self._explorer_get(url, "token transfers")

    async def _explorer_get(self, url: str, label: str) -> list[dict]:
        try:
            async with aiohttp.ClientSession(connector=_make_connector()) as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    data = await resp.json()
                    if data.get("status") == "1":
                        return data.get("result", [])
                    logger.debug("%s response: %s", label, data.get("message", ""))
        except Exception as exc:
            logger.warning("%s fetch failed on %s: %s", label, self.chain.name, exc)
        return []

    def _build_timeline(
        self,
        transactions: list[dict],
        scam_tokens: list[dict],
        approvals: list[dict],
        risky_interactions: list[dict],
    ) -> list[dict]:
        events: list[dict] = []
        scam_addrs = {t["contractAddress"].lower() for t in scam_tokens}

        for tx in transactions[:30]:
            if tx.get("contractAddress", "").lower() in scam_addrs:
                events.append({
                    "timestamp": int(tx.get("timeStamp", 0)),
                    "event": f"Received suspicious token from {tx.get('from', '')[:10]}…",
                    "severity": "high",
                    "txHash": tx.get("hash"),
                })

        for approval in approvals:
            if approval["riskLevel"] in ("high", "critical"):
                events.append({
                    "timestamp": 0,
                    "event": (
                        f"Granted unlimited approval to {approval['spenderAddress'][:10]}…"
                        f" for {approval['contractName']}"
                    ),
                    "severity": "critical",
                    "txHash": None,
                })

        for interaction in risky_interactions:
            events.append({
                "timestamp": 0,
                "event": interaction["description"],
                "severity": interaction["severity"],
                "txHash": None,
            })

        events.sort(key=lambda e: e["timestamp"], reverse=True)
        return events
