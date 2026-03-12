"""
ApprovalChecker – scans ERC-20 approval events.
Chain-aware: uses ChainConfig for the correct explorer API + key.
"""

import logging
import ssl
from typing import Any

import aiohttp
import certifi
from web3 import AsyncWeb3

from chains import ChainConfig

logger = logging.getLogger("walletguard.services.approval_checker")

SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())

APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
MAX_UINT256 = 2**256 - 1
UNLIMITED_THRESHOLD = MAX_UINT256 - 10**18

KNOWN_SAFE_SPENDERS: dict[str, str] = {
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router",
    "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3 Router",
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap Universal Router",
    "0x1111111254fb6c44bac0bed2854e76f90643097d": "1inch v4 Router",
    "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch v5 Router",
    "0xdef1c0ded9bec7f1a1670819833240f027b25eff": "0x Exchange Proxy",
    "0x00000000006c3852cbef3e08e8df289169ede581": "OpenSea Seaport",
    "0x2626664c2603336e57b271c5c0b26f421741e481": "Uniswap V3 Router (Base)",
    "0xa5e0829caced8ffdd4de3c43696c57f7d7a678ff": "QuickSwap Router",
    "0x1b02da8cb0d097eb8d57a175b88c7d8b47997506": "SushiSwap Router (Arbitrum)",
}


class ApprovalChecker:
    def __init__(self, wallet_address: str, w3: AsyncWeb3, chain: ChainConfig):
        self.wallet_address = wallet_address
        self.w3 = w3
        self.chain = chain

    async def detect(self) -> list[dict[str, Any]]:
        raw_logs = await self._fetch_approval_logs()
        findings: list[dict] = []
        seen: set[str] = set()

        for log in raw_logs:
            try:
                finding = self._parse_approval_log(log)
                if finding is None:
                    continue
                key = f"{finding['spenderAddress']}:{finding['contractAddress']}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append(finding)
            except Exception as exc:
                logger.debug("Could not parse log: %s", exc)

        logger.info(
            "Found %d approval(s) for %s on %s",
            len(findings), self.wallet_address, self.chain.name
        )
        return findings

    async def _fetch_approval_logs(self) -> list[dict]:
        owner_topic = "0x" + self.wallet_address.lower().replace("0x", "").zfill(64)
        url = (
            f"{self.chain.explorer_api}"
            f"?module=logs&action=getLogs"
            f"&fromBlock=0&toBlock=latest"
            f"&topic0={APPROVAL_TOPIC}"
            f"&topic1={owner_topic}"
            f"&topic0_1_opr=and"
            f"&apikey={self.chain.explorer_key}"
        )
        try:
            connector = aiohttp.TCPConnector(ssl=SSL_CONTEXT)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=12)) as resp:
                    data = await resp.json()
                    if data.get("status") == "1":
                        return data.get("result", [])
        except Exception as exc:
            logger.warning("Approval log fetch error on %s: %s", self.chain.name, exc)
        return []

    def _parse_approval_log(self, log: dict) -> dict | None:
        topics = log.get("topics", [])
        if len(topics) < 3:
            return None

        contract_address = log.get("address", "").lower()
        spender_address = "0x" + topics[2][-40:]

        try:
            amount_int = int(log.get("data", "0x0"), 16)
        except ValueError:
            amount_int = 0

        is_unlimited = amount_int >= UNLIMITED_THRESHOLD
        is_known = spender_address.lower() in KNOWN_SAFE_SPENDERS

        if is_unlimited and not is_known:
            risk_level = "critical"
        elif is_unlimited:
            risk_level = "high"
        elif not is_known:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "contractName": KNOWN_SAFE_SPENDERS.get(spender_address.lower(), "Unknown Contract"),
            "contractAddress": contract_address,
            "spenderAddress": spender_address,
            "approvalAmount": "Unlimited" if is_unlimited else str(amount_int),
            "riskLevel": risk_level,
            "isUnlimited": is_unlimited,
            "isKnownSpender": is_known,
        }
