"""
chains.py – Multi-chain configuration for WalletGuard.

All Etherscan-family explorers (Etherscan, Basescan, Polygonscan,
Arbiscan, BscScan, Optimistic Etherscan) share the same API key —
one ETHERSCAN_API_KEY covers all chains.
"""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class ChainConfig:
    id: str                  # internal key e.g. "ethereum"
    name: str
    chain_id: int
    rpc_url: str
    explorer_api: str        # base URL for Etherscan-compatible API
    explorer_key: str        # shared Etherscan API key
    native_symbol: str


def _env(var: str, fallback: str = "") -> str:
    return os.getenv(var, fallback)


# One key for all Etherscan-family explorers
_ETHERSCAN_KEY = _env("ETHERSCAN_API_KEY", "")


CHAINS: dict[str, ChainConfig] = {
    "ethereum": ChainConfig(
        id="ethereum",
        name="Ethereum Mainnet",
        chain_id=1,
        rpc_url=_env("ETH_RPC_URL", "https://cloudflare-eth.com"),
        explorer_api="https://api.etherscan.io/api",
        explorer_key=_ETHERSCAN_KEY,
        native_symbol="ETH",
    ),
    "base": ChainConfig(
        id="base",
        name="Base",
        chain_id=8453,
        rpc_url=_env("BASE_RPC_URL", "https://mainnet.base.org"),
        explorer_api="https://api.basescan.org/api",
        explorer_key=_ETHERSCAN_KEY,
        native_symbol="ETH",
    ),
    "polygon": ChainConfig(
        id="polygon",
        name="Polygon",
        chain_id=137,
        rpc_url=_env("POLYGON_RPC_URL", "https://polygon-rpc.com"),
        explorer_api="https://api.polygonscan.com/api",
        explorer_key=_ETHERSCAN_KEY,
        native_symbol="MATIC",
    ),
    "arbitrum": ChainConfig(
        id="arbitrum",
        name="Arbitrum One",
        chain_id=42161,
        rpc_url=_env("ARBITRUM_RPC_URL", "https://arb1.arbitrum.io/rpc"),
        explorer_api="https://api.arbiscan.io/api",
        explorer_key=_ETHERSCAN_KEY,
        native_symbol="ETH",
    ),
    "bsc": ChainConfig(
        id="bsc",
        name="BNB Smart Chain",
        chain_id=56,
        rpc_url=_env("BSC_RPC_URL", "https://bsc-dataseed.binance.org"),
        explorer_api="https://api.bscscan.com/api",
        explorer_key=_ETHERSCAN_KEY,
        native_symbol="BNB",
    ),
    "optimism": ChainConfig(
        id="optimism",
        name="Optimism",
        chain_id=10,
        rpc_url=_env("OPTIMISM_RPC_URL", "https://mainnet.optimism.io"),
        explorer_api="https://api-optimistic.etherscan.io/api",
        explorer_key=_ETHERSCAN_KEY,
        native_symbol="ETH",
    ),
}

DEFAULT_CHAIN = "ethereum"


def get_chain(chain_id: str) -> ChainConfig:
    """Return ChainConfig by id string, raising ValueError if unknown."""
    if chain_id not in CHAINS:
        raise ValueError(
            f"Unsupported chain '{chain_id}'. "
            f"Available: {', '.join(CHAINS.keys())}"
        )
    return CHAINS[chain_id]
