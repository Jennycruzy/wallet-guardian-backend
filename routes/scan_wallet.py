"""
POST /scan-wallet – orchestrates all scanning services and returns
a structured wallet risk report, with optional multi-chain support.
"""

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator

from chains import CHAINS, DEFAULT_CHAIN, get_chain
from services.wallet_scanner import WalletScanner
from services.risk_scoring import RiskScorer
from ai.og_risk_analysis import OGRiskAnalyzer

logger = logging.getLogger("walletguard.routes.scan_wallet")

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    wallet_address: str
    chain: str = DEFAULT_CHAIN   # e.g. "ethereum" | "base" | "polygon" | ...

    @field_validator("wallet_address")
    @classmethod
    def validate_address(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith("0x") or len(v) != 42:
            raise ValueError(
                "wallet_address must be a valid EVM address (0x + 40 hex chars)"
            )
        return v.lower()

    @field_validator("chain")
    @classmethod
    def validate_chain(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in CHAINS:
            raise ValueError(
                f"Unsupported chain '{v}'. Supported: {', '.join(CHAINS.keys())}"
            )
        return v


class ScamToken(BaseModel):
    tokenName: str
    contractAddress: str
    riskLevel: str


class Approval(BaseModel):
    contractName: str
    spenderAddress: str
    approvalAmount: str
    riskLevel: str


class RiskSignal(BaseModel):
    type: str
    description: str
    severity: str


class CloneWallet(BaseModel):
    suspectedAddress: str
    similarityScore: float
    matchType: str


class TimelineEvent(BaseModel):
    timestamp: int
    event: str
    severity: str
    txHash: str | None = None


class AIExplanationResult(BaseModel):
    explanation: str
    verifiableProof: dict | None = None
    teeEnabled: bool


class ScanResponse(BaseModel):
    walletAddress: str
    chain: str
    chainName: str
    walletRiskScore: int
    riskSignals: list[RiskSignal]
    scamTokens: list[ScamToken]
    cloneWallets: list[CloneWallet]
    approvals: list[Approval]
    timelineEvents: list[TimelineEvent]
    aiExplanation: AIExplanationResult


# ---------------------------------------------------------------------------
# Supported chains info endpoint
# ---------------------------------------------------------------------------

@router.get("/chains")
async def list_chains():
    """List all supported chains."""
    return {
        "chains": [
            {"id": c.id, "name": c.name, "chainId": c.chain_id, "nativeSymbol": c.native_symbol}
            for c in CHAINS.values()
        ]
    }


# ---------------------------------------------------------------------------
# Main scan endpoint
# ---------------------------------------------------------------------------

@router.post("/scan-wallet", response_model=ScanResponse)
async def scan_wallet(body: ScanRequest):
    """
    Full wallet security scan across any supported EVM chain.
    Specify 'chain' in the request body (default: ethereum).
    """
    address = body.wallet_address
    chain_cfg = get_chain(body.chain)

    logger.info("Starting scan for %s on %s", address, chain_cfg.name)

    try:
        scanner = WalletScanner(address, chain_cfg)
        scan_data = await scanner.run_all_checks()
    except Exception as exc:
        logger.exception("Scanning failed for %s on %s", address, chain_cfg.name)
        raise HTTPException(status_code=502, detail=f"Scanning error: {exc}") from exc

    scorer = RiskScorer(scan_data)
    risk_score = scorer.compute()
    timeline = scan_data.get("timeline", [])

    try:
        analyzer = OGRiskAnalyzer()
        ai_result = await analyzer.explain(
            risk_score=risk_score,
            risk_signals=scan_data.get("risk_signals", []),
            timeline_events=timeline,
        )
    except Exception as exc:
        logger.warning("AI explanation failed: %s", exc)
        ai_result = AIExplanationResult(
            explanation="AI analysis temporarily unavailable.",
            verifiableProof=None,
            teeEnabled=False,
        )

    return ScanResponse(
        walletAddress=address,
        chain=chain_cfg.id,
        chainName=chain_cfg.name,
        walletRiskScore=risk_score,
        riskSignals=[RiskSignal(**s) for s in scan_data.get("risk_signals", [])],
        scamTokens=[ScamToken(**t) for t in scan_data.get("scam_tokens", [])],
        cloneWallets=[CloneWallet(**c) for c in scan_data.get("clone_wallets", [])],
        approvals=[Approval(**a) for a in scan_data.get("approvals", [])],
        timelineEvents=[TimelineEvent(**e) for e in timeline],
        aiExplanation=ai_result,
    )
