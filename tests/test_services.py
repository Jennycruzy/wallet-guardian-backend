"""
WalletGuard – test suite
Run with: pytest tests/ -v
"""

import pytest
import asyncio

# ---------------------------------------------------------------------------
# ScamTokenDetector
# ---------------------------------------------------------------------------
from services.scam_token_detector import ScamTokenDetector

WALLET = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"

MOCK_TOKEN_TRANSFERS = [
    # Scam airdrop token
    {
        "contractAddress": "0x1111111111111111111111111111111111111111",
        "tokenName": "Free Airdrop 2024 Claim Now",
        "tokenSymbol": "AIRDROP",
        "value": "0",
        "to": WALLET,
        "from": "0x9999999999999999999999999999999999999999",
        "timeStamp": "1700000000",
        "hash": "0xaaa",
    },
    # Legitimate token
    {
        "contractAddress": "0x2222222222222222222222222222222222222222",
        "tokenName": "Chainlink Token",
        "tokenSymbol": "LINK",
        "value": "1000000000000000000",
        "to": WALLET,
        "from": "0x8888888888888888888888888888888888888888",
        "timeStamp": "1700000001",
        "hash": "0xbbb",
    },
]


@pytest.mark.asyncio
async def test_scam_token_detected():
    detector = ScamTokenDetector(WALLET, MOCK_TOKEN_TRANSFERS)
    results = await detector.detect()
    # Should detect the airdrop scam token
    assert any("Airdrop" in r["tokenName"] or "airdrop" in r["tokenName"].lower() for r in results)


@pytest.mark.asyncio
async def test_legitimate_token_not_flagged():
    detector = ScamTokenDetector(WALLET, MOCK_TOKEN_TRANSFERS)
    results = await detector.detect()
    # Chainlink should not be flagged
    contracts = [r["contractAddress"] for r in results]
    assert "0x2222222222222222222222222222222222222222" not in contracts


# ---------------------------------------------------------------------------
# CloneDetector
# ---------------------------------------------------------------------------
from services.clone_detector import CloneDetector

MOCK_TRANSACTIONS_CLONE = [
    # Near-clone of target: same first 4 chars and last 4 chars
    {
        "from": "0xabcd1234567890abcdefabcdefabcdef0000abce",  # slightly different suffix
        "to": WALLET,
        "contractAddress": "",
        "hash": "0xccc",
        "timeStamp": "1700000010",
        "input": "0x",
    },
    # Completely different
    {
        "from": "0x0000000000000000000000000000000000000001",
        "to": WALLET,
        "contractAddress": "",
        "hash": "0xddd",
        "timeStamp": "1700000011",
        "input": "0x",
    },
]


@pytest.mark.asyncio
async def test_clone_detected():
    detector = CloneDetector(WALLET, MOCK_TRANSACTIONS_CLONE)
    clones = await detector.detect()
    # The near-clone should be detected
    addresses = [c["suspectedAddress"] for c in clones]
    assert "0xabcd1234567890abcdefabcdefabcdef0000abce" in addresses


@pytest.mark.asyncio
async def test_no_self_clone():
    """The wallet itself must never be flagged as its own clone."""
    txs = [{"from": WALLET, "to": "0x1234", "contractAddress": "", "hash": "0x1", "input": "0x"}]
    detector = CloneDetector(WALLET, txs)
    clones = await detector.detect()
    assert all(c["suspectedAddress"] != WALLET for c in clones)


# ---------------------------------------------------------------------------
# PhishingDetector
# ---------------------------------------------------------------------------
from services.phishing_detector import PhishingDetector

MOCK_TXS_PHISHING = [
    # permit() call - selector d505accf
    {
        "from": WALLET,
        "to": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "input": "0xd505accf000000000000000000000000000000000000000000000000",
        "hash": "0xeee",
        "timeStamp": "1700000020",
    },
    # Normal ETH transfer
    {
        "from": WALLET,
        "to": "0xaaaa",
        "input": "0x",
        "hash": "0xfff",
        "timeStamp": "1700000021",
    },
]


@pytest.mark.asyncio
async def test_phishing_signature_detected():
    detector = PhishingDetector(WALLET, MOCK_TXS_PHISHING)
    signals = await detector.detect()
    assert any(s["type"] == "phishing_signature" for s in signals)
    assert any("permit" in s["description"].lower() for s in signals)


@pytest.mark.asyncio
async def test_normal_tx_not_flagged():
    txs = [{"from": WALLET, "to": "0xaaaa", "input": "0x", "hash": "0x1", "timeStamp": "0"}]
    detector = PhishingDetector(WALLET, txs)
    signals = await detector.detect()
    assert len(signals) == 0


# ---------------------------------------------------------------------------
# RiskScorer
# ---------------------------------------------------------------------------
from services.risk_scoring import RiskScorer


def test_perfect_score_no_findings():
    scorer = RiskScorer({"risk_signals": [], "scam_tokens": [], "approvals": [], "clone_wallets": []})
    assert scorer.compute() == 100


def test_score_deduction_unlimited_approval():
    scan_data = {
        "risk_signals": [],
        "scam_tokens": [],
        "approvals": [{"isUnlimited": True, "riskLevel": "critical"}],
        "clone_wallets": [],
    }
    scorer = RiskScorer(scan_data)
    score = scorer.compute()
    assert score == 80  # 100 - 20


def test_score_multiple_deductions():
    scan_data = {
        "risk_signals": [
            {"type": "risky_wallet_interaction", "severity": "critical", "description": "test"},
            {"type": "phishing_signature", "severity": "critical", "description": "test"},
        ],
        "scam_tokens": [{"riskLevel": "high"}],
        "approvals": [{"isUnlimited": True, "riskLevel": "critical"}],
        "clone_wallets": [{"suspectedAddress": "0xabce", "similarityScore": 80}],
    }
    scorer = RiskScorer(scan_data)
    score = scorer.compute()
    # 100 - 20 (token) - 20 (approval) - 15 (risky) - 15 (clone) - 10 (phishing) = 20
    assert score == 20


def test_score_never_below_zero():
    scan_data = {
        "risk_signals": [
            {"type": "risky_wallet_interaction", "severity": "critical", "description": "x"}
            for _ in range(20)
        ] + [
            {"type": "phishing_signature", "severity": "critical", "description": "x"}
            for _ in range(20)
        ],
        "scam_tokens": [{"riskLevel": "critical"} for _ in range(10)],
        "approvals": [{"isUnlimited": True, "riskLevel": "critical"} for _ in range(10)],
        "clone_wallets": [{"x": 1}],
    }
    scorer = RiskScorer(scan_data)
    assert scorer.compute() >= 0
