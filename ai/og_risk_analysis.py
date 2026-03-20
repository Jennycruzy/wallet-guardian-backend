import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
import opengradient as og 

load_dotenv()
logger = logging.getLogger("walletguard.ai.og_risk_analysis")

# THE FIX: ACTUALLY use Llama-3 this time!
OG_LLM_MODEL = os.getenv("OPENGRADIENT_LLM_MODEL", "meta-llama/Llama-3-8b-chat-hf")
OG_EXPLORER_URL = "https://explorer.opengradient.ai/tx"

def _load_private_key() -> str:
    """Load OG private key from ~/.opengradient_config.json then .env fallback."""
    config_path = Path.home() / ".opengradient_config.json"
    if config_path.exists():
        try:
            data = json.loads(config_path.read_text())
            key = data.get("private_key", "")
            if key:
                return key
        except Exception as exc:
            logger.warning("Could not read OG config: %s", exc)
    return os.getenv("OPENGRADIENT_PRIVATE_KEY", "")

class OGRiskAnalyzer:
    def __init__(self):
        self.client = self._init_sdk()
        self._approval_checked = False

    def _init_sdk(self):
        try:
            private_key = _load_private_key()
            if not private_key:
                logger.error("❌ No OG private key found.")
                return None
            return og.Client(private_key=private_key)
        except Exception as exc:
            logger.error("❌ OpenGradient init failed: %s", exc)
            return None

    async def explain(self, risk_score: int, risk_signals: list[dict], timeline_events: list[dict]) -> dict[str, Any]:
        if not self.client:
            return self._fallback_explain(risk_score, risk_signals)
        return await self._og_explain(risk_score, risk_signals, timeline_events)

    async def _og_explain(self, risk_score: int, risk_signals: list[dict], timeline_events: list[dict]) -> dict[str, Any]:
        prompt = self._build_prompt(risk_score, risk_signals, timeline_events)
        messages = [
            {"role": "system", "content": "You are a blockchain security expert. Explain wallet risks for a non-technical user."},
            {"role": "user", "content": prompt},
        ]

        if not self._approval_checked:
            try:
                logger.info("Setting OpenGradient token allowance ceiling...")
                # Safe ceiling that won't revert a 0.3 balance check
                await asyncio.to_thread(self.client.llm.ensure_opg_approval, opg_amount=2.0)
                logger.info("Waiting 5 seconds for blockchain to mine approval...")
                await asyncio.sleep(5) 
                self._approval_checked = True
                logger.info("✅ OpenGradient token allowance verified and mined.")
            except Exception as e:
                logger.warning("⚠️ Could not verify OPG token approval: %s", e)

        max_retries = 3
        for attempt in range(max_retries):
            try:
                logger.info("Calling OpenGradient (model=%s) - Attempt %d", OG_LLM_MODEL, attempt + 1)
                
                # THE FIX: Llama-3 + max_tokens cap
                response = await asyncio.to_thread(
                    self.client.llm.chat,
                    model=OG_LLM_MODEL,
                    messages=messages,
                    max_tokens=300
                )

                if not response or not hasattr(response, 'chat_output') or not response.chat_output:
                    raise ValueError("TEE node returned an empty response.")

                tx_hash = getattr(response, "transaction_hash", None)
                
                if not tx_hash or tx_hash == "external":
                    display_hash = "Processing..."
                    explorer_url = "https://explorer.opengradient.ai/txs"
                else:
                    display_hash = tx_hash
                    explorer_url = f"{OG_EXPLORER_URL}/{tx_hash}"

                content = response.chat_output.get("content", "No analysis content received.")

                return {
                    "explanation": content.strip(),
                    "verifiableProof": {
                        "transactionHash": display_hash,
                        "teeProvider": "OpenGradient (AWS Nitro Enclave)",
                        "explorerUrl": explorer_url,
                    },
                    "teeEnabled": True,
                }

            except Exception as exc:
                if "500" in str(exc) or "Internal Server Error" in str(exc):
                    wait = 2 ** attempt
                    logger.warning("⚠️ TEE node busy. Retry %d/%d in %ds", attempt + 1, max_retries, wait)
                    await asyncio.sleep(wait)
                    continue
                
                logger.error("❌ OG Inference Error: %s", exc)
                break

        return self._fallback_explain(risk_score, risk_signals)

    def _build_prompt(self, risk_score: int, risk_signals: list[dict], timeline_events: list[dict]) -> str:
        risk_label = "CRITICAL" if risk_score < 30 else "HIGH" if risk_score < 50 else "MEDIUM" if risk_score < 70 else "LOW"
        signal_lines = "\n".join(f"- [{s.get('severity','?').upper()}] {s.get('description','')}" for s in risk_signals) or "None detected."
        return f"Wallet Risk Score: {risk_score}/100 ({risk_label} RISK)\n\nSignals:\n{signal_lines}\n\nExplain clearly."

    @staticmethod
    def _fallback_explain(risk_score: int, risk_signals: list[dict]) -> dict[str, Any]:
        return {
            "explanation": f"Note: AI analysis is offline. Your risk score is {risk_score}/100.",
            "verifiableProof": None,
            "teeEnabled": False,
        }