"""Central configuration for SQLiRLLM.

Holds the reward-function weights (exactly as defined in the paper), the
reinforcement-learning hyper-parameters, the testing strategy/state vocabulary,
and the GapGPT (OpenAI-compatible) client settings.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List

from dotenv import load_dotenv

# Load .env (if present) so GAPGPT_API_KEY etc. become available.
load_dotenv()


# --------------------------------------------------------------------------- #
# Action space (Section III): six primary SQLi testing strategies.            #
# --------------------------------------------------------------------------- #
STRATEGIES: List[str] = [
    "union_based",
    "error_based",
    "boolean_blind",
    "time_blind",
    "stacked_queries",
    "second_order",
]

# State-space vocabularies (Section III, State Space).
FRAMEWORKS: List[str] = ["laravel", "django", "express", "flask", "rails"]
DATABASES: List[str] = ["mysql", "postgresql", "oracle", "mssql", "sqlite"]
PHASES: List[str] = ["initial", "refinement", "exploitation", "verification"]


@dataclass(frozen=True)
class RewardWeights:
    """Multi-objective reward weights, matching the paper exactly.

    R(s, a, s') = alpha*VDR(a) + beta*ESR(a) - gamma*FPR(a) - delta*Time(a)
    """

    alpha: float = 0.6   # Vulnerability Detection Rate weight
    beta: float = 0.3    # Ethical Safeguard Rating weight
    gamma: float = 0.1   # False Positive Rate penalty
    delta: float = 0.05  # Time penalty
    ethical_violation_penalty: float = -100.0


@dataclass(frozen=True)
class QLearningParams:
    """Tabular Q-learning hyper-parameters (Strategic Planning Layer)."""

    learning_rate: float = 0.15      # alpha in the Q-update
    discount_factor: float = 0.90    # gamma (future reward discount)
    epsilon_start: float = 1.0       # initial exploration
    epsilon_min: float = 0.05
    epsilon_decay: float = 0.995     # per-episode multiplicative decay
    max_steps_per_episode: int = 12


@dataclass
class LLMConfig:
    """GapGPT / OpenAI-compatible client configuration."""

    base_url: str = field(default_factory=lambda: os.getenv("GAPGPT_BASE_URL", "https://api.gapgpt.app/v1"))
    api_key: str = field(default_factory=lambda: os.getenv("GAPGPT_API_KEY", ""))
    # Tier 2 — payload generation (small, efficient model: Phi-3-Mini analog).
    payload_model: str = field(default_factory=lambda: os.getenv("SQLIRLLM_PAYLOAD_MODEL", "gapgpt-qwen-3.6"))
    # Tier 3 — post-execution analysis (Qwen2.5-Coder-14B analog).
    analysis_model: str = field(default_factory=lambda: os.getenv("SQLIRLLM_ANALYSIS_MODEL", "qwen3-235b-a22b-instruct-2507"))
    payload_temperature: float = 0.7
    analysis_temperature: float = 0.0
    request_timeout: float = 60.0
    max_retries: int = 3
    # If True, components fall back to a deterministic offline synthesiser when
    # the API key is missing or a call fails, so experiments never hard-crash.
    allow_offline_fallback: bool = True

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key) and not self.api_key.startswith("YOUR_")


@dataclass(frozen=True)
class Config:
    reward: RewardWeights = field(default_factory=RewardWeights)
    qlearning: QLearningParams = field(default_factory=QLearningParams)
    llm: LLMConfig = field(default_factory=LLMConfig)
    seed: int = 42


# A ready-to-use default instance.
CONFIG = Config()
