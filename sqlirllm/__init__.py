"""SQLiRLLM: a multi-tier AI framework for adaptive SQL injection testing.

This package is a research reference implementation of the methodology described
in the paper "SQLiRLLM: A Multi-Tier AI Framework for Adaptive SQL Injection
Testing with Ethical Constraints".

IMPORTANT — ETHICAL USE
-----------------------
Every component in this package operates exclusively against the *local,
in-process simulated targets* defined in ``sqlirllm.environment``. No payload is
ever sent over the network to a real system. The framework is intended for
academic evaluation and reproducible experiments only.
"""

__all__ = [
    "config",
    "environment",
    "ethics",
    "reward",
    "qlearning",
    "payload_generator",
    "analyzer",
    "baseline",
    "framework",
    "metrics",
]
