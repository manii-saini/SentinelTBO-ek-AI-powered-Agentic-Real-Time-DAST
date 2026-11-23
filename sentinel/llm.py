from __future__ import annotations

import hashlib
import os
import time


class LLM:
    def __init__(self):
        self.provider = os.getenv("SENTINEL_LLM_PROVIDER", "mock")
        self.model = os.getenv("SENTINEL_LLM_MODEL", "sentinel-deterministic-1")

    def complete(self, system: str, prompt: str) -> dict:
        started = time.perf_counter()
        if self.provider == "mock" or not os.getenv("SENTINEL_LLM_API_KEY"):
            text = self._mock(prompt)
            return {"provider": "mock", "text": text, "latencyMs": int((time.perf_counter()-started)*1000)}
        # Non-mock providers intentionally optional; keep deterministic fallback-safe behavior.
        return {"provider": "mock", "text": self._mock(prompt), "latencyMs": int((time.perf_counter()-started)*1000)}

    def _mock(self, prompt: str) -> str:
        digest = hashlib.sha256(prompt.encode()).hexdigest()
        import re
        topic = (re.search(r"Endpoint:\s*(\S+)", prompt) or [None, "this endpoint"])[1]
        test = (re.search(r"Test:\s*([^\n]+)", prompt) or [None, "the selected test"])[1]
        variants = [
            f"Targeted because {topic} exposes a state-changing parameter and the selected control ({test}) isolates a single authorization or trust boundary; deterministic seed {digest[:6]}.",
            f"Chosen over broad fuzzing: {topic} is used in the search-to-payment flow, so {test} exercises the business impact path with one synthetic account pair and minimal requests.",
            f"Reasoning: observed parameters and role requirements on {topic} make {test} the highest-signal, lowest-noise check; mock reasoning seed {digest[:6]}.",
        ]
        return variants[int(digest[:2], 16) % len(variants)]
