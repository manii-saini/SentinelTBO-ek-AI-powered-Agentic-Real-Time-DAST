from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from ..llm import LLM
from ..mock_platform import SyntheticTravelPlatform
from ..safety import SafeHttpClient, SafetyLayer
from ..store import Store


@dataclass
class AgentContext:
    store: Store
    safety: SafetyLayer
    http: SafeHttpClient
    llm: LLM
    target: str
    run_id: str
    mode: str
    auto_approve: bool
    approval_for: Callable[[str], str | None]
    emit: Callable[[str, str, str, dict | None], None]
    platform: SyntheticTravelPlatform
