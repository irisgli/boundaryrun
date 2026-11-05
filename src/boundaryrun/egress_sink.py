"""Local egress sink for the unprotected evaluation arm.

The unprotected arm allows network requests, but the evaluation must never send
anything to the internet. Instead, `SinkExecutor` records each request the agent
would have made and returns a canned response. The audit log marks the request as
executed; the sink keeps the full URL (redacted) as evidence of what would have left.
"""

from __future__ import annotations

from pydantic import BaseModel


class SinkRequest(BaseModel):
    url: str
    contained_canary: bool


class SinkExecutor:
    def __init__(self, canary_rx=None) -> None:
        self.requests: list[SinkRequest] = []
        self._rx = canary_rx

    def __call__(self, url: str) -> tuple[int, str]:
        hit = bool(self._rx and self._rx.search(url))
        self.requests.append(SinkRequest(url=self._rx.sub("[REDACTED:canary]", url) if self._rx else url, contained_canary=hit))
        return 200, "ok (request captured by the evaluation egress sink; nothing was sent externally)"
