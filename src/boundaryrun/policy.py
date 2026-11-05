"""Deterministic authorization policy.

The policy is pure data loaded from the scenario file and is never visible to, or
modifiable by, the agent. Decisions are a function of (policy, task state, request);
no model output is consulted. Deny rules take precedence over allow rules, and any
operation not matched by an allow rule is denied.
"""

from __future__ import annotations

from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from .paths import first_match


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ReadPolicy(_Strict):
    allow: list[str]
    deny: list[str] = []
    max_bytes: int = 65536


class WritePolicy(_Strict):
    allow: list[str]
    deny: list[str] = []
    max_bytes_per_file: int = 32768
    max_edits: int = 12


class NetworkPolicy(_Strict):
    allow_hosts: list[str] = []


class ExecutionPolicy(_Strict):
    allow_functional_tests: bool = False
    max_test_runs: int = 0


class BudgetPolicy(_Strict):
    max_tool_calls: int = 60
    max_model_turns: int = 30


class Policy(_Strict):
    read: ReadPolicy
    write: WritePolicy
    network: NetworkPolicy = NetworkPolicy()
    execution: ExecutionPolicy = ExecutionPolicy()
    budget: BudgetPolicy = BudgetPolicy()


class Decision(_Strict):
    effect: Literal["allow", "deny"]
    rule: str = Field(description="Stable identifier of the rule that produced the decision")
    reason: str


def allow(rule: str, reason: str) -> Decision:
    return Decision(effect="allow", rule=rule, reason=reason)


def deny(rule: str, reason: str) -> Decision:
    return Decision(effect="deny", rule=rule, reason=reason)


class TaskState(BaseModel):
    """Counters the gateway maintains for budget rules. Owned by the gateway, not the agent."""

    tool_calls: int = 0
    edits: int = 0
    test_runs: int = 0
    submitted: bool = False


def decide_read(policy: Policy, canonical_path: str) -> Decision:
    if (p := first_match(canonical_path, policy.read.deny)) is not None:
        return deny("read.deny", f"path matches read deny rule '{p}'")
    if (p := first_match(canonical_path, policy.read.allow)) is not None:
        return allow("read.allow", f"path matches read allow rule '{p}'")
    return deny("read.default_deny", "path is not covered by any read allow rule")


def decide_write(policy: Policy, state: TaskState, canonical_path: str, new_size: int) -> Decision:
    if (p := first_match(canonical_path, policy.write.deny)) is not None:
        return deny("write.deny", f"path matches write deny rule '{p}'")
    if first_match(canonical_path, policy.write.allow) is None:
        return deny("write.default_deny", "path is not covered by any write allow rule")
    if state.edits >= policy.write.max_edits:
        return deny("write.max_edits", f"edit budget of {policy.write.max_edits} exhausted")
    if new_size > policy.write.max_bytes_per_file:
        return deny("write.max_bytes", f"resulting file exceeds {policy.write.max_bytes_per_file} bytes")
    return allow("write.allow", "path is writable in the disposable workspace")


def decide_network(policy: Policy, url: str) -> Decision:
    try:
        parts = urlsplit(url)
    except ValueError:
        return deny("network.malformed_url", "URL could not be parsed")
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or not host:
        return deny("network.scheme", "only https URLs with a hostname are considered")
    if parts.username or parts.password or parts.port not in (None, 443):
        return deny("network.url_form", "credentials and non-default ports are not permitted")
    if host not in {h.lower() for h in policy.network.allow_hosts}:
        return deny("network.default_deny", f"host '{host}' is not in the egress allowlist")
    return allow("network.allow", f"host '{host}' is allowlisted")


def decide_tests(policy: Policy, state: TaskState) -> Decision:
    if not policy.execution.allow_functional_tests:
        return deny("exec.disabled", "functional test execution is disabled for this task")
    if state.test_runs >= policy.execution.max_test_runs:
        return deny("exec.max_runs", f"test run budget of {policy.execution.max_test_runs} exhausted")
    return allow("exec.allow", "functional tests run in the network-isolated sandbox")
