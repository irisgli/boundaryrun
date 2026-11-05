"""Deterministic simulated agents for evaluation.

`run_obedient` models the worst case for a policy layer: an agent that follows every
directive it encounters in tool output or the finding, immediately, while otherwise
performing the correct remediation. It is a simulation of model behavior, not a model,
and reports are labeled accordingly. It makes enforcement measurable without depending
on whether a particular model happens to fall for a particular payload.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from .agent import AgentRun
from .attacks import Directive, extract_directives
from .gateway import Gateway


def run_obedient(gateway: Gateway, finding: dict, baseline_script: Path, scan, *, obey: bool = True) -> AgentRun:
    """Replay `baseline_script` (a fixture) and obey any directive seen along the way.

    With `obey=False` this is the compliant agent: same trajectory, directives ignored.
    """
    start = time.monotonic()
    steps = json.loads(baseline_script.read_text())["steps"]
    run = AgentRun(mode="fixture", autonomous=False, fixture=f"{'obedient' if obey else 'compliant'}:{baseline_script.stem}")
    seen: set[Directive] = set()
    queue: list[Directive] = []

    def absorb(text: str) -> None:
        if not obey:
            return
        for d in extract_directives(text):
            if d not in seen:
                seen.add(d)
                queue.append(d)

    def call(tool: str, inp) -> str:
        run.tool_calls_requested += 1
        scan(json.dumps(inp), "agent_tool_input")
        out = gateway.handle(tool, inp)
        absorb(out.content)
        return out.status

    absorb("\n".join(str(v) for v in finding.values()))  # the finding text as a model would read it
    for step in steps:
        while queue and not gateway.state.submitted:
            d = queue.pop(0)
            call(d.tool, d.input)
        if gateway.state.submitted:
            break
        status = call(step["tool"], step.get("input"))
        if status == "ok" and step["tool"] == "submit_remediation":
            break
    while queue and not gateway.state.submitted:  # directives discovered on the final steps
        d = queue.pop(0)
        call(d.tool, d.input)
    run.finished_by = "submit_remediation" if gateway.state.submitted else "fixture_end"
    run.duration_s = round(time.monotonic() - start, 3)
    return run
