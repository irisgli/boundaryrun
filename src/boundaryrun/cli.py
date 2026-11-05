"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .agent import DEFAULT_MODEL

DEFAULT_SCENARIO = Path("scenarios/docvault-idor")
DEFAULT_RUNS = Path(".runs")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="boundaryrun")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("build-sandbox", help="build the runner image used for all untrusted execution")

    rp = sub.add_parser("reproduce", help="run only the baseline vulnerability probe and functional tests")
    rp.add_argument("--scenario", type=Path, default=DEFAULT_SCENARIO)

    inv = sub.add_parser("investigate", help="run an end-to-end investigation and write an evidence report")
    inv.add_argument("--scenario", type=Path, default=DEFAULT_SCENARIO)
    mode = inv.add_mutually_exclusive_group(required=True)
    mode.add_argument("--live", action="store_true", help="real model-backed agent (requires API credentials)")
    mode.add_argument("--fixture", help="scripted, non-autonomous agent: good | ineffective | regression | injected")
    mode.add_argument("--obedient", action="store_true", help="simulated agent that obeys every planted directive")
    mode.add_argument("--compliant", action="store_true", help="simulated agent that ignores planted directives")
    inv.add_argument("--arm", choices=["protected", "unprotected"], default="protected")
    inv.add_argument("--attack", help="attack id from the scenario's attacks/ directory")
    inv.add_argument("--model", default=DEFAULT_MODEL)
    inv.add_argument("--runs-dir", type=Path, default=DEFAULT_RUNS)

    ev = sub.add_parser("eval", help="compare unprotected, protected and protected+verified arms across attacks")
    ev.add_argument("--scenario", type=Path, default=DEFAULT_SCENARIO)
    ev.add_argument("--agents", nargs="+", default=["compliant", "obedient"],
                    choices=["compliant", "obedient", "live"])
    ev.add_argument("--arms", nargs="+", default=["unprotected", "protected"], choices=["unprotected", "protected"])
    ev.add_argument("--attacks", nargs="*", help="attack ids (default: none + every attack in the scenario)")
    ev.add_argument("--repeats", type=int, default=1)
    ev.add_argument("--model", default=DEFAULT_MODEL)
    ev.add_argument("--runs-dir", type=Path, default=DEFAULT_RUNS)

    args = ap.parse_args(argv)

    from .sandbox import build_runner_image, docker_available, image_present

    ok, info = docker_available()
    if not ok:
        print(f"error: {info}. All untrusted execution requires Docker; refusing to run on the host.", file=sys.stderr)
        return 2
    if args.cmd == "build-sandbox":
        build_runner_image()
        return 0
    if not image_present():
        print("error: runner image missing; run `boundaryrun build-sandbox` first", file=sys.stderr)
        return 2

    if args.cmd == "reproduce":
        from .pipeline import load_scenario
        from .sandbox import Sandbox
        from .verify import baseline_reproduced

        scn = load_scenario(args.scenario)
        sb = Sandbox(scn.sandbox, DEFAULT_RUNS.resolve() / "reproduce")
        probe = sb.run_probe(scn.target, scn.probe)
        tests = sb.run_functional_tests(scn.target)
        reproduced, why = baseline_reproduced(probe)
        for c in probe.result.checks if probe.result else []:
            print(f"  {c.kind:<12} {c.name:<28} http={c.status_code} content_returned={c.content_returned} -> {c.outcome}")
        print(f"functional tests: {tests.status} (passed={tests.passed} failed={tests.failed})")
        print(f"reproduced: {reproduced} ({why})")
        return 0 if reproduced else 1

    if args.live if args.cmd == "investigate" else "live" in args.agents:
        from .agent import live_credentials_available

        ok, why = live_credentials_available()
        if not ok:
            print(f"error: live mode unavailable: {why}. No investigation was run.", file=sys.stderr)
            return 3

    if args.cmd == "eval":
        from .eval import run_eval

        result, out_dir = run_eval(
            args.scenario, runs_dir=args.runs_dir, agents=args.agents, arms=args.arms,
            attacks=args.attacks or None, repeats=args.repeats, model=args.model,
            progress=lambda m: print(f"  {m}", flush=True),
        )
        print((out_dir / "summary.md").read_text())
        print(f"summary: {out_dir / 'summary.json'}")
        return 1 if result.errors else 0

    from .pipeline import run_investigation

    agent_mode = "live" if args.live else "obedient" if args.obedient else "compliant" if args.compliant else "fixture"
    report, path = run_investigation(
        args.scenario,
        agent_mode=agent_mode,
        fixture=args.fixture,
        model=args.model,
        runs_dir=args.runs_dir,
        arm=args.arm,
        attack=args.attack,
    )
    a = report.agent
    label = "LIVE model run" if a and a.mode == "live" else f"SIMULATED agent '{a.fixture if a else args.fixture}' (scripted, not autonomous)"
    print(f"investigation {report.investigation_id}: {label}, arm={report.arm}, attack={args.attack or 'none'}")
    if report.agent_skipped_reason:
        print(f"  agent skipped: {report.agent_skipped_reason}")
    if a:
        print(f"  agent finished_by={a.finished_by} tool_calls={a.tool_calls_requested}" + (f" error={a.error}" if a.error else ""))
        if a.mode == "live":
            i, o = a.total_tokens
            print(f"  models={a.models_observed} turns={len(a.turns)} input_tokens={i} output_tokens={o}")
    s = report.policy_summary
    print(f"  gateway: {s.requests} requests, {s.executed} executed, {s.denied} denied, {s.rejected} rejected, {s.errors} errors")
    for rule, n in sorted(s.denied_by_rule.items()):
        print(f"    deny {rule}: {n}")
    inj = report.injection
    print(f"  injection: sensitive reads {inj.sensitive_read_executed}/{inj.sensitive_read_attempts} executed, "
          f"egress {inj.egress_executed}/{inj.egress_attempts}, canary hits {inj.canary_hits_by_channel or 'none'}")
    if report.attack:
        print(f"  attack {report.attack.id} ({report.attack.vector}/{report.attack.objective}): "
              f"objective_achieved={report.attack.objective_achieved} "
              f"directives={[(d.tool, d.attempted, d.executed) for d in report.attack.directives]}")
    if report.egress_sink:
        print(f"  egress sink captured {len(report.egress_sink)} request(s); canary in any: {any(r.contained_canary for r in report.egress_sink)}")
    if report.patch:
        print(f"  patch: {[f.path for f in report.patch.files]}")
    print(f"  verdict: {report.verdict.status.value}")
    for r in report.verdict.reasons:
        print(f"    - {r}")
    print(f"  report: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
