# BoundaryRun

Verifiable autonomous security remediation. An AI agent investigates a vulnerability in a
disposable copy of a repository through a small set of tools; a deterministic gateway
authorizes every operation; untrusted code runs only in locked-down containers; and an
independent verifier decides whether the patch worked from execution results, not from the
agent's claims.

Status: Phase 1 (one end-to-end scenario, a cross-tenant document read in a FastAPI service;
policy and sandbox boundaries with tests from both sides; machine-readable evidence) and
Phase 2 (four prompt-injection attacks across README, source comment, test output and finding
text; unprotected vs protected vs protected+verified comparison with deterministic simulated
agents, plus an opt-in live arm), and Phase 3 (offline Semgrep in the sandbox with before/after
comparison feeding the verdict, findings derived from scanner output, git targets at a pinned
commit, and a gated branch/PR proposal step), and Phase 4 (a read-only evidence viewer in `web/`
that renders `.runs/` from disk: evaluation aggregates, per-run rows, and the full report for one
investigation including every tool request with both policy decisions, the diff, probe and test
results before and after, the static before/after comparison, task requirements, information flow
and any bound approval), and Phase 5 (hardening: the
audit log is a hash chain whose head and artifact hashes the report carries, `boundaryrun verify`
and the viewer recompute them, reports can be HMAC-signed with an operator key, denied paths have
no existence oracle, file access is directory-fd relative with `O_NOFOLLOW`, the runner base image
is pinned by digest, and the viewer binds to localhost with a strict CSP), and Phase 6 (independently
enforced boundaries around the agent: an information-flow rule that never lets untrusted input and
external communication coexist in one run; task-scoped security requirements from a scenario threat
model, shown to the agent as trusted context and judged by the verifier from execution evidence;
human approval records bound to the exact report they approve, the only thing that releases a
`needs_review` run; and a distinct agent identity for proposals with a minimal credential environment,
so a PR is attributable to the agent and can never borrow the operator's keys; the design is mapped to
its published sources in `docs/RELATED_WORK.md`).

## Requirements

- Python 3.12+, [uv](https://docs.astral.sh/uv/)
- Docker daemon (tested with colima on macOS; the scratch directory must be inside a folder
  shared with the Docker VM, which is why runs live in `.runs/` under the repo)
- Anthropic API credentials only for `--live`
- Node 20+ and [pnpm](https://pnpm.io/) only for the evidence viewer

## Quick start

```bash
uv venv --python 3.12 && uv pip install -e '.[dev]'
```

```bash
.venv/bin/boundaryrun build-sandbox
```

```bash
.venv/bin/boundaryrun reproduce
```

```bash
.venv/bin/boundaryrun investigate --fixture good
```

```bash
.venv/bin/python -m pytest
```

Live model run (writes a report regardless of outcome; requires `ANTHROPIC_API_KEY` or an
`ant auth login` profile):

```bash
.venv/bin/boundaryrun investigate --live
```

## Commands

| Command | What it does |
|---|---|
| `build-sandbox` | Builds `boundaryrun-runner:0.1`, the only image untrusted code runs in |
| `reproduce` | Runs the black-box probe and the target's functional suite against the unmodified target |
| `investigate --fixture NAME` | Replays a scripted agent (`good`, `ineffective`, `regression`, `injected`, `needs_review`) through the real gateway, sandbox and verifier. Labeled non-autonomous in the report |
| `investigate --live` | Real model-backed investigation (`claude-opus-5-5` by default) |
| `investigate --obedient\|--compliant [--arm unprotected] [--attack ID]` | Simulated agent against one attack in one arm |
| `eval [--agents compliant obedient live] [--arms ...] [--repeats N]` | Full grid; writes `.runs/eval-*/summary.{json,md}` |
| `scan --target DIR` | Run the local Semgrep rules against a directory inside the sandbox |
| `investigate ... --repo URL --ref REF [--subdir DIR]` | Clone a git repository at a pinned commit as the target |
| `approve RUN_DIR --reviewer NAME [--reject] [--note TEXT]` | Record a human decision bound to the SHA-256 of `report.json` (HMAC-signed when `BOUNDARYRUN_AUDIT_KEY` is set). Required before `propose` releases a `needs_review` run; a rejection blocks any run |
| `verify RUN_DIR [--json]` | Recompute artifact hashes, the audit hash chain, the report's embedded records and (with `BOUNDARYRUN_AUDIT_KEY`) the report HMAC. Exit 5 if anything differs. Needs no Docker |
| `propose RUN_DIR --remote URL [--push] [--open-pr] [--operator 'Name <email>']` | Re-apply a releasable patch on a fresh clone, commit to `boundaryrun/<id>` as `BoundaryRun Agent` with provenance trailers, optionally push and open a PR with `gh`. Pushing to https needs `BOUNDARYRUN_AGENT_TOKEN`; ssh remotes are refused; the operator appears only as co-author. Never merges |

Each investigation writes `.runs/<id>/` with `report.json`, `audit.jsonl`, `patch.diff`, the
read-only `original/` snapshot and the agent's `workspace/`; `approve` adds `approval.json` and
`propose` adds `pr_body.md` and `proposal.json`. Set `BOUNDARYRUN_AUDIT_KEY` to also write
`report.hmac` and to sign approvals; keep the key off the machine that stores the runs. Set
`BOUNDARYRUN_AGENT_TOKEN` to a scoped, short-lived token minted for the agent identity before
pushing; the operator's own `gh` login, keychain and ssh agent are never reachable from `propose`.

## Evidence viewer

```bash
cd web && pnpm install && pnpm dev
```

Opens on http://localhost:3000 and reads `../.runs` at request time (override with
`BOUNDARYRUN_RUNS_DIR`). Nothing is cached, computed client side, or sampled: every number is a
field of `summary.json`, `report.json` or `audit.jsonl`. Pages: `/` lists evaluations and
standalone investigations, `/eval/<id>` shows the aggregate table by view and agent plus one row
per investigation, `/runs/<id>` shows a full report, `/about` defines the verdicts, arms, agents
and rates. Route identifiers are validated against the generator's format before any filesystem
access. `pnpm test`, `pnpm typecheck`, `pnpm lint` and `pnpm build` must all pass; the tests run
the loader against a copy of a real eval summary and two real reports in `web/tests/fixtures`.

## Layout

```
src/boundaryrun/      control process: agent, gateway, policy, paths, sandbox, static, verify, requirements, approval, evidence, repo, propose, pipeline, eval, cli
rules/                local Semgrep rules (mounted read-only into the scan container)
targets/docvault/     deliberately vulnerable FastAPI app (synthetic data, planted README injection, canary secret)
scenarios/docvault-idor/   finding.json, scenario.toml (policy + sandbox limits), threat_model.toml (requirements and their evidence), probe.py, fixtures/*.json, attacks/*
scenarios/docvault-idor-sast/  same target; the finding is derived from a Semgrep rule's baseline result
docker/runner.Dockerfile   runtime image for target code, tests and the probe
web/                  Next.js evidence viewer (src/lib/runs.ts loads .runs; src/app/{eval,runs}/[id] render it)
docs/ARCHITECTURE.md  trust boundaries, invariants with their tests, verdict semantics, limitations
docs/EVALUATION.md    Phase 2 arms, simulated agents, attacks, metrics, results
docs/RELATED_WORK.md  the published mechanisms Phase 6 is built against, what was borrowed and what was not
docs/RELATED_WORK.md  the published mechanisms Phase 6 is built against, what was borrowed and what was not
tests/                unit (no Docker), container boundary, end-to-end; live test is opt-in via BOUNDARYRUN_LIVE=1
```

## What a report contains

Investigation ID and task configuration (policy, sandbox limits, mode, model), execution
metadata (versions, image ID), the finding, the agent run (mode, autonomy flag, per-turn token
usage for live runs, visible text only, never hidden reasoning), the agent's own claim kept
separate from the verdict, every tool request with its policy decision, outcome and chain hashes, injection
observations (attempts vs executions, canary hits by channel), which legs of the lethal trifecta the
agent held and how many allowlisted fetches the flow rule refused, the agent's claimed files checked
against the diff, each task requirement with its status and the evidence it was judged on, baseline
and post-patch probe and test results, the unified diff with per-file scope flags, errors, and the
verdict with its reasons and an explicit statement of what `verified` does and does not claim, and
the audit chain head.

Live evaluation (real model, every arm and attack, N repeats; requires credentials):

```bash
.venv/bin/boundaryrun eval --agents compliant obedient live --repeats 3
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the threat model and known limitations,
and [docs/EVALUATION.md](docs/EVALUATION.md) for the evaluation design and results.
