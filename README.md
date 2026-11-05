# BoundaryRun

Verifiable autonomous security remediation. An AI agent investigates a vulnerability in a
disposable copy of a repository through a small set of tools; a deterministic gateway
authorizes every operation; untrusted code runs only in locked-down containers; and an
independent verifier decides whether the patch worked from execution results, not from the
agent's claims.

Phase 1 status: one end-to-end scenario (a cross-tenant document read in a FastAPI service),
policy and sandbox boundaries with tests that exercise them from both sides, and a
machine-readable evidence report. No frontend, no GitHub integration, no benchmarks yet.

## Requirements

- Python 3.12+, [uv](https://docs.astral.sh/uv/)
- Docker daemon (tested with colima on macOS; the scratch directory must be inside a folder
  shared with the Docker VM, which is why runs live in `.runs/` under the repo)
- Anthropic API credentials only for `--live`

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
| `investigate --fixture NAME` | Replays a scripted agent (`good`, `ineffective`, `regression`, `injected`) through the real gateway, sandbox and verifier. Labeled non-autonomous in the report |
| `investigate --live` | Real model-backed investigation (`claude-opus-5-5` by default) |

Each investigation writes `.runs/<id>/` with `report.json`, `audit.jsonl`, `patch.diff`, the
read-only `original/` snapshot and the agent's `workspace/`.

## Layout

```
src/boundaryrun/      control process: agent, gateway, policy, paths, sandbox, verify, pipeline, cli
targets/docvault/     deliberately vulnerable FastAPI app (synthetic data, planted README injection, canary secret)
scenarios/docvault-idor/   finding.json, scenario.toml (policy + sandbox limits), probe.py, fixtures/*.json
docker/runner.Dockerfile   runtime image for target code, tests and the probe
docs/ARCHITECTURE.md  trust boundaries, invariants with their tests, verdict semantics, limitations
tests/                unit (no Docker), container boundary, end-to-end; live test is opt-in via BOUNDARYRUN_LIVE=1
```

## What a report contains

Investigation ID and task configuration (policy, sandbox limits, mode, model), execution
metadata (versions, image ID), the finding, the agent run (mode, autonomy flag, per-turn token
usage for live runs, visible text only, never hidden reasoning), the agent's own claim kept
separate from the verdict, every tool request with its policy decision and outcome, injection
observations (attempts vs executions, canary hits by channel), baseline and post-patch probe
and test results, the unified diff with per-file scope flags, errors, and the verdict with its
reasons and an explicit statement of what `verified` does and does not claim.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the threat model and known limitations.
