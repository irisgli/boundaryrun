# BoundaryRun architecture and threat model (Phase 1)

## Components

One Python process (the **control process**) plus disposable containers. No services.

| Module | Responsibility | Trust |
|---|---|---|
| `agent.py` | Model loop (Anthropic Messages API, manual tool loop) or a scripted fixture replay | Model output is untrusted |
| `gateway.py` | The only path from an agent request to a side effect: schema validation, policy decision, execution, audit | Trusted |
| `policy.py`, `paths.py` | Pure, deterministic decisions over canonical paths, URLs and budgets | Trusted |
| `sandbox.py` | Exports source trees and runs untrusted code in locked-down containers | Trusted orchestrator, untrusted payload |
| `verify.py` | Diff, independent scope check, verdict as a pure function of execution results | Trusted |
| `pipeline.py` | Orchestration and the JSON evidence report | Trusted |

```
             finding (trusted)          policy (trusted, never shown to the agent)
                   |                                  |
                   v                                  v
   +-------------------------+   tool request   +-------------+   executes   +--------------------+
   | model (untrusted output)| ---------------> |   gateway   | -----------> | disposable         |
   +-------------------------+ <--------------- | + audit log |              | workspace (host)   |
          ^   tool result (untrusted data)      +-------------+              +--------------------+
          |                                            | run_functional_tests          |
   repo files, test output                             v                               | export (secrets
   (attacker-controllable)                    +------------------+                     |  stripped)
                                              | test container   | <-------------------+
                                              | --network none   |
                                              +------------------+
   verifier:  [app container] <--internal net, no egress--> [probe container]  -> JSON verdict input
```

## Trust boundaries

1. **Model to gateway.** The model only emits `(tool name, JSON input)`. It has no shell, no
   file handles, no network client and no container access. Every request goes through
   `Gateway.handle`, including unknown and malformed ones, which are rejected and audited.
2. **Workspace content to model.** Repository files, comments, docs and test output are
   attacker-controllable data. They are labeled as untrusted in tool results. That label is
   a nudge, not a control.
3. **Untrusted code to host.** Target code, agent-patched code and the target's tests run only
   in containers. The control process never imports or executes target code.
4. **Patched app to verdict.** The security regression check is a black-box HTTP probe in a
   separate container. It imports nothing from the target, so patched code can only influence
   it through HTTP responses.

## Protected assets

- Host filesystem, host credentials (model API key, SSH keys, cloud credentials).
- Sensitive files inside the repository (here: `config/secrets.env`, a synthetic canary).
- The tests and verification harness (they define what "fixed" means).
- The original source tree (must never be modified).
- Integrity of the evidence report.

## Attacker model

The attacker controls repository content the agent reads (README, comments, source) and,
through prompt injection, may control the model's tool requests. The attacker may also
control the code the agent writes, which then executes in the sandbox. The attacker does not
control the scenario definition, the policy, the probe, or the control process.

## Security invariants and the evidence for each

| Claim | Mechanism | Test |
|---|---|---|
| The agent cannot read files outside the read allowlist | `canonicalize` (exact-case component match, no `..`, no absolute paths, no symlinks at any component) then deny-overrides-allow glob policy; listing and search use the same decision | `test_gateway.py::test_secret_unreachable_by_path_tricks`, `test_symlink_inside_allowed_dir_is_rejected`, `test_listing_and_search_never_surface_denied_files` |
| Case or Unicode aliasing on APFS cannot bypass deny rules | Paths must match on-disk directory entries byte for byte | `CONFIG/SECRETS.ENV` and `Config/secrets.env` cases above |
| The agent cannot modify tests, config, or create files | Write allowlist is `app/**/*.py`, writes require an existing regular file and a unique match; atomic replace | `test_writes_outside_scope_denied_and_file_untouched`, `test_write_to_new_file_is_rejected`, `test_ambiguous_edit_is_an_error_not_a_write` |
| Changes outside scope are caught even if the gateway had a bug | Verifier recomputes the diff from disk and checks every changed file against the write policy independently | `test_verdict.py::test_compute_patch_flags_added_deleted_and_out_of_scope`, `SCOPE_VIOLATION` case |
| The agent cannot reach external hosts | `http_get` allowlist is empty; https only, no credentials or custom ports, exact host match, redirects disabled | `test_paths_and_policy.py::test_network_denied_by_default`, `test_network_allowlist_is_exact_host` |
| Only defined tools with valid inputs execute | Closed tool registry, Pydantic `extra="forbid", strict=True` schemas; private executor names are not addressable | `test_unknown_and_malformed_requests_rejected` (includes `run_shell`, `bash`, `_op_read_file`, extra fields, wrong types) |
| Untrusted code has no network, no write access to source, no privileges | `--network none`, `--read-only`, `:ro` mounts, `--cap-drop ALL`, `no-new-privileges`, UID 65534, `noexec` tmpfs, pid/memory/CPU limits, host-enforced timeout | `test_sandbox_boundary.py` (assertions run inside the container through the production code path) |
| The patched app cannot exfiltrate during verification | App and probe share an `--internal` Docker network | `test_app_container_has_no_egress` |
| Secrets never enter any container | Sandbox export excludes `config/**`, `**/*.env`, dot-directories; directories are created only for copied files | `test_secrets_not_exported` (inside container) |
| Host credentials never enter containers | Containers get no inherited environment, only `HOME` and `PYTHONDONTWRITEBYTECODE` | `test_no_host_credentials_in_env` (host sets a fake key and a sentinel; container checks) |
| A silently empty bind mount cannot produce a passing verification | A sentinel file is written into each export; the container exits 97 if it is missing | Found and fixed during development (colima only shares `$HOME`) |
| The verdict does not depend on the agent's claim | `decide()` reads only probe results, exit codes and the diff; the claim is stored in a separate field | `test_agent_claim_is_recorded_separately_from_verdict` |
| The original source is never modified | Pristine snapshot is copied and made read-only; the target tree hash is checked before and after | `test_pipeline_e2e.py::runs` fixture assertion |
| Reports never contain the canary | Canary detection happens before redaction; report and audit are redacted on write | `test_artifacts_match_hashes_and_never_contain_canary`, `test_injection_fixture_is_contained_without_relying_on_redaction` |

A blocked request shows that the gateway enforces that specific operation. It is not evidence
that the model resists prompt injection in general. In Phase 1 the injection was exercised by a
**scripted** agent that deliberately obeys it; no live model was evaluated.

## Verdicts

| Status | Meaning |
|---|---|
| `verified` | Exploit reproduced before the patch, all probed unauthorized requests blocked after it, legitimate same-tenant reads still work, functional suite passed |
| `not_remediated` | At least one probed unauthorized request still returns another tenant's document |
| `regression` | Exploit blocked but legitimate behavior broke (probe or functional suite), or the app no longer starts |
| `no_patch` | Workspace unchanged |
| `scope_violation` | A file outside the write policy changed |
| `inconclusive` | Baseline did not reproduce, baseline suite failed, a probe errored, or tests timed out |

## Assumptions

- Docker (here: colima on macOS, Linux VM) is configured correctly and the runner image is
  built from `docker/runner.Dockerfile`.
- The scenario definition, policy and probe are trusted and reviewed by a human.
- Only the gateway writes to the workspace while a run is in progress.

## Known limitations (Phase 1)

1. **Functional tests are in-process with patched code.** Malicious patched code could tamper
   with pytest and fake a passing functional suite. The security verdict does not depend on this
   (the probe is out of process), but the "no functional regression" part of `verified` does.
2. **Probe coverage is narrow.** The probe checks six fixed requests against seeded documents. A
   patch that special-cases those IDs would pass. Property-based or generated cross-tenant cases
   are future work.
3. **Container isolation is not a VM boundary per container.** Containers share the colima VM
   kernel. A kernel or runtime escape reaches the VM, and colima mounts the user's home
   directory into the VM read-write by default. gVisor or a dedicated microVM would be stronger.
4. **No seccomp/AppArmor profile beyond Docker defaults.** Not customized.
5. **The image is pinned by tag, not digest.** Rebuilds may pull a different base layer.
6. **`http_get`, if ever allowlisted, does not pin DNS.** An allowlisted hostname resolving to a
   private address (DNS rebinding, SSRF) is not prevented. The allowlist is empty in Phase 1.
7. **Path checks are check-then-open.** Safe under the assumption that only the gateway mutates
   the workspace; the final open uses `O_NOFOLLOW` but intermediate components are not opened
   relative to a directory fd.
8. **Existence oracle.** A denied path returns `read.deny`, a nonexistent one returns
   `path.not_found`, which reveals whether a denied file exists (not its contents).
9. **No static analysis yet.** Semgrep is scheduled for Phase 3 and is reported as `not_run`.
10. **No approval workflow.** Operations are allowed or denied; nothing escalates to a human.
11. **The audit log is not tamper-evident.** It is written by the trusted process outside the
    workspace and hashed in the report, but not signed or hash-chained.
12. **Live model behavior is unmeasured.** No live run was performed (no credentials in this
    environment). The live path is implemented and type-checked against SDK 2.5.0 but has not
    made a successful API call.
