# Related work and what BoundaryRun borrows from it

Phase 6 was designed against published mechanisms from six sources rather than against
their talking points. For each source this page states the mechanism as the source describes
it, where it lands in BoundaryRun, and what BoundaryRun deliberately does not borrow. Where
only an abstract or press coverage was available, that is said, and no stronger claim is made.

## Summary

| Source | Mechanism in the source | Where it lands here | Not borrowed |
|---|---|---|---|
| Tsao, USENIX Security 2026 | Isolate the three trifecta legs across components, move only typed abstractions across boundaries, gate release on requester trust | `policy.FlowPolicy` and rule `flow.trifecta`; closed tool schemas; the approval gate in `propose` | The causal isolation architecture itself; the release judge as a model-backed component |
| Notion custom agents | Permissions independent of the user, deterministic access checks, pause and confirm before an unexpected external action, halt when access is lost | Default-deny policy that the model never sees; `needs_review` halts release until a human records a decision | Runtime confirmation inside the agent loop (the gateway never escalates) |
| Clover Kura | Outcome-phrased, per-task requirements from a continuous threat model; requirements enforced elsewhere are removed; requirements are verified in code, not from the agent's claims | `scenarios/*/threat_model.toml`, `requirements.py`, the `requirements` field of the report, `verify.decide` | The continuous threat model; adaptive selection of requirements by a model |
| Vercel Agent | Commits and PRs made by a dedicated GitHub App identity with the requesting human as co-author; approval before any write; short-lived repository credentials; no ambient `git push`, `gh` or copied credentials | `propose.py`: agent identity, co-author trailer, minimal environment for `git` and `gh`, `BOUNDARYRUN_AGENT_TOKEN`, ssh remotes refused | Signed commits; a hosted credential broker |
| Eric Brandwine, Amazon | "Accountability end to end": every agent has its own identity, so audit records attribute actions to the agent acting for a person; policies scoped per action | Agent identity in every commit, trailers tying the commit to the investigation, verdict, audit chain head, report hash and approver | Replacing human review with attribution (Brandwine argues against routine human-in-the-loop; BoundaryRun keeps a human at release time for anything short of `verified`) |
| Nancy Wang, 1Password | Agent identity at issuance can differ from identity at execution; just-in-time, per-task credentials; never hand the agent the secret; prove the last task finished before the next credential | The token is read by name by a credential helper, never placed in agent context; it is needed only for the push step and only on https remotes; the proposal step is bound to a finished, hashed report | Biometric approval; a vault or broker; identity attestation for the agent process |

## Tsao, "Breaking the Lethal Trifecta: Secure Agentic Computing via Causal Isolation Architecture"

USENIX Security 2026 program entry: https://www.usenix.org/conference/usenixsecurity26/presentation-4
(David Tsao, Notion Labs). Only the program listing and abstract were available; the paper
text was not read, so nothing below relies on its evaluation details.

The term comes from Simon Willison's June 2025 post: an agent that reads untrusted content,
has access to private data, and can communicate externally is exploitable by construction.
Tsao's abstract frames leakage as a systems design problem: separate the legs across isolated
components, pass only typed abstractions across boundaries, and let a release judge decide
what private-derived content may leave based on requester trust.

What BoundaryRun takes from this:

- **The flow rule.** `FlowPolicy.egress_after_untrusted_input = "deny"` makes the third leg
  unreachable once the first has been held. `TaskState.untrusted_inputs` counts executed
  operations that put attacker-controllable text in front of the model (listing, reading,
  searching, test output, fetched bodies). After the first one, `decide_network` denies every
  allowlisted host with rule `flow.trifecta`. The rule is structural: it is a function of the
  task state the gateway owns, not a judgement about what the model will do. Tests:
  `tests/test_flow.py`.
- **Typed boundaries.** The agent can only emit `(tool name, JSON object)` against a closed
  registry of Pydantic schemas with `extra="forbid"` and strict types. This predates Phase 6
  and is the nearest thing here to "typed abstractions across boundaries".
- **Release gated on trust.** The nearest analogue of the release judge is the approval gate:
  a `needs_review` patch leaves the run directory only with a human approval bound to the
  exact report. The judge in BoundaryRun is a person, not a model.

Not borrowed: the architecture that isolates components from each other at runtime.
BoundaryRun has one control process; its isolation is between the model and side effects,
and between untrusted code and the host, not between the legs of the trifecta as separate
processes. The 0.0 percent leakage figure in the abstract is Tsao's result for Tsao's system
and is not claimed here.

## Notion custom agents, security features

Help page: https://www.notion.com/help/custom-agents-security-features

As documented: an agent's permissions are independent of the person using it; sharing an
agent that reaches sensitive resources (private pages, email, calendar, integrations)
requires confirmation; an agent that produces a URL not present in the original prompt pauses
and asks before continuing; an agent whose editors all lose access to a connected resource
stops running; access cannot be widened by anyone but the person who connected an
integration.

What BoundaryRun takes from this:

- **Access decided outside the model.** The policy is data the model never sees; every
  operation not matched by an allow rule is denied; deny overrides allow. This predates
  Phase 6 and is the counterpart of permissions that are independent of the user.
- **Halt rather than proceed.** Anything short of `verified` halts at release. There is no
  path from `needs_review` to a branch without `boundaryrun approve`, and a rejection blocks
  even a `verified` run.

Not borrowed: confirmation prompts inside the agent loop. The gateway allows or denies and
never escalates (see ARCHITECTURE.md, limitation 10). The one human decision enters after
the run, bound to the report hash, so the thing being approved is fixed before the approver
sees it. The documentation describes the product's behavior, not its implementation; nothing
here is a claim about how Notion implements it.

## Clover Security, Kura

Press release, 3 August 2026:
https://www.newswire.com/news/clover-security-releases-kura-adaptive-security-context-outperforming-frontier

As described by Clover: Kura keeps a continuous threat model of an application and, per task,
pulls the relevant threats and countermeasures for the agent while it plans and writes code.
It removes requirements already enforced elsewhere in the stack. Clover separately describes
verifying requirements in code rather than taking the agent's word. The reported prevention
rates are vendor-reported and were not independently checked.

What BoundaryRun takes from this:

- **Outcome-phrased, per-task requirements linked to named threats.**
  `scenarios/docvault-idor/threat_model.toml` lists threats and requirements. Each
  requirement states what the patched code must do (not a principle), names a threat, and
  names its evidence: probe checks that must pass, static rules that must produce nothing.
  `load_threat_model` rejects a requirement with no evidence unless it is marked
  `enforced_elsewhere`, which keeps it for traceability but excludes it from the task.
- **Shown to the agent as trusted context, never from the repository.** `task_context` is
  appended to the finding message, which comes from the scenario, not from any file the agent
  reads.
- **Assessed from execution evidence only.** `requirements.assess` reads probe results and
  the static comparison and never the agent's text. `not_satisfied` downgrades the verdict to
  `needs_review`; `no_evidence` makes it `inconclusive`. The report's `claim_check` compares
  the files the agent claimed to have changed with the diff on disk.

Not borrowed: the continuous threat model and its generation. The threat model here is a
hand-written file for one scenario, and the requirement set is fixed per scenario rather
than selected per task by a model.

## Vercel Agent, GitHub integration

Documentation: https://vercel.com/docs/agent/chat/github

As documented: the agent asks for approval before it writes to GitHub; commits and pull
requests are created and signed by the Vercel Agent GitHub App with the requesting user
added as a git co-author; each write is recorded in the team's activity history; the agent
uses short-lived repository credentials during authorized operations and does not use
`git push`, `gh` or copied GitHub credentials from a shell. Vercel Connect
(https://vercel.com/kb/guide/github-agent-eve) issues short-lived GitHub App installation
tokens to deployments by identity; whether the Agent's own credentials come from Vercel
Connect is not stated and is not assumed here.

What BoundaryRun takes from this:

- **Agent identity with a human co-author.** Every proposal commit is authored and committed
  by `BoundaryRun Agent <agent@boundaryrun.invalid>`, never by the operator, and carries a
  `Co-authored-by` trailer when an operator is named.
- **Approval scoped to a fixed plan.** The thing approved is a finished report with a hashed
  diff. `propose` re-applies that exact diff at the pinned commit and refuses if the file list
  differs.
- **No ambient credentials.** `git` and `gh` run with a minimal environment (`PATH`, `HOME`,
  `GIT_TERMINAL_PROMPT=0`). An https push requires `BOUNDARYRUN_AGENT_TOKEN`, which is read by
  a credential helper and never placed in agent context; configured credential helpers are
  cleared first. ssh remotes are refused because they would use the operator's ssh identity.
  Tests: `tests/test_propose_gates.py`.

Not borrowed: commit signing and a hosted broker that mints the token. The operator supplies
a scoped, short-lived token out of band.

## Eric Brandwine, Amazon, on identity and accountability

Coverage: https://thenextweb.com/news/amazon-human-in-the-loop-ai-governance-normalization-deviance
(secondary coverage of an interview; the original wording was not checked against the
primary source). AWS guidance on per-agent identity:
https://docs.aws.amazon.com/prescriptive-guidance/latest/strategy-operationalizing-agentic-ai/focus-areas-trust.html

As reported: Brandwine, VP and distinguished engineer at Amazon Security, argues that routine
human-in-the-loop approval fails because people stop paying attention, and proposes
"accountability end to end" instead: every agent has its own identity, so audit logs
attribute an action to the agent acting for a person, and policies are scoped down per
action.

Melissa Bishop is on the event panel but has no published positions on agent governance
that could be found; the accountability framing on this page is Brandwine's, not hers.

What BoundaryRun takes from this:

- **Attribution that survives the run.** The commit author is the agent; the trailers
  `Investigation`, `Verdict`, `Audit-Chain-Head`, `Report-SHA256`, `Agent-Mode`,
  `Approved-by` and `Co-authored-by` tie the commit to the hash-chained audit log, the exact
  report, the human who approved it and the human on whose behalf it was proposed. The same
  identity appears in the PR body.
- **Per-action scope.** Every tool request is decided individually against a policy with
  per-operation budgets; there is no session-level grant.

Not borrowed: removing the human from release. BoundaryRun agrees that approving every
operation trains people to click through, which is why the gateway never prompts. It keeps a
single human decision at the point where a patch leaves the sandbox, and only when the
evidence falls short of `verified`.

## Nancy Wang, 1Password, on agent identity and credentials

Sources: https://stackoverflow.blog/2026/03/27/prevent-agentic-identity-theft/ (podcast,
March 2026), https://siliconangle.com/2026/09/28/1password-ties-ai-agent-access-individual-tasks-oktane/
(September 2026), and the July 2026 1Password for Claude announcement
(https://1password.com/it/press/2026/july/1password-for-claude). The event listing names
Wang as "Head of Applied AI, OpenAI"; every source found names her CTO of 1Password, and the
listing is treated as an error.

As reported: agents are ephemeral, so the identity an agent was issued may not be the
identity acting at execution time; standing credentials are already compromised, so access
should be just-in-time and per task, approved per request; the agent should never hold the
secret itself, which is injected out of its view; an agent should prove it finished its last
task with the right permissions before it is leased the next credential.

What BoundaryRun takes from this:

- **Issuance versus execution.** A proposal is bound to the report hash and the audit chain
  head of the run that produced it. The identity doing the push is the agent identity, with
  the operator's co-authorship and the approver's name recorded, so what executed and who
  authorized it are both on the commit.
- **The agent never holds the secret.** The token is read from the environment by the git
  credential helper at push time. It is not a tool, not in the model's context, and not in
  the sandbox. The model has no `git`, no shell and no network client at any point.
- **Prove completion before the next step.** `propose` runs only against a finished run
  with a verdict, a diff whose hash matches the report, and (if needed) an approval bound to
  that report. Nothing is leased for a run that has not finished.

Not borrowed: biometric per-request approval and a vault that injects credentials into a
browser or process. The operator holds the token and decides when to set it.

## Reading this page honestly

Every mechanism above is implemented and tested in this repository, but at the scale of one
scenario, one target application and simulated agents. The sources describe production
systems with live models and many users. Borrowing a mechanism is not borrowing its results:
no number from any source applies to BoundaryRun, and BoundaryRun's own numbers
(EVALUATION.md) come from deterministic scripted agents.
