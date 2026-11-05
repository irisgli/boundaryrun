import Link from "next/link";
import { Suspense } from "react";
import { notFound } from "next/navigation";
import { getInvestigation } from "@/lib/runs";
import { ms, seconds, shortHash, utc, VERDICT_MEANING, yesNo } from "@/lib/format";
import { Badge, Bool, Effect, Empty, KV, Mono, Note, Outcome, Panel, Section, VerdictBadge } from "@/components/ui";
import { Diff } from "@/components/diff";
import type { ProbeResult, StaticFinding, StaticScan, TestResult, Verdict } from "@/lib/types";

function Probe({ probe }: { probe: ProbeResult | undefined }) {
  if (!probe) return <Empty>Not run.</Empty>;
  const checks = probe.result?.checks ?? [];
  return (
    <div className="space-y-1.5">
      <div className="text-xs flex gap-3 flex-wrap">
        <span>
          container <Bool value={probe.ok} />
        </span>
        <span>
          app healthy <Bool value={probe.result?.healthy ?? null} />
        </span>
        <span className="text-muted">{seconds(probe.duration_s, 2)}</span>
        {probe.error ? <span className="text-bad">{probe.error}</span> : null}
        {probe.result?.error ? <span className="text-bad">{probe.result.error}</span> : null}
      </div>
      {checks.length > 0 ? (
        <table className="data">
          <thead>
            <tr>
              <th>check</th>
              <th>kind</th>
              <th className="num">status</th>
              <th>content</th>
              <th>outcome</th>
            </tr>
          </thead>
          <tbody>
            {checks.map((c) => (
              <tr key={c.name}>
                <td>
                  <Mono>{c.name}</Mono>
                </td>
                <td>{c.kind}</td>
                <td className="num">{c.status_code ?? "n/a"}</td>
                <td>{yesNo(c.content_returned)}</td>
                <td>
                  <Badge tone={c.outcome === "pass" ? "good" : c.outcome === "fail" ? "bad" : "warn"}>{c.outcome}</Badge>
                  {c.error ? <span className="text-bad ml-2">{c.error}</span> : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </div>
  );
}

function Tests({ t }: { t: TestResult | undefined }) {
  if (!t) return <Empty>Not run.</Empty>;
  const tone = t.status === "passed" ? "good" : t.status === "failed" ? "bad" : "warn";
  return (
    <div className="space-y-1.5">
      <div className="text-xs flex gap-3 flex-wrap items-center">
        <Badge tone={tone}>{t.status}</Badge>
        <span>
          {t.passed} passed, {t.failed} failed, {t.errors} errors
        </span>
        <span className="text-muted">exit {t.exit_code ?? "n/a"}</span>
        <span className="text-muted">{seconds(t.duration_s, 2)}</span>
      </div>
      {t.output_tail ? (
        <details>
          <summary className="text-xs text-muted cursor-pointer">output tail</summary>
          <pre className="block mt-1">{t.output_tail}</pre>
        </details>
      ) : null}
    </div>
  );
}

function Findings({ rows, empty }: { rows: StaticFinding[]; empty: string }) {
  if (rows.length === 0) return <Empty>{empty}</Empty>;
  return (
    <table className="data">
      <thead>
        <tr>
          <th>rule</th>
          <th>severity</th>
          <th>location</th>
          <th>cwe</th>
          <th>message</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((f, i) => (
          <tr key={`${f.rule_id}:${f.path}:${f.line}:${i}`}>
            <td>
              <Mono>{f.rule_id}</Mono>
            </td>
            <td>
              <Badge tone={f.severity === "ERROR" ? "bad" : f.severity === "WARNING" ? "warn" : "muted"}>
                {f.severity}
              </Badge>
            </td>
            <td>
              <Mono>
                {f.path}:{f.line}
              </Mono>
            </td>
            <td>{f.cwe ?? ""}</td>
            <td className="wrap">
              {f.message}
              {f.snippet ? <pre className="block mt-1 whitespace-pre-wrap">{f.snippet}</pre> : null}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ScanMeta({ label, scan }: { label: string; scan: StaticScan | null | undefined }) {
  if (!scan) return <span className="text-muted">{label}: not run</span>;
  return (
    <span className="text-muted">
      {label}: {scan.status}, semgrep {scan.semgrep_version ?? "n/a"}, {scan.findings.length} findings,{" "}
      {scan.parse_errors} parse errors, {seconds(scan.duration_s, 2)}
      {scan.error ? <span className="text-bad"> {scan.error}</span> : null}
    </span>
  );
}

async function RunPageBody({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const loaded = await getInvestigation(id);
  if (!loaded) notFound();
  const { report: r, evalId, audit, auditError, integrity } = loaded;
  const intact = integrity.every((c) => c.ok !== false);

  const meaning = (VERDICT_MEANING as Record<string, string>)[r.verdict.status as Verdict];
  const hashesMatch = audit.length === r.tool_requests.length;
  const totalIn = r.agent.turns.reduce((a, t) => a + (t.input_tokens ?? 0), 0);
  const totalOut = r.agent.turns.reduce((a, t) => a + (t.output_tokens ?? 0), 0);

  return (
    <div className="space-y-7">
      <div className="space-y-1">
        <div className="text-xs text-muted">
          <Link href="/">Runs</Link>
          {evalId ? (
            <>
              {" / "}
              <Link href={`/eval/${evalId}`}>{evalId}</Link>
            </>
          ) : null}
          {" / investigation"}
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          <h1 className="text-base font-semibold tracking-tight font-mono">{r.investigation_id}</h1>
          <VerdictBadge status={r.verdict.status} />
          <Badge tone="muted">{r.arm}</Badge>
          <Badge tone="muted">{r.task.agent_mode}</Badge>
          {r.task.attack ? <Badge tone="warn">attack {r.task.attack}</Badge> : <Badge tone="muted">no attack</Badge>}
          {r.agent.autonomous ? <Badge tone="good">autonomous</Badge> : <Badge tone="muted">not autonomous</Badge>}
        </div>
      </div>

      {!r.agent.autonomous ? (
        <Note>
          This run used a scripted agent ({r.agent.fixture ?? r.agent.mode}). The trajectory is deterministic and
          measures what the gateway and verifier allowed, not how a model behaves.
        </Note>
      ) : null}

      <Section
        title="Integrity"
        aside="artifact hashes and the audit hash chain recomputed from the files on disk at request time"
      >
        <Panel className="p-3">
          <div className="flex items-center gap-2 mb-2">
            <Badge tone={intact ? "good" : "bad"}>{intact ? "intact" : "tampered or incomplete"}</Badge>
            {r.audit_chain_head ? (
              <span className="text-xs text-muted">
                chain head <Mono>{shortHash(r.audit_chain_head, 16)}</Mono>
              </span>
            ) : null}
          </div>
          <table className="data">
            <tbody>
              {integrity.map((c) => (
                <tr key={c.name}>
                  <td>
                    <Badge tone={c.ok === null ? "muted" : c.ok ? "good" : "bad"}>
                      {c.ok === null ? "n/a" : c.ok ? "ok" : "fail"}
                    </Badge>
                  </td>
                  <td>{c.name}</td>
                  <td className="wrap text-muted">{c.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      </Section>

      <Section title="Verdict">
        <Panel className="p-3 space-y-2">
          <div className="flex items-center gap-3">
            <VerdictBadge status={r.verdict.status} />
            {meaning ? <span className="text-xs">{meaning}</span> : null}
          </div>
          <ul className="list-disc pl-5 text-xs space-y-0.5">
            {r.verdict.reasons.map((reason, i) => (
              <li key={i}>{reason}</li>
            ))}
          </ul>
          <p className="text-[11px] text-muted leading-relaxed">{r.verdict.claim_scope}</p>
        </Panel>
      </Section>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Section title="Agent claim" aside="stored separately from the verdict; never an input to it">
          {r.agent_claim ? (
            <KV
              rows={[
                ["summary", r.agent_claim.summary],
                ["files claimed", r.agent_claim.files_changed.map((f) => <Mono key={f}>{f} </Mono>)],
                ["files actually changed", r.patch.files.map((f) => <Mono key={f.path}>{f.path} </Mono>)],
                [
                  "verifier agrees",
                  <Bool key="agree" value={r.verdict.status === "verified"} />,
                ],
              ]}
            />
          ) : (
            <Empty>No claim submitted ({r.agent.finished_by ?? r.agent.error ?? "agent did not finish"}).</Empty>
          )}
        </Section>

        <Section title="Finding">
          <KV
            rows={[
              ["id", <Mono key="id">{r.finding.id}</Mono>],
              ["title", r.finding.title],
              ["severity / cwe", `${r.finding.severity} / ${r.finding.cwe ?? "n/a"}`],
              ["endpoint", <Mono key="e">{r.finding.affected_endpoint ?? "n/a"}</Mono>],
              ["description", r.finding.description],
              ...(r.finding.reproduction
                ? Object.entries(r.finding.reproduction).map(([k, v]) => [`repro ${k}`, v] as [string, string])
                : []),
              ["source", r.finding.source ?? "n/a"],
            ]}
          />
        </Section>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Section title="Agent">
          <KV
            rows={[
              ["mode", r.agent.mode],
              ["fixture", r.agent.fixture ?? "none"],
              ["model requested", r.agent.model_requested ?? "none"],
              ["models observed", r.agent.models_observed.length ? r.agent.models_observed.join(", ") : "none"],
              ["turns", String(r.agent.turns.length)],
              ["tokens in / out", `${totalIn} / ${totalOut}`],
              ["tool calls requested", String(r.agent.tool_calls_requested)],
              ["finished by", r.agent.finished_by ?? "n/a"],
              ["refusal", r.agent.refusal_category ?? "none"],
              ["error", r.agent.error ?? "none"],
              ["duration", seconds(r.agent.duration_s, 2)],
              ["skipped", r.agent_skipped_reason ?? "no"],
            ]}
          />
        </Section>

        <Section title="Policy summary">
          <KV
            rows={[
              ["requests", String(r.policy_summary.requests)],
              ["executed", String(r.policy_summary.executed)],
              ["denied", String(r.policy_summary.denied)],
              ["rejected", String(r.policy_summary.rejected)],
              ["errors", String(r.policy_summary.errors)],
              [
                "denied by rule",
                Object.keys(r.policy_summary.denied_by_rule).length
                  ? Object.entries(r.policy_summary.denied_by_rule).map(([k, v]) => (
                      <div key={k}>
                        <Mono>{k}</Mono> {v}
                      </div>
                    ))
                  : "none",
              ],
            ]}
          />
        </Section>

        <Section title="Injection observations">
          <KV
            rows={[
              ["injection files", r.injection.injection_files.join(", ") || "none"],
              ["read by agent", r.injection.injection_files_read.join(", ") || "none"],
              [
                "sensitive reads att / exec",
                <span key="s" className={r.injection.sensitive_read_executed > 0 ? "text-bad" : ""}>
                  {r.injection.sensitive_read_attempts} / {r.injection.sensitive_read_executed}
                </span>,
              ],
              [
                "egress att / exec",
                <span key="e" className={r.injection.egress_executed > 0 ? "text-bad" : ""}>
                  {r.injection.egress_attempts} / {r.injection.egress_executed}
                </span>,
              ],
              [
                "out of scope writes att / exec",
                <span key="w" className={r.injection.out_of_scope_write_executed > 0 ? "text-bad" : ""}>
                  {r.injection.out_of_scope_write_attempts} / {r.injection.out_of_scope_write_executed}
                </span>,
              ],
              [
                "canary hits by channel",
                Object.keys(r.injection.canary_hits_by_channel).length
                  ? Object.entries(r.injection.canary_hits_by_channel).map(([k, v]) => (
                      <div key={k} className="text-bad">
                        {k}: {v}
                      </div>
                    ))
                  : "none",
              ],
              ["egress sink entries", String(r.egress_sink.length)],
            ]}
          />
        </Section>
      </div>

      {r.attack ? (
        <Section title="Planted attack" aside={`${r.attack.vector}, objective ${r.attack.objective}`}>
          <div className="text-xs mb-2">
            objective achieved <Bool value={r.attack.objective_achieved} invert />
          </div>
          <table className="data">
            <thead>
              <tr>
                <th>directive</th>
                <th>input</th>
                <th>attempted</th>
                <th>executed</th>
              </tr>
            </thead>
            <tbody>
              {r.attack.directives.map((d, i) => (
                <tr key={i}>
                  <td>
                    <Mono>{d.tool}</Mono>
                  </td>
                  <td className="wrap">
                    <pre className="block">{JSON.stringify(d.input, null, 1)}</pre>
                  </td>
                  <td>{yesNo(d.attempted)}</td>
                  <td>
                    <Bool value={d.executed} invert />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>
      ) : null}

      <Section
        title="Tool requests"
        aside={`${r.tool_requests.length} in report, ${auditError ? "audit.jsonl unreadable" : `${audit.length} in audit.jsonl`}${hashesMatch || auditError ? "" : ", counts differ"}`}
      >
        {auditError ? <Note>audit.jsonl: {auditError}</Note> : null}
        <div className="overflow-x-auto">
          <table className="data">
            <thead>
              <tr>
                <th className="num">#</th>
                <th>time</th>
                <th>tool</th>
                <th>input</th>
                <th>decision</th>
                <th>rule</th>
                <th>reference</th>
                <th>outcome</th>
                <th className="num">bytes</th>
                <th>sha256</th>
                <th className="num">ms</th>
              </tr>
            </thead>
            <tbody>
              {r.tool_requests.map((t) => {
                const refDeny = t.reference_decision?.effect === "deny";
                return (
                  <tr key={t.seq} className={refDeny && t.outcome === "executed" ? "bg-bad-bg/40" : ""}>
                    <td className="num">{t.seq}</td>
                    <td className="text-muted">{t.timestamp.slice(11, 23)}</td>
                    <td>
                      <Mono>{t.tool}</Mono>
                    </td>
                    <td className="wrap max-w-[420px]">
                      <Mono>{JSON.stringify(t.input)}</Mono>
                    </td>
                    <td>
                      <Effect effect={t.decision.effect} />
                    </td>
                    <td title={t.decision.reason}>
                      <Mono>{t.decision.rule}</Mono>
                    </td>
                    <td title={t.reference_decision?.reason ?? ""}>
                      {t.reference_decision ? <Effect effect={t.reference_decision.effect} /> : "n/a"}
                    </td>
                    <td>
                      <Outcome outcome={t.outcome} />
                      {t.error ? <span className="text-bad ml-1">{t.error}</span> : null}
                    </td>
                    <td className="num">{t.output_bytes ?? ""}</td>
                    <td>
                      <Mono>{shortHash(t.output_sha256)}</Mono>
                    </td>
                    <td className="num">{ms(t.duration_ms)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <p className="text-muted text-[11px]">
          Decision is what this arm&apos;s policy did. Reference is what the Phase 1 policy would have done, recorded in every
          arm so that unauthorized has one meaning. Rows shaded red were reference-denied yet executed, which can only
          happen in the unprotected arm.
        </p>
      </Section>

      <Section title="Patch" aside={`${r.patch.files.length} files, diff sha256 ${shortHash(r.artifacts["patch.diff"])}`}>
        {r.patch.files.length > 0 ? (
          <table className="data mb-2">
            <thead>
              <tr>
                <th>file</th>
                <th>change</th>
                <th>in write scope</th>
              </tr>
            </thead>
            <tbody>
              {r.patch.files.map((f) => (
                <tr key={f.path}>
                  <td>
                    <Mono>{f.path}</Mono>
                  </td>
                  <td>{f.change}</td>
                  <td>
                    <Bool value={f.in_write_scope} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
        <Diff text={r.patch.diff} />
      </Section>

      <Section title="Execution results" aside="black-box probe and functional suite, before and after the patch">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Panel className="p-3 space-y-3">
            <h3 className="text-xs font-semibold">Baseline (unmodified target)</h3>
            <Probe probe={r.baseline.probe} />
            <Tests t={r.baseline.functional_tests} />
          </Panel>
          <Panel className="p-3 space-y-3">
            <h3 className="text-xs font-semibold">Post patch</h3>
            {r.post_patch ? (
              <>
                <Probe probe={r.post_patch.probe} />
                <Tests t={r.post_patch.functional_tests} />
              </>
            ) : (
              <Empty>Not run (no patch or baseline inconclusive).</Empty>
            )}
          </Panel>
        </div>
      </Section>

      {r.static_analysis ? (
        <Section
          title="Static analysis"
          aside={r.static_analysis.conclusive ? "conclusive" : "inconclusive: a scan did not complete"}
        >
          <div className="text-[11px] flex flex-col gap-0.5 mb-2">
            <ScanMeta label="baseline" scan={r.static_analysis.baseline} />
            <ScanMeta label="patched" scan={r.static_analysis.patched} />
            <span className="text-muted">
              unchanged {r.static_analysis.unchanged}, rules sha256{" "}
              {shortHash(r.static_analysis.baseline?.rules_sha256 ?? r.static_analysis.patched?.rules_sha256)}
            </span>
          </div>
          <div className="space-y-4">
            <div className="space-y-1">
              <h3 className="text-xs font-semibold">Introduced by the patch</h3>
              <Findings rows={r.static_analysis.introduced} empty="None. Nothing new appeared in the patched tree." />
            </div>
            <div className="space-y-1">
              <h3 className="text-xs font-semibold">Resolved by the patch</h3>
              <Findings rows={r.static_analysis.resolved} empty="None." />
            </div>
          </div>
        </Section>
      ) : null}

      {r.errors.length > 0 ? (
        <Section title="Errors" aside={`${r.errors.length}`}>
          <ul className="list-disc pl-5 text-xs">
            {r.errors.map((e, i) => (
              <li key={i} className="text-bad">
                {e}
              </li>
            ))}
          </ul>
        </Section>
      ) : null}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Section title="Task configuration">
          <KV
            rows={[
              ["target", <Mono key="t">{r.task.target}</Mono>],
              [
                "repo",
                r.task.repo ? (
                  <Mono key="r">
                    {r.task.repo.url} @ {r.task.repo.ref}
                    {r.task.repo.subdir ? ` /${r.task.repo.subdir}` : ""}
                  </Mono>
                ) : (
                  "local directory"
                ),
              ],
              ["fixture", r.task.fixture ?? "none"],
              ["model", r.task.model ?? "none"],
            ]}
          />
          <details className="mt-2">
            <summary className="text-xs text-muted cursor-pointer">policy</summary>
            <pre className="block mt-1">{JSON.stringify(r.task.policy, null, 2)}</pre>
          </details>
          <details className="mt-1">
            <summary className="text-xs text-muted cursor-pointer">sandbox limits</summary>
            <pre className="block mt-1">{JSON.stringify(r.task.sandbox, null, 2)}</pre>
          </details>
        </Section>

        <Section title="Execution environment">
          <KV
            rows={Object.entries(r.execution).map(([k, v]) => [
              k,
              k.endsWith("_at") ? utc(v) : <Mono key={k}>{v ?? "n/a"}</Mono>,
            ])}
          />
        </Section>

        <Section title="Artifacts" aside="sha256 recorded in the report at write time">
          <KV
            rows={Object.entries(r.artifacts).map(([k, v]) => [k, <Mono key={k}>{v}</Mono>])}
          />
          <p className="text-[11px] text-muted mt-2">
            schema <Mono>{r.schema_version}</Mono>, scenario <Mono>{r.scenario_id}</Mono>
          </p>
        </Section>
      </div>
    </div>
  );
}

export default function RunPage(props: PageProps<"/runs/[id]">) {
  return (
    <Suspense fallback={<p className="text-muted text-xs">Reading .runs ...</p>}>
      <RunPageBody params={props.params} />
    </Suspense>
  );
}
