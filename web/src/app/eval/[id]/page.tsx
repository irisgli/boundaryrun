import Link from "next/link";
import { Suspense } from "react";
import { notFound } from "next/navigation";
import { getEval } from "@/lib/runs";
import { duration, rate, seconds, utc } from "@/lib/format";
import { Badge, Bool, KV, Mono, Note, Section, VerdictBadge } from "@/components/ui";
import type { EvalRun } from "@/lib/types";

function InjectionCell({ run }: { run: EvalRun }) {
  if (run.injection_success === null) return <span className="text-muted">no attack</span>;
  return <Bool value={run.injection_success} invert />;
}

async function EvalPageBody({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const ev = await getEval(id);
  if (!ev) notFound();

  const byAgent = new Map<string, EvalRun[]>();
  for (const run of ev.runs) {
    const key = `${run.arm}/${run.agent}`;
    byAgent.set(key, [...(byAgent.get(key) ?? []), run]);
  }
  const liveRuns = ev.runs.filter((r) => !r.simulated).length;

  return (
    <div className="space-y-7">
      <div className="space-y-1">
        <div className="text-xs text-muted">
          <Link href="/">Runs</Link> / evaluation
        </div>
        <h1 className="text-base font-semibold tracking-tight font-mono">{ev.eval_id}</h1>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <KV
          rows={[
            ["scenario", ev.scenario_id],
            ["schema", <Mono key="s">{ev.schema_version}</Mono>],
            ["started", utc(ev.started_at)],
            ["finished", utc(ev.finished_at)],
            ["wall clock", duration(ev.started_at, ev.finished_at)],
          ]}
        />
        <KV
          rows={[
            ["agents", ev.agents.join(", ")],
            ["arms", ev.arms.join(", ")],
            ["attacks", ev.attacks.join(", ")],
            ["repeats", String(ev.repeats)],
            ["model", ev.model ?? "none"],
            ["investigations", `${ev.runs.length} (${liveRuns} live, ${ev.runs.length - liveRuns} simulated)`],
          ]}
        />
      </div>

      {ev.note ? <Note>{ev.note}</Note> : null}
      {liveRuns === 0 ? (
        <Note>
          No live model runs in this evaluation. Every rate below describes what the gateway and verifier allowed
          under a deterministic scripted agent. It is not an attack success rate for any model.
        </Note>
      ) : null}

      <Section
        title="Aggregate by view and agent"
        aside="protected and protected_verified are two views of the same executions; only the reported outcome differs"
      >
        <div className="overflow-x-auto">
          <table className="data">
            <thead>
              <tr>
                <th>view</th>
                <th>agent</th>
                <th className="num">runs</th>
                <th className="num">attacked</th>
                <th className="num">task done</th>
                <th className="num">reported fixed</th>
                <th className="num">verified fixed</th>
                <th className="num">unauth attempts /run</th>
                <th className="num">unauth executed /attempt</th>
                <th className="num">injection success</th>
                <th className="num">denials /run</th>
                <th className="num">false denials /run</th>
                <th className="num">regression</th>
                <th className="num">scope violation</th>
                <th className="num">canary exposed</th>
                <th className="num">trifecta held</th>
                <th className="num">requirements met</th>
                <th className="num">mean s</th>
                <th className="num">mean in tok</th>
                <th className="num">mean out tok</th>
              </tr>
            </thead>
            <tbody>
              {ev.summary.map((s) => {
                const gap = s.reported_remediation_rate !== s.verified_remediation_rate;
                return (
                  <tr key={`${s.view}/${s.agent}`}>
                    <td>{s.view}</td>
                    <td>{s.agent}</td>
                    <td className="num">{s.runs}</td>
                    <td className="num">{s.attacked_runs}</td>
                    <td className="num">{rate(s.task_completion_rate)}</td>
                    <td className={`num ${gap ? "text-warn" : ""}`}>{rate(s.reported_remediation_rate)}</td>
                    <td className="num">{rate(s.verified_remediation_rate)}</td>
                    <td className="num">{s.unauthorized_attempt_rate.toFixed(2)}</td>
                    <td className="num">{rate(s.unauthorized_execution_rate)}</td>
                    <td className="num">{rate(s.injection_success_rate)}</td>
                    <td className="num">{s.denial_rate.toFixed(2)}</td>
                    <td className="num">{s.false_denial_rate.toFixed(2)}</td>
                    <td className="num">{rate(s.regression_rate)}</td>
                    <td className="num">{rate(s.scope_violation_rate)}</td>
                    <td className="num">{rate(s.canary_exposure_rate)}</td>
                    <td className="num">{s.trifecta_rate === undefined ? "n/a" : rate(s.trifecta_rate)}</td>
                    <td className="num">{s.requirements_met_rate === undefined ? "n/a" : rate(s.requirements_met_rate)}</td>
                    <td className="num">{s.mean_duration_s.toFixed(2)}</td>
                    <td className="num">{Math.round(s.mean_input_tokens)}</td>
                    <td className="num">{Math.round(s.mean_output_tokens)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <p className="text-muted text-[11px]">
          Reported fixed is highlighted where it differs from verified fixed: the view reports the agent claim and the
          verifier disagreed. Unauthorized means denied by the reference policy, in every arm, including unprotected.
        </p>
      </Section>

      <Section title="Per investigation" aside={`${ev.runs.length} rows, one per report.json`}>
        <div className="overflow-x-auto">
          <table className="data">
            <thead>
              <tr>
                <th>investigation</th>
                <th>arm</th>
                <th>agent</th>
                <th>attack</th>
                <th>verdict</th>
                <th>claimed</th>
                <th>verified</th>
                <th className="num">unauth att / exec</th>
                <th className="num">denials</th>
                <th>injection blocked</th>
                <th>canary</th>
                <th>scope</th>
                <th>regression</th>
                <th className="num">s</th>
                <th className="num">tokens in / out</th>
              </tr>
            </thead>
            <tbody>
              {ev.runs.map((r) => (
                <tr key={r.investigation_id}>
                  <td>
                    <Link href={`/runs/${r.investigation_id}`}>
                      <Mono>{r.investigation_id}</Mono>
                    </Link>
                    {!r.simulated ? (
                      <>
                        {" "}
                        <Badge tone="good">live</Badge>
                      </>
                    ) : null}
                  </td>
                  <td>{r.arm}</td>
                  <td>{r.agent}</td>
                  <td>{r.attack}</td>
                  <td>
                    <VerdictBadge status={r.verdict} />
                  </td>
                  <td>{r.claimed_remediated ? "yes" : "no"}</td>
                  <td>{r.verified_remediated ? "yes" : "no"}</td>
                  <td className={`num ${r.unauthorized_executed > 0 ? "text-bad" : ""}`}>
                    {r.unauthorized_attempts} / {r.unauthorized_executed}
                  </td>
                  <td className="num">{r.denials}</td>
                  <td>
                    <InjectionCell run={r} />
                  </td>
                  <td>
                    <Bool value={r.canary_exposed} invert />
                  </td>
                  <td>
                    <Bool value={r.scope_violation} invert />
                  </td>
                  <td>
                    <Bool value={r.functional_regression} invert />
                  </td>
                  <td className="num">{seconds(r.duration_s, 2)}</td>
                  <td className="num">
                    {r.input_tokens} / {r.output_tokens}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-muted text-[11px]">
          Injection blocked is yes when at least one directive of the planted attack did not execute. For runs without an
          attack there is nothing to block.
        </p>
      </Section>

      {ev.errors.length > 0 ? (
        <Section title="Errors" aside={`${ev.errors.length}`}>
          <pre className="block">{JSON.stringify(ev.errors, null, 2)}</pre>
        </Section>
      ) : null}
    </div>
  );
}

export default function EvalPage(props: PageProps<"/eval/[id]">) {
  return (
    <Suspense fallback={<p className="text-muted text-xs">Reading .runs ...</p>}>
      <EvalPageBody params={props.params} />
    </Suspense>
  );
}
