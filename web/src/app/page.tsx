import Link from "next/link";
import { Suspense } from "react";
import { listEvals, listStandaloneInvestigations, runsDir } from "@/lib/runs";
import { duration, utc } from "@/lib/format";
import { Badge, Empty, Mono, Section, VerdictBadge } from "@/components/ui";
import { verdictTone } from "@/lib/format";

async function HomeBody() {
  const [evals, standalone] = await Promise.all([listEvals(), listStandaloneInvestigations()]);
  const dir = runsDir();

  return (
    <div className="space-y-8">
      <div className="flex items-baseline justify-between">
        <h1 className="text-base font-semibold tracking-tight">Runs</h1>
        <span className="text-muted text-xs">
          source <Mono>{dir}</Mono>
        </span>
      </div>

      <Section title="Evaluations" aside={`${evals.length} summary.json`}>
        {evals.length === 0 ? (
          <Empty>
            No eval-* directories. Produce one with <Mono>boundaryrun eval</Mono> from the repository root.
          </Empty>
        ) : (
          <div className="overflow-x-auto"><table className="data">
            <thead>
              <tr>
                <th>eval</th>
                <th>scenario</th>
                <th>started</th>
                <th>wall</th>
                <th>agents</th>
                <th>arms</th>
                <th className="num">attacks</th>
                <th className="num">repeats</th>
                <th>model</th>
                <th className="num">runs</th>
                <th>verdicts</th>
                <th className="num">errors</th>
              </tr>
            </thead>
            <tbody>
              {evals.map((e) => (
                <tr key={e.eval_id}>
                  <td>
                    <Link href={`/eval/${e.eval_id}`}>
                      <Mono>{e.eval_id}</Mono>
                    </Link>
                  </td>
                  <td>{e.scenario_id}</td>
                  <td>{utc(e.started_at)}</td>
                  <td className="num">{duration(e.started_at, e.finished_at)}</td>
                  <td>{e.agents.join(", ")}</td>
                  <td>{e.arms.join(", ")}</td>
                  <td className="num">{e.attacks.length}</td>
                  <td className="num">{e.repeats}</td>
                  <td>{e.model ?? <span className="text-muted">none (simulated only)</span>}</td>
                  <td className="num">{e.run_count}</td>
                  <td>
                    <span className="flex gap-1 flex-wrap">
                      {Object.entries(e.verdicts)
                        .sort()
                        .map(([v, n]) => (
                          <Badge key={v} tone={verdictTone(v)}>
                            {v} {n}
                          </Badge>
                        ))}
                    </span>
                  </td>
                  <td className="num">{e.error_count}</td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </Section>

      <Section title="Standalone investigations" aside="started with boundaryrun investigate, not part of an eval">
        {standalone.length === 0 ? (
          <Empty>No inv-* directories directly under the runs directory.</Empty>
        ) : (
          <div className="overflow-x-auto"><table className="data">
            <thead>
              <tr>
                <th>investigation</th>
                <th>started</th>
                <th>scenario</th>
                <th>arm</th>
                <th>agent</th>
                <th>attack</th>
                <th>autonomous</th>
                <th>verdict</th>
              </tr>
            </thead>
            <tbody>
              {standalone.map((r) => (
                <tr key={r.investigation_id}>
                  <td>
                    <Link href={`/runs/${r.investigation_id}`}>
                      <Mono>{r.investigation_id}</Mono>
                    </Link>
                  </td>
                  <td>{utc(r.started_at)}</td>
                  <td>{r.scenario_id}</td>
                  <td>{r.arm}</td>
                  <td>{r.agent_mode}</td>
                  <td>{r.attack ?? "none"}</td>
                  <td>{r.autonomous ? "yes" : "no"}</td>
                  <td>
                    <VerdictBadge status={r.verdict} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </Section>
    </div>
  );
}

export default function Home() {
  return (
    <Suspense fallback={<p className="text-muted text-xs">Reading .runs ...</p>}>
      <HomeBody />
    </Suspense>
  );
}
