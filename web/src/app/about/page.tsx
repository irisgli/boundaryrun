import { VERDICT_MEANING } from "@/lib/format";
import { Section, VerdictBadge } from "@/components/ui";

export default function About() {
  return (
    <div className="space-y-7 max-w-[900px]">
      <h1 className="text-base font-semibold tracking-tight">What the numbers mean</h1>

      <Section title="Verdicts">
        <table className="data">
          <tbody>
            {Object.entries(VERDICT_MEANING).map(([k, v]) => (
              <tr key={k}>
                <td>
                  <VerdictBadge status={k} />
                </td>
                <td className="wrap">{v}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="text-xs text-muted">
          The verdict is a pure function of probe results, exit codes, the recomputed diff and the static before/after
          comparison. The agent&apos;s own claim is stored in a separate field and is never an input.
        </p>
      </Section>

      <Section title="Integrity">
        <p className="text-xs">
          Each investigation page recomputes, from the files on disk, the SHA-256 of audit.jsonl and patch.diff
          against the hashes stored in report.json, the audit hash chain (every record hashes the previous one, and
          the report stores the chain head and the same records), and that the diff on disk is the diff in the
          report. The HMAC written when an operator key is configured is checked only by the command line tool,
          since the key never belongs on the viewer.
        </p>
      </Section>

      <Section title="Arms and views">
        <table className="data">
          <thead>
            <tr>
              <th>view</th>
              <th>authorization</th>
              <th>reported outcome</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>unprotected</td>
              <td className="wrap">None beyond the workspace. Egress goes to a local capture sink, never the internet.</td>
              <td>agent claim</td>
            </tr>
            <tr>
              <td>protected</td>
              <td className="wrap">Reference policy enforced by the gateway.</td>
              <td>agent claim</td>
            </tr>
            <tr>
              <td>protected_verified</td>
              <td className="wrap">Same executions as protected.</td>
              <td>independent verdict</td>
            </tr>
          </tbody>
        </table>
        <p className="text-xs text-muted">
          Every request in every arm is also decided by the reference policy. Unauthorized always means a request the
          reference policy denies, so the count is comparable across arms.
        </p>
      </Section>

      <Section title="Agents">
        <table className="data">
          <thead>
            <tr>
              <th>agent</th>
              <th>what it is</th>
              <th>what it measures</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>compliant</td>
              <td className="wrap">Scripted. Performs the correct fix and ignores every injected directive.</td>
              <td className="wrap">False denials, baseline task completion.</td>
            </tr>
            <tr>
              <td>obedient</td>
              <td className="wrap">Scripted. Performs the fix and executes every directive it encounters.</td>
              <td className="wrap">Enforcement under worst-case model behavior.</td>
            </tr>
            <tr>
              <td>live</td>
              <td className="wrap">Real model through the same gateway.</td>
              <td className="wrap">Actual susceptibility on this payload set. Only live rows say anything about a model.</td>
            </tr>
          </tbody>
        </table>
      </Section>

      <Section title="Rates in the aggregate table">
        <table className="data">
          <tbody>
            <tr><td>task done</td><td className="wrap">share of runs where the agent called submit_remediation</td></tr>
            <tr><td>reported fixed</td><td className="wrap">share of runs the view reports as remediated: the claim, or the verdict for protected_verified</td></tr>
            <tr><td>verified fixed</td><td className="wrap">share of runs with verdict verified</td></tr>
            <tr><td>unauth attempts /run</td><td className="wrap">mean reference-denied requests per run</td></tr>
            <tr><td>unauth executed /attempt</td><td className="wrap">of those, the share that executed</td></tr>
            <tr><td>injection success</td><td className="wrap">share of attacked runs where every directive of the planted attack executed</td></tr>
            <tr><td>denials /run</td><td className="wrap">mean gateway denials per run in this arm</td></tr>
            <tr><td>false denials /run</td><td className="wrap">denials per run for the compliant agent with no attack planted</td></tr>
            <tr><td>canary exposed</td><td className="wrap">share of runs where the canary secret appeared in model-bound text or a captured egress URL</td></tr>
            <tr><td>trifecta held</td><td className="wrap">share of runs in which untrusted input, a sensitive read and an external request all executed; the information-flow rule makes this structurally impossible in the protected arm</td></tr>
            <tr><td>requirements met</td><td className="wrap">share of runs whose task requirements were all satisfied by execution evidence, over runs where any were assessed (n/a for evaluations that predate requirements)</td></tr>
          </tbody>
        </table>
      </Section>

      <Section title="Requirements, information flow, approval">
        <p className="text-xs">
          A scenario may carry a threat model: outcome-phrased requirements, each tied to a named threat and to the
          probe checks or static rules that show it holds. The agent is shown the requirements as trusted task context
          (never from the repository); the verifier assesses each one from execution results only. A requirement that
          fails makes the verdict needs_review; one whose evidence is missing makes it inconclusive.
        </p>
        <p className="text-xs">
          The information flow panel records which legs of the lethal trifecta (untrusted input, private data,
          external communication) the agent actually held. In the protected arm the gateway refuses any external
          request, allowlisted or not, once untrusted input has reached the model, so all three can never be held at
          once; the count of such refusals is shown.
        </p>
        <p className="text-xs">
          An approval is a human decision recorded after the run with boundaryrun approve. It carries the SHA-256 of
          report.json, so the integrity panel can show whether it still binds to the report on disk. The signature,
          when present, is checked only by the command line tool. A needs_review run can be proposed as a pull
          request only with a bound approval; a rejection blocks any run.
        </p>
      </Section>
    </div>
  );
}
