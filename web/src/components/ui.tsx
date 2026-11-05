import type { ReactNode } from "react";
import { verdictTone } from "@/lib/format";

type Tone = "good" | "warn" | "bad" | "muted";

const toneClass: Record<Tone, string> = {
  good: "bg-good-bg text-good",
  warn: "bg-warn-bg text-warn",
  bad: "bg-bad-bg text-bad",
  muted: "bg-neutral-bg text-neutral",
};

export function Badge({ tone = "muted", children }: { tone?: Tone; children: ReactNode }) {
  return (
    <span
      className={`inline-block rounded-sm px-1.5 py-[1px] font-mono text-[11px] leading-[16px] ${toneClass[tone]}`}
    >
      {children}
    </span>
  );
}

export function VerdictBadge({ status }: { status: string }) {
  return <Badge tone={verdictTone(status)}>{status}</Badge>;
}

export function Effect({ effect }: { effect: string }) {
  const tone: Tone = effect === "allow" ? "good" : effect === "deny" ? "bad" : "warn";
  return <Badge tone={tone}>{effect}</Badge>;
}

export function Outcome({ outcome }: { outcome: string }) {
  const tone: Tone = outcome === "executed" ? "good" : outcome === "denied" ? "bad" : "warn";
  return <Badge tone={tone}>{outcome}</Badge>;
}

export function Bool({ value, invert = false }: { value: boolean | null | undefined; invert?: boolean }) {
  if (value === null || value === undefined) return <span className="text-muted">n/a</span>;
  const good = invert ? !value : value;
  return <Badge tone={good ? "good" : "bad"}>{value ? "yes" : "no"}</Badge>;
}

export function Section({ title, aside, children }: { title: string; aside?: ReactNode; children: ReactNode }) {
  return (
    <section className="space-y-2">
      <div className="flex items-baseline gap-3">
        <h2 className="text-[13px] font-semibold tracking-tight">{title}</h2>
        {aside ? <span className="text-muted text-xs">{aside}</span> : null}
      </div>
      {children}
    </section>
  );
}

export function Panel({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={`rounded border border-line bg-panel ${className}`}>{children}</div>;
}

export function KV({ rows }: { rows: Array<[string, ReactNode]> }) {
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-xs">
      {rows.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-muted">{k}</dt>
          <dd className="min-w-0 break-words">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Mono({ children }: { children: ReactNode }) {
  return <span className="font-mono text-[12px]">{children}</span>;
}

export function Note({ children }: { children: ReactNode }) {
  return (
    <div className="rounded border border-warn/40 bg-warn-bg text-warn px-3 py-2 text-xs leading-relaxed">
      {children}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="text-muted text-xs">{children}</p>;
}
