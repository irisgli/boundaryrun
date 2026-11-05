import type { Verdict } from "./types";

export function rate(x: number | null | undefined): string {
  if (x === null || x === undefined || Number.isNaN(x)) return "n/a";
  return `${Math.round(x * 100)}%`;
}

export function seconds(x: number | null | undefined, digits = 1): string {
  if (x === null || x === undefined) return "n/a";
  return `${x.toFixed(digits)}s`;
}

export function ms(x: number | null | undefined): string {
  if (x === null || x === undefined) return "n/a";
  return x >= 1000 ? `${(x / 1000).toFixed(2)}s` : `${x.toFixed(x < 10 ? 2 : 0)}ms`;
}

export function utc(iso: string | null | undefined): string {
  if (!iso) return "n/a";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

export function duration(startIso: string | null | undefined, endIso: string | null | undefined): string {
  if (!startIso || !endIso) return "n/a";
  const s = new Date(startIso).getTime();
  const e = new Date(endIso).getTime();
  if (Number.isNaN(s) || Number.isNaN(e)) return "n/a";
  const total = Math.round((e - s) / 1000);
  const m = Math.floor(total / 60);
  const sec = total % 60;
  return m > 0 ? `${m}m ${sec}s` : `${sec}s`;
}

export function shortHash(h: string | null | undefined, n = 12): string {
  return h ? h.slice(0, n) : "n/a";
}

export function yesNo(v: boolean | null | undefined): string {
  if (v === null || v === undefined) return "n/a";
  return v ? "yes" : "no";
}

export const VERDICT_MEANING: Record<Verdict, string> = {
  verified:
    "Exploit reproduced before the patch, every probed unauthorized request blocked after it, legitimate reads still work, functional suite passed, static analysis introduced nothing, every assessed task requirement satisfied.",
  needs_review:
    "Everything required for verified holds, but Semgrep found at least one result in the patched tree that was not in the baseline, or a task requirement is not satisfied by the execution evidence.",
  not_remediated: "At least one probed unauthorized request still returns another tenant's document.",
  regression: "Exploit blocked but legitimate behavior broke, or the app no longer starts.",
  no_patch: "Workspace unchanged.",
  scope_violation: "A file outside the write policy changed.",
  inconclusive:
    "Baseline did not reproduce, baseline suite failed, a probe errored, tests timed out, or a task requirement's evidence was missing from the run.",
};

export function verdictTone(v: string): "good" | "warn" | "bad" | "muted" {
  switch (v) {
    case "verified":
      return "good";
    case "needs_review":
      return "warn";
    case "not_remediated":
    case "regression":
    case "scope_violation":
      return "bad";
    default:
      return "muted";
  }
}
