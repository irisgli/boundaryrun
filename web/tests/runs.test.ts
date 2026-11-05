import path from "node:path";
import { beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("next/server", () => ({ connection: async () => {} }));

const FIXTURES = path.resolve(__dirname, "fixtures", "runs");
const EVAL = "eval-20261105T023154Z";
const INV = "inv-20261105T023450Z-f14bac";

beforeAll(() => {
  process.env.BOUNDARYRUN_RUNS_DIR = FIXTURES;
});

describe("identifier validation", () => {
  it("accepts the ids the control process generates and nothing else", async () => {
    const { isEvalId, isInvestigationId } = await import("@/lib/runs");
    expect(isEvalId(EVAL)).toBe(true);
    expect(isInvestigationId(INV)).toBe(true);
    expect(isEvalId("../etc")).toBe(false);
    expect(isInvestigationId("inv-20261105T023450Z-F14BAC")).toBe(false);
    expect(isInvestigationId("inv-20261105T023450Z-f14bac/../x")).toBe(false);
  });

  it("refuses traversal through the route param", async () => {
    const { getEval, getInvestigation } = await import("@/lib/runs");
    expect(await getEval("../" + EVAL)).toBeNull();
    expect(await getInvestigation("..")).toBeNull();
  });
});

describe("evaluation index", () => {
  it("lists summary.json files with verdict counts taken from the runs array", async () => {
    const { listEvals } = await import("@/lib/runs");
    const evals = await listEvals();
    expect(evals).toHaveLength(1);
    const e = evals[0];
    expect(e.eval_id).toBe(EVAL);
    expect(e.run_count).toBe(20);
    expect(e.model).toBeNull();
    expect(e.verdicts).toEqual({ verified: 17, needs_review: 2, scope_violation: 1 });
  });

  it("loads a summary with aggregates for every view and agent", async () => {
    const { getEval } = await import("@/lib/runs");
    const ev = await getEval(EVAL);
    expect(ev?.schema_version).toBe("boundaryrun.eval/v1");
    expect(ev?.summary.map((s) => `${s.view}/${s.agent}`)).toEqual([
      "unprotected/compliant",
      "unprotected/obedient",
      "protected/compliant",
      "protected/obedient",
      "protected_verified/compliant",
      "protected_verified/obedient",
    ]);
  });

  it("returns null for an unknown eval", async () => {
    const { getEval } = await import("@/lib/runs");
    expect(await getEval("eval-20000101T000000Z")).toBeNull();
  });
});

describe("investigations", () => {
  it("finds an investigation nested under an eval and parses its audit log", async () => {
    const { getInvestigation } = await import("@/lib/runs");
    const inv = await getInvestigation(INV);
    expect(inv?.evalId).toBe(EVAL);
    expect(inv?.report.verdict.status).toBe("needs_review");
    expect(inv?.auditError).toBeNull();
    expect(inv?.audit).toHaveLength(inv!.report.tool_requests.length);
    expect(inv?.audit[0].seq).toBe(1);
  });

  it("reports a missing audit log instead of failing the page", async () => {
    const { getInvestigation } = await import("@/lib/runs");
    const inv = await getInvestigation("inv-20261105T023154Z-8b523b");
    expect(inv?.report.verdict.status).toBe("verified");
    expect(inv?.audit).toEqual([]);
    expect(inv?.auditError).toMatch(/ENOENT/);
  });

  it("lists no standalone investigations when all are nested", async () => {
    const { listStandaloneInvestigations } = await import("@/lib/runs");
    expect(await listStandaloneInvestigations()).toEqual([]);
  });
});

describe("formatting", () => {
  it("formats rates, durations and verdict tones", async () => {
    const { rate, duration, verdictTone, utc } = await import("@/lib/format");
    expect(rate(0.25)).toBe("25%");
    expect(rate(null)).toBe("n/a");
    expect(duration("2026-11-05T02:31:54Z", "2026-11-05T02:36:27Z")).toBe("4m 33s");
    expect(utc("2026-11-05T02:31:54.710684+00:00")).toBe("2026-11-05 02:31:54 UTC");
    expect(verdictTone("verified")).toBe("good");
    expect(verdictTone("scope_violation")).toBe("bad");
    expect(verdictTone("no_patch")).toBe("muted");
  });
});
