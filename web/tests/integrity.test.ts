import { promises as fs } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { GENESIS, sha256, verifyChain } from "@/lib/integrity";
import { integrityChecks } from "@/lib/runs";
import type { Report } from "@/lib/types";

const RUN = path.resolve(__dirname, "fixtures", "chained", "inv-20260101T000000Z-abcdef");

async function load() {
  const [report, audit, patch] = await Promise.all([
    fs.readFile(path.join(RUN, "report.json"), "utf8").then((t) => JSON.parse(t) as Report),
    fs.readFile(path.join(RUN, "audit.jsonl")),
    fs.readFile(path.join(RUN, "patch.diff")),
  ]);
  return { report, audit, patch };
}

describe("audit hash chain (must agree with boundaryrun.evidence)", () => {
  it("verifies a chain written by the Python control process, including unicode and floats", async () => {
    const { report, audit } = await load();
    const lines = audit.toString("utf8").split("\n").filter(Boolean);
    const r = verifyChain(lines);
    expect(r.ok).toBe(true);
    expect(r.head).toBe(report.audit_chain_head);
    expect(r.records).toBe(3);
  });

  it("uses the documented definition: sha256(prev || line without record_hash)", async () => {
    const { audit } = await load();
    const first = audit.toString("utf8").split("\n")[0];
    const text = first.slice(0, first.lastIndexOf(',"record_hash":')) + "}";
    expect(JSON.parse(first).record_hash).toBe(sha256(GENESIS + text));
  });

  it.each(["edit", "delete", "insert", "reorder", "truncate"])("rejects a %s", async (mutation) => {
    const { report, audit } = await load();
    let lines = audit.toString("utf8").split("\n").filter(Boolean);
    if (mutation === "edit") lines[1] = lines[1].replace('"outcome":"executed"', '"outcome":"denied"');
    if (mutation === "delete") lines.splice(1, 1);
    if (mutation === "insert") lines.splice(1, 0, lines[0]);
    if (mutation === "reorder") lines = [lines[0], lines[2], lines[1]];
    if (mutation === "truncate") lines = lines.slice(0, 2);
    const r = verifyChain(lines);
    expect(r.ok && r.head === report.audit_chain_head).toBe(false);
  });
});

describe("integrity checks", () => {
  it("passes on the intact run", async () => {
    const { report, audit, patch } = await load();
    const checks = integrityChecks(report, { audit, patch, hmac: false });
    expect(checks.filter((c) => c.ok === false)).toEqual([]);
    expect(checks.map((c) => c.name)).toEqual([
      "artifact audit.jsonl",
      "artifact patch.diff",
      "audit chain",
      "chain head in report",
      "report tool_requests vs audit.jsonl",
      "patch.diff vs report.patch.diff",
      "report HMAC",
    ]);
  });

  it("flags a rewritten audit log and a swapped diff", async () => {
    const { report, audit, patch } = await load();
    const badAudit = Buffer.from(audit.toString("utf8").replace('"outcome":"executed"', '"outcome":"denied"'));
    const badPatch = Buffer.from(patch.toString("utf8").replace("+y", "+z"));
    const failed = integrityChecks(report, { audit: badAudit, patch: badPatch, hmac: false })
      .filter((c) => c.ok === false)
      .map((c) => c.name);
    expect(failed).toEqual(
      expect.arrayContaining(["artifact audit.jsonl", "audit chain", "artifact patch.diff", "patch.diff vs report.patch.diff"]),
    );
  });

  it("marks pre-chaining reports as unverifiable rather than failed", async () => {
    const { report, audit, patch } = await load();
    const old: Report = { ...report, audit_chain_head: null };
    const checks = integrityChecks(old, { audit, patch, hmac: false });
    expect(checks.find((x) => x.name === "audit chain")?.ok).toBeNull();
    expect(checks.filter((x) => x.ok === false)).toEqual([]);
  });
});

describe("approval binding (must agree with boundaryrun.approval.check_approval)", () => {
  const approvalFor = (digest: string) =>
    Buffer.from(
      JSON.stringify({
        investigation_id: "inv-20260101T000000Z-abcdef",
        report_sha256: digest,
        verdict: "needs_review",
        decision: "approve",
        reviewer: "ada",
        note: "",
        recorded_at: "2026-11-05T00:00:00+00:00",
        hmac: null,
      }),
    );

  it("binds when the approval carries the sha256 of report.json on disk", async () => {
    const { checkApproval } = await import("@/lib/integrity");
    const reportRaw = await fs.readFile(path.join(RUN, "report.json"));
    const r = checkApproval(reportRaw, approvalFor(sha256(reportRaw)));
    expect(r.bound).toBe(true);
    expect(r.problem).toBeNull();
    expect(r.approval?.reviewer).toBe("ada");
  });

  it("is orphaned when report.json changes by one byte", async () => {
    const { checkApproval } = await import("@/lib/integrity");
    const reportRaw = await fs.readFile(path.join(RUN, "report.json"));
    const edited = Buffer.concat([reportRaw, Buffer.from(" ")]);
    const r = checkApproval(edited, approvalFor(sha256(reportRaw)));
    expect(r.bound).toBe(false);
    expect(r.problem).toMatch(/different report\.json/);
  });

  it("reports an unreadable or incomplete approval rather than ignoring it", async () => {
    const { checkApproval } = await import("@/lib/integrity");
    const reportRaw = await fs.readFile(path.join(RUN, "report.json"));
    expect(checkApproval(reportRaw, Buffer.from("{nope")).bound).toBe(false);
    expect(checkApproval(reportRaw, Buffer.from('{"reviewer":"x"}')).problem).toMatch(/lacks/);
    expect(checkApproval(reportRaw, null)).toEqual({ approval: null, bound: null, problem: null });
  });

  it("appears in the integrity checks only when approval.json exists", async () => {
    const { report, audit, patch } = await load();
    const reportRaw = await fs.readFile(path.join(RUN, "report.json"));
    const without = integrityChecks(report, { audit, patch, hmac: false, report: reportRaw, approval: null });
    expect(without.find((c) => c.name === "approval")).toBeUndefined();
    const withIt = integrityChecks(report, { audit, patch, hmac: false, report: reportRaw, approval: approvalFor(sha256(reportRaw)) });
    const check = withIt.find((c) => c.name === "approval");
    expect(check?.ok).toBe(true);
    expect(check?.detail).toMatch(/approve by ada, bound to this report; unsigned/);
  });
});
