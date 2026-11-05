// Mirror of boundaryrun.evidence.verify_chain: hash_n = sha256(hash_{n-1} || text_n)
// where text_n is the audit line with its trailing `,"record_hash":"..."` member removed.
import { createHash } from "node:crypto";

export const GENESIS = "0".repeat(64);
const HASH_SUFFIX = /,"record_hash":"([0-9a-f]{64})"\}$/;

export interface ChainResult {
  ok: boolean;
  head: string;
  records: number;
  problem: string | null;
}

export function verifyChain(lines: string[]): ChainResult {
  let prev = GENESIS;
  for (let i = 0; i < lines.length; i++) {
    const n = i + 1;
    const line = lines[i];
    const m = HASH_SUFFIX.exec(line);
    if (!m) return { ok: false, head: prev, records: n, problem: `record ${n} has no record_hash` };
    const text = line.slice(0, m.index) + "}";
    let rec: { prev_hash?: unknown; seq?: unknown };
    try {
      rec = JSON.parse(line);
    } catch {
      return { ok: false, head: prev, records: n, problem: `record ${n} is not valid JSON` };
    }
    if (rec.prev_hash !== prev) {
      return { ok: false, head: prev, records: n, problem: `record ${n} prev_hash does not match the previous record` };
    }
    if (rec.seq !== n) return { ok: false, head: prev, records: n, problem: `record ${n} has seq ${String(rec.seq)}` };
    const expected = createHash("sha256").update(prev + text, "utf8").digest("hex");
    if (m[1] !== expected) return { ok: false, head: prev, records: n, problem: `record ${n} hash mismatch` };
    prev = expected;
  }
  return { ok: true, head: prev, records: lines.length, problem: null };
}

export function sha256(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

export interface IntegrityCheck {
  name: string;
  ok: boolean | null;
  detail: string;
}

// Mirror of boundaryrun.approval.check_approval minus the HMAC (the operator key never
// belongs on the viewer): the approval is bound to report.json by SHA-256, so a rewritten
// report orphans it.
export interface ApprovalCheck {
  approval: Record<string, unknown> | null;
  bound: boolean | null;
  problem: string | null;
}

export function checkApproval(reportRaw: Buffer | null, approvalRaw: Buffer | null): ApprovalCheck {
  if (approvalRaw === null) return { approval: null, bound: null, problem: null };
  let approval: Record<string, unknown>;
  try {
    approval = JSON.parse(approvalRaw.toString("utf8")) as Record<string, unknown>;
  } catch {
    return { approval: null, bound: false, problem: "approval.json is not valid JSON" };
  }
  if (typeof approval.report_sha256 !== "string" || typeof approval.reviewer !== "string" || typeof approval.decision !== "string") {
    return { approval: null, bound: false, problem: "approval.json lacks report_sha256, reviewer or decision" };
  }
  if (reportRaw === null) return { approval, bound: false, problem: "report.json missing" };
  const bound = sha256(reportRaw) === approval.report_sha256;
  return { approval, bound, problem: bound ? null : "approval is bound to a different report.json than the one on disk" };
}
