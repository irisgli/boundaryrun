// Shapes of the JSON the Python control process writes. Mirrors
// boundaryrun.eval (schema boundaryrun.eval/v1) and boundaryrun.pipeline
// (schema boundaryrun.report/v1). Fields the UI does not render are typed
// loosely rather than omitted so unknown data is still passed through.

export type Verdict =
  | "verified"
  | "needs_review"
  | "not_remediated"
  | "regression"
  | "no_patch"
  | "scope_violation"
  | "inconclusive";

export interface EvalRun {
  investigation_id: string;
  arm: string;
  agent: string;
  attack: string;
  simulated: boolean;
  task_completed: boolean;
  claimed_remediated: boolean;
  verified_remediated: boolean;
  verdict: Verdict | string;
  unauthorized_attempts: number;
  unauthorized_executed: number;
  denials: number;
  injection_success: boolean | null;
  functional_regression: boolean;
  scope_violation: boolean;
  canary_exposed: boolean;
  duration_s: number;
  input_tokens: number;
  output_tokens: number;
}

export interface EvalAggregate {
  view: string;
  agent: string;
  runs: number;
  attacked_runs: number;
  task_completion_rate: number;
  reported_remediation_rate: number;
  verified_remediation_rate: number;
  unauthorized_attempt_rate: number;
  unauthorized_execution_rate: number;
  injection_success_rate: number;
  denial_rate: number;
  false_denial_rate: number;
  regression_rate: number;
  scope_violation_rate: number;
  canary_exposure_rate: number;
  mean_duration_s: number;
  mean_input_tokens: number;
  mean_output_tokens: number;
}

export interface EvalSummary {
  schema_version: string;
  eval_id: string;
  scenario_id: string;
  started_at: string;
  finished_at: string;
  agents: string[];
  arms: string[];
  attacks: string[];
  repeats: number;
  model: string | null;
  note: string;
  runs: EvalRun[];
  summary: EvalAggregate[];
  errors: unknown[];
}

export interface Decision {
  effect: string;
  rule: string;
  reason: string;
}

export interface ToolRequest {
  seq: number;
  timestamp: string;
  tool: string;
  input: Record<string, unknown>;
  decision: Decision;
  reference_decision: Decision | null;
  outcome: string;
  output_bytes: number | null;
  output_sha256: string | null;
  error: string | null;
  duration_ms: number | null;
  prev_hash?: string | null;
  record_hash?: string | null;
}

export interface ProbeCheck {
  name: string;
  kind: string;
  status_code: number | null;
  content_returned: boolean | null;
  outcome: string;
  error: string | null;
}

export interface ProbeResult {
  ok: boolean;
  result: { healthy: boolean; error: string | null; checks: ProbeCheck[] } | null;
  error: string | null;
  duration_s: number | null;
  app_log_tail: string | null;
}

export interface TestResult {
  exit_code: number | null;
  status: string;
  passed: number;
  failed: number;
  errors: number;
  duration_s: number | null;
  output_tail: string | null;
}

export interface StaticFinding {
  rule_id: string;
  severity: string;
  path: string;
  line: number;
  message: string;
  snippet: string;
  cwe: string | null;
}

export interface StaticScan {
  status: string;
  semgrep_version: string | null;
  rules_sha256: string | null;
  findings: StaticFinding[];
  parse_errors: number;
  error: string | null;
  duration_s: number | null;
}

export interface Stage {
  probe: ProbeResult;
  functional_tests: TestResult;
  static_scan?: StaticScan;
}

export interface PatchFile {
  path: string;
  change: string;
  in_write_scope: boolean;
}

export interface Directive {
  tool: string;
  input: Record<string, unknown>;
  attempted: boolean;
  executed: boolean;
}

export interface Report {
  schema_version: string;
  investigation_id: string;
  scenario_id: string;
  arm: string;
  task: {
    agent_mode: string;
    attack: string | null;
    repo: { url: string; ref: string; subdir: string | null } | null;
    target: string;
    fixture: string | null;
    model: string | null;
    policy: Record<string, unknown>;
    sandbox: Record<string, unknown>;
  };
  execution: Record<string, string | null>;
  finding: {
    id: string;
    title: string;
    cwe: string | null;
    severity: string;
    description: string;
    affected_endpoint: string | null;
    reproduction: Record<string, string> | null;
    source: string | null;
  };
  agent: {
    mode: string;
    autonomous: boolean;
    fixture: string | null;
    model_requested: string | null;
    models_observed: string[];
    turns: Array<{ turn: number; input_tokens: number; output_tokens: number; stop_reason?: string | null }>;
    visible_messages: string[];
    tool_calls_requested: number;
    finished_by: string | null;
    error: string | null;
    refusal_category: string | null;
    duration_s: number | null;
  };
  agent_skipped_reason: string | null;
  agent_claim: { summary: string; files_changed: string[] } | null;
  tool_requests: ToolRequest[];
  policy_summary: {
    requests: number;
    executed: number;
    denied: number;
    rejected: number;
    errors: number;
    denied_by_rule: Record<string, number>;
  };
  injection: {
    injection_files: string[];
    injection_files_read: string[];
    sensitive_read_attempts: number;
    sensitive_read_executed: number;
    egress_attempts: number;
    egress_executed: number;
    out_of_scope_write_attempts: number;
    out_of_scope_write_executed: number;
    canary_hits_by_channel: Record<string, number>;
  };
  attack: {
    id: string;
    vector: string;
    objective: string;
    directives: Directive[];
    objective_achieved: boolean;
  } | null;
  egress_sink: Array<Record<string, unknown>>;
  baseline: Stage;
  patch: { files: PatchFile[]; diff: string };
  post_patch: Stage | null;
  static_analysis: {
    baseline: StaticScan | null;
    patched: StaticScan | null;
    resolved: StaticFinding[];
    introduced: StaticFinding[];
    unchanged: number;
    conclusive: boolean;
  } | null;
  errors: string[];
  verdict: { status: Verdict | string; reasons: string[]; claim_scope: string };
  artifacts: Record<string, string>;
  audit_chain_head?: string | null;
}

export interface EvalIndexEntry {
  eval_id: string;
  scenario_id: string;
  started_at: string;
  finished_at: string;
  agents: string[];
  arms: string[];
  attacks: string[];
  repeats: number;
  model: string | null;
  run_count: number;
  error_count: number;
  verdicts: Record<string, number>;
}

export interface InvestigationIndexEntry {
  investigation_id: string;
  eval_id: string | null;
  scenario_id: string;
  arm: string;
  agent_mode: string;
  attack: string | null;
  autonomous: boolean;
  verdict: string;
  started_at: string | null;
}
