// TypeScript mirror of feasible/domains/base.py view-models (FROZEN schema).
// Field names/types track the dataclasses 1:1. Datacenter-only fields are nullable.

export interface ScenarioInfo {
  domain_id: string;
  display_name: string;
  data: string; // "real" | "synthetic"
}

export interface InputsView {
  domain_id: string;
  jobs: Record<string, unknown>[];
  operations: Record<string, unknown>[];
  machines: string[];
  units: Record<string, unknown>[] | null;
  groups: Record<string, unknown>[] | null;
}

export interface ConstraintsView {
  domain_id: string;
  rules: Record<string, unknown>[];
  dropped: Record<string, unknown>[];
  draft: Record<string, unknown> | null;
}

export interface TrustVector {
  signature: string; // "authenticated" | "self_described" | "unverified"
  checker: string; // "pass" | "fail"
  coverage: string; // "calibrated" | "preview"
  conflict_replay: string; // "verified" | "illustrative"
  data: string; // "real" | "synthetic"
  signer_note: string; // Spec 0.5: canonical authenticated/self-described sentence — rendered VERBATIM
}

export interface CertifyResult {
  domain_id: string;
  plan_cert: Record<string, unknown>;
  rule_pack_cert: Record<string, unknown>;
  trust_vector: TrustVector;
}

export interface Interval {
  op_id: string;
  machine: string;
  start: number;
  end: number;
  reason?: string;
}

export interface CapacityPoint {
  t: number;
  value: number;
  group?: string;
}

export interface ThresholdLine {
  label: string;
  value: number;
}

export interface TimelineView {
  domain_id: string;
  lanes: Record<string, unknown>[];
  intervals: Interval[];
  capacity_series: CapacityPoint[] | null;
  threshold_lines: ThresholdLine[] | null;
}

export interface CertsView {
  domain_id: string;
  plan_cert: Record<string, unknown>;
  rule_pack_cert: Record<string, unknown>;
}

export interface VerifyView {
  ok: boolean;
  reasons: string[];
  trust_vector: TrustVector | null;
  // Spec 0.5 mirrors TrustVector.signer_note onto VerifyView (byte-matches the CLI
  // auth line) so a verify consumer reads it without unwrapping the trust vector.
  // Rendered VERBATIM; the console never fabricates this prose.
  signer_note: string;
}
