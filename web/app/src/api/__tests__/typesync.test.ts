import { describe, it, expect } from "vitest";
import type {
  ScenarioInfo,
  InputsView,
  ConstraintsView,
  TrustVector,
  CertifyResult,
  TimelineView,
  CertsView,
  VerifyView,
} from "../types";
// the LIVE field-key sets emitted by web/schema_fixture.py from feasible/domains/base.py
import fixture from "./schema_fixture.json";

// One canonical literal per view-model. TS field names are the SAME strings the Python
// dataclass declares; Object.keys(...) of each MUST equal fixture[Name]. A Python-side
// rename changes the fixture and fails here; a TS-side rename fails `tsc` + here.
const SAMPLES = {
  ScenarioInfo: { domain_id: "m", display_name: "M", data: "real" } as ScenarioInfo,
  InputsView: {
    domain_id: "m", jobs: [], operations: [], machines: [], units: null, groups: null,
  } as InputsView,
  ConstraintsView: {
    domain_id: "m", rules: [], dropped: [], draft: null,
  } as ConstraintsView,
  TrustVector: {
    signature: "self_described", checker: "pass", coverage: "calibrated",
    conflict_replay: "verified", data: "real", signer_note: "…",
  } as TrustVector,
  CertifyResult: {
    domain_id: "m", plan_cert: {}, rule_pack_cert: {},
    trust_vector: {
      signature: "self_described", checker: "pass", coverage: "calibrated",
      conflict_replay: "verified", data: "real", signer_note: "…",
    },
  } as CertifyResult,
  TimelineView: {
    domain_id: "m", lanes: [], intervals: [], capacity_series: null, threshold_lines: null,
  } as TimelineView,
  CertsView: { domain_id: "m", plan_cert: {}, rule_pack_cert: {} } as CertsView,
  // Spec 0.5 threads signer_note onto VerifyView too (mirrors TrustVector.signer_note);
  // the live schema_fixture.json carries it, so the TS mirror must as well.
  VerifyView: { ok: true, reasons: [], trust_vector: null, signer_note: "" } as VerifyView,
} as const;

describe("frozen facade type-sync (Python<->TS drift tripwire)", () => {
  it("every TS view-model's key set equals the live Python dataclass fixture", () => {
    for (const [name, sample] of Object.entries(SAMPLES)) {
      const tsKeys = Object.keys(sample).sort();
      const pyKeys = (fixture as Record<string, string[]>)[name];
      expect(pyKeys, `missing fixture entry for ${name}`).toBeDefined();
      expect(tsKeys, `TS<->Python drift on ${name}`).toEqual([...pyKeys].sort());
    }
  });

  it("TrustVector carries signer_note (the Spec 0.5 canonical sentence)", () => {
    expect((fixture as Record<string, string[]>).TrustVector).toContain("signer_note");
  });

  it("datacenter-only fields stay nullable in the TS mirror", () => {
    expect(SAMPLES.InputsView.units).toBeNull();
    expect(SAMPLES.TimelineView.capacity_series).toBeNull();
    expect(SAMPLES.ConstraintsView.draft).toBeNull();
  });
});
