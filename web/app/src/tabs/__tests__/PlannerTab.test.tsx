import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import type { TimelineView, CertifyResult } from "../../api/types";

const timeline: TimelineView = {
  domain_id: "manufacturing",
  lanes: [{ machine: "Labeler" }],
  intervals: [{ op_id: "J1-mix", machine: "Labeler", start: 0, end: 31 }],
  capacity_series: null, threshold_lines: null,
};
const cert: CertifyResult = {
  domain_id: "manufacturing",
  plan_cert: {
    kpi_vs_incumbent_B: {
      weighted_tardiness: { optimized: 0, incumbent_b: 1698 },
    },
    incumbent_A_failure: {
      violated_rule_ref: "R-6.1-NIGHT-CLEANOUT",
      span: { quoted_text: "Cleanouts may only be performed during the day shift" },
    },
  },
  rule_pack_cert: {},
  trust_vector: { signature: "self_described", checker: "pass", coverage: "calibrated", conflict_replay: "verified", data: "real", signer_note: "signer SELF-DESCRIBED — pass --signer-key to authenticate (re-check passed, identity UNVERIFIED)" },
};

vi.mock("../../api/client", () => ({
  getTimeline: vi.fn(async () => timeline),
  certify: vi.fn(async () => cert),
}));

import { PlannerTab } from "../PlannerTab";

describe("PlannerTab", () => {
  it("renders the timeline + KPI vs incumbent verbatim", async () => {
    render(<PlannerTab />);
    await waitFor(() => expect(screen.getByLabelText("gantt")).toBeInTheDocument());
    expect(screen.getByText("1698")).toBeInTheDocument(); // incumbent_b verbatim
  });

  it("renders the gotcha rule ref + quoted span verbatim", async () => {
    render(<PlannerTab />);
    await waitFor(() =>
      expect(screen.getByText("R-6.1-NIGHT-CLEANOUT")).toBeInTheDocument()
    );
    expect(
      screen.getByText(/Cleanouts may only be performed during the day shift/)
    ).toBeInTheDocument();
  });
});
