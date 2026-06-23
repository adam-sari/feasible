import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { TrustVectorPanel } from "../TrustVectorPanel";
import type { TrustVector } from "../../api/types";

const authed: TrustVector = {
  signature: "authenticated", checker: "pass", coverage: "calibrated",
  conflict_replay: "verified", data: "real",
  signer_note: "SIGNER AUTHENTICATED (pinned key)",
};
const synthetic: TrustVector = {
  signature: "self_described", checker: "pass", coverage: "preview",
  conflict_replay: "illustrative", data: "synthetic",
  signer_note: "signer SELF-DESCRIBED — pass --signer-key to authenticate (re-check passed, identity UNVERIFIED)",
};
const unverified: TrustVector = {
  signature: "unverified", checker: "fail", coverage: "preview",
  conflict_replay: "illustrative", data: "synthetic",
  signer_note: "signer UNVERIFIED",
};

describe("TrustVectorPanel", () => {
  it("renders all five honesty fields verbatim", () => {
    render(<TrustVectorPanel tv={authed} />);
    for (const f of ["signature", "checker", "coverage", "conflict_replay", "data"]) {
      expect(screen.getByTestId(`tv-${f}`)).toBeInTheDocument();
    }
    expect(screen.getByTestId("tv-signature")).toHaveTextContent("authenticated");
    expect(screen.getByTestId("tv-checker")).toHaveTextContent("pass");
  });

  it("marks synthetic data visually distinct (pill-synthetic)", () => {
    render(<TrustVectorPanel tv={synthetic} />);
    expect(screen.getByTestId("tv-data").className).toContain("pill-synthetic");
  });

  it("handles the 'unverified' signature enum explicitly (A-6) — distinct, never collapsed to self_described", () => {
    render(<TrustVectorPanel tv={unverified} />);
    const sig = screen.getByTestId("tv-signature");
    expect(sig).toHaveTextContent("unverified");
    expect(sig.className).toContain("pill-fail"); // a failed/absent signature is NOT styled as a benign self-described one
  });
});
