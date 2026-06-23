import { describe, it, expect } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { CheckerVerdict } from "../CheckerVerdict";
import type { TrustVector } from "../../api/types";

const tv: TrustVector = {
  signature: "self_described", checker: "pass", coverage: "calibrated",
  conflict_replay: "verified", data: "real",
  signer_note: "signer SELF-DESCRIBED — pass --signer-key to authenticate (re-check passed, identity UNVERIFIED)",
};

describe("CheckerVerdict — structural honesty (A-5)", () => {
  it("the checker pill ALWAYS has the 5 trust-vector fields in the SAME container", () => {
    render(<CheckerVerdict tv={tv} />);
    const pill = screen.getByTestId("checker-pill");
    const container = pill.closest("[data-testid='verdict']") as HTMLElement;
    expect(container).not.toBeNull();
    for (const f of ["signature", "checker", "coverage", "conflict_replay", "data"]) {
      expect(within(container).getByTestId(`tv-${f}`)).toBeInTheDocument();
    }
  });

  it("renders the signer_note VERBATIM (no fabricated prose)", () => {
    render(<CheckerVerdict tv={tv} />);
    expect(screen.getByTestId("signer-note")).toHaveTextContent(tv.signer_note);
  });
});
