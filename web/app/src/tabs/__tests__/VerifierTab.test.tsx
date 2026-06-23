import { describe, it, expect, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import type { CertsView, VerifyView } from "../../api/types";

const certs: CertsView = {
  domain_id: "manufacturing",
  plan_cert: { signature: { public_key_hex: "abc123" } },
  rule_pack_cert: { rule_pack_id: "rule-pack-golden" },
};
// the engine's CANONICAL self-described sentence (Spec 0.5 signer_note), carried verbatim
const SELF_DESCRIBED_NOTE =
  "signer SELF-DESCRIBED — pass --signer-key to authenticate (re-check passed, identity UNVERIFIED)";
const verifyView: VerifyView = {
  ok: true,
  reasons: [],
  trust_vector: {
    signature: "self_described", checker: "pass", coverage: "calibrated",
    conflict_replay: "verified", data: "real", signer_note: SELF_DESCRIBED_NOTE,
  },
  // Spec 0.5 mirrors signer_note onto VerifyView (byte-matches TrustVector.signer_note);
  // the frozen VerifyView type requires it, so the mock carries it verbatim too.
  signer_note: SELF_DESCRIBED_NOTE,
};

vi.mock("../../api/client", () => ({
  getCertificates: vi.fn(async () => certs),
  verify: vi.fn(async () => verifyView),
}));

import { VerifierTab } from "../VerifierTab";

describe("VerifierTab — console honesty invariant", () => {
  it("never renders a checker=pass pill without the 5 trust-vector fields beside it", async () => {
    render(<VerifierTab />);
    // trigger the offline re-verify so a verdict exists
    const btn = await screen.findByRole("button", { name: /re-verify offline/i });
    btn.click();
    const pill = await screen.findByTestId("checker-pill");
    expect(pill).toHaveTextContent("pass");
    // INVARIANT (structural): the pill lives inside <CheckerVerdict>'s verdict container,
    // which ALWAYS holds the full trust vector — the five fields are in the SAME container.
    const container = pill.closest("[data-testid='verdict']") as HTMLElement;
    expect(container).not.toBeNull();
    for (const f of ["signature", "checker", "coverage", "conflict_replay", "data"]) {
      expect(within(container).getByTestId(`tv-${f}`)).toBeInTheDocument();
    }
  });

  it("renders the engine's signer_note VERBATIM (no fabricated prose) — [MAJOR A-1]", async () => {
    render(<VerifierTab />);
    const btn = await screen.findByRole("button", { name: /re-verify offline/i });
    btn.click();
    const note = await screen.findByTestId("signer-note");
    // byte-for-byte the engine's signer_note — NOT a hand-written TS string
    expect(note).toHaveTextContent(SELF_DESCRIBED_NOTE);
    expect(note).toHaveTextContent(/UNVERIFIED/);
  });
});
