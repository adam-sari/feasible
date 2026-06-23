import type { TrustVector } from "../api/types";
import { TrustVectorPanel } from "./TrustVectorPanel";

/**
 * The single render path for ANY checker verdict. Inside ONE `verdict` container it
 * ALWAYS renders: the checker pill, the full 5-field TrustVectorPanel, the VERBATIM
 * engine `signer_note` (the canonical authenticated/self-described/unverified
 * sentence — Spec 0.5; the console NEVER authors this prose), and any reasons. No
 * other component renders a `checker-pill`; routing every verdict here makes the
 * console-honesty invariant STRUCTURAL, not per-call discipline.
 */
export function CheckerVerdict({ tv, reasons = [] }: { tv: TrustVector; reasons?: string[] }) {
  return (
    <div data-testid="verdict" className="verdict">
      <span
        data-testid="checker-pill"
        className={"pill " + (tv.checker === "pass" ? "pill-pass" : "pill-fail")}
      >
        checker: {tv.checker}
      </span>
      <TrustVectorPanel tv={tv} />
      {/* the engine's auth/UNVERIFIED sentence, rendered byte-for-byte (no hand-written copy) */}
      <p data-testid="signer-note">{tv.signer_note}</p>
      {reasons.length > 0 && (
        <ul data-testid="verdict-reasons">
          {reasons.map((r, i) => (
            <li key={i} className="pill-fail">{r}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
