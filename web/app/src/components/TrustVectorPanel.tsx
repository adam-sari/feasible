import type { TrustVector } from "../api/types";

const FIELDS: (keyof TrustVector)[] = [
  "signature", "checker", "coverage", "conflict_replay", "data",
];

/**
 * The honesty-invariant guarantor. Renders ALL FIVE trust-vector fields together,
 * each labeled with its raw engine value (verbatim). Any "verified"/pass pill MUST
 * sit beside this panel — a green checker is never shown without these qualifiers.
 * Synthetic data + preview/illustrative claims render visually distinct. The
 * `signature="unverified"` enum (A-6) is a FAILED identity, not a benign one: it
 * renders pill-fail, distinct from both "authenticated" (pass) and the cautionary
 * "self_described" (synthetic) — it is never collapsed into self-described.
 */
export function TrustVectorPanel({ tv }: { tv: TrustVector }) {
  return (
    <div className="trust-vector" data-testid="trust-vector">
      {FIELDS.map((f) => {
        const v = tv[f];
        // pill class per field: pass (green), synthetic/cautionary (amber), fail (red).
        let cls = "pill pill-pass";
        if (f === "signature") {
          // explicit 3-way on the enum (A-6): authenticated→pass, self_described→synthetic, unverified→fail
          cls = "pill " + (v === "authenticated" ? "pill-pass" : v === "unverified" ? "pill-fail" : "pill-synthetic");
        } else if (f === "checker") {
          cls = "pill " + (v === "pass" ? "pill-pass" : "pill-fail");
        } else if (
          (f === "data" && v === "synthetic") ||
          (f === "coverage" && v === "preview") ||
          (f === "conflict_replay" && v === "illustrative")
        ) {
          cls = "pill pill-synthetic";
        }
        return (
          <span key={f} data-testid={`tv-${f}`} className={cls} title={f}>
            {f}: {v}
          </span>
        );
      })}
    </div>
  );
}
