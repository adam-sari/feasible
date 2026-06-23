import { useEffect, useState } from "react";
import { getConstraints } from "../api/client";
import type { ConstraintsView } from "../api/types";
import { useScenarioStore } from "../state/scenarioStore";

export function ConstraintStudioTab() {
  const domainId = useScenarioStore((s) => s.domainId);
  const [view, setView] = useState<ConstraintsView | null>(null);

  useEffect(() => {
    getConstraints(domainId).then(setView).catch(() => setView(null));
  }, [domainId]);

  if (!view) return <p>Loading…</p>;
  return (
    <section>
      <h2>Constraint Studio</h2>
      <h3>Approved universe rules ({view.rules.length})</h3>
      <table>
        <thead><tr><th>rule_id</th><th>kind</th><th>severity</th><th>clause</th></tr></thead>
        <tbody>
          {view.rules.map((r, i) => (
            <tr key={i}>
              <td>{String(r.rule_id)}</td><td>{String(r.kind)}</td>
              <td>{String(r.severity)}</td><td>{String(r.clause_kind)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h3>Policy-dropped rules ({view.dropped.length})</h3>
      {view.dropped.length === 0 ? (
        <p className="nodata">none dropped by policy</p>
      ) : (
        <ul>
          {view.dropped.map((d, i) => (
            <li key={i}>
              {String(d.rule_id)} — {String(d.drop_reason)} ({String(d.resolution_mode)})
            </li>
          ))}
        </ul>
      )}

      <h3>Gemini draft (Constraint Studio)</h3>
      <div className="nodata" data-testid="gemini-draft">
        {view.draft
          ? `draft, non-gating: ${JSON.stringify(view.draft)}`
          : "draft, non-gating — lands with Gemini extraction (Track C). Drafts are never auto-promoted; only a human-approved golden_ir is certified."}
      </div>
    </section>
  );
}
