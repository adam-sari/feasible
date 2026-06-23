import { useEffect, useState } from "react";
import { getTimeline, certify } from "../api/client";
import type { TimelineView, CertifyResult } from "../api/types";
import { useScenarioStore } from "../state/scenarioStore";
import { Timeline } from "../components/Timeline";

export function PlannerTab() {
  const domainId = useScenarioStore((s) => s.domainId);
  const [tl, setTl] = useState<TimelineView | null>(null);
  const [cert, setCert] = useState<CertifyResult | null>(null);

  useEffect(() => {
    getTimeline(domainId).then(setTl).catch(() => setTl(null));
    certify(domainId).then(setCert).catch(() => setCert(null));
  }, [domainId]);

  const pc = cert?.plan_cert as Record<string, any> | undefined;
  const kpis = (pc?.kpi_vs_incumbent_B ?? {}) as Record<string, { optimized: number; incumbent_b: number }>;
  const gotcha = pc?.incumbent_A_failure as
    | { violated_rule_ref: string; span: { quoted_text: string } }
    | undefined;

  return (
    <section>
      <h2>Planner</h2>
      {tl ? <Timeline view={tl} /> : <p>Loading timeline…</p>}

      <h3>KPI vs incumbent B (verbatim from the plan cert)</h3>
      <table>
        <thead><tr><th>kpi</th><th>optimized</th><th>incumbent_b</th></tr></thead>
        <tbody>
          {Object.entries(kpis).map(([k, v]) => (
            <tr key={k}><td>{k}</td><td>{v.optimized}</td><td>{v.incumbent_b}</td></tr>
          ))}
        </tbody>
      </table>

      <h3>Gotcha — incumbent A failure (verbatim)</h3>
      {gotcha ? (
        <p>
          violates <strong>{gotcha.violated_rule_ref}</strong>:{" "}
          <q>{gotcha.span.quoted_text}</q>
        </p>
      ) : (
        <p className="nodata">no gotcha</p>
      )}
    </section>
  );
}
