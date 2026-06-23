import { useEffect, useState } from "react";
import { getScenarios, certify } from "../api/client";
import type { ScenarioInfo, CertifyResult } from "../api/types";
import { useScenarioStore } from "../state/scenarioStore";
import { CheckerVerdict } from "../components/CheckerVerdict";

export function OverviewTab() {
  const domainId = useScenarioStore((s) => s.domainId);
  const [info, setInfo] = useState<ScenarioInfo | null>(null);
  const [result, setResult] = useState<CertifyResult | null>(null);

  useEffect(() => {
    getScenarios().then((ss) => setInfo(ss.find((s) => s.domain_id === domainId) ?? null));
    certify(domainId).then(setResult).catch(() => setResult(null));
  }, [domainId]);

  if (!info) return <p>Loading…</p>;
  return (
    <section>
      <h2>{info.display_name}</h2>
      <p>data: {info.data}</p>
      {result ? (
        <>
          <p>Trust vector (the honesty descriptor — never a bare "verified"):</p>
          <CheckerVerdict tv={result.trust_vector} />
        </>
      ) : (
        <p className="nodata">No certificate yet.</p>
      )}
    </section>
  );
}
