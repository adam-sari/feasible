import { useEffect, useState } from "react";
import { getCertificates, verify } from "../api/client";
import type { CertsView, VerifyView } from "../api/types";
import { useScenarioStore } from "../state/scenarioStore";
import { CheckerVerdict } from "../components/CheckerVerdict";

export function VerifierTab() {
  const domainId = useScenarioStore((s) => s.domainId);
  const [certs, setCerts] = useState<CertsView | null>(null);
  const [view, setView] = useState<VerifyView | null>(null);

  useEffect(() => {
    getCertificates(domainId).then(setCerts).catch(() => setCerts(null));
    setView(null);
  }, [domainId]);

  async function reVerify() {
    if (!certs) return;
    setView(await verify(certs.plan_cert, certs.rule_pack_cert));
  }

  return (
    <section>
      <h2>Verifier / Certificates</h2>
      {!certs ? (
        <p>Loading certs…</p>
      ) : (
        <>
          <p>Two-cert bundle: plan cert + rule-pack cert (binding re-checked offline).</p>
          <button onClick={reVerify}>Re-verify offline</button>

          {/* INVARIANT: the verdict is rendered ONLY through <CheckerVerdict>, which owns
              the (single) checker pill AND always renders the 5 trust-vector fields + the
              VERBATIM engine signer_note. The tab authors no pill and no trust prose. */}
          {view && view.trust_vector && (
            <CheckerVerdict tv={view.trust_vector} reasons={view.reasons} />
          )}

          <details>
            <summary>Raw plan cert (JSON)</summary>
            <pre>{JSON.stringify(certs.plan_cert, null, 2)}</pre>
          </details>
          <details>
            <summary>Raw rule-pack cert (JSON)</summary>
            <pre>{JSON.stringify(certs.rule_pack_cert, null, 2)}</pre>
          </details>
        </>
      )}
    </section>
  );
}
