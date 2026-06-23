import { useEffect, useState } from "react";
import { getInputs } from "../api/client";
import type { InputsView } from "../api/types";
import { useScenarioStore } from "../state/scenarioStore";
import { NoData } from "../components/NoData";

export function InputsTab() {
  const domainId = useScenarioStore((s) => s.domainId);
  const [view, setView] = useState<InputsView | null>(null);

  useEffect(() => {
    getInputs(domainId).then(setView).catch(() => setView(null));
  }, [domainId]);

  if (!view) return <p>Loading…</p>;
  return (
    <section>
      <h2>Inputs</h2>
      <h3>Jobs</h3>
      <table>
        <thead><tr><th>id</th><th>product</th><th>family</th><th>qty</th><th>due</th><th>prio</th></tr></thead>
        <tbody>
          {view.jobs.map((j, i) => (
            <tr key={i}>
              <td>{String(j.id)}</td><td>{String(j.product)}</td><td>{String(j.family)}</td>
              <td>{String(j.qty)}</td><td>{String(j.due_date)}</td><td>{String(j.priority)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <h3>Operations ({view.operations.length})</h3>
      <h3>Machines</h3>
      <ul>{view.machines.map((m) => <li key={m}>{m}</li>)}</ul>
      {view.units == null && view.groups == null && (
        <NoData label="Datacenter units/groups" />
      )}
    </section>
  );
}
