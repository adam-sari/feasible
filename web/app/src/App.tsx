import { useEffect, useState } from "react";
import { NavLink, Route, Routes, Navigate } from "react-router-dom";
import { getScenarios } from "./api/client";
import type { ScenarioInfo } from "./api/types";
import { useScenarioStore } from "./state/scenarioStore";
import { OverviewTab } from "./tabs/OverviewTab";
import { InputsTab } from "./tabs/InputsTab";
import { ConstraintStudioTab } from "./tabs/ConstraintStudioTab";
import { PlannerTab } from "./tabs/PlannerTab";
import { VerifierTab } from "./tabs/VerifierTab";

const TABS = [
  { to: "/overview", label: "Overview" },
  { to: "/inputs", label: "Inputs" },
  { to: "/constraints", label: "Constraint Studio" },
  { to: "/planner", label: "Planner" },
  { to: "/verifier", label: "Verifier" },
];

export function App() {
  const { domainId, setDomain } = useScenarioStore();
  const [scenarios, setScenarios] = useState<ScenarioInfo[]>([]);

  useEffect(() => {
    getScenarios().then(setScenarios).catch(() => setScenarios([]));
  }, []);

  return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      <aside style={{ width: 200, borderRight: "1px solid #ddd", padding: 12 }}>
        <h1 style={{ fontSize: 18 }}>Feasible</h1>
        <h3 style={{ fontSize: 13 }}>Scenarios</h3>
        <ul style={{ listStyle: "none", padding: 0 }}>
          {scenarios.map((s) => (
            <li key={s.domain_id}>
              <button
                onClick={() => setDomain(s.domain_id)}
                style={{ fontWeight: s.domain_id === domainId ? 700 : 400 }}
              >
                {s.display_name} ({s.data})
              </button>
            </li>
          ))}
        </ul>
      </aside>
      <main style={{ flex: 1, padding: 16 }}>
        <nav className="tab-nav">
          {TABS.map((t) => (
            <NavLink key={t.to} to={t.to}
              className={({ isActive }) => (isActive ? "active" : "")}>
              {t.label}
            </NavLink>
          ))}
        </nav>
        <Routes>
          <Route path="/" element={<Navigate to="/overview" replace />} />
          <Route path="/overview" element={<OverviewTab />} />
          <Route path="/inputs" element={<InputsTab />} />
          <Route path="/constraints" element={<ConstraintStudioTab />} />
          <Route path="/planner" element={<PlannerTab />} />
          <Route path="/verifier" element={<VerifierTab />} />
        </Routes>
      </main>
    </div>
  );
}
