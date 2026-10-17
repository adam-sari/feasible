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
    <div className="shell">
      <aside className="sidebar">
        <h1>Feasible</h1>
        <h3>Scenarios</h3>
        <ul>
          {scenarios.map((s) => (
            <li key={s.domain_id}>
              <button
                onClick={() => setDomain(s.domain_id)}
                className={s.domain_id === domainId ? "scenario active" : "scenario"}
              >
                {s.display_name}
              </button>
            </li>
          ))}
        </ul>
        <p className="sidebar-note">Both scenarios use illustrative data; verification is real.</p>
      </aside>
      <main className="content">
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
