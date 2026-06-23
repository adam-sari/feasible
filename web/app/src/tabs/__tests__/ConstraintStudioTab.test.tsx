import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import type { ConstraintsView } from "../../api/types";

const view: ConstraintsView = {
  domain_id: "manufacturing",
  rules: [
    { rule_id: "R-6.1-NIGHT-CLEANOUT", kind: "night_cleanout", severity: "HARD", clause_kind: "PROHIBITION" },
    { rule_id: "R-SETUP", kind: "setup_cleanout", severity: "HARD", clause_kind: "OBLIGATION" },
  ],
  dropped: [],
  draft: null,
};

vi.mock("../../api/client", () => ({ getConstraints: vi.fn(async () => view) }));

import { ConstraintStudioTab } from "../ConstraintStudioTab";

describe("ConstraintStudioTab", () => {
  it("lists the approved universe rules", async () => {
    render(<ConstraintStudioTab />);
    await waitFor(() => expect(screen.getByText("R-6.1-NIGHT-CLEANOUT")).toBeInTheDocument());
    expect(screen.getByText("R-SETUP")).toBeInTheDocument();
  });

  it("shows the Gemini draft panel as a non-gating placeholder when draft is null", async () => {
    render(<ConstraintStudioTab />);
    await waitFor(() => expect(screen.getByTestId("gemini-draft")).toBeInTheDocument());
    expect(screen.getByTestId("gemini-draft")).toHaveTextContent(/draft, non-gating/i);
  });
});
