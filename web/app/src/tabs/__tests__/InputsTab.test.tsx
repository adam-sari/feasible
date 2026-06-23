import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import type { InputsView } from "../../api/types";

const view: InputsView = {
  domain_id: "manufacturing",
  jobs: [{ id: "J1", product: "PeanutGold", family: "Allergen", qty: 100, due_date: 360, priority: 1 }],
  operations: [{ op_id: "J1-mix", job_id: "J1", seq: 0, duration: 31 }],
  machines: ["Mixer-A", "Labeler"],
  units: null,
  groups: null,
};

vi.mock("../../api/client", () => ({
  getInputs: vi.fn(async () => view),
}));

import { InputsTab } from "../InputsTab";

beforeEach(() => vi.clearAllMocks());

describe("InputsTab", () => {
  it("renders jobs + machines from the facade view", async () => {
    render(<InputsTab />);
    await waitFor(() => expect(screen.getByText("PeanutGold")).toBeInTheDocument());
    expect(screen.getByText("Mixer-A")).toBeInTheDocument();
    expect(screen.getByText("Labeler")).toBeInTheDocument();
  });

  it("shows NoData for datacenter units/groups when null", async () => {
    render(<InputsTab />);
    await waitFor(() => expect(screen.getByTestId("nodata")).toBeInTheDocument());
  });
});
