import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { Timeline } from "../Timeline";
import type { TimelineView } from "../../api/types";

const gantt: TimelineView = {
  domain_id: "manufacturing",
  lanes: [{ machine: "Mixer-A" }, { machine: "Labeler" }],
  intervals: [
    { op_id: "J1-mix", machine: "Mixer-A", start: 0, end: 31 },
    { op_id: "CLEANOUT", machine: "Labeler", start: 360, end: 450, reason: "x" },
  ],
  capacity_series: null,
  threshold_lines: null,
};

const capacity: TimelineView = {
  domain_id: "datacenter",
  lanes: [{ feed: "FeedA" }],
  intervals: [],
  capacity_series: [
    { t: 0, value: 3, group: "FeedA" },
    { t: 1, value: 2, group: "FeedA" },
  ],
  threshold_lines: [{ label: "N+1 floor", value: 2 }],
};

describe("Timeline", () => {
  it("renders a Gantt rect per interval when capacity_series is null", () => {
    render(<Timeline view={gantt} />);
    expect(screen.getAllByTestId("interval")).toHaveLength(2);
    expect(screen.queryByTestId("capacity-line")).toBeNull();
  });

  it("renders capacity-over-time + threshold lines when capacity_series is present", () => {
    render(<Timeline view={capacity} />);
    expect(screen.getByTestId("capacity-line")).toBeInTheDocument();
    expect(screen.getAllByTestId("threshold")).toHaveLength(1);
    expect(screen.getByText("N+1 floor")).toBeInTheDocument();
  });
});
