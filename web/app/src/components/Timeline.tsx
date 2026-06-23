import type { TimelineView } from "../api/types";

const WIDTH = 720;
const ROW_H = 28;
const PAD = 8;

/**
 * The ONE timeline. Renders a Gantt (lanes + intervals) AND — when the plan
 * carries a capacity_series — a capacity-over-time polyline with horizontal
 * threshold_lines (the N+1 floor). Pure SVG/div; no chart lib. Display-only:
 * the truth (margin/capacity) is re-derived by verify, never trusted from here.
 */
export function Timeline({ view }: { view: TimelineView }) {
  const hasCapacity = view.capacity_series != null && view.capacity_series.length > 0;

  if (hasCapacity) {
    const series = view.capacity_series!;
    const thresholds = view.threshold_lines ?? [];
    const maxT = Math.max(1, ...series.map((p) => p.t));
    const maxV = Math.max(1, ...series.map((p) => p.value), ...thresholds.map((t) => t.value));
    const h = 220;
    const x = (t: number) => PAD + (t / maxT) * (WIDTH - 2 * PAD);
    const y = (v: number) => h - PAD - (v / maxV) * (h - 2 * PAD);
    const points = series.map((p) => `${x(p.t)},${y(p.value)}`).join(" ");
    return (
      <svg width={WIDTH} height={h} role="img" aria-label="capacity over time">
        {thresholds.map((th, i) => (
          <g key={`th-${i}`} data-testid="threshold">
            <line x1={PAD} y1={y(th.value)} x2={WIDTH - PAD} y2={y(th.value)}
                  stroke="#c0392b" strokeDasharray="4 3" />
            <text x={WIDTH - PAD} y={y(th.value) - 4} textAnchor="end" fontSize="11" fill="#c0392b">
              {th.label}
            </text>
          </g>
        ))}
        <polyline data-testid="capacity-line" points={points}
                  fill="none" stroke="#2c7fb8" strokeWidth="2" />
      </svg>
    );
  }

  // Gantt: one row per lane, one rect per interval.
  const lanes = view.lanes.map((l) => String(l.machine ?? l.feed ?? Object.values(l)[0]));
  const laneIndex = new Map(lanes.map((m, i) => [m, i]));
  const maxEnd = Math.max(1, ...view.intervals.map((iv) => iv.end));
  const scale = (WIDTH - 2 * PAD) / maxEnd;
  const h = PAD * 2 + lanes.length * ROW_H;
  return (
    <svg width={WIDTH} height={Math.max(h, ROW_H + 2 * PAD)} role="img" aria-label="gantt">
      {lanes.map((m, i) => (
        <text key={`lbl-${m}`} x={2} y={PAD + i * ROW_H + ROW_H / 2} fontSize="11">{m}</text>
      ))}
      {view.intervals.map((iv) => {
        const row = laneIndex.get(iv.machine) ?? 0;
        return (
          <rect
            key={iv.op_id + iv.machine + iv.start}
            data-testid="interval"
            x={PAD + iv.start * scale}
            y={PAD + row * ROW_H + 3}
            width={Math.max(1, (iv.end - iv.start) * scale)}
            height={ROW_H - 6}
            fill={iv.reason ? "#e67e22" : "#27ae60"}
          >
            <title>{`${iv.op_id} [${iv.start}-${iv.end}]${iv.reason ? " " + iv.reason : ""}`}</title>
          </rect>
        );
      })}
    </svg>
  );
}
