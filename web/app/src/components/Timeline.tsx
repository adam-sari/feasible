import type { TimelineView } from "../api/types";

const WIDTH = 760;
const ROW_H = 28;
const PAD = 8;
const LABEL_W = 84; // left gutter for lane labels / y-axis ticks
const AXIS_H = 34; // bottom gutter for x-axis ticks + title

const AXIS = "#8a8f98";
const GRID = "#e6e8eb";
const INK = "#2d3138";

function niceStep(span: number, target: number): number {
  const raw = Math.max(1, span / target);
  const mag = Math.pow(10, Math.floor(Math.log10(raw)));
  for (const m of [1, 2, 5, 10]) if (raw <= m * mag) return m * mag;
  return 10 * mag;
}

/**
 * The ONE timeline. Renders a Gantt (lanes + intervals) AND — when the plan
 * carries a capacity_series — a capacity-over-time step line with horizontal
 * threshold_lines (the N+1 floor). Pure SVG/div; no chart lib. Display-only:
 * the truth (margin/capacity) is re-derived by verify, never trusted from here.
 */
export function Timeline({ view }: { view: TimelineView }) {
  const hasCapacity = view.capacity_series != null && view.capacity_series.length > 0;

  if (hasCapacity) {
    const series = view.capacity_series!;
    const thresholds = view.threshold_lines ?? [];
    const maxT = Math.max(1, ...series.map((p) => p.t)) + 1; // each point covers [t, t+1)
    const maxV = Math.max(1, ...series.map((p) => p.value), ...thresholds.map((t) => t.value)) + 1;
    const h = 200;
    const plotL = LABEL_W;
    const plotR = WIDTH - PAD;
    const plotT = PAD + 6;
    const plotB = h - AXIS_H;
    const x = (t: number) => plotL + (t / maxT) * (plotR - plotL);
    const y = (v: number) => plotB - (v / maxV) * (plotB - plotT);
    // step line: value holds for the whole timestep
    const points = series
      .flatMap((p) => [`${x(p.t)},${y(p.value)}`, `${x(p.t + 1)},${y(p.value)}`])
      .join(" ");
    const yTicks = Array.from({ length: maxV + 1 }, (_, i) => i);
    const xTicks = Array.from({ length: maxT + 1 }, (_, i) => i);
    return (
      <svg width={WIDTH} height={h} viewBox={`0 0 ${WIDTH} ${h}`} role="img" aria-label="capacity over time" className="chart">
        {yTicks.map((v) => (
          <g key={`y-${v}`}>
            <line x1={plotL} y1={y(v)} x2={plotR} y2={y(v)} stroke={GRID} />
            <text x={plotL - 6} y={y(v) + 4} textAnchor="end" fontSize="11" fill={AXIS}>{v}</text>
          </g>
        ))}
        {xTicks.map((t) => (
          <text key={`x-${t}`} x={x(t)} y={plotB + 14} textAnchor="middle" fontSize="11" fill={AXIS}>{t}</text>
        ))}
        <line x1={plotL} y1={plotB} x2={plotR} y2={plotB} stroke={AXIS} />
        <line x1={plotL} y1={plotT} x2={plotL} y2={plotB} stroke={AXIS} />
        <text x={(plotL + plotR) / 2} y={h - 4} textAnchor="middle" fontSize="11" fill={INK}>timestep</text>
        <text x={12} y={(plotT + plotB) / 2} textAnchor="middle" fontSize="11" fill={INK}
              transform={`rotate(-90 12 ${(plotT + plotB) / 2})`}>available units</text>
        {thresholds.map((th, i) => (
          <g key={`th-${i}`} data-testid="threshold">
            <line x1={plotL} y1={y(th.value)} x2={plotR} y2={y(th.value)}
                  stroke="#c0392b" strokeDasharray="4 3" />
            <text x={plotR - 2} y={y(th.value) + 14} textAnchor="end" fontSize="11" fill="#c0392b">
              {th.label}
            </text>
          </g>
        ))}
        <polyline data-testid="capacity-line" points={points}
                  fill="none" stroke="#2c7fb8" strokeWidth="2.5" />
      </svg>
    );
  }

  // Gantt: one row per lane, one rect per interval.
  const lanes = view.lanes.map((l) => String(l.machine ?? l.feed ?? Object.values(l)[0]));
  const laneIndex = new Map(lanes.map((m, i) => [m, i]));
  const maxEnd = Math.max(1, ...view.intervals.map((iv) => iv.end));
  const plotL = LABEL_W;
  const plotR = WIDTH - PAD;
  const scale = (plotR - plotL) / maxEnd;
  const plotB = PAD + lanes.length * ROW_H;
  const h = Math.max(plotB, ROW_H + PAD) + AXIS_H;
  const step = niceStep(maxEnd, 8);
  const xTicks = Array.from({ length: Math.floor(maxEnd / step) + 1 }, (_, i) => i * step);
  return (
    <svg width={WIDTH} height={h} viewBox={`0 0 ${WIDTH} ${h}`} role="img" aria-label="gantt" className="chart">
      {lanes.map((m, i) => (
        <g key={`lane-${m}`}>
          <rect x={plotL} y={PAD + i * ROW_H} width={plotR - plotL} height={ROW_H}
                fill={i % 2 ? "#ffffff" : "#f6f7f9"} />
          <text x={plotL - 8} y={PAD + i * ROW_H + ROW_H / 2 + 4} textAnchor="end"
                fontSize="12" fill={INK}>{m}</text>
        </g>
      ))}
      {xTicks.map((t) => (
        <g key={`x-${t}`}>
          <line x1={plotL + t * scale} y1={PAD} x2={plotL + t * scale} y2={plotB} stroke={GRID} />
          <text x={plotL + t * scale} y={plotB + 14} textAnchor="middle" fontSize="11" fill={AXIS}>{t}</text>
        </g>
      ))}
      <line x1={plotL} y1={plotB} x2={plotR} y2={plotB} stroke={AXIS} />
      <text x={(plotL + plotR) / 2} y={h - 4} textAnchor="middle" fontSize="11" fill={INK}>minutes from start</text>
      {view.intervals.map((iv) => {
        const row = laneIndex.get(iv.machine) ?? 0;
        return (
          <rect
            key={iv.op_id + iv.machine + iv.start}
            data-testid="interval"
            x={plotL + iv.start * scale}
            y={PAD + row * ROW_H + 4}
            width={Math.max(1, (iv.end - iv.start) * scale)}
            height={ROW_H - 8}
            rx={3}
            fill={iv.reason ? "#e67e22" : "#27ae60"}
            stroke="#ffffff"
            strokeWidth={1}
          >
            <title>{`${iv.op_id} [${iv.start}-${iv.end}]${iv.reason ? " " + iv.reason : ""}`}</title>
          </rect>
        );
      })}
    </svg>
  );
}
