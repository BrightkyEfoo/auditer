import { gradeTone } from "@/lib/api";

/**
 * Score history as a plotted line. Hand-drawn SVG rather than a charting
 * library: one series of at most twelve points does not justify shipping a
 * chart runtime, and a library's defaults would fight the art direction.
 *
 * The Y axis is pinned to 0-100 on purpose — auto-scaling a score chart makes a
 * two-point wobble look like a collapse.
 */
export function Trend({ points }: { points: Array<{ runId: string; createdAt: string; riskScore: number }> }) {
  if (points.length === 0) {
    return (
      <div className="flex h-28 items-center border border-dashed border-line px-5">
        <p className="font-mono text-label uppercase text-mute">
          La tendance apparaît à partir du deuxième relevé terminé
        </p>
      </div>
    );
  }

  const W = 100;
  const H = 34;
  const last = points[points.length - 1]!;
  // A single point has no line to draw; place it mid-width so the dot is visible.
  const x = (i: number) => (points.length === 1 ? W / 2 : (i / (points.length - 1)) * W);
  const y = (v: number) => H - (Math.max(0, Math.min(100, v)) / 100) * H;
  const line = points.map((p, i) => `${x(i).toFixed(2)},${y(p.riskScore).toFixed(2)}`).join(" ");

  return (
    <div className="border border-line bg-void">
      <div className="relative h-28 px-4 py-3">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          preserveAspectRatio="none"
          className="h-full w-full overflow-visible"
          role="img"
          aria-label={`Évolution du score sur ${points.length} relevés, dernière valeur ${last.riskScore} sur 100.`}
        >
          {/* Reference lines at 50 and 80 — the E and B thresholds. */}
          {[50, 80].map((v) => (
            <line
              key={v}
              x1="0"
              x2={W}
              y1={y(v)}
              y2={y(v)}
              stroke="currentColor"
              strokeWidth="0.25"
              className="text-line"
              vectorEffect="non-scaling-stroke"
            />
          ))}
          <polyline
            points={line}
            fill="none"
            stroke="currentColor"
            strokeWidth="1.5"
            className="text-acid"
            vectorEffect="non-scaling-stroke"
          />
          {points.map((p, i) => (
            <circle
              key={p.runId}
              cx={x(i)}
              cy={y(p.riskScore)}
              r="2"
              className={i === points.length - 1 ? "fill-acid" : "fill-line-bright"}
              vectorEffect="non-scaling-stroke"
            />
          ))}
        </svg>
      </div>
      <div className="flex items-center justify-between border-t border-line px-4 py-2.5 font-mono text-label uppercase text-mute">
        <span>{points.length} relevé(s)</span>
        <span className={gradeTone(last.riskScore)}>dernier : {last.riskScore}/100</span>
      </div>
    </div>
  );
}
