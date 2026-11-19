interface GaugeProps {
  value: number; // 0-100
  size?: number;
  label?: string;
  sublabel?: string;
}

const TICKS = 12;

/**
 * Risk readout. Thin arc on a neutral track, tick marks every 25 points, the
 * figure in tabular numerals. No glow, no colored shadow.
 */
export default function Gauge({ value, size = 148, label, sublabel }: GaugeProps) {
  const stroke = 6;
  const r = (size - stroke) / 2;
  const cx = size / 2;
  const cy = size / 2;
  const circ = 2 * Math.PI * r;
  const arc = circ * 0.75;
  const clamped = Math.max(0, Math.min(100, value));
  const pct = clamped / 100;
  const tone =
    clamped >= 75 ? 'hsl(var(--severity-critical))'
    : clamped >= 50 ? 'hsl(var(--severity-high))'
    : clamped >= 25 ? 'hsl(var(--severity-medium))'
    : 'hsl(var(--severity-low))';

  const ticks = Array.from({ length: TICKS + 1 }, (_, i) => i / TICKS);

  return (
    <div className="flex flex-col items-center">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={`Risk ${clamped} of 100`}>
        <circle
          cx={cx} cy={cy} r={r} fill="none"
          stroke="hsl(var(--secondary))" strokeWidth={stroke}
          strokeDasharray={`${arc} ${circ}`} strokeLinecap="round"
          transform={`rotate(135 ${cx} ${cy})`}
        />
        <circle
          cx={cx} cy={cy} r={r} fill="none"
          stroke={tone} strokeWidth={stroke}
          strokeDasharray={`${arc * pct} ${circ}`} strokeLinecap="round"
          transform={`rotate(135 ${cx} ${cy})`}
          style={{ transition: 'stroke-dasharray 400ms ease' }}
        />
        {ticks.map((t) => {
          const angle = (135 + t * 270) * (Math.PI / 180);
          const outer = r - stroke / 2 - 3;
          const inner = outer - (t % 0.25 === 0 ? 5 : 3);
          return (
            <line
              key={t}
              x1={cx + Math.cos(angle) * inner}
              y1={cy + Math.sin(angle) * inner}
              x2={cx + Math.cos(angle) * outer}
              y2={cy + Math.sin(angle) * outer}
              stroke="hsl(var(--border))"
              strokeWidth={1}
            />
          );
        })}
        <text
          x="50%" y="49%"
          textAnchor="middle"
          fill="hsl(var(--foreground))"
          fontSize={size * 0.2}
          fontWeight={600}
          letterSpacing="-0.02em"
          style={{ fontVariantNumeric: 'tabular-nums' }}
        >
          {clamped.toFixed(0)}
        </text>
        <text x="50%" y="62%" textAnchor="middle" fill="hsl(var(--muted-foreground))" fontSize={size * 0.075} fontWeight={500}>
          of 100
        </text>
      </svg>
      {label && <p className="mt-0.5 text-[12.5px] font-medium text-foreground">{label}</p>}
      {sublabel && <p className="text-[11px] text-muted-foreground">{sublabel}</p>}
    </div>
  );
}
