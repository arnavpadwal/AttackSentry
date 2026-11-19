interface GaugeProps {
  value: number; // 0-100
  size?: number;
  label?: string;
  sublabel?: string;
}

export default function Gauge({ value, size = 140, label, sublabel }: GaugeProps) {
  const stroke = size * 0.09;
  const r = (size - stroke) / 2;
  const circ = 2 * Math.PI * r;
  const arc = circ * 0.75;
  const pct = Math.max(0, Math.min(100, value)) / 100;
  const color = value >= 75 ? 'hsl(0 72% 51%)' : value >= 50 ? 'hsl(24 95% 53%)' : value >= 25 ? 'hsl(38 92% 50%)' : 'hsl(217 91% 60%)';

  return (
    <div className="flex flex-col items-center">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="hsl(var(--secondary))" strokeWidth={stroke} strokeDasharray={`${arc} ${circ}`} strokeLinecap="round" transform={`rotate(135 ${size / 2} ${size / 2})`} />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={stroke} strokeDasharray={`${arc * pct} ${circ}`} strokeLinecap="round" transform={`rotate(135 ${size / 2} ${size / 2})`} style={{ transition: 'stroke-dasharray 0.6s ease' }} />
        <text x="50%" y="48%" textAnchor="middle" fill="hsl(var(--foreground))" fontSize={size * 0.22} fontWeight={600} letterSpacing="-0.02em">
          {value.toFixed(0)}
        </text>
        <text x="50%" y="62%" textAnchor="middle" fill="hsl(var(--muted-foreground))" fontSize={size * 0.09} fontWeight={600} letterSpacing="0.08em">
          RISK
        </text>
      </svg>
      {label && <p className="mt-1 text-sm font-medium text-foreground">{label}</p>}
      {sublabel && <p className="text-xs text-muted-foreground">{sublabel}</p>}
    </div>
  );
}
