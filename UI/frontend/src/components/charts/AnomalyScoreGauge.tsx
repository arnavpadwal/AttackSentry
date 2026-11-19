import { anomalyColor } from '@/lib/utils';

interface AnomalyScoreGaugeProps {
  score: number;
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
}

const sizes = {
  sm: { r: 30, stroke: 5, dim: 70 },
  md: { r: 44, stroke: 8, dim: 100 },
  lg: { r: 60, stroke: 10, dim: 136 },
};

export default function AnomalyScoreGauge({ score, size = 'md', showLabel = true }: AnomalyScoreGaugeProps) {
  const { r, stroke, dim } = sizes[size];
  const color = anomalyColor(score);
  const circumference = 2 * Math.PI * r;
  const arc = circumference * 0.75; // 270 degree arc
  const offset = arc - (score / 100) * arc;

  return (
    <div className="flex flex-col items-center gap-1">
      <svg width={dim} height={dim} viewBox={`0 0 ${dim} ${dim}`}>
        {/* Background arc */}
        <circle
          cx={dim / 2} cy={dim / 2} r={r}
          fill="none"
          stroke="#e2e8f0"
          strokeWidth={stroke}
          strokeDasharray={`${arc} ${circumference}`}
          strokeDashoffset={0}
          strokeLinecap="round"
          transform={`rotate(135 ${dim / 2} ${dim / 2})`}
        />
        {/* Score arc */}
        <circle
          cx={dim / 2} cy={dim / 2} r={r}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeDasharray={`${arc} ${circumference}`}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform={`rotate(135 ${dim / 2} ${dim / 2})`}
          style={{ transition: 'stroke-dashoffset 0.6s ease' }}
        />
        {showLabel && (
          <>
            <text x={dim / 2} y={dim / 2 + 6} textAnchor="middle" fontSize={size === 'lg' ? 22 : size === 'md' ? 16 : 11} fontWeight="700" fill={color}>
              {score.toFixed(0)}
            </text>
            <text x={dim / 2} y={dim / 2 + 20} textAnchor="middle" fontSize={9} fill="#94a3b8">
              ANOMALY
            </text>
          </>
        )}
      </svg>
    </div>
  );
}
