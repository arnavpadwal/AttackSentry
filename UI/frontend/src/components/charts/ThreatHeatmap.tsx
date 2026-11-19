import { anomalyColor } from '@/lib/utils';

interface ThreatHeatmapProps {
  hosts: { id: string; hostname: string; ip: string; risk_score: number }[];
  onNodeClick?: (id: string) => void;
}

export default function ThreatHeatmap({ hosts, onNodeClick }: ThreatHeatmapProps) {
  if (!hosts.length) {
    return <div className="flex h-32 items-center justify-center text-sm text-ink-faint">No hosts monitored</div>;
  }

  return (
    <div className="flex flex-wrap gap-2">
      {hosts.map((host) => {
        const color = anomalyColor(host.risk_score);
        return (
          <button
            key={host.id}
            onClick={() => onNodeClick?.(host.id)}
            title={`${host.hostname || host.ip} — risk ${host.risk_score.toFixed(0)}`}
            className="group relative flex h-14 w-14 flex-col items-center justify-center rounded-lg transition-transform hover:scale-110"
            style={{ backgroundColor: `${color}14`, border: `1.5px solid ${color}55` }}
          >
            <span className="text-[11px] font-bold" style={{ color }}>{host.risk_score.toFixed(0)}</span>
            <span className="max-w-[48px] truncate text-center text-[9px] text-ink-faint">
              {(host.hostname || host.ip).split('-')[0]}
            </span>
          </button>
        );
      })}
    </div>
  );
}
