import { useMemo, useState } from 'react';
import type { NetworkGraph as GraphData } from '@/queries/network';
import { anomalyColor } from '@/lib/utils';

interface NetworkGraphProps {
  data: GraphData;
  onNodeClick?: (node: { id: string; ip: string; hostname: string; external: boolean; node_type?: string }) => void;
  height?: number;
}

export default function NetworkGraph({ data, onNodeClick, height = 460 }: NetworkGraphProps) {
  const [hover, setHover] = useState<string | null>(null);

  const layout = useMemo(() => {
    const internal = data.nodes.filter((n) => !n.external);
    const external = data.nodes.filter((n) => n.external);

    const groups: Record<string, typeof internal> = {};
    internal.forEach((n) => {
      (groups[n.group] ||= []).push(n);
    });
    const groupNames = Object.keys(groups);

    const W = 1000;
    const H = height;
    const pos: Record<string, { x: number; y: number }> = {};
    const cx = W * 0.62; // centre of internal area
    const cy = H / 2;
    const radiusX = W * 0.52;
    const radiusY = H * 0.42;

    // Internal nodes: radial layout around the centre, clustered by group.
    let idx = 0;
    const total = internal.length || 1;
    internal.forEach((n) => {
      const gi = groupNames.indexOf(n.group);
      const baseAngle = (gi / Math.max(groupNames.length, 1)) * Math.PI * 2;
      const within = groups[n.group].length;
      const wi = groups[n.group].indexOf(n);
      const spread = Math.PI / Math.max(groupNames.length, 1);
      const angle = baseAngle + (wi / Math.max(within, 1) - 0.5) * spread + (idx / total) * 0.3;
      const r = 0.25 + (wi / Math.max(within, 1)) * 0.75;
      pos[n.ip] = {
        x: cx + Math.cos(angle) * radiusX * r,
        y: cy + Math.sin(angle) * radiusY * r,
      };
      idx++;
    });

    // External nodes: right column.
    external.forEach((n, i) => {
      pos[n.ip] = {
        x: W - 40,
        y: 40 + (i / Math.max(external.length, 1)) * (H - 80),
      };
    });

    return { pos, W, H };
  }, [data, height]);

  const nodeRadius = (risk: number, external: boolean) =>
    external ? 5 : 4 + Math.min(risk / 100, 1) * 9;

  const riskColor = (n: { risk: number; external: boolean }) => {
    if (n.external) return 'hsl(220 9% 60%)';
    if (n.risk >= 75) return 'hsl(0 72% 51%)';
    if (n.risk >= 40) return 'hsl(24 95% 53%)';
    if (n.risk >= 15) return 'hsl(38 92% 50%)';
    return 'hsl(217 91% 60%)';
  };

  return (
    <div className="graph-canvas relative w-full overflow-hidden rounded-lg border border-border bg-surface" style={{ height }}>
      <svg width="100%" height={height} viewBox={`0 0 ${layout.W} ${layout.H}`} preserveAspectRatio="xMidYMid meet">
        {data.edges.map((e) => {
          const a = layout.pos[e.src];
          const b = layout.pos[e.dst];
          if (!a || !b) return null;
          const threat = e.flows > 50 || e.bytes > 10_000_000;
          return (
            <line key={e.id} x1={a.x} y1={a.y} x2={b.x} y2={b.y}
              className={threat ? 'graph-edge threat' : 'graph-edge'}
              strokeWidth={Math.min(3, 0.5 + Math.log10(e.flows + 1))} />
          );
        })}

        {data.nodes.map((n) => {
          const p = layout.pos[n.ip];
          if (!p) return null;
          const r = nodeRadius(n.risk, n.external);
          const color = riskColor(n);
          const active = hover === n.ip;
          return (
            <g key={n.id} className="graph-node" opacity={active || !hover ? 1 : 0.3}
              onMouseEnter={() => setHover(n.ip)} onMouseLeave={() => setHover(null)}
              onClick={() => onNodeClick?.(n)}>
              {n.risk >= 40 && <circle cx={p.x} cy={p.y} r={r + 6} fill={color} opacity={0.12} />}
              <circle cx={p.x} cy={p.y} r={r} fill={color} stroke="hsl(var(--card))" strokeWidth={1.5} strokeDasharray={n.node_type === 'group' ? '3 2' : undefined} />
              {n.risk >= 75 && (
                <circle cx={p.x} cy={p.y} r={r + 4} fill="none" stroke={color} strokeWidth={1.5}
                  strokeDasharray="3 3" className="animate-pulse" />
              )}
              <text x={p.x} y={p.y + r + 12} textAnchor="middle" fill="hsl(var(--muted-foreground))" fontSize={9}>
                {n.hostname.length > 16 ? n.hostname.slice(0, 15) + '…' : n.hostname}
              </text>
            </g>
          );
        })}
      </svg>

      {hover && (() => {
        const n = data.nodes.find((x) => x.ip === hover);
        if (!n) return null;
        const p = layout.pos[n.ip];
        return (
          <div className="pointer-events-none absolute z-10 rounded-lg border border-border bg-surface px-3 py-2 text-xs shadow-modal"
            style={{ left: Math.min(p.x + 16, 820), top: Math.min(p.y, height - 70) }}>
            <p className="font-medium text-ink">{n.hostname}</p>
            <p className="text-ink-faint">{n.node_type === 'group' ? 'Logical segment' : `${n.ip} · ${n.group}`}</p>
            <p className="text-accent-text">{n.node_type === 'group' ? 'segment hierarchy' : `risk ${n.risk.toFixed(0)}`}</p>
            {n.vlan && <p className="text-ink-faint">VLAN / subnet: {n.vlan}</p>}
          </div>
        );
      })()}

      <div className="absolute bottom-3 left-3 flex items-center gap-4 rounded-lg border bg-card/90 px-3 py-1.5 text-[10px] text-muted-foreground backdrop-blur">
        <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full" style={{ background: 'hsl(0 72% 51%)' }} /> critical</span>
        <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full" style={{ background: 'hsl(24 95% 53%)' }} /> high</span>
        <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full" style={{ background: 'hsl(38 92% 50%)' }} /> medium</span>
        <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full" style={{ background: 'hsl(217 91% 60%)' }} /> normal</span>
        <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full" style={{ background: 'hsl(220 9% 60%)' }} /> external</span>
      </div>
    </div>
  );
}
