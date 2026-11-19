import { useMemo, useState } from 'react';
import type { GraphNode, NetworkGraph as GraphData } from '@/queries/network';

export type RiskTier = 'normal' | 'elevated' | 'critical';

export function riskTier(risk: number): RiskTier {
  if (risk >= 75) return 'critical';
  if (risk >= 40) return 'elevated';
  return 'normal';
}

export function isThreatEdge(edge: { flows: number; bytes: number }): boolean {
  return edge.flows > 50 || edge.bytes > 10_000_000;
}

const tierColor: Record<RiskTier, string> = {
  normal: 'hsl(var(--border))',
  elevated: 'hsl(var(--severity-high))',
  critical: 'hsl(var(--severity-critical))',
};

interface NetworkGraphProps {
  data: GraphData;
  onNodeClick?: (node: GraphNode) => void;
  selectedId?: string | null;
  /** Node IPs to draw. Layout still uses the full graph, so positions never move. */
  visibleIps?: Set<string>;
  /** View-box height. Rendering height is 420px on small screens, 600px from lg. */
  height?: number;
}

export default function NetworkGraph({
  data,
  onNodeClick,
  selectedId = null,
  visibleIps,
  height = 600,
}: NetworkGraphProps) {
  const [hover, setHover] = useState<string | null>(null);

  const layout = useMemo(() => {
    // Sort by IP so polling order changes never move a node.
    const nodes = [...data.nodes].sort((a, b) => a.ip.localeCompare(b.ip));
    const internal = nodes.filter((n) => !n.external);
    const external = nodes.filter((n) => n.external);
    const groups: Record<string, typeof internal> = {};
    internal.forEach((n) => {
      (groups[n.group] ||= []).push(n);
    });
    const groupNames = Object.keys(groups).sort();
    const W = 1000;
    const H = height;
    const pos: Record<string, { x: number; y: number }> = {};
    const GOLDEN_ANGLE = Math.PI * (3 - Math.sqrt(5));
    const FIELD = { left: 40, right: W - 96, top: 32, bottom: H - 32 };
    const EXTERNAL_X = W - 24;
    const diskRadius = (count: number) => Math.max(18, Math.sqrt(count) * 16);

    // Group centroids: golden-angle spiral on an ellipse, with room for each disk.
    const maxDisk = groupNames.reduce(
      (max, name) => Math.max(max, diskRadius(groups[name].length)),
      18
    );
    const cx = (FIELD.left + FIELD.right) / 2;
    const cy = (FIELD.top + FIELD.bottom) / 2;
    const rx = Math.max(40, (FIELD.right - FIELD.left) / 2 - maxDisk);
    const ry = Math.max(40, (FIELD.bottom - FIELD.top) / 2 - maxDisk);

    groupNames.forEach((name, gi) => {
      const members = groups[name];
      const radius = diskRadius(members.length);
      const t = groupNames.length === 1 ? 0 : (gi + 0.5) / groupNames.length;
      const angle = gi * GOLDEN_ANGLE - Math.PI / 2;
      const orbit = groupNames.length === 1 ? 0 : 0.35 + 0.65 * Math.sqrt(t);
      const gx = cx + Math.cos(angle) * rx * orbit;
      const gy = cy + Math.sin(angle) * ry * orbit;
      const x = Math.min(Math.max(gx, FIELD.left + radius), FIELD.right - radius);
      const y = Math.min(Math.max(gy, FIELD.top + radius), FIELD.bottom - radius);

      // Inside each group: phyllotaxis disk, densest at the centre.
      members.forEach((n, k) => {
        if (members.length === 1) {
          pos[n.ip] = { x, y };
          return;
        }
        const r = radius * Math.sqrt((k + 0.5) / members.length);
        const theta = k * GOLDEN_ANGLE;
        pos[n.ip] = { x: x + Math.cos(theta) * r, y: y + Math.sin(theta) * r };
      });
    });

    // External nodes: right column, full height, 24px right padding.
    external.forEach((n, i) => {
      pos[n.ip] = {
        x: EXTERNAL_X,
        y: 16 + ((i + 0.5) / Math.max(external.length, 1)) * (H - 32),
      };
    });

    return { pos, W, H };
  }, [data, height]);

  const nodeRadius = (risk: number, external: boolean) =>
    external ? 5 : 4 + Math.min(risk / 100, 1) * 8;

  const focusId = hover ?? selectedId;
  const focusNode = focusId ? data.nodes.find((n) => n.id === focusId) : undefined;
  const focusIp =
    focusNode && (!visibleIps || visibleIps.has(focusNode.ip)) ? focusNode.ip : undefined;
  const hoverNode = hover ? data.nodes.find((n) => n.id === hover) : undefined;

  return (
    <div className="graph-canvas relative h-[420px] w-full overflow-hidden rounded-lg border border-border bg-card lg:h-[600px]">
      <svg
        className="block h-full w-full"
        viewBox={`0 0 ${layout.W} ${layout.H}`}
        preserveAspectRatio="xMidYMid meet"
        role="group"
        aria-label="Network entity graph"
      >
        {data.edges.map((e) => {
          const a = layout.pos[e.src];
          const b = layout.pos[e.dst];
          if (!a || !b) return null;
          if (visibleIps && (!visibleIps.has(e.src) || !visibleIps.has(e.dst))) return null;
          const dim = focusIp ? e.src !== focusIp && e.dst !== focusIp : false;
          return (
            <line
              key={e.id}
              x1={a.x}
              y1={a.y}
              x2={b.x}
              y2={b.y}
              className={isThreatEdge(e) ? 'graph-edge threat' : 'graph-edge'}
              strokeWidth={1}
              style={dim ? { opacity: 0.18 } : undefined}
            />
          );
        })}

        {data.nodes.map((n) => {
          if (visibleIps && !visibleIps.has(n.ip)) return null;
          const p = layout.pos[n.ip];
          if (!p) return null;
          const r = nodeRadius(n.risk, n.external);
          const tier = riskTier(n.risk);
          const active = focusId === n.id;
          const selected = selectedId === n.id;
          const isSegment = n.node_type === 'group';
          const showLabel =
            selected || hover === n.id || n.risk >= 40 || data.nodes.length <= 40;
          const anchor = p.x < 120 ? 'start' : p.x > layout.W - 120 ? 'end' : 'middle';
          const labelX =
            anchor === 'middle' ? p.x : anchor === 'start' ? p.x + r + 4 : p.x - r - 4;
          const labelY = anchor === 'middle' ? p.y + r + 13 : p.y + 3.5;
          const label = n.hostname.length > 22 ? `${n.hostname.slice(0, 21)}…` : n.hostname;
          return (
            <g
              key={n.id}
              className="graph-node"
              opacity={focusId && !active ? 0.35 : 1}
              tabIndex={0}
              role="button"
              aria-label={`${n.hostname}, ${n.ip}, risk ${n.risk.toFixed(0)}`}
              onMouseEnter={() => setHover(n.id)}
              onMouseLeave={() => setHover(null)}
              onFocus={() => setHover(n.id)}
              onBlur={() => setHover(null)}
              onClick={() => onNodeClick?.(n)}
              onKeyDown={(event) => {
                if (event.key !== 'Enter' && event.key !== ' ') return;
                event.preventDefault();
                onNodeClick?.(n);
              }}
            >
              <circle
                cx={p.x}
                cy={p.y}
                r={r}
                fill="hsl(var(--secondary))"
                stroke="hsl(var(--border))"
                strokeWidth={1}
                strokeDasharray={isSegment ? '3 3' : n.external ? '2 2' : undefined}
              />
              {tier !== 'normal' && (
                <circle
                  cx={p.x}
                  cy={p.y}
                  r={r + 4}
                  fill="none"
                  stroke={tierColor[tier]}
                  strokeWidth={2}
                  opacity={0.85}
                />
              )}
              {selected && (
                <circle
                  cx={p.x}
                  cy={p.y}
                  r={r + 7}
                  fill="none"
                  stroke="hsl(var(--primary))"
                  strokeWidth={1}
                />
              )}
              {showLabel && (
                <text
                  x={labelX}
                  y={labelY}
                  textAnchor={anchor}
                  className="mono"
                  fontSize={10}
                  fill={selected ? 'hsl(var(--foreground))' : 'hsl(var(--muted-foreground))'}
                >
                  {label}
                </text>
              )}
            </g>
          );
        })}

        {hoverNode &&
          (() => {
            const p = layout.pos[hoverNode.ip];
            if (!p || (visibleIps && !visibleIps.has(hoverNode.ip))) return null;
            const title =
              hoverNode.hostname.length > 30
                ? `${hoverNode.hostname.slice(0, 29)}…`
                : hoverNode.hostname;
            const sub =
              hoverNode.node_type === 'group'
                ? 'logical segment'
                : `${hoverNode.ip} · ${hoverNode.group}`;
            const clippedSub = sub.length > 36 ? `${sub.slice(0, 35)}…` : sub;
            const w = Math.min(
              248,
              Math.max(148, Math.max(title.length * 6.2, clippedSub.length * 5.8) + 22)
            );
            const h = 56;
            const x = Math.min(Math.max(p.x + 14, 8), layout.W - w - 8);
            const y = Math.min(Math.max(p.y - h - 12, 8), layout.H - h - 8);
            const tier = riskTier(hoverNode.risk);
            return (
              <g pointerEvents="none" transform={`translate(${x} ${y})`}>
                <rect
                  width={w}
                  height={h}
                  rx={6}
                  fill="hsl(var(--popover))"
                  stroke="hsl(var(--border))"
                />
                <text x={10} y={18} fontSize={11} fill="hsl(var(--foreground))">
                  {title}
                </text>
                <text x={10} y={33} className="mono" fontSize={10} fill="hsl(var(--muted-foreground))">
                  {clippedSub}
                </text>
                <text
                  x={10}
                  y={46}
                  fontSize={10}
                  fill={tier === 'normal' ? 'hsl(var(--muted-foreground))' : tierColor[tier]}
                >
                  risk {hoverNode.risk.toFixed(0)}
                </text>
              </g>
            );
          })()}
      </svg>
    </div>
  );
}
