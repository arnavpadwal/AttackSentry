import { useEffect, useMemo, useState } from 'react';
import { useTelemetryStore } from '@/stores';
import { formatBytes, cn } from '@/lib/utils';

interface TrafficWavesProps {
  height?: number;
  className?: string;
}

const W = 900;
const WINDOW = 60;
const X_PAD = 4;
const TOP_PAD = 8;
const BOTTOM_PAD = 20;

interface Point {
  t: number;
  inbound: number;
  outbound: number;
}

function xFor(timestamp: number, start: number): number {
  return X_PAD + ((timestamp - start) / WINDOW) * (W - X_PAD * 2);
}

function linePath(points: Point[], key: 'inbound' | 'outbound', start: number, height: number, max: number): string {
  const usable = height - TOP_PAD - BOTTOM_PAD;
  return points.map((point, index) => {
    const x = xFor(point.t, start);
    const y = height - BOTTOM_PAD - Math.max(0, Math.min(1, point[key] / max)) * usable;
    return `${index === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`;
  }).join(' ');
}

function areaPath(points: Point[], key: 'inbound' | 'outbound', start: number, height: number, max: number): string {
  if (!points.length) return '';
  const line = linePath(points, key, start, height, max);
  const last = points[points.length - 1];
  const first = points[0];
  return `${line} L ${xFor(last.t, start).toFixed(1)} ${height - BOTTOM_PAD} L ${xFor(first.t, start).toFixed(1)} ${height - BOTTOM_PAD} Z`;
}

/** A true 60-second rolling traffic chart, fed by live flow buckets. */
export default function TrafficWaves({ height = 180, className = '' }: TrafficWavesProps) {
  const { timestamps, bytesInPerSec, bytesOutPerSec } = useTelemetryStore((s) => s.aggregated);
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));

  // Advance the window even when no flows arrive, so idle periods are visible.
  useEffect(() => {
    const id = setInterval(() => setNow(Math.floor(Date.now() / 1000)), 1000);
    return () => clearInterval(id);
  }, []);

  const { points, max, currentIn, currentOut, idle } = useMemo(() => {
    const buckets = new Map<number, { inbound: number; outbound: number }>();
    timestamps.forEach((timestamp, index) => {
      buckets.set(Math.floor(timestamp), {
        inbound: bytesInPerSec[index] ?? 0,
        outbound: bytesOutPerSec[index] ?? 0,
      });
    });

    const start = now - WINDOW;
    const next: Point[] = [];
    for (let timestamp = start; timestamp <= now; timestamp += 1) {
      const bucket = buckets.get(timestamp);
      next.push({ t: timestamp, inbound: bucket?.inbound ?? 0, outbound: bucket?.outbound ?? 0 });
    }

    const peak = Math.max(1, ...next.map((point) => Math.max(point.inbound, point.outbound)));
    const latest = next[next.length - 1];
    return {
      points: next,
      max: peak * 1.15,
      currentIn: latest?.inbound ?? 0,
      currentOut: latest?.outbound ?? 0,
      idle: peak <= 1,
    };
  }, [timestamps, bytesInPerSec, bytesOutPerSec, now]);

  const start = now - WINDOW;
  const inboundLine = linePath(points, 'inbound', start, height, max);
  const outboundLine = linePath(points, 'outbound', start, height, max);
  const lastPoint = points[points.length - 1];
  const usable = height - TOP_PAD - BOTTOM_PAD;
  const lastY = (value: number) => height - BOTTOM_PAD - Math.max(0, Math.min(1, value / max)) * usable;

  return (
    <div className={cn('relative w-full overflow-hidden', className)} style={{ height }}>
      <div className="pointer-events-none absolute left-3 top-1 flex items-center gap-4 text-[10px] tabular-nums text-muted-foreground">
        <span className="flex items-center gap-1.5"><span className="h-1.5 w-1.5 rounded-full bg-chart-1" />In {formatBytes(currentIn)}/s</span>
        <span className="flex items-center gap-1.5"><span className="h-1.5 w-1.5 rounded-full bg-chart-2" />Out {formatBytes(currentOut)}/s</span>
      </div>

      <svg
        width="100%"
        height={height}
        viewBox={`0 0 ${W} ${height}`}
        preserveAspectRatio="none"
        role="img"
        aria-label="Real-time inbound and outbound network traffic for the last 60 seconds"
      >
        <defs>
          <linearGradient id="traffic-in-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="hsl(var(--chart-1))" stopOpacity="0.20" />
            <stop offset="100%" stopColor="hsl(var(--chart-1))" stopOpacity="0" />
          </linearGradient>
          <linearGradient id="traffic-out-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="hsl(var(--chart-2))" stopOpacity="0.14" />
            <stop offset="100%" stopColor="hsl(var(--chart-2))" stopOpacity="0" />
          </linearGradient>
        </defs>

        {[0.25, 0.5, 0.75].map((fraction) => {
          const y = TOP_PAD + usable * fraction;
          return <line key={fraction} x1={X_PAD} x2={W - X_PAD} y1={y} y2={y} stroke="hsl(var(--border))" strokeOpacity="0.5" strokeDasharray="3 5" vectorEffect="non-scaling-stroke" />;
        })}

        {idle ? (
          <text x={W / 2} y={height / 2} textAnchor="middle" fill="hsl(var(--muted-foreground))" fontSize="12">
            Waiting for live traffic…
          </text>
        ) : (
          <>
            <path d={areaPath(points, 'outbound', start, height, max)} fill="url(#traffic-out-fill)" />
            <path d={areaPath(points, 'inbound', start, height, max)} fill="url(#traffic-in-fill)" />
            <path d={outboundLine} fill="none" stroke="hsl(var(--chart-2))" strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
            <path d={inboundLine} fill="none" stroke="hsl(var(--chart-1))" strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
            {lastPoint && (
              <>
                <circle cx={xFor(lastPoint.t, start)} cy={lastY(lastPoint.inbound)} r="2.5" fill="hsl(var(--chart-1))" />
                <circle cx={xFor(lastPoint.t, start)} cy={lastY(lastPoint.outbound)} r="2.5" fill="hsl(var(--chart-2))" />
              </>
            )}
          </>
        )}
      </svg>

      <div className="pointer-events-none absolute bottom-0 left-3 right-3 flex justify-between text-[9px] tabular-nums text-muted-foreground/70">
        <span>-60s</span><span>-30s</span><span>now</span>
      </div>
    </div>
  );
}
