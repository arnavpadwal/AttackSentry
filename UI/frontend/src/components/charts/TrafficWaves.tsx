import { useEffect, useMemo, useState } from 'react';
import { useTelemetryStore } from '@/stores';
import { formatBytes, cn } from '@/lib/utils';

interface TrafficWavesProps {
  className?: string;
}

const SM_HEIGHT = 240;
const XL_HEIGHT = 280;
const XL_QUERY = '(min-width: 1280px)';

function useChartHeight(): number {
  const [height, setHeight] = useState(() =>
    window.matchMedia(XL_QUERY).matches ? XL_HEIGHT : SM_HEIGHT,
  );
  useEffect(() => {
    const query = window.matchMedia(XL_QUERY);
    const update = () => setHeight(query.matches ? XL_HEIGHT : SM_HEIGHT);
    query.addEventListener('change', update);
    return () => query.removeEventListener('change', update);
  }, []);
  return height;
}

const W = 900;
const WINDOW = 60;
const X_PAD = 4;
const TOP_PAD = 24;
const BOTTOM_PAD = 24;

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

/** A true 60-second rolling traffic chart, fed by live flow buckets. */
export default function TrafficWaves({ className = '' }: TrafficWavesProps) {
  const height = useChartHeight();
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
      <div className="pointer-events-none absolute left-4 top-1 flex items-center gap-4 text-[11px] tabular-nums text-muted-foreground">
        <span className="flex items-center gap-1.5">
          <span className="h-[1.5px] w-3 rounded-full bg-primary" aria-hidden />
          In {formatBytes(currentIn)}/s
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-[1.5px] w-3 rounded-full bg-muted-foreground" aria-hidden />
          Out {formatBytes(currentOut)}/s
        </span>
      </div>

      <svg
        width="100%"
        height={height}
        viewBox={`0 0 ${W} ${height}`}
        preserveAspectRatio="none"
        role="img"
        aria-label="Real-time inbound and outbound network traffic for the last 60 seconds"
      >
        {[0, 0.5, 1].map((fraction) => {
          const x = X_PAD + fraction * (W - X_PAD * 2);
          return (
            <line
              key={`v-${fraction}`}
              x1={x} x2={x}
              y1={TOP_PAD} y2={height - BOTTOM_PAD}
              stroke="hsl(var(--border))" strokeWidth="1" strokeOpacity="0.8"
              vectorEffect="non-scaling-stroke"
            />
          );
        })}

        {[0, 0.25, 0.5, 0.75, 1].map((fraction) => {
          const y = TOP_PAD + usable * fraction;
          return (
            <line
              key={`h-${fraction}`}
              x1={X_PAD} x2={W - X_PAD}
              y1={y} y2={y}
              stroke="hsl(var(--border))" strokeWidth="1" strokeOpacity="0.8"
              vectorEffect="non-scaling-stroke"
            />
          );
        })}

        {idle ? (
          <text x={W / 2} y={TOP_PAD + usable / 2} textAnchor="middle" fill="hsl(var(--muted-foreground))" fontSize="11">
            Waiting for live traffic
          </text>
        ) : (
          <>
            <path d={outboundLine} fill="none" stroke="hsl(var(--muted-foreground))" strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
            <path d={inboundLine} fill="none" stroke="hsl(var(--primary))" strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
            {lastPoint && (
              <>
                <circle cx={xFor(lastPoint.t, start)} cy={lastY(lastPoint.outbound)} r="2" fill="hsl(var(--muted-foreground))" />
                <circle cx={xFor(lastPoint.t, start)} cy={lastY(lastPoint.inbound)} r="2" fill="hsl(var(--primary))" />
              </>
            )}
          </>
        )}
      </svg>

      <div className="pointer-events-none absolute bottom-1 left-4 right-4 flex justify-between text-[11px] tabular-nums text-muted-foreground">
        <span>-60s</span><span>-30s</span><span>now</span>
      </div>
    </div>
  );
}
