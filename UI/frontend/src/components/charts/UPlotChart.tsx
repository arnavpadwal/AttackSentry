import { useEffect, useRef } from 'react';
import uPlot from 'uplot';
import 'uplot/dist/uPlot.min.css';

interface UPlotChartProps {
  options: Partial<uPlot.Options>;
  data: uPlot.AlignedData;
  height?: number;
  className?: string;
}

export default function UPlotChart({ options, data, height = 120, className = '' }: UPlotChartProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const uplotRef = useRef<uPlot | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    const opts: uPlot.Options = {
      width: containerRef.current.clientWidth || 400,
      height,
      cursor: { show: false },
      legend: { show: false },
      axes: [{ show: false }, { show: false }],
      scales: { x: { time: true }, y: { auto: true } },
      ...options,
    } as uPlot.Options;

    const u = new uPlot(opts, data, containerRef.current);
    uplotRef.current = u;

    const ro = new ResizeObserver((entries) => {
      for (const entry of entries) {
        if (uplotRef.current) {
          uplotRef.current.setSize({ width: entry.contentRect.width, height });
        }
      }
    });
    ro.observe(containerRef.current);

    return () => {
      ro.disconnect();
      u.destroy();
      uplotRef.current = null;
    };
  }, []);

  // Update data imperatively without re-creating the chart
  useEffect(() => {
    if (uplotRef.current && data[0]?.length) {
      uplotRef.current.setData(data);
    }
  }, [data]);

  return <div ref={containerRef} className={className} />;
}
