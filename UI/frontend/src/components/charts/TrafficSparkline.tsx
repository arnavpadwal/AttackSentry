import { useMemo } from 'react';
import { useTelemetryStore } from '@/stores';
import UPlotChart from './UPlotChart';

interface TrafficSparklineProps {
  height?: number;
  color?: string;
  className?: string;
}

export default function TrafficSparkline({ height = 80, color = '#6366f1', className = '' }: TrafficSparklineProps) {
  const { timestamps, bytesPerSec } = useTelemetryStore((s) => s.aggregated);

  const data = useMemo<uPlot.AlignedData>(() => {
    if (timestamps.length < 2) {
      const now = Date.now() / 1000;
      return [[now - 60, now], [0, 0]];
    }
    return [
      new Float64Array(timestamps),
      new Float64Array(bytesPerSec),
    ] as unknown as uPlot.AlignedData;
  }, [timestamps, bytesPerSec]);

  const options = useMemo(() => ({
    cursor: { show: false },
    legend: { show: false },
    axes: [{ show: false }, { show: false }],
    series: [
      {},
      {
        stroke: color,
        fill: `${color}18`,
        width: 2,
        spanGaps: true,
      },
    ],
    padding: [4, 0, 0, 0] as [number, number, number, number],
  }), [color]);

  return <UPlotChart options={options} data={data} height={height} className={className} />;
}
