import { useMemo } from 'react';
import type { MitreCoverage } from '@/queries/network';

const MITRE_TACTIC_ORDER = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact',
];

export default function MitreMatrix({ data }: { data: MitreCoverage }) {
  const byTactic = useMemo(() => {
    const map: Record<string, { tactic: string; technique: string; count: number }[]> = {};
    data.techniques.forEach((t) => {
      (map[t.tactic] ||= []).push(t);
    });
    return map;
  }, [data]);

  const max = Math.max(1, ...data.techniques.map((t) => t.count));

  const cellColor = (count: number) => {
    const ratio = count / max;
    if (ratio > 0.66) return 'hsl(0 72% 51%)';
    if (ratio > 0.33) return 'hsl(24 95% 53%)';
    return 'hsl(217 91% 60%)';
  };

  return (
    <div className="scroll-x">
      <div className="flex gap-3" style={{ minWidth: 900 }}>
        {MITRE_TACTIC_ORDER.map((tactic) => {
          const techniques = byTactic[tactic] || [];
          return (
            <div key={tactic} className="flex min-w-[128px] flex-1 flex-col rounded-lg border border-border bg-surface-subtle p-2">
              <p className="mb-2 text-[10px] font-semibold uppercase tracking-wide text-ink-3">{tactic}</p>
              {techniques.length ? (
                <div className="space-y-1">
                  {techniques.map((t) => (
                    <div key={t.technique} className="rounded px-2 py-1 text-[10px] font-medium text-ink-inverse"
                      style={{ background: cellColor(t.count) }} title={`${t.technique} — ${t.count} detections`}>
                      {t.technique}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="rounded px-2 py-1 text-[10px] text-ink-faint">—</div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
