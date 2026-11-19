import { useNavigate } from 'react-router-dom';
import { FileText, Download, RefreshCw, ArrowRight } from 'lucide-react';
import PageHeader from '@/components/shared/PageHeader';
import Metric from '@/components/shared/Metric';
import EmptyState from '@/components/shared/EmptyState';
import SeverityBadge from '@/components/shared/SeverityBadge';
import Badge from '@/components/shared/Badge';
import Button from '@/components/shared/Button';
import Card from '@/components/shared/Card';
import { Skeleton } from '@/components/ui/skeleton';
import { Progress } from '@/components/ui/progress';
import { useTrafficSummary } from '@/queries/sentry';
import { useAlerts } from '@/queries/alerts';
import { useIncidents } from '@/queries/incidents';
import { useHosts } from '@/queries/hosts';
import { useMitreCoverage } from '@/queries/network';
import { useInvestorReport } from '@/queries/reports';
import { formatBytes, parseTimestamp, relativeTime } from '@/lib/utils';

const REPORT_RANGE = 'Last 30 days';

export default function ReportsPage() {
  const navigate = useNavigate();
  const { data: traffic } = useTrafficSummary('24h');
  const { data: alerts } = useAlerts({ page: 1, page_size: 8 });
  const { data: incidents } = useIncidents();
  const { data: hosts } = useHosts();
  const { data: mitre } = useMitreCoverage();
  const { data: report, isLoading, isError, isFetching, refetch } = useInvestorReport();

  const reportText = report
    ? [report.title, `Generated: ${new Date(report.generated_at).toLocaleString()}`, '', ...report.sections.map((s) => `${s.heading}\n${s.body}`)].join('\n\n')
    : '';
  const reportSize = reportText ? formatBytes(new Blob([reportText]).size) : '—';

  const downloadReport = () => {
    if (!reportText) return;
    const url = URL.createObjectURL(new Blob([reportText], { type: 'text/plain;charset=utf-8' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = `attacksentry-report-${new Date().toISOString().slice(0, 10)}.txt`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const stats = [
    { label: 'Alerts (24h)', value: traffic?.total_alerts_24h ?? 0 },
    { label: 'Critical (24h)', value: traffic?.critical_24h ?? 0, tone: 'critical' as const },
    { label: 'Open incidents', value: incidents?.filter((i) => i.status === 'open').length ?? 0 },
    { label: 'Entities monitored', value: hosts?.length ?? 0 },
    { label: 'Entities at risk', value: traffic?.entities_at_risk ?? 0 },
    { label: 'MITRE-mapped detections', value: mitre?.total ?? 0 },
  ];

  const reportTypes = [
    {
      name: 'Investor security report',
      description: 'Thirty-day counts of detections, critical findings, correlated incidents, monitored hosts and analyzed flows, with an executive summary.',
      format: 'Plain text · .txt',
    },
  ];

  return (
    <div className="animate-fade-in space-y-4">
      <PageHeader
        title="Reports"
        description="One export is available: a 30-day security summary of the monitored estate, built from live detection data."
        meta={<span className="meta">{report ? `Last generated ${relativeTime(parseTimestamp(report.generated_at))}` : 'Not generated yet'}</span>}
        actions={<Button size="sm" variant="outline" disabled={!report} onClick={downloadReport}><Download size={14} strokeWidth={1.5} /> Download</Button>}
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-3 xl:grid-cols-6">
        {stats.map((s) => <Metric key={s.label} label={s.label} value={s.value} tone={s.tone} />)}
      </div>

      <section className="space-y-2">
        <div className="flex items-baseline justify-between gap-3">
          <h2 className="text-[13px] font-semibold text-foreground">Available exports</h2>
          <span className="meta">Reports are generated on request</span>
        </div>
        <div className="grid gap-3">
          {reportTypes.map((type) => (
            <article key={type.name} className="panel flex flex-col gap-3 p-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex min-w-0 items-start gap-3">
                <FileText size={15} strokeWidth={1.5} className="mt-0.5 shrink-0 text-muted-foreground" aria-hidden />
                <div className="min-w-0">
                  <p className="text-[13px] font-medium text-foreground">{type.name}</p>
                  <p className="mt-1 max-w-[80ch] text-[12px] leading-5 text-muted-foreground">{type.description}</p>
                </div>
              </div>
              <div className="flex shrink-0 flex-wrap items-center gap-3 sm:justify-end">
                <p className="meta">{type.format} · {REPORT_RANGE}{report ? ` · ${reportSize}` : ''}</p>
                <Button size="sm" variant="outline" loading={isFetching} disabled={isFetching} onClick={() => refetch()}>
                  {!isFetching && <RefreshCw size={14} strokeWidth={1.5} />} {report ? 'Regenerate' : 'Generate'}
                </Button>
              </div>
            </article>
          ))}
        </div>
      </section>

      <Card
        title="Generated reports"
        subtitle="Every generated document, most recent first"
        noPadding
        action={<span className="meta">{report ? `1 document · ${reportSize}` : 'No documents'}</span>}
      >
        <div className="overflow-x-auto">
          <table className="table-shell min-w-[720px]">
            <thead>
              <tr>
                <th>Report</th>
                <th>Status</th>
                <th>Range</th>
                <th>Created</th>
                <th className="text-right">Size</th>
                <th className="text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={6}><Skeleton className="h-4 w-full" /></td>
                </tr>
              ) : isError ? (
                <tr>
                  <td colSpan={6}>
                    <EmptyState
                      icon={FileText}
                      title="Report unavailable"
                      description="The report service did not return a document. Retry to request a fresh 30-day report."
                      action={<Button size="sm" variant="outline" onClick={() => refetch()}>Retry</Button>}
                    />
                  </td>
                </tr>
              ) : !report ? (
                <tr>
                  <td colSpan={6}>
                    <EmptyState
                      icon={FileText}
                      title="No report generated yet"
                      description="After the first report, this table lists its status, reporting range, generation time, file size and download action."
                      action={<Button size="sm" loading={isFetching} onClick={() => refetch()}>Generate report</Button>}
                    />
                  </td>
                </tr>
              ) : (
                <tr>
                  <td className="font-medium">{report.title}</td>
                  <td><Badge variant="default" dot>{isFetching ? 'Generating' : 'Ready'}</Badge></td>
                  <td className="text-muted-foreground">{REPORT_RANGE}</td>
                  <td>
                    <span className="mono text-[11px] text-muted-foreground">{new Date(parseTimestamp(report.generated_at)).toLocaleString()}</span>
                  </td>
                  <td className="mono tnum text-right text-muted-foreground">{reportSize}</td>
                  <td className="text-right">
                    <Button size="sm" variant="ghost" onClick={downloadReport}><Download size={14} strokeWidth={1.5} /> Download</Button>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>

      <div className="grid gap-3 xl:grid-cols-[1.1fr_1fr_1fr]">
        <Card title="Latest report" subtitle={report ? new Date(parseTimestamp(report.generated_at)).toLocaleString() : 'Nothing generated yet'}>
          {report?.sections.length ? (
            <div className="space-y-3">
              {report.sections.map((section) => (
                <div key={section.heading}>
                  <p className="text-[12px] font-medium text-foreground">{section.heading}</p>
                  <p className="mt-0.5 text-[12px] leading-5 text-muted-foreground">{section.body}</p>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState icon={FileText} title="No report body" description="Generate the report to read its sections here before downloading." className="py-8" />
          )}
        </Card>

        <Card title="Tactics covered" subtitle="MITRE ATT&CK distribution" noPadding>
          <div className="space-y-2.5 p-4">
            {mitre?.tactics.length ? (
              mitre.tactics.slice(0, 8).map((t) => (
                <div key={t.tactic}>
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="truncate text-[12px] text-foreground">{t.tactic}</span>
                    <span className="mono tnum text-[11px] text-muted-foreground">{t.count}</span>
                  </div>
                  <Progress value={Math.min(100, t.pct * 4)} className="mt-1 h-1" />
                </div>
              ))
            ) : (
              <EmptyState icon={FileText} title="No mapped detections" description="Tactics appear once detections map to ATT&CK techniques." className="py-6" />
            )}
          </div>
        </Card>

        <Card
          title="Recent detections"
          subtitle="Feeds the report counts"
          noPadding
          action={<Button size="sm" variant="ghost" onClick={() => navigate('/threats')}>View all <ArrowRight size={14} strokeWidth={1.5} /></Button>}
        >
          <div className="overflow-x-auto">
            <table className="table-shell min-w-[320px]">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Detection</th>
                  <th className="text-right">Time</th>
                </tr>
              </thead>
              <tbody>
                {(alerts?.items ?? []).slice(0, 6).map((a) => (
                  <tr key={a.id} className="cursor-pointer" onClick={() => navigate(`/alerts/${a.id}`)}>
                    <td className="w-0"><SeverityBadge severity={a.severity} /></td>
                    <td className="max-w-[180px] truncate font-medium">{a.detection_type}</td>
                    <td className="text-right"><span className="meta">{relativeTime(parseTimestamp(a.timestamp))}</span></td>
                  </tr>
                ))}
                {!alerts?.items.length && (
                  <tr>
                    <td colSpan={3}>
                      <EmptyState icon={FileText} title="No detections in view" description="Detections appear here as the sensor reports them." className="py-6" />
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      </div>
    </div>
  );
}
