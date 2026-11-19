import { useNavigate } from 'react-router-dom';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '@/components/ui/table';
import { Progress } from '@/components/ui/progress';
import { useTrafficSummary } from '@/queries/sentry';
import { useAlerts } from '@/queries/alerts';
import { useIncidents } from '@/queries/incidents';
import { useHosts } from '@/queries/hosts';
import { useMitreCoverage } from '@/queries/network';
import { useInvestorReport } from '@/queries/reports';
import { parseTimestamp, relativeTime } from '@/lib/utils';
import { ArrowRight, Download } from 'lucide-react';

export default function ReportsPage() {
  const navigate = useNavigate();
  const { data: traffic } = useTrafficSummary('24h');
  const { data: alerts } = useAlerts({ page: 1, page_size: 8 });
  const { data: incidents } = useIncidents();
  const { data: hosts } = useHosts();
  const { data: mitre } = useMitreCoverage();
  const { data: report } = useInvestorReport();

  const sevVariant = (s: string) => s === 'critical' ? 'destructive' : s === 'high' ? 'default' : s === 'medium' ? 'secondary' : 'muted';
  const downloadReport = () => {
    if (!report) return;
    const text = [report.title, `Generated: ${new Date(report.generated_at).toLocaleString()}`, '', ...report.sections.map((s) => `${s.heading}\n${s.body}`)].join('\n\n');
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }));
    const link = document.createElement('a'); link.href = url; link.download = `attacksentry-report-${new Date().toISOString().slice(0, 10)}.txt`; link.click(); URL.revokeObjectURL(url);
  };

  const stats = [
    { label: 'Alerts (24h)', value: traffic?.total_alerts_24h ?? 0 },
    { label: 'Critical', value: traffic?.critical_24h ?? 0 },
    { label: 'Open incidents', value: incidents?.filter((i) => i.status === 'open').length ?? 0 },
    { label: 'Entities monitored', value: hosts?.length ?? 0 },
    { label: 'Entities at risk', value: traffic?.entities_at_risk ?? 0 },
    { label: 'MITRE-mapped', value: mitre?.total ?? 0 },
  ];

  return (
    <div className="animate-fade-in space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Security Overview Report</h1>
        <div className="flex flex-wrap items-center justify-between gap-3"><p className="text-sm text-muted-foreground">SOC metrics across the monitored estate</p><Button variant="outline" size="sm" disabled={!report} onClick={downloadReport}><Download size={14} /> Download report</Button></div>
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-6">
        {stats.map((s) => (
          <Card key={s.label}>
            <CardContent className="pt-5">
              <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{s.label}</p>
              <p className="mt-2 text-2xl font-semibold tracking-tight">{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Top tactics</CardTitle>
            <CardDescription className="text-xs">MITRE ATT&CK distribution</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {mitre?.tactics.length ? (
              mitre.tactics.slice(0, 8).map((t) => (
                <div key={t.tactic}>
                  <div className="flex justify-between text-xs"><span>{t.tactic}</span><span className="text-muted-foreground">{t.count}</span></div>
                  <Progress value={Math.min(100, t.pct * 4)} className="mt-1 h-1.5" />
                </div>
              ))
            ) : <p className="py-6 text-center text-sm text-muted-foreground">No mapped detections yet</p>}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex-row items-center justify-between space-y-0">
            <CardTitle className="text-sm">Recent detections</CardTitle>
            <Button variant="ghost" size="sm" onClick={() => navigate('/threats')}>View all <ArrowRight size={14} /></Button>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>Severity</TableHead>
                  <TableHead>Detection</TableHead>
                  <TableHead className="text-right">Time</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(alerts?.items ?? []).slice(0, 6).map((a) => (
                  <TableRow key={a.id} className="cursor-pointer" onClick={() => navigate(`/alerts/${a.id}`)}>
                    <TableCell><Badge variant={sevVariant(a.severity)}>{a.severity}</Badge></TableCell>
                    <TableCell className="max-w-[240px] truncate font-medium">{a.detection_type}</TableCell>
                    <TableCell className="text-right text-xs text-muted-foreground">{relativeTime(parseTimestamp(a.timestamp))}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>

      {report?.sections?.length ? (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">{report.title}</CardTitle>
            <CardDescription className="text-xs">Generated {new Date(report.generated_at).toLocaleString()}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {report.sections.map((s) => (
              <div key={s.heading}>
                <p className="text-sm font-medium">{s.heading}</p>
                <p className="mt-1 text-sm text-muted-foreground">{s.body}</p>
              </div>
            ))}
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}
