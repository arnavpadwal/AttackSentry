import { useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ArrowUpRight, Network, RefreshCw, X } from 'lucide-react';
import PageHeader from '@/components/shared/PageHeader';
import Card from '@/components/shared/Card';
import EmptyState from '@/components/shared/EmptyState';
import Button from '@/components/shared/Button';
import NetworkGraph, { isThreatEdge, riskTier } from '@/components/network/NetworkGraph';
import { useNetworkGraph } from '@/queries/network';
import { useHost } from '@/queries/hosts';
import { formatBytes, parseTimestamp, relativeTime } from '@/lib/utils';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';

type RiskFilter = 'all' | 'elevated' | 'critical';

const riskColor = (risk: number) => {
  const tier = riskTier(risk);
  if (tier === 'critical') return 'hsl(var(--severity-critical))';
  if (tier === 'elevated') return 'hsl(var(--severity-high))';
  return 'hsl(var(--muted-foreground))';
};

const roleLabel = (nodeType?: string, external?: boolean) =>
  nodeType === 'group' ? 'Segment' : external ? 'External' : 'Host';

/** Selected host facts that only the host detail endpoint knows. */
function HostFacts({ hostId }: { hostId: string }) {
  const { data } = useHost(hostId);
  return (
    <>
      <dt className="text-muted-foreground">Detections 24h</dt>
      <dd className="mono">{data ? data.alert_count : '—'}</dd>
      <dt className="text-muted-foreground">Last seen</dt>
      <dd>{data?.last_seen ? relativeTime(parseTimestamp(data.last_seen)) : '—'}</dd>
    </>
  );
}

export default function NetworkMapPage() {
  const navigate = useNavigate();
  const { data, isLoading, isError, isFetching, refetch } = useNetworkGraph();
  const [riskFilter, setRiskFilter] = useState<RiskFilter>('all');
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const nodes = data?.nodes ?? [];
  const edges = data?.edges ?? [];
  const hostNodes = nodes.filter((n) => n.node_type === 'host' && !n.external);
  const activeLinks = edges.filter((e) => e.relation !== 'contains').length;
  const threatEdges = edges.filter(isThreatEdge).length;
  const selectedNode = nodes.find((n) => n.id === selectedId) ?? null;
  const topRisky = [...hostNodes].sort((a, b) => b.risk - a.risk).slice(0, 8);
  const topLinks = [...edges]
    .filter((e) => e.relation !== 'contains')
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, 8);

  const visibleIps = useMemo(() => {
    if (!data || riskFilter === 'all') return undefined;
    const floor = riskFilter === 'critical' ? 75 : 40;
    return new Set(
      data.nodes.filter((n) => n.external || n.risk >= floor).map((n) => n.ip)
    );
  }, [data, riskFilter]);

  return (
    <div className="space-y-4">
      <PageHeader
        title="Network"
        description="Entity graph and live flow relationships from the last 24 hours."
        meta={
          data ? (
            <p className="text-[11px] text-muted-foreground">
              <span className="mono text-foreground">{hostNodes.length}</span> entities
              <span className="mx-2">·</span>
              <span className="mono text-foreground">{activeLinks}</span> links
              <span className="mx-2">·</span>
              <span className="mono text-foreground">{threatEdges}</span> threat edges
            </p>
          ) : null
        }
      />

      <Card noPadding>
        <div className="flex flex-wrap items-center justify-between gap-3 border-b px-4 py-2">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
            <span className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full border border-border bg-secondary" />
              Normal
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full border-2 border-severity-high" />
              Elevated
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full border-2 border-severity-critical" />
              Critical
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-px w-4 bg-severity-high opacity-55" />
              Threat edge
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full border border-dashed border-border bg-secondary" />
              Segment
            </span>
          </div>
          <div className="flex items-center gap-2">
            <Select
              value={riskFilter}
              onValueChange={(value) => {
                setRiskFilter(value as RiskFilter);
                setSelectedId(null);
              }}
            >
              <SelectTrigger className="h-7 w-[136px] text-[11.5px]" aria-label="Filter by risk">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All risk levels</SelectItem>
                <SelectItem value="elevated">Elevated and above</SelectItem>
                <SelectItem value="critical">Critical only</SelectItem>
              </SelectContent>
            </Select>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => refetch()}
              loading={isFetching}
              className="[&_svg]:size-3.5"
            >
              <RefreshCw />
              Refresh
            </Button>
          </div>
        </div>

        {isLoading ? (
          <div className="p-4">
            <Skeleton className="h-[420px] w-full lg:h-[600px]" />
          </div>
        ) : isError && !data ? (
          <EmptyState
            icon={Network}
            title="Network graph unavailable"
            description="The graph endpoint did not respond. Check the sensor and API, then retry."
            action={
              <Button variant="secondary" size="sm" onClick={() => refetch()}>
                Retry
              </Button>
            }
          />
        ) : !nodes.length ? (
          <EmptyState
            icon={Network}
            title="No network activity yet"
            description="Entities appear here after the sensor reports host and flow data."
          />
        ) : (
          <div className="flex flex-col lg:flex-row">
            <div className="min-w-0 flex-1 p-3 lg:p-4">
              {activeLinks === 0 && (
                <p className="mb-3 text-[11.5px] text-muted-foreground">
                  No flow relationships in this window — showing entity placement by group.
                </p>
              )}
              <NetworkGraph
                data={data!}
                selectedId={selectedId}
                visibleIps={visibleIps}
                onNodeClick={(node) => setSelectedId(node.id)}
              />
            </div>
            {selectedNode && (!visibleIps || visibleIps.has(selectedNode.ip)) && (
              <aside className="w-full border-t p-4 lg:w-[300px] lg:shrink-0 lg:border-l lg:border-t-0">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <p className="truncate text-[13px] font-medium text-foreground">
                      {selectedNode.hostname}
                    </p>
                    <p className="mono mt-1 truncate text-[11.5px] text-muted-foreground">
                      {selectedNode.ip}
                    </p>
                  </div>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-6 w-6 [&_svg]:size-3.5"
                    onClick={() => setSelectedId(null)}
                    aria-label="Close entity panel"
                  >
                    <X />
                  </Button>
                </div>

                <dl className="mt-3 grid grid-cols-[88px_1fr] gap-x-3 gap-y-2 text-[12px]">
                  <dt className="text-muted-foreground">Role</dt>
                  <dd>{roleLabel(selectedNode.node_type, selectedNode.external)}</dd>
                  <dt className="text-muted-foreground">Segment</dt>
                  <dd className="truncate">{selectedNode.group}</dd>
                  <dt className="text-muted-foreground">Status</dt>
                  <dd className="capitalize">{selectedNode.status}</dd>
                  {selectedNode.vlan && (
                    <>
                      <dt className="text-muted-foreground">VLAN</dt>
                      <dd className="mono">{selectedNode.vlan}</dd>
                    </>
                  )}
                  {selectedNode.node_type === 'host' && !selectedNode.external && (
                    <HostFacts hostId={selectedNode.id} />
                  )}
                </dl>

                <div className="mt-4">
                  <div className="flex items-baseline justify-between">
                    <span className="label">Risk</span>
                    <span
                      className="mono text-[13px]"
                      style={{ color: riskColor(selectedNode.risk) }}
                    >
                      {selectedNode.risk.toFixed(0)}
                    </span>
                  </div>
                  <div className="mt-2 h-1 w-full overflow-hidden rounded-full bg-muted">
                    <div
                      className="h-full rounded-full"
                      style={{
                        width: `${Math.min(100, Math.max(0, selectedNode.risk))}%`,
                        background: riskColor(selectedNode.risk),
                      }}
                    />
                  </div>
                </div>

                {selectedNode.node_type === 'host' && !selectedNode.external && (
                  <Link
                    to={`/hosts/${selectedNode.id}`}
                    className="mt-4 inline-flex h-7 w-full items-center justify-center gap-1.5 rounded-md border border-input text-[12px] font-medium text-foreground transition-colors hover:bg-accent hover:text-accent-foreground"
                  >
                    Open asset
                    <ArrowUpRight size={14} strokeWidth={1.5} />
                  </Link>
                )}
              </aside>
            )}
          </div>
        )}
      </Card>

      {(topRisky.length > 0 || topLinks.length > 0) && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {topRisky.length > 0 && (
            <Card title="Highest-risk entities" subtitle="Internal hosts by risk score" noPadding>
              <table className="dense-table w-full">
                <thead>
                  <tr className="border-b border-border">
                    <th className="text-left text-[11px] font-medium text-muted-foreground">Entity</th>
                    <th className="text-left text-[11px] font-medium text-muted-foreground">Address</th>
                    <th className="text-left text-[11px] font-medium text-muted-foreground">Segment</th>
                    <th className="text-right text-[11px] font-medium text-muted-foreground">Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {topRisky.map((n) => (
                    <tr
                      key={n.id}
                      className="row-hover cursor-pointer border-b border-border last:border-0"
                      tabIndex={0}
                      onClick={() => navigate(`/hosts/${n.id}`)}
                      onKeyDown={(event) => {
                        if (event.key === 'Enter') navigate(`/hosts/${n.id}`);
                      }}
                    >
                      <td className="max-w-[180px] truncate text-foreground">{n.hostname}</td>
                      <td className="mono text-muted-foreground">{n.ip}</td>
                      <td className="text-muted-foreground">{n.group}</td>
                      <td className="text-right">
                        <span className="mono" style={{ color: riskColor(n.risk) }}>
                          {n.risk.toFixed(0)}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>
          )}

          {topLinks.length > 0 && (
            <Card title="Busiest links" subtitle="Relationships by bytes, last 24 hours" noPadding>
              <table className="dense-table w-full">
                <thead>
                  <tr className="border-b border-border">
                    <th className="text-left text-[11px] font-medium text-muted-foreground">Source</th>
                    <th className="text-left text-[11px] font-medium text-muted-foreground">Destination</th>
                    <th className="text-right text-[11px] font-medium text-muted-foreground">Flows</th>
                    <th className="text-right text-[11px] font-medium text-muted-foreground">Bytes</th>
                  </tr>
                </thead>
                <tbody>
                  {topLinks.map((e) => (
                    <tr key={e.id} className="border-b border-border last:border-0">
                      <td className="mono text-foreground">{e.src}</td>
                      <td className="mono text-muted-foreground">{e.dst}</td>
                      <td className="text-right tabular-nums">{e.flows}</td>
                      <td className="text-right tabular-nums text-muted-foreground">
                        {formatBytes(e.bytes)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}
