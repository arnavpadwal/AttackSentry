import { useNavigate } from 'react-router-dom';
import Card from '@/components/shared/Card';
import Badge from '@/components/shared/Badge';
import NetworkGraph from '@/components/network/NetworkGraph';
import { useNetworkGraph } from '@/queries/network';
import { relativeTime } from '@/lib/utils';

export default function NetworkMapPage() {
  const navigate = useNavigate();
  const { data } = useNetworkGraph();

  const internal = data?.nodes.filter((n) => !n.external) ?? [];
  const topRisky = [...internal].sort((a, b) => b.risk - a.risk).slice(0, 8);

  return (
    <div className="animate-fade-in space-y-6">
      <div>
        <h1 className="page-title">Network Threat Visualizer</h1>
        <p className="page-subtitle">Entity graph — size and color encode risk; edges show live traffic</p>
      </div>

      <Card noPadding>
        {data && data.nodes.length ? (
          <div className="p-4">
            <NetworkGraph
              data={data}
              onNodeClick={(n) => { if (!n.external && n.node_type !== 'group') navigate(`/hosts/${n.id}`); }}
            />
          </div>
        ) : (
          <p className="py-16 text-center text-sm text-ink-faint">No network activity yet — waiting for sensor traffic</p>
        )}
      </Card>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card title="Highest risk entities" noPadding>
          {topRisky.length ? (
            <ul className="divide-y divide-border">
              {topRisky.map((n) => (
                <li key={n.id} className="flex cursor-pointer items-center justify-between px-5 py-2.5 hover:bg-surface-subtle"
                  onClick={() => navigate(`/hosts/${n.id}`)}>
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium text-ink">{n.hostname}</p>
                    <p className="text-xs text-ink-faint">{n.ip} · {n.group}</p>
                  </div>
                  <Badge variant={n.risk >= 75 ? 'critical' : n.risk >= 40 ? 'high' : 'low'}>{n.risk.toFixed(0)}</Badge>
                </li>
              ))}
            </ul>
          ) : (
            <p className="p-6 text-center text-sm text-ink-faint">No entities yet</p>
          )}
        </Card>

        <Card title="Traffic relationships" noPadding>
          {data?.edges.length ? (
            <table className="dense-table w-full">
              <thead>
                <tr className="border-b border-border">
                  <th className="px-5 py-2 text-left">Source</th>
                  <th className="px-5 py-2 text-left">Destination</th>
                  <th className="px-5 py-2 text-right">Flows</th>
                  <th className="px-5 py-2 text-right">Bytes</th>
                </tr>
              </thead>
              <tbody>
                {[...data.edges].sort((a, b) => b.bytes - a.bytes).slice(0, 12).map((e) => (
                  <tr key={e.id} className="border-b border-border last:border-0">
                    <td className="px-5 py-1.5 text-ink">{e.src}</td>
                    <td className="px-5 py-1.5 text-ink-2">{e.dst}</td>
                    <td className="px-5 py-1.5 text-right text-ink">{e.flows}</td>
                    <td className="px-5 py-1.5 text-right text-ink-faint">{formatBytes(e.bytes)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="p-6 text-center text-sm text-ink-faint">No relationships yet</p>
          )}
        </Card>
      </div>
    </div>
  );
}

function formatBytes(b: number) {
  if (b < 1024) return `${b} B`;
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1073741824) return `${(b / 1048576).toFixed(1)} MB`;
  return `${(b / 1073741824).toFixed(2)} GB`;
}
