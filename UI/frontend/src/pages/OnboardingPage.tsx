import { useNavigate } from 'react-router-dom';
import Card from '@/components/shared/Card';
import Button from '@/components/shared/Button';
import { api } from '@/lib/axios';

export default function OnboardingPage() {
  const navigate = useNavigate();

  const complete = async () => {
    try { await api.post('/api/setup/complete'); } catch { /* ignore */ }
    navigate('/');
  };

  return (
    <div className="flex flex-col items-center justify-center py-16">
      <div className="w-full max-w-lg space-y-6">
        <div className="text-center">
          <h1 className="page-title">Welcome to AttackSentry</h1>
          <p className="page-subtitle">Get your environment ready for autonomous detection</p>
        </div>

        {[
          { title: 'Authentication', body: 'Secure your admin account and configure RBAC roles.' },
          { title: 'Environment', body: 'Define network segments, subnets and IAM mappings.' },
          { title: 'Sensors', body: 'Deploy Rust sensors on SPAN/TAP ports and register them.' },
          { title: 'Baselining', body: 'The platform learns normal behaviour over a learning window.' },
          { title: 'Active detection', body: 'Anomalies are triaged by the MoE and AI analyst.' },
        ].map((step, i) => (
          <Card key={step.title}>
            <div className="flex items-center gap-4">
              <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-ink text-sm font-semibold text-ink-inverse">{i + 1}</span>
              <div>
                <p className="text-sm font-medium text-ink">{step.title}</p>
                <p className="text-sm text-ink-2">{step.body}</p>
              </div>
            </div>
          </Card>
        ))}

        <Button className="w-full" onClick={complete}>Complete setup</Button>
      </div>
    </div>
  );
}
