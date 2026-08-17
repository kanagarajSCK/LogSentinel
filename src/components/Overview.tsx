import { useMemo } from 'react';
import type { SecurityEvent, Incident, DashboardStats } from '@/types';
import { EventFeed } from '@/components/EventFeed';
import { IncidentList } from '@/components/IncidentList';
import { EventsChart } from '@/components/EventsChart';
import { ShieldCheck, XCircle, CheckCircle, AlertTriangle, Zap, Clock } from 'lucide-react';

interface OverviewProps {
  events: SecurityEvent[];
  incidents: Incident[];
  stats: DashboardStats;
  onSelectIncident: (id: string) => void;
}

export function Overview({ events, incidents, stats, onSelectIncident }: OverviewProps) {
  const recentIncidents = useMemo(
    () => incidents.slice(0, 5),
    [incidents]
  );

  const cards = [
    { label: 'Total Events', value: stats.totalEvents, icon: ShieldCheck, color: 'blue' as const },
    { label: 'Failed Logins', value: stats.failedLogins, icon: XCircle, color: 'red' as const },
    { label: 'Successful Logins', value: stats.successfulLogins, icon: CheckCircle, color: 'green' as const },
    { label: 'Active Incidents', value: stats.activeIncidents, icon: AlertTriangle, color: 'orange' as const },
    { label: 'High-Risk Incidents', value: stats.highRiskIncidents, icon: Zap, color: 'critical' as const },
  ];

  return (
    <div>
      <div className="stats-grid">
        {cards.map((card) => {
          const Icon = card.icon;
          return (
            <div className="stat-card" key={card.label}>
              <div className={`stat-icon ${card.color}`}>
                <Icon size={20} />
              </div>
              <div className="stat-label">{card.label}</div>
              <div className="stat-value">{card.value}</div>
            </div>
          );
        })}
      </div>

      <div className="panel">
        <div className="panel-header">
          <h3>Events Over Time</h3>
        </div>
        <div className="panel-body">
          <EventsChart events={events} />
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <h3>Live Event Feed</h3>
          <Clock size={16} color="#64748b" />
        </div>
        <div className="panel-body" style={{ padding: 0 }}>
          <EventFeed events={events.slice(0, 30)} />
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <h3>Recent Incidents</h3>
        </div>
        <div className="panel-body" style={{ padding: 0 }}>
          <IncidentList
            incidents={recentIncidents}
            onSelect={onSelectIncident}
            onRefresh={() => {}}
            compact
          />
        </div>
      </div>
    </div>
  );
}
