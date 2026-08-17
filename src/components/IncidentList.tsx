import { useState } from 'react';
import type { Incident } from '@/types';
import { RefreshCw } from 'lucide-react';

interface IncidentListProps {
  incidents: Incident[];
  onSelect: (incidentId: string) => void;
  onRefresh: () => void;
  compact?: boolean;
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
}

export function IncidentList({ incidents, onSelect, onRefresh, compact }: IncidentListProps) {
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [search, setSearch] = useState('');

  const filtered = incidents.filter((inc) => {
    if (severityFilter && inc.severity !== severityFilter) return false;
    if (statusFilter && inc.status !== statusFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        inc.incident_id.toLowerCase().includes(q) ||
        inc.detection_type.toLowerCase().includes(q) ||
        (inc.source_ip ?? '').includes(q) ||
        (inc.username ?? '').toLowerCase().includes(q)
      );
    }
    return true;
  });

  if (incidents.length === 0) {
    return (
      <div style={{ padding: '40px 20px', textAlign: 'center', color: '#64748b' }}>
        No incidents detected. Security monitoring is active.
      </div>
    );
  }

  return (
    <div>
      {!compact && (
        <>
          <div className="filter-bar">
            <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
              <option value="">All Severities</option>
              <option value="LOW">Low</option>
              <option value="MEDIUM">Medium</option>
              <option value="HIGH">High</option>
              <option value="CRITICAL">Critical</option>
            </select>
            <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
              <option value="">All Statuses</option>
              <option value="NEW">New</option>
              <option value="INVESTIGATING">Investigating</option>
              <option value="RESOLVED">Resolved</option>
              <option value="FALSE_POSITIVE">False Positive</option>
            </select>
            <input
              type="text"
              placeholder="Search incidents..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            <button className="btn btn-ghost btn-sm" onClick={onRefresh}>
              <RefreshCw size={14} /> Refresh
            </button>
          </div>
        </>
      )}
      <table className="incident-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Type</th>
            <th>Severity</th>
            <th>Source IP</th>
            <th>User</th>
            {!compact && <th>Events</th>}
            <th>Status</th>
            <th>Time</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((inc) => (
            <tr key={inc.incident_id} onClick={() => onSelect(inc.incident_id)}>
              <td className="incident-id">{inc.incident_id}</td>
              <td>{inc.detection_type.replace(/_/g, ' ')}</td>
              <td><span className={`badge badge-${inc.severity}`}>{inc.severity}</span></td>
              <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{inc.source_ip || '—'}</td>
              <td>{inc.username || '—'}</td>
              {!compact && <td>{inc.event_count}</td>}
              <td><span className={`badge badge-${inc.status}`}>{inc.status.replace(/_/g, ' ')}</span></td>
              <td style={{ color: '#64748b', fontSize: 12 }}>{formatTime(inc.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {filtered.length === 0 && (
        <div style={{ padding: '20px', textAlign: 'center', color: '#64748b', fontSize: 14 }}>
          No incidents match the current filters.
        </div>
      )}
    </div>
  );
}
