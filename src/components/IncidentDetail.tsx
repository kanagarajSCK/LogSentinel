import { useState, useEffect, useCallback } from 'react';
import { supabase, callEdgeFunction } from '@/lib/supabase';
import { useAuth } from '@/lib/auth';
import type { Incident, SecurityEvent, AgentAction } from '@/types';
import { ArrowLeft, CheckCircle2, XCircle, Loader2, Brain, Clock, FileWarning, Gavel } from 'lucide-react';

interface IncidentDetailProps {
  incidentId: string;
  onBack: () => void;
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

export function IncidentDetail({ incidentId, onBack }: IncidentDetailProps) {
  const { user } = useAuth();
  const [incident, setIncident] = useState<Incident | null>(null);
  const [relatedEvents, setRelatedEvents] = useState<SecurityEvent[]>([]);
  const [actions, setActions] = useState<AgentAction[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [statusUpdating, setStatusUpdating] = useState(false);
  const [aiAnalyzing, setAiAnalyzing] = useState(false);

  const fetchIncident = useCallback(async () => {
    const { data } = await supabase
      .from('incidents')
      .select('*')
      .eq('incident_id', incidentId)
      .maybeSingle();
    if (data) setIncident(data as Incident);
  }, [incidentId]);

  const fetchRelatedEvents = useCallback(async () => {
    if (!incident) return;
    const { data } = await supabase
      .from('security_events')
      .select('*')
      .or(`incident_id.eq.${incident.id},source_ip.eq.${incident.source_ip}`)
      .order('created_at', { ascending: true })
      .limit(50);
    if (data) setRelatedEvents(data as SecurityEvent[]);
  }, [incident]);

  const fetchActions = useCallback(async () => {
    if (!incident) return;
    const { data } = await supabase
      .from('agent_actions')
      .select('*')
      .eq('incident_id', incident.id)
      .order('created_at', { ascending: false });
    if (data) setActions(data as AgentAction[]);
  }, [incident]);

  useEffect(() => {
    setLoading(true);
    fetchIncident().then(() => setLoading(false));
  }, [fetchIncident]);

  useEffect(() => {
    if (incident) {
      fetchRelatedEvents();
      fetchActions();
    }
  }, [incident, fetchRelatedEvents, fetchActions]);

  // Subscribe to incident updates (AI analysis fills in async)
  useEffect(() => {
    if (!incident) return;
    const channel = supabase
      .channel(`incident-${incident.id}`)
      .on('postgres_changes', { event: 'UPDATE', schema: 'public', table: 'incidents', filter: `id=eq.${incident.id}` }, () => {
        fetchIncident();
      })
      .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'agent_actions', filter: `incident_id=eq.${incident.id}` }, () => {
        fetchActions();
      })
      .subscribe();
    return () => { supabase.removeChannel(channel); };
  }, [incident, fetchIncident, fetchActions]);

  async function handleAction(action: 'approve' | 'reject') {
    setActionLoading(true);
    try {
      await callEdgeFunction('incident-management', {
        incident_id: incidentId,
        action,
        approved_by: user?.username || 'analyst',
      }, { path: '/action' });
      await fetchIncident();
      await fetchActions();
    } catch (err) {
      console.error('Action failed:', err);
    } finally {
      setActionLoading(false);
    }
  }

  async function handleStatusChange(status: string) {
    setStatusUpdating(true);
    try {
      await callEdgeFunction('incident-management', {
        incident_id: incidentId,
        status,
        approved_by: user?.username,
      }, { path: '/status' });
      await fetchIncident();
    } catch (err) {
      console.error('Status update failed:', err);
    } finally {
      setStatusUpdating(false);
    }
  }

  async function handleReanalyze() {
    setAiAnalyzing(true);
    try {
      await callEdgeFunction('ai-analysis', { incident_id: incidentId });
      await fetchIncident();
    } catch (err) {
      console.error('Re-analysis failed:', err);
    } finally {
      setAiAnalyzing(false);
    }
  }

  if (loading) {
    return <div style={{ textAlign: 'center', padding: '60px', color: '#64748b' }}>Loading incident...</div>;
  }
  if (!incident) {
    return <div style={{ textAlign: 'center', padding: '60px', color: '#64748b' }}>Incident not found.</div>;
  }

  const ai = incident.ai_analysis;
  const isResolved = incident.status === 'RESOLVED' || incident.status === 'FALSE_POSITIVE';
  const hasApprovedAction = actions.some((a) => a.status === 'APPROVED');

  return (
    <div>
      <button className="detail-back" onClick={onBack}>
        <ArrowLeft size={16} /> Back to Incidents
      </button>

      <div className="detail-header">
        <div>
          <h2>{incident.detection_type.replace(/_/g, ' ')}</h2>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: '#64748b' }}>{incident.incident_id}</div>
        </div>
        <div className="badges">
          <span className={`badge badge-${incident.severity}`}>{incident.severity}</span>
          <span className={`badge badge-${incident.status}`}>{incident.status.replace(/_/g, ' ')}</span>
        </div>
      </div>

      <div className="detail-meta">
        <div className="meta-item">
          <div className="label">Source IP</div>
          <div className="value mono">{incident.source_ip || '—'}</div>
        </div>
        <div className="meta-item">
          <div className="label">Target User</div>
          <div className="value">{incident.username || '—'}</div>
        </div>
        <div className="meta-item">
          <div className="label">Event Count</div>
          <div className="value">{incident.event_count}</div>
        </div>
        <div className="meta-item">
          <div className="label">First Detected</div>
          <div className="value" style={{ fontSize: 13 }}>{formatTime(incident.first_detected_at)}</div>
        </div>
        <div className="meta-item">
          <div className="label">Last Detected</div>
          <div className="value" style={{ fontSize: 13 }}>{formatTime(incident.last_detected_at)}</div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <h3 style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <FileWarning size={16} color="#f59e0b" /> Detection Reason
          </h3>
        </div>
        <div className="panel-body">
          <div className="reason-box">{incident.detection_reason}</div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <h3 style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Brain size={16} color="#38bdf8" /> Investigation Analysis
          </h3>
          {!aiAnalyzing && (
            <button className="btn btn-ghost btn-sm" onClick={handleReanalyze}>
              Re-analyze
            </button>
          )}
        </div>
        <div className="panel-body">
          {aiAnalyzing && <div className="ai-loading"><span className="spinner" />Analyzing incident evidence...</div>}
          {!aiAnalyzing && !ai && (
            <div className="ai-loading">Analysis pending. The investigation engine will process this incident shortly.</div>
          )}
          {!aiAnalyzing && ai && (
            <div className="ai-box">
              <div className="ai-header">
                <span className="ai-title">{ai.summary}</span>
                <span className="ai-source">{ai.source === 'llm' ? 'AI Analysis' : 'Rule-Based Fallback'}</span>
              </div>
              <div className="ai-reasoning">{ai.reasoning}</div>
              {ai.evidence.length > 0 && (
                <ul className="ai-evidence">
                  {ai.evidence.map((ev, i) => <li key={i}>{ev}</li>)}
                </ul>
              )}
              <div className="ai-confidence">
                Confidence:
                <div className="confidence-bar">
                  <div className="confidence-fill" style={{ width: `${ai.confidence * 100}%` }} />
                </div>
                {Math.round(ai.confidence * 100)}%
                {ai.fallback_reason && <span style={{ marginLeft: 8, color: '#f59e0b' }}>({ai.fallback_reason})</span>}
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <h3 style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Gavel size={16} color="#22c55e" /> Recommended Response
          </h3>
        </div>
        <div className="panel-body">
          <div className="action-panel">
            <div className="action-label">Recommended Action</div>
            <div className="action-desc">{incident.recommended_action}</div>
            {!isResolved && !hasApprovedAction && (
              <div className="action-buttons">
                <button className="btn btn-success" onClick={() => handleAction('approve')} disabled={actionLoading}>
                  {actionLoading ? <Loader2 size={16} className="spin" /> : <CheckCircle2 size={16} />}
                  Approve Action
                </button>
                <button className="btn btn-danger" onClick={() => handleAction('reject')} disabled={actionLoading}>
                  <XCircle size={16} /> Reject
                </button>
              </div>
            )}
            {hasApprovedAction && (
              <div className="alert alert-info" style={{ margin: 0 }}>
                <CheckCircle2 size={16} style={{ verticalAlign: 'middle', marginRight: 6 }} />
                Response action has been approved and executed.
              </div>
            )}
            {isResolved && !hasApprovedAction && (
              <div className="alert alert-info" style={{ margin: 0 }}>
                This incident has been {incident.status.toLowerCase().replace(/_/g, ' ')}.
              </div>
            )}
          </div>

          {actions.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <div className="section-title">Action History</div>
              <div className="timeline">
                {actions.map((action) => (
                  <div className="timeline-item" key={action.action_id}>
                    <div className="tl-time">{formatTime(action.created_at)}</div>
                    <div className="tl-content">
                      <strong>{action.status}</strong> — {action.description}
                      {action.approved_by && ` (by ${action.approved_by})`}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <h3 style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Clock size={16} color="#94a3b8" /> Event Timeline
          </h3>
        </div>
        <div className="panel-body" style={{ padding: 0 }}>
          <div className="related-events">
            {relatedEvents.length === 0 ? (
              <div className="feed-empty">No related events found.</div>
            ) : (
              <div className="event-feed" style={{ maxHeight: 'none' }}>
                {relatedEvents.map((event) => (
                  <div className="event-row" key={event.event_id}>
                    <span className="event-time">{formatTime(event.created_at)}</span>
                    <span className={`event-type ${event.event_type}`}>{event.event_type}</span>
                    <span className="event-username">{event.username || '—'}</span>
                    <span className="event-ip">{event.source_ip || '—'}</span>
                    <span className="event-detail">{event.detail}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <h3>Incident Management</h3>
        </div>
        <div className="panel-body">
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            {incident.status !== 'INVESTIGATING' && incident.status !== 'RESOLVED' && incident.status !== 'FALSE_POSITIVE' && (
              <button className="btn btn-ghost btn-sm" onClick={() => handleStatusChange('INVESTIGATING')} disabled={statusUpdating}>
                Mark Investigating
              </button>
            )}
            {incident.status !== 'RESOLVED' && (
              <button className="btn btn-ghost btn-sm" onClick={() => handleStatusChange('RESOLVED')} disabled={statusUpdating}>
                Mark Resolved
              </button>
            )}
            {incident.status !== 'FALSE_POSITIVE' && (
              <button className="btn btn-ghost btn-sm" onClick={() => handleStatusChange('FALSE_POSITIVE')} disabled={statusUpdating}>
                Mark False Positive
              </button>
            )}
            {incident.status !== 'NEW' && (
              <button className="btn btn-ghost btn-sm" onClick={() => handleStatusChange('NEW')} disabled={statusUpdating}>
                Reset to New
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
