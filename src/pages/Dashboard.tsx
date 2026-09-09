import { useState, useEffect, useCallback } from 'react';
import { useAuth } from '@/lib/auth';
import { supabase } from '@/lib/supabase';
import { callEdgeFunction } from '@/lib/supabase';
import type { SecurityEvent, Incident, BlockedIP, DashboardStats } from '@/types';
import { Shield, LayoutDashboard, AlertTriangle, Ban, FlaskConical, LogOut, Activity, Trash2, Loader2, Menu, X } from 'lucide-react';
import { Overview } from '@/components/Overview';
import { IncidentList } from '@/components/IncidentList';
import { IncidentDetail } from '@/components/IncidentDetail';
import { DemoPanel } from '@/components/DemoPanel';
import { BlockedIPs } from '@/components/BlockedIPs';

type View = 'overview' | 'incidents' | 'demo' | 'blocked';

export function Dashboard() {
  const { user, logout } = useAuth();
  const [view, setView] = useState<View>('overview');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [blockedIPs, setBlockedIPs] = useState<BlockedIP[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [stats, setStats] = useState<DashboardStats>({
    totalEvents: 0,
    failedLogins: 0,
    successfulLogins: 0,
    activeIncidents: 0,
    highRiskIncidents: 0,
  });
  const [showClearConfirm, setShowClearConfirm] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [dataError, setDataError] = useState<string | null>(null);

  const fetchEvents = useCallback(async () => {
    const { data, error } = await supabase
      .from('security_events')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(100);
    if (error) {
      setDataError(error.message);
      return;
    }
    if (data) setEvents(data as SecurityEvent[]);
  }, []);

  const fetchIncidents = useCallback(async () => {
    const { data, error } = await supabase
      .from('incidents')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(50);
    if (error) {
      setDataError(error.message);
      return;
    }
    if (data) setIncidents(data as Incident[]);
  }, []);

  const fetchBlockedIPs = useCallback(async () => {
    try {
      const result = await callEdgeFunction<{ blocked_ips: BlockedIP[] }>('incident-management', {}, { path: '/blocked-ips' });
      setBlockedIPs(result.blocked_ips ?? []);
    } catch (error) {
      setDataError(error instanceof Error ? error.message : 'Unable to load blocked IPs');
    }
  }, []);

  const fetchStats = useCallback(async () => {
    const { count: total, error: totalError } = await supabase.from('security_events').select('*', { count: 'exact', head: true });
    const { count: failed, error: failedError } = await supabase.from('security_events').select('*', { count: 'exact', head: true }).eq('login_status', 'FAILED');
    const { count: success, error: successError } = await supabase.from('security_events').select('*', { count: 'exact', head: true }).eq('login_status', 'SUCCESS');
    const { count: active, error: activeError } = await supabase.from('incidents').select('*', { count: 'exact', head: true }).neq('status', 'RESOLVED').neq('status', 'FALSE_POSITIVE');
    const { count: highRisk, error: highRiskError } = await supabase.from('incidents').select('*', { count: 'exact', head: true }).in('severity', ['HIGH', 'CRITICAL']).neq('status', 'RESOLVED').neq('status', 'FALSE_POSITIVE');
    const error = totalError || failedError || successError || activeError || highRiskError;
    if (error) {
      setDataError(error.message);
      return;
    }
    setStats({
      totalEvents: total ?? 0,
      failedLogins: failed ?? 0,
      successfulLogins: success ?? 0,
      activeIncidents: active ?? 0,
      highRiskIncidents: highRisk ?? 0,
    });
  }, []);

  const refreshAll = useCallback(() => {
    fetchEvents();
    fetchIncidents();
    fetchBlockedIPs();
    fetchStats();
  }, [fetchEvents, fetchIncidents, fetchBlockedIPs, fetchStats]);

  useEffect(() => {
    refreshAll();

    const eventChannel = supabase
      .channel('security-events-feed')
      .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'security_events' }, () => {
        fetchEvents();
        fetchStats();
      })
      .on('postgres_changes', { event: 'UPDATE', schema: 'public', table: 'security_events' }, () => {
        fetchEvents();
      })
      .subscribe();

    const incidentChannel = supabase
      .channel('incidents-feed')
      .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'incidents' }, () => {
        fetchIncidents();
        fetchStats();
      })
      .on('postgres_changes', { event: 'UPDATE', schema: 'public', table: 'incidents' }, () => {
        fetchIncidents();
        fetchStats();
      })
      .subscribe();

    const blockedChannel = supabase
      .channel('blocked-ips-feed')
      .on('postgres_changes', { event: '*', schema: 'public', table: 'blocked_ips' }, () => {
        fetchBlockedIPs();
      })
      .subscribe();

    return () => {
      supabase.removeChannel(eventChannel);
      supabase.removeChannel(incidentChannel);
      supabase.removeChannel(blockedChannel);
    };
  }, [refreshAll, fetchEvents, fetchIncidents, fetchBlockedIPs, fetchStats]);

  function handleSelectIncident(incidentId: string) {
    setSelectedIncidentId(incidentId);
  }

  function handleBackToList() {
    setSelectedIncidentId(null);
    fetchIncidents();
    fetchStats();
  }

  async function handleRunDemo(scenario: string) {
    try {
      await callEdgeFunction('demo-events', { scenario });
      refreshAll();
    } catch (err) {
      console.error('Demo generation failed:', err);
    }
  }

  async function handleUnblockIP(ip: string) {
    try {
      await callEdgeFunction('incident-management', { ip }, { path: '/unblock' });
      fetchBlockedIPs();
    } catch (err) {
      console.error('Unblock failed:', err);
    }
  }

  async function handleClearHistory() {
    setClearing(true);
    try {
      await callEdgeFunction('incident-management', {}, { path: '/clear-history' });
      setEvents([]);
      setIncidents([]);
      setBlockedIPs([]);
      setStats({ totalEvents: 0, failedLogins: 0, successfulLogins: 0, activeIncidents: 0, highRiskIncidents: 0 });
      setSelectedIncidentId(null);
      setShowClearConfirm(false);
    } catch (err) {
      console.error('Clear history failed:', err);
    } finally {
      setClearing(false);
    }
  }

  const navItems: { key: View; label: string; icon: typeof Shield }[] = [
    { key: 'overview', label: 'Overview', icon: LayoutDashboard },
    { key: 'incidents', label: 'Incidents', icon: AlertTriangle },
    { key: 'demo', label: 'Demo Mode', icon: FlaskConical },
    { key: 'blocked', label: 'Blocked IPs', icon: Ban },
  ];

  return (
    <div className="dashboard">
      <aside className={`sidebar ${mobileMenuOpen ? 'mobile-open' : ''}`}>
        <div className="sidebar-header">
          <Shield color="#38bdf8" size={24} />
          <span>LogSentinel</span>
          <button className="mobile-close-btn" onClick={() => setMobileMenuOpen(false)}>
            <X size={20} />
          </button>
        </div>
        <nav className="nav">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.key}
                className={`nav-item ${view === item.key ? 'active' : ''}`}
                onClick={() => { setView(item.key); setSelectedIncidentId(null); setMobileMenuOpen(false); }}
              >
                <Icon size={18} />
                {item.label}
              </button>
            );
          })}
        </nav>
        <div className="sidebar-footer">
          <div className="user-info">
            <div className="name">{user?.display_name || user?.username}</div>
            <div className="role">{user?.role}</div>
          </div>
          <button className="logout-btn" onClick={logout}>
            <LogOut size={14} style={{ verticalAlign: 'middle', marginRight: 4 }} />
            Sign Out
          </button>
        </div>
      </aside>

      {mobileMenuOpen && <div className="mobile-overlay" onClick={() => setMobileMenuOpen(false)}></div>}

      <div className="main">
        <div className="main-header">
          <button className="mobile-menu-btn" onClick={() => setMobileMenuOpen(true)}>
            <Menu size={20} />
          </button>
          <h2>
            {view === 'overview' && 'Security Operations Dashboard'}
            {view === 'incidents' && (selectedIncidentId ? 'Incident Details' : 'Active Incidents')}
            {view === 'demo' && 'Demo Mode — Test Event Generator'}
            {view === 'blocked' && 'Blocked IP Addresses'}
          </h2>
          <div className="header-actions">
            <div className="live-indicator">
              <span className="live-dot"></span>
              <Activity size={14} />
              Live
            </div>
            <button
              className="btn btn-ghost btn-sm"
              onClick={() => setShowClearConfirm(true)}
              title="Clear all security events, incidents, and blocked IPs"
            >
              <Trash2 size={14} /> Clear History
            </button>
          </div>
        </div>

        {dataError && (
          <div className="alert alert-error dashboard-alert">
            Dashboard data could not be loaded: {dataError}. Check the Supabase anon key in .env and restart Vite.
          </div>
        )}

        {showClearConfirm && (
          <div className="modal-overlay" onClick={() => !clearing && setShowClearConfirm(false)}>
            <div className="modal" onClick={(e) => e.stopPropagation()}>
              <h3>Clear All History?</h3>
              <p>This will permanently delete all security events, incidents, blocked IPs, and action records. This cannot be undone.</p>
              <div className="modal-actions">
                <button className="btn btn-ghost" onClick={() => setShowClearConfirm(false)} disabled={clearing}>
                  Cancel
                </button>
                <button className="btn btn-danger" onClick={handleClearHistory} disabled={clearing}>
                  {clearing ? <Loader2 size={16} className="spin" /> : <Trash2 size={16} />}
                  {clearing ? 'Clearing...' : 'Clear Everything'}
                </button>
              </div>
            </div>
          </div>
        )}

        <div className="content">
          {view === 'overview' && (
            <Overview events={events} incidents={incidents} stats={stats} onSelectIncident={handleSelectIncident} />
          )}
          {view === 'incidents' && !selectedIncidentId && (
            <IncidentList incidents={incidents} onSelect={handleSelectIncident} onRefresh={fetchIncidents} />
          )}
          {view === 'incidents' && selectedIncidentId && (
            <IncidentDetail incidentId={selectedIncidentId} onBack={handleBackToList} />
          )}
          {view === 'demo' && <DemoPanel onRun={handleRunDemo} />}
          {view === 'blocked' && <BlockedIPs blockedIPs={blockedIPs} onUnblock={handleUnblockIP} />}
        </div>
      </div>
    </div>
  );
}
