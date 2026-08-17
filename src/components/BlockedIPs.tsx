import type { BlockedIP } from '@/types';
import { Ban, Unlock } from 'lucide-react';

interface BlockedIPsProps {
  blockedIPs: BlockedIP[];
  onUnblock: (ip: string) => void;
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

export function BlockedIPs({ blockedIPs, onUnblock }: BlockedIPsProps) {
  const active = blockedIPs.filter((b) => b.is_active);
  const inactive = blockedIPs.filter((b) => !b.is_active);

  return (
    <div>
      <div className="alert alert-warning">
        These IP addresses have been blocked at the application level. Login attempts from blocked IPs
        are denied immediately. Blocks expire automatically after 1 hour or can be manually removed.
      </div>

      <div className="panel">
        <div className="panel-header">
          <h3 style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Ban size={16} color="#ef4444" /> Active Blocks ({active.length})
          </h3>
        </div>
        <div className="panel-body">
          {active.length === 0 ? (
            <div className="feed-empty">No active IP blocks.</div>
          ) : (
            <div className="blocked-list">
              {active.map((block) => (
                <div className="blocked-row" key={block.id}>
                  <div>
                    <div className="ip">{block.ip}</div>
                    <div className="reason">{block.reason}</div>
                    <div className="blocked-time">
                      Blocked {formatTime(block.blocked_at)}
                      {block.expires_at && ` · Expires ${formatTime(block.expires_at)}`}
                      {block.blocked_by && ` · by ${block.blocked_by}`}
                    </div>
                  </div>
                  <button className="btn btn-ghost btn-sm" onClick={() => onUnblock(block.ip)}>
                    <Unlock size={14} /> Unblock
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {inactive.length > 0 && (
        <div className="panel">
          <div className="panel-header">
            <h3>Expired / Removed Blocks ({inactive.length})</h3>
          </div>
          <div className="panel-body">
            <div className="blocked-list">
              {inactive.slice(0, 10).map((block) => (
                <div className="blocked-row" key={block.id} style={{ opacity: 0.6 }}>
                  <div>
                    <div className="ip">{block.ip}</div>
                    <div className="reason">{block.reason}</div>
                    <div className="blocked-time">Blocked {formatTime(block.blocked_at)}</div>
                  </div>
                  <span className="badge badge-RESOLVED">Inactive</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
