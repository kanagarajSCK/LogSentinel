import type { SecurityEvent } from '@/types';

interface EventFeedProps {
  events: SecurityEvent[];
}

function formatTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleTimeString('en-US', { hour12: false });
}

export function EventFeed({ events }: EventFeedProps) {
  if (events.length === 0) {
    return <div className="feed-empty">No security events recorded yet.</div>;
  }

  return (
    <div className="event-feed">
      {events.map((event) => (
        <div className="event-row" key={event.event_id}>
          <span className="event-time">{formatTime(event.created_at)}</span>
          <span className={`event-type ${event.event_type}`}>{event.event_type}</span>
          <span className="event-username">{event.username || '—'}</span>
          <span className="event-ip">{event.source_ip || '—'}</span>
          <span className="event-detail">{event.detail}</span>
        </div>
      ))}
    </div>
  );
}
