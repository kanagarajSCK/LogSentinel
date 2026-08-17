import { useMemo } from 'react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';
import type { SecurityEvent } from '@/types';

interface EventsChartProps {
  events: SecurityEvent[];
}

interface Bucket {
  time: string;
  label: string;
  failed: number;
  success: number;
  blocked: number;
}

function formatBucketLabel(d: Date, spanSec: number): string {
  if (spanSec <= 600) {
    return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  }
  if (spanSec <= 7200) {
    return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
  }
  return d.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false });
}

export function EventsChart({ events }: EventsChartProps) {
  const data = useMemo<Bucket[]>(() => {
    if (events.length === 0) return [];

    const now = Date.now();
    const timestamps = events.map((e) => new Date(e.created_at).getTime());
    const newest = Math.max(...timestamps, now);
    const oldest = Math.min(...timestamps, newest - 60_000);
    const spanSec = Math.max((newest - oldest) / 1000, 60);
    const bucketCount = 12;
    const bucketSec = spanSec / bucketCount;

    const buckets: Bucket[] = [];
    for (let i = 0; i < bucketCount; i++) {
      const bucketStart = oldest + i * bucketSec * 1000;
      const d = new Date(bucketStart);
      buckets.push({
        time: d.toISOString(),
        label: formatBucketLabel(d, spanSec),
        failed: 0,
        success: 0,
        blocked: 0,
      });
    }

    for (const event of events) {
      const ts = new Date(event.created_at).getTime();
      let idx = Math.floor((ts - oldest) / (bucketSec * 1000));
      if (idx < 0) idx = 0;
      if (idx >= bucketCount) idx = bucketCount - 1;
      if (event.login_status === 'FAILED') buckets[idx].failed++;
      else if (event.login_status === 'SUCCESS') buckets[idx].success++;
      else if (event.login_status === 'BLOCKED') buckets[idx].blocked++;
    }

    return buckets;
  }, [events]);

  if (data.length === 0) {
    return (
      <div style={{ height: 240, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#64748b', fontSize: 14 }}>
        No event data to display yet.
      </div>
    );
  }

  return (
    <div className="chart-container">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 8, right: 16, left: -8, bottom: 0 }}>
          <defs>
            <linearGradient id="gradFailed" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#ef4444" stopOpacity={0.35} />
              <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="gradSuccess" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#22c55e" stopOpacity={0.35} />
              <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="gradBlocked" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#dc2626" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#dc2626" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
          <XAxis dataKey="label" stroke="#64748b" fontSize={10} tickLine={false} interval="preserveStartEnd" minTickGap={20} />
          <YAxis stroke="#64748b" fontSize={11} tickLine={false} allowDecimals={false} />
          <Tooltip
            contentStyle={{
              background: '#1a2332',
              border: '1px solid #334155',
              borderRadius: '6px',
              fontSize: '12px',
            }}
            labelStyle={{ color: '#94a3b8' }}
          />
          <Legend wrapperStyle={{ fontSize: '12px' }} />
          <Area type="monotone" dataKey="failed" name="Failed" stroke="#ef4444" fill="url(#gradFailed)" strokeWidth={2} />
          <Area type="monotone" dataKey="success" name="Success" stroke="#22c55e" fill="url(#gradSuccess)" strokeWidth={2} />
          <Area type="monotone" dataKey="blocked" name="Blocked" stroke="#dc2626" fill="url(#gradBlocked)" strokeWidth={2} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
