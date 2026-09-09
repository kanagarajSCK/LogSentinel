import { createClient } from '@supabase/supabase-js';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL as string;
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY as string;
const isSupabaseConfigured = Boolean(supabaseUrl && supabaseAnonKey);

// Keep the app renderable when local environment variables have not been set.
export const supabase = createClient(
  supabaseUrl || 'http://localhost:54321',
  supabaseAnonKey || 'missing-anon-key',
  {
  realtime: {
    params: { eventsPerSecond: 10 },
  },
  }
);

export const edgeFunctionUrl = `${supabaseUrl}/functions/v1`;

export async function callEdgeFunction<T = unknown>(
  slug: string,
  body: Record<string, unknown>,
  options?: { path?: string }
): Promise<T> {
  if (!isSupabaseConfigured) {
    throw new Error('Supabase is not configured. Add VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY to .env.local.');
  }

  const url = options?.path ? `${edgeFunctionUrl}/${slug}${options.path}` : `${edgeFunctionUrl}/${slug}`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = typeof data.error === 'string' ? data.error : `Request failed (${response.status})`;
    const err = new Error(message) as Error & { status?: number; blocked?: boolean };
    err.status = response.status;
    err.blocked = data.blocked === true;
    throw err;
  }
  return data as T;
}
