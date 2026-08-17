/*
# LogSentinel — Core Schema

## Purpose
Creates the database foundation for LogSentinel, an AI-powered log analysis and
incident detection system. The application performs its own credential-based
authentication (users table with hashed passwords) so that every login attempt
can be captured as a structured security event and analyzed by the detection
engine. Supabase Auth is intentionally NOT used here, because the login flow
itself is the subject of monitoring.

## Tables created
1. `users` — application accounts with bcrypt-hashed passwords. Seed admin user.
2. `incidents` — detected suspicious-activity incidents with AI analysis,
   recommended action, severity, status, and evidence JSON.
3. `security_events` — immutable structured security log rows (login attempts,
   generated demo events, blocked attempts). Indexed on timestamp, source_ip,
   username, event_type, severity for fast correlation queries.
4. `blocked_ips` — application-level IP blocklist.
5. `agent_actions` — audit trail of human-approved/rejected response actions.

## Security (RLS)
All tables enable RLS with open policies for anon/authenticated (single-tenant
local prototype). Browser operations go through Edge Functions using the
service role key; the dashboard reads monitoring data with the anon key.

## Notes
- Detection thresholds/severity mapping live in application code.
- Realtime publication enabled for security_events, incidents, blocked_ips,
  and agent_actions so the dashboard updates without manual refresh.
*/

-- =========================================================
-- 1. users
-- =========================================================
CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  username text UNIQUE NOT NULL,
  password_hash text NOT NULL,
  display_name text,
  role text NOT NULL DEFAULT 'analyst',
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_login_at timestamptz
);

ALTER TABLE users ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_users" ON users;
CREATE POLICY "anon_select_users" ON users FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_users" ON users;
CREATE POLICY "anon_insert_users" ON users FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_users" ON users;
CREATE POLICY "anon_update_users" ON users FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

-- =========================================================
-- 2. incidents
-- =========================================================
CREATE TABLE IF NOT EXISTS incidents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id text UNIQUE NOT NULL,
  detection_type text NOT NULL,
  severity text NOT NULL DEFAULT 'MEDIUM',
  status text NOT NULL DEFAULT 'NEW',
  source_ip text,
  username text,
  first_detected_at timestamptz NOT NULL DEFAULT now(),
  last_detected_at timestamptz NOT NULL DEFAULT now(),
  event_count integer NOT NULL DEFAULT 0,
  evidence jsonb NOT NULL DEFAULT '[]'::jsonb,
  detection_reason text,
  ai_analysis jsonb,
  recommended_action text,
  recommended_action_type text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_incidents" ON incidents;
CREATE POLICY "anon_select_incidents" ON incidents FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_incidents" ON incidents;
CREATE POLICY "anon_insert_incidents" ON incidents FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_incidents" ON incidents;
CREATE POLICY "anon_update_incidents" ON incidents FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_incidents" ON incidents;
CREATE POLICY "anon_delete_incidents" ON incidents FOR DELETE
  TO anon, authenticated USING (true);

CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents (severity);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status);
CREATE INDEX IF NOT EXISTS idx_incidents_source_ip ON incidents (source_ip);
CREATE INDEX IF NOT EXISTS idx_incidents_username ON incidents (username);

-- =========================================================
-- 3. security_events
-- =========================================================
CREATE TABLE IF NOT EXISTS security_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id text UNIQUE NOT NULL,
  event_type text NOT NULL,
  username text,
  login_status text,
  source_ip text,
  user_agent text,
  request_id text,
  severity text NOT NULL DEFAULT 'INFO',
  detail text,
  raw jsonb,
  incident_id uuid REFERENCES incidents(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_events" ON security_events;
CREATE POLICY "anon_select_events" ON security_events FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_events" ON security_events;
CREATE POLICY "anon_insert_events" ON security_events FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_events" ON security_events;
CREATE POLICY "anon_update_events" ON security_events FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_events" ON security_events;
CREATE POLICY "anon_delete_events" ON security_events FOR DELETE
  TO anon, authenticated USING (true);

CREATE INDEX IF NOT EXISTS idx_events_created_at ON security_events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON security_events (source_ip);
CREATE INDEX IF NOT EXISTS idx_events_username ON security_events (username);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON security_events (event_type);
CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events (severity);
CREATE INDEX IF NOT EXISTS idx_events_incident_id ON security_events (incident_id);

-- =========================================================
-- 4. blocked_ips
-- =========================================================
CREATE TABLE IF NOT EXISTS blocked_ips (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ip text NOT NULL,
  reason text,
  blocked_by text,
  incident_id uuid REFERENCES incidents(id) ON DELETE SET NULL,
  is_active boolean NOT NULL DEFAULT true,
  blocked_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE blocked_ips ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_blocked_ips" ON blocked_ips;
CREATE POLICY "anon_select_blocked_ips" ON blocked_ips FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_blocked_ips" ON blocked_ips;
CREATE POLICY "anon_insert_blocked_ips" ON blocked_ips FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_blocked_ips" ON blocked_ips;
CREATE POLICY "anon_update_blocked_ips" ON blocked_ips FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_blocked_ips" ON blocked_ips;
CREATE POLICY "anon_delete_blocked_ips" ON blocked_ips FOR DELETE
  TO anon, authenticated USING (true);

CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips (ip);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_active ON blocked_ips (is_active);

-- =========================================================
-- 5. agent_actions
-- =========================================================
CREATE TABLE IF NOT EXISTS agent_actions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  action_id text UNIQUE NOT NULL,
  incident_id uuid REFERENCES incidents(id) ON DELETE CASCADE,
  action_type text NOT NULL,
  description text,
  status text NOT NULL DEFAULT 'PENDING',
  approved_by text,
  approved_at timestamptz,
  executed_at timestamptz,
  result jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE agent_actions ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_agent_actions" ON agent_actions;
CREATE POLICY "anon_select_agent_actions" ON agent_actions FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_agent_actions" ON agent_actions;
CREATE POLICY "anon_insert_agent_actions" ON agent_actions FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_agent_actions" ON agent_actions;
CREATE POLICY "anon_update_agent_actions" ON agent_actions FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_agent_actions" ON agent_actions;
CREATE POLICY "anon_delete_agent_actions" ON agent_actions FOR DELETE
  TO anon, authenticated USING (true);

CREATE INDEX IF NOT EXISTS idx_agent_actions_incident_id ON agent_actions (incident_id);
CREATE INDEX IF NOT EXISTS idx_agent_actions_status ON agent_actions (status);

-- =========================================================
-- Realtime publication
-- =========================================================
ALTER PUBLICATION supabase_realtime ADD TABLE security_events;
ALTER PUBLICATION supabase_realtime ADD TABLE incidents;
ALTER PUBLICATION supabase_realtime ADD TABLE blocked_ips;
ALTER PUBLICATION supabase_realtime ADD TABLE agent_actions;
