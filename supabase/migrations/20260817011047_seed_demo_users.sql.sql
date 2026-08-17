/*
# LogSentinel — Seed Demo Users

## Purpose
Inserts three demo application accounts with bcrypt-hashed passwords so the
login page can be exercised immediately. These are application-level accounts
(stored in the `users` table), NOT Supabase Auth accounts — the login flow
itself is what LogSentinel monitors, so authentication is handled by the
auth-verify Edge Function against this table.

## Accounts created
- admin / admin123      (Administrator)
- analyst / analyst123  (Security Analyst)
- jsmith / password123  (John Smith, regular user)

## Notes
- Passwords are hashed with bcrypt (cost 10).
- Idempotent: re-running upserts on username so existing accounts keep any
  updated last_login_at values, but reset the hash to the known demo value.
- These credentials are documented in the README as demo-only.
*/

INSERT INTO users (username, password_hash, display_name, role, is_active)
VALUES
  ('admin',   '$2b$10$iAqPzLa3eMZzolwdsgFDAeGQlfjqkDuB/5oS.bgzqUVHfsiXcv/XK', 'Administrator',    'admin',    true),
  ('analyst', '$2b$10$Tiu17y2eJVSWHTGEZsbLZuE1OWz2v2vYhUMRlhLsW.Rr8oQJLR9Ne', 'Security Analyst',  'analyst',  true),
  ('jsmith',  '$2b$10$vP1dIaoSD7.W8meOqBkZzO9vFqLHryaotiy/7GBqSPPfuXMPACAaK', 'John Smith',        'user',     true)
ON CONFLICT (username) DO UPDATE
SET password_hash = EXCLUDED.password_hash,
    display_name = EXCLUDED.display_name,
    role = EXCLUDED.role,
    is_active = EXCLUDED.is_active;
