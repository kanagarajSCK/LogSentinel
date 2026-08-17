# LogSentinel

## AI-Powered Log Analysis &amp; Automated Incident Detection

LogSentinel is a full-stack security monitoring application that captures real
authentication events, analyzes them through a hybrid rule-based + AI detection
engine, generates incidents for suspicious activity, and provides a
human-in-the-loop response workflow with application-level IP blocking.

> **Note:** This is a local prototype / simulated enterprise environment. It is
> not a production SOC platform and should not be used to protect real
> infrastructure. It is designed for demonstration, education, and technical
> presentation.

---

## Project Overview

LogSentinel demonstrates a complete security operations workflow:

```
User Login Attempt
      ↓
Authentication Service (credential verification, IP block check)
      ↓
Security Event Generated (structured log with timestamp, IP, user agent, request ID)
      ↓
Log Storage (PostgreSQL via Supabase)
      ↓
Detection Engine (rule-based pattern matching)
      ↓
Pattern / Anomaly Detection (brute-force, credential attack, compromise, targeting)
      ↓
AI Investigation (LLM-powered analysis with rule-based fallback)
      ↓
Risk Assessment (severity: LOW / MEDIUM / HIGH / CRITICAL)
      ↓
Security Incident Created
      ↓
Recommended Response (e.g. block source IP)
      ↓
Human Approval (approve / reject)
      ↓
Optional Response Action (application-level IP block)
```

---

## Architecture

```
LogSentinel/
├── src/                        # Frontend (React + TypeScript + Vite)
│   ├── components/             # Dashboard components
│   │   ├── Overview.tsx        # Stats cards, event feed, charts, incident preview
│   │   ├── EventFeed.tsx       # Real-time event stream
│   │   ├── EventsChart.tsx     # Time-series chart of login events
│   │   ├── IncidentList.tsx    # Filterable incident table
│   │   ├── IncidentDetail.tsx  # Full incident view with AI analysis & approval
│   │   ├── DemoPanel.tsx       # Test event generator
│   │   └── BlockedIPs.tsx      # IP blocklist management
│   ├── lib/
│   │   ├── supabase.ts         # Supabase client & edge function helper
│   │   └── auth.tsx            # Authentication context
│   ├── pages/
│   │   ├── Login.tsx           # Login page
│   │   └── Dashboard.tsx       # Main dashboard layout
│   ├── types.ts                # Shared TypeScript types
│   ├── App.tsx                 # Root component
│   ├── main.tsx                # Entry point
│   └── index.css               # Global styles
├── supabase/functions/         # Backend (Deno Edge Functions)
│   ├── auth-verify/            # Login verification + event logging + detection + incident creation
│   ├── ai-analysis/            # LLM-powered incident analysis (with fallback)
│   ├── demo-events/            # Simulated event generation for testing
│   └── incident-management/    # Status changes, approve/reject actions, IP blocking
├── public/
├── index.html
├── package.json
├── tsconfig.json
├── vite.config.ts
└── .env.example
```

### Hybrid Detection Architecture

The system uses a two-tier analysis approach:

1. **Rule-based detection (deterministic):** Runs on every login event. Checks
   for brute-force, credential attacks, account targeting, and suspicious
   successful logins using configurable thresholds and time windows.

2. **AI investigation (LLM-powered):** Triggered after an incident is created.
   Sends structured security evidence to an LLM, which returns a severity
   assessment, reasoning, evidence summary, and recommended action. If the LLM
   is unavailable, the system falls back to rule-based analysis and continues
   functioning normally.

---

## Features

- **Real authentication:** Login page with bcrypt-hashed passwords stored in the
  database. Every attempt generates a structured security event.
- **Structured security logging:** Each event includes timestamp, username, login
  status, source IP, user agent, request ID, and event type.
- **Detection engine:** Four detection rules with configurable thresholds:
  - Brute-force: 5+ failed logins from one IP within 60 seconds
  - Credential attack: Failed logins against 3+ usernames from one IP
  - Suspicious successful login: Multiple failures followed by success
  - Account targeting: One username receiving 5+ failed attempts
- **Incident management:** Auto-created incidents with severity, status,
  evidence, AI analysis, and recommended actions.
- **Real-time dashboard:** Updates via Supabase Realtime (WebSockets) without
  page refresh.
- **Human-in-the-loop response:** Approve or reject recommended actions before
  any response is executed.
- **Application-level IP blocking:** Blocked IPs are denied at the login service.
  No OS firewall modifications.
- **AI investigation:** LLM-powered analysis with rule-based fallback when the
  API is unavailable.
- **Demo mode:** Generate test events for brute-force, credential attack, account
  compromise, and normal login scenarios.
- **Professional SOC UI:** Dark dashboard with overview cards, live event feed,
  incident tables, timeline views, charts, filters, and search.

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, TypeScript, Vite, Recharts, Lucide icons |
| Backend | Supabase Edge Functions (Deno runtime) |
| Database | PostgreSQL (Supabase) |
| Real-time | Supabase Realtime (Postgres Changes / WebSockets) |
| Auth | Application-level bcrypt (users table) |
| AI | LLM API (OpenAI-compatible) via secure backend |
| Styling | Custom CSS (dark SOC theme) |

---

## Installation

### Prerequisites

- Node.js 18+
- npm

### Steps

```bash
# Install dependencies
npm install

# Copy environment template
cp .env.example .env

# (Optional) Add your LLM API key to .env for AI-powered analysis
# The app works without it — rule-based fallback is used.

# Start the development server
npm run dev
```

The Supabase database and backend functions are pre-configured and deployed.
No additional database setup is required.

---

## Environment Configuration

The following variables are pre-populated:

- `VITE_SUPABASE_URL` — Supabase project URL
- `VITE_SUPABASE_ANON_KEY` — Supabase anonymous key (frontend access)

Optional (for AI-powered analysis only):

- `LLM_API_KEY` — API key for the LLM service
- `LLM_MODEL` — Model name (default: `gpt-4o-mini`)
- `LLM_API_URL` — API endpoint (default: OpenAI chat completions)

When `LLM_API_KEY` is not set, the system uses rule-based analysis. Incidents
are still created, detection works normally, and the AI analysis field shows a
rule-based summary with a note that the LLM was unavailable.

---

## Database Setup

The database schema is already applied. Tables:

| Table | Purpose |
|-------|---------|
| `users` | Application accounts with bcrypt-hashed passwords |
| `security_events` | Structured security log (immutable) |
| `incidents` | Detected incidents with AI analysis and recommended actions |
| `blocked_ips` | Application-level IP blocklist |
| `agent_actions` | Audit trail of approved/rejected response actions |

Indexes are created on: `timestamp`, `source_ip`, `username`, `event_type`,
`severity`, `status`, and `incident_id`.

---

## Running the Application

```bash
npm run dev
```

Open the URL shown in the terminal (typically `http://localhost:5173`).

### Demo Accounts

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Administrator |
| analyst | analyst123 | Security Analyst |
| jsmith | password123 | Regular User |

---

## Demo Instructions

### Live Login Demonstration

1. Open the login page in your browser.
2. Enter `admin` as the username and any wrong password (e.g. `wrongpass`).
3. Submit the login form repeatedly (5+ times within 60 seconds).
4. Switch to the **Overview** tab — watch failed login events appear in real time.
5. After 5 failures, a **HIGH severity brute-force incident** is automatically created.
6. Go to the **Incidents** tab and click the incident to open its details.
7. View the detection reason, event timeline, and AI investigation summary.
8. Read the recommended response: "Temporarily block source IP".
9. Click **Approve Action** to execute the IP block.
10. Return to the login page and attempt another login.
11. The application denies the request with a "blocked IP" message.

### Demo Mode (Automated)

Use the **Demo Mode** tab to generate pre-built scenarios:

- **Normal Failed Login** — single failed attempt, no incident
- **Brute-Force Attack** — 10 rapid failures against one account
- **Credential Stuffing** — failures across multiple usernames from one IP
- **Account Compromise** — failures followed by a successful login
- **Account Targeting** — failures against one user from multiple IPs

---

## Detection Rules

| Rule | Trigger | Severity |
|------|---------|----------|
| Brute-force | 5+ failed logins from one IP within 60s | HIGH |
| Credential attack | 5+ failures targeting 3+ usernames from one IP | CRITICAL |
| Suspicious login | 3+ failures from one IP followed by success | HIGH |
| Account compromise | 3+ failures against one user followed by success | CRITICAL |
| Account targeting | 5+ failures against one username within 120s | MEDIUM |

Thresholds are configurable in the `auth-verify` edge function source.

---

## AI Architecture

The AI integration follows a secure backend pattern:

1. **Evidence collection:** The detection engine gathers structured evidence
   (event type, source IP, username, failed attempt count, related events).
2. **Backend call:** The edge function sends this evidence to the LLM API. API
   keys are stored in environment variables and never exposed to the frontend.
3. **Structured output:** The LLM returns a JSON object with summary, severity,
   reasoning, evidence, recommended action, and confidence score.
4. **Validation:** The response is validated before storage. Invalid fields fall
   back to rule-based values.
5. **Fallback:** If the LLM API is unavailable, returns an error, or produces
   malformed output, the system uses rule-based analysis. The incident is still
   created with detection details and a confidence score.

```
LLM available   →  AI analysis stored with source: "llm"
LLM unavailable →  Rule-based analysis stored with source: "rule-based"
```

---

## Security Considerations

- **Password hashing:** bcrypt with cost factor 10
- **API key protection:** LLM keys stored in environment variables, accessed only
  by backend edge functions
- **Parameterized queries:** All database access via Supabase client (ORM layer)
- **Input validation:** Required fields validated at the API boundary
- **Error handling:** User-facing errors never expose stack traces or secrets
- **Application-level blocking:** IP blocks are enforced in the auth service, not
  the OS firewall
- **Immutable security log:** Events are insert-only; no update/delete from the
  login flow
- **Human-in-the-loop:** No destructive actions execute without explicit approval

This is a **local prototype** and does not implement all production security
controls (CSRF tokens, rate limiting middleware, session JWTs, etc.). It is
designed for demonstration purposes.

---

## Limitations

- Single-tenant: no multi-user data isolation (all data is shared)
- IP blocking is application-level only (not network-level)
- Detection thresholds are hardcoded in the edge function (not runtime-configurable)
- No persistent session management (sessionStorage used for demo)
- LLM analysis is synchronous in the fallback path
- No alerting integrations (email, Slack, etc.)

---

## Future Improvements

- Runtime-configurable detection thresholds via admin UI
- Multi-user accounts with Supabase Auth for analyst access control
- Alerting integrations (email, Slack, PagerDuty)
- Additional detection rules (geolocation anomalies, impossible travel, lateral movement)
- Incident correlation across time windows
- Custom detection rule builder
- Exportable incident reports
- SIEM integration (Splunk, Elastic, Datadog)
- Rate limiting and CSRF protection for production deployment
- Session management with JWT and refresh tokens
