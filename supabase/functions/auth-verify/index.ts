import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.45.0";
import bcrypt from "npm:bcryptjs@2.4.3";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

interface SecurityEventInput {
  event_type: string;
  username: string | null;
  login_status: string | null;
  source_ip: string | null;
  user_agent: string | null;
  request_id: string;
  severity: string;
  detail: string;
  raw: Record<string, unknown>;
}

const THRESHOLDS = {
  BRUTE_FORCE_COUNT: 5,
  BRUTE_FORCE_WINDOW_SEC: 60,
  CREDENTIAL_ATTACK_USERS: 3,
  CREDENTIAL_ATTACK_WINDOW_SEC: 120,
  ACCOUNT_TARGET_COUNT: 5,
  ACCOUNT_TARGET_WINDOW_SEC: 120,
  COMPROMISE_FAIL_COUNT: 3,
  COMPROMISE_WINDOW_SEC: 120,
};

function severityRank(s: string): number {
  return { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }[s] ?? 0;
}

function genEventId(): string {
  return "EVT-" + Date.now().toString(36).toUpperCase() + "-" + Math.random().toString(36).slice(2, 8).toUpperCase();
}

function genIncidentId(): string {
  return "INC-" + Date.now().toString(36).toUpperCase() + "-" + Math.random().toString(36).slice(2, 6).toUpperCase();
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  try {
    const url = new URL(req.url);
    if (url.pathname.endsWith("/health")) {
      return new Response(JSON.stringify({ status: "ok" }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const body = await req.json();
    const { username, password, source_ip, user_agent, request_id } = body as {
      username: string;
      password: string;
      source_ip: string;
      user_agent: string;
      request_id: string;
    };

    if (!username || !password || !request_id) {
      return new Response(
        JSON.stringify({ success: false, error: "Missing required fields" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    // 1. Check IP block first
    const { data: blockRow } = await supabase
      .from("blocked_ips")
      .select("id, reason, expires_at")
      .eq("ip", source_ip)
      .eq("is_active", true)
      .maybeSingle();

    const now = new Date();
    let isBlocked = false;
    if (blockRow) {
      const expired = blockRow.expires_at && new Date(blockRow.expires_at) < now;
      if (!expired) {
        isBlocked = true;
      } else {
        await supabase.from("blocked_ips").update({ is_active: false }).eq("id", blockRow.id);
      }
    }

    if (isBlocked) {
      const blockedEvent: SecurityEventInput = {
        event_type: "LOGIN_BLOCKED",
        username,
        login_status: "BLOCKED",
        source_ip,
        user_agent,
        request_id,
        severity: "HIGH",
        detail: `Login attempt from blocked IP ${source_ip} denied`,
        raw: { username, source_ip, user_agent, request_id, reason: blockRow?.reason ?? "blocked" },
      };
      await logEvent(supabase, blockedEvent);
      return new Response(
        JSON.stringify({
          success: false,
          error: "Access denied: your IP address has been blocked due to suspicious activity.",
          blocked: true,
        }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // 2. Verify credentials
    const { data: user } = await supabase
      .from("users")
      .select("id, username, password_hash, display_name, role, is_active")
      .eq("username", username)
      .maybeSingle();

    let loginStatus: "SUCCESS" | "FAILED";
    let userDisplayName: string | null = null;
    let userRole: string | null = null;

    if (!user || !user.is_active) {
      loginStatus = "FAILED";
    } else {
      const passwordOk = bcrypt.compareSync(password, user.password_hash);
      loginStatus = passwordOk ? "SUCCESS" : "FAILED";
      if (loginStatus === "SUCCESS") {
        userDisplayName = user.display_name;
        userRole = user.role;
        await supabase.from("users").update({ last_login_at: now.toISOString() }).eq("id", user.id);
      }
    }

    // 3. Generate structured security log
    const severity = loginStatus === "SUCCESS" ? "INFO" : "LOW";
    const eventInput: SecurityEventInput = {
      event_type: loginStatus === "SUCCESS" ? "LOGIN_SUCCESS" : "LOGIN_FAILED",
      username,
      login_status: loginStatus,
      source_ip,
      user_agent,
      request_id,
      severity,
      detail:
        loginStatus === "SUCCESS"
          ? `Successful authentication for user '${username}'`
          : `Failed authentication for user '${username}'`,
      raw: {
        timestamp: now.toISOString(),
        username,
        login_status: loginStatus,
        source_ip,
        user_agent,
        request_id,
        event_type: loginStatus === "SUCCESS" ? "LOGIN_SUCCESS" : "LOGIN_FAILED",
      },
    };

    const inserted = await logEvent(supabase, eventInput);
    const eventId = inserted?.event_id;

    // 4. Run detection engine
    const detection = await runDetection(supabase, source_ip, username, loginStatus, now);

    let incidentId: string | null = null;
    if (detection) {
      incidentId = await createOrUpdateIncident(supabase, detection, now);
      // Link the triggering event to the incident
      if (eventId) {
        await supabase.from("security_events").update({ incident_id: incidentId }).eq("event_id", eventId);
      }
      // Trigger AI analysis asynchronously (fire and forget)
      try {
        EdgeRuntime.waitUntil(analyzeIncidentWithAI(supabase, incidentId));
      } catch {
        // waitUntil may not be available; run synchronously as fallback
        await analyzeIncidentWithAI(supabase, incidentId);
      }
    }

    // 5. Return result
    const response: Record<string, unknown> = {
      success: loginStatus === "SUCCESS",
      login_status: loginStatus,
      incident_detected: !!detection,
      incident_id: incidentId,
      detection_type: detection?.detection_type ?? null,
    };
    if (loginStatus === "SUCCESS") {
      response.user = {
        username,
        display_name: userDisplayName,
        role: userRole,
      };
    } else {
      response.error = "Invalid username or password";
    }

    return new Response(JSON.stringify(response), {
      status: loginStatus === "SUCCESS" ? 200 : 401,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (err) {
    console.error("auth-verify error:", err);
    return new Response(
      JSON.stringify({ success: false, error: "Authentication service unavailable" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});

async function logEvent(supabase: ReturnType<typeof createClient>, input: SecurityEventInput) {
  const { data, error } = await supabase
    .from("security_events")
    .insert({
      event_id: genEventId(),
      event_type: input.event_type,
      username: input.username,
      login_status: input.login_status,
      source_ip: input.source_ip,
      user_agent: input.user_agent,
      request_id: input.request_id,
      severity: input.severity,
      detail: input.detail,
      raw: input.raw,
    })
    .select()
    .maybeSingle();
  if (error) console.error("logEvent error:", error);
  return data;
}

interface DetectionResult {
  detection_type: string;
  severity: string;
  source_ip: string | null;
  username: string | null;
  event_count: number;
  evidence: Record<string, unknown>[];
  detection_reason: string;
  recommended_action: string;
  recommended_action_type: string;
}

async function runDetection(
  supabase: ReturnType<typeof createClient>,
  sourceIp: string,
  username: string,
  loginStatus: string,
  now: Date
): Promise<DetectionResult | null> {
  const windowStart = (sec: number) => new Date(now.getTime() - sec * 1000).toISOString();

  // Fetch recent failed login events from this IP
  const { data: ipFailures } = await supabase
    .from("security_events")
    .select("event_id, event_type, username, login_status, source_ip, created_at, detail")
    .eq("source_ip", sourceIp)
    .eq("login_status", "FAILED")
    .gte("created_at", windowStart(THRESHOLDS.BRUTE_FORCE_WINDOW_SEC))
    .order("created_at", { ascending: true });

  const ipFails = ipFailures ?? [];

  // Brute-force: same IP, 5+ failures within 60s
  if (ipFails.length >= THRESHOLDS.BRUTE_FORCE_COUNT) {
    const distinctUsers = new Set(ipFails.map((e) => e.username));
    // Credential attack: multiple usernames from same IP
    if (distinctUsers.size >= THRESHOLDS.CREDENTIAL_ATTACK_USERS) {
      return {
        detection_type: "CREDENTIAL_ATTACK",
        severity: "CRITICAL",
        source_ip: sourceIp,
        username: null,
        event_count: ipFails.length,
        evidence: ipFails.slice(-10).map((e) => ({
          event_id: e.event_id,
          timestamp: e.created_at,
          username: e.username,
          event_type: e.event_type,
        })),
        detection_reason: `${ipFails.length} failed login attempts targeting ${distinctUsers.size} different usernames from IP ${sourceIp} within ${THRESHOLDS.BRUTE_FORCE_WINDOW_SEC}s. This pattern is consistent with a credential stuffing attack.`,
        recommended_action: `Temporarily block source IP ${sourceIp} and review targeted accounts for compromise.`,
        recommended_action_type: "BLOCK_IP",
      };
    }
    return {
      detection_type: "BRUTE_FORCE",
      severity: "HIGH",
      source_ip: sourceIp,
      username: ipFails[0]?.username ?? username,
      event_count: ipFails.length,
      evidence: ipFails.slice(-10).map((e) => ({
        event_id: e.event_id,
        timestamp: e.created_at,
        username: e.username,
        event_type: e.event_type,
      })),
      detection_reason: `${ipFails.length} failed login attempts from IP ${sourceIp} against user '${ipFails[0]?.username ?? username}' within ${THRESHOLDS.BRUTE_FORCE_WINDOW_SEC}s, exceeding the brute-force threshold of ${THRESHOLDS.BRUTE_FORCE_COUNT} attempts.`,
      recommended_action: `Temporarily block source IP ${sourceIp} to stop the brute-force attack.`,
      recommended_action_type: "BLOCK_IP",
    };
  }

  // Account targeting: one username receiving many failures
  const { data: userFails } = await supabase
    .from("security_events")
    .select("event_id, event_type, username, source_ip, created_at")
    .eq("username", username)
    .eq("login_status", "FAILED")
    .gte("created_at", windowStart(THRESHOLDS.ACCOUNT_TARGET_WINDOW_SEC))
    .order("created_at", { ascending: true });

  const userFailsList = userFails ?? [];
  const distinctIps = new Set(userFailsList.map((e) => e.source_ip));
  if (userFailsList.length >= THRESHOLDS.ACCOUNT_TARGET_COUNT && distinctIps.size >= 1) {
    // Suspicious successful login: failures followed by success
    if (loginStatus === "SUCCESS") {
      const recentFails = userFailsList.slice(-THRESHOLDS.COMPROMISE_FAIL_COUNT);
      if (recentFails.length >= THRESHOLDS.COMPROMISE_FAIL_COUNT) {
        return {
          detection_type: "ACCOUNT_COMPROMISE",
          severity: "CRITICAL",
          source_ip: sourceIp,
          username,
          event_count: userFailsList.length + 1,
          evidence: [
            ...recentFails.map((e) => ({
              event_id: e.event_id,
              timestamp: e.created_at,
              username: e.username,
              event_type: e.event_type,
              source_ip: e.source_ip,
            })),
            {
              event_id: "current",
              timestamp: now.toISOString(),
              username,
              event_type: "LOGIN_SUCCESS",
              source_ip: sourceIp,
            },
          ],
          detection_reason: `${recentFails.length} failed login attempts against user '${username}' followed by a successful login. This pattern suggests a potential account compromise via password brute-forcing.`,
          recommended_action: `Force password reset for user '${username}', review recent account activity, and temporarily block source IP ${sourceIp}.`,
          recommended_action_type: "BLOCK_IP",
        };
      }
    }
    return {
      detection_type: "ACCOUNT_TARGETING",
      severity: "MEDIUM",
      source_ip: sourceIp,
      username,
      event_count: userFailsList.length,
      evidence: userFailsList.slice(-10).map((e) => ({
        event_id: e.event_id,
        timestamp: e.created_at,
        username: e.username,
        event_type: e.event_type,
        source_ip: e.source_ip,
      })),
      detection_reason: `User '${username}' received ${userFailsList.length} failed login attempts from ${distinctIps.size} IP address(es) within ${THRESHOLDS.ACCOUNT_TARGET_WINDOW_SEC}s, indicating targeted account access attempts.`,
      recommended_action: `Monitor user '${username}' for subsequent successful logins and consider notifying the account owner.`,
      recommended_action_type: "MONITOR",
    };
  }

  // Suspicious successful login: failures from same IP then success
  if (loginStatus === "SUCCESS" && ipFails.length >= THRESHOLDS.COMPROMISE_FAIL_COUNT) {
    return {
      detection_type: "SUSPICIOUS_LOGIN",
      severity: "HIGH",
      source_ip: sourceIp,
      username,
      event_count: ipFails.length + 1,
      evidence: [
        ...ipFails.slice(-5).map((e) => ({
          event_id: e.event_id,
          timestamp: e.created_at,
          username: e.username,
          event_type: e.event_type,
        })),
        {
          event_id: "current",
          timestamp: now.toISOString(),
          username,
          event_type: "LOGIN_SUCCESS",
          source_ip: sourceIp,
        },
      ],
      detection_reason: `${ipFails.length} failed login attempts from IP ${sourceIp} immediately followed by a successful login for '${username}'. This is a classic brute-force-then-compromise signature.`,
      recommended_action: `Require step-up verification for user '${username}' and temporarily restrict source IP ${sourceIp}.`,
      recommended_action_type: "BLOCK_IP",
    };
  }

  return null;
}

async function createOrUpdateIncident(
  supabase: ReturnType<typeof createClient>,
  detection: DetectionResult,
  now: Date
): Promise<string> {
  // Check for an existing active incident with same type + source_ip or username
  let query = supabase
    .from("incidents")
    .select("id, incident_id, event_count, evidence")
    .eq("detection_type", detection.detection_type)
    .neq("status", "RESOLVED")
    .neq("status", "FALSE_POSITIVE");

  if (detection.source_ip) {
    query = query.eq("source_ip", detection.source_ip);
  }
  if (detection.username) {
    query = query.eq("username", detection.username);
  }

  const { data: existing } = await query.order("created_at", { ascending: false }).limit(1).maybeSingle();

  if (existing) {
    const mergedEvidence = [...(existing.evidence ?? []), ...detection.evidence].slice(-50);
    const newSeverity =
      severityRank(detection.severity) > severityRank("MEDIUM")
        ? detection.severity
        : "MEDIUM";
    await supabase
      .from("incidents")
      .update({
        severity: newSeverity,
        last_detected_at: now.toISOString(),
        event_count: (existing.event_count ?? 0) + detection.event_count,
        evidence: mergedEvidence,
        detection_reason: detection.detection_reason,
        recommended_action: detection.recommended_action,
        recommended_action_type: detection.recommended_action_type,
        updated_at: now.toISOString(),
        status: "INVESTIGATING",
      })
      .eq("id", existing.id);
    return existing.incident_id;
  }

  const incidentId = genIncidentId();
  await supabase.from("incidents").insert({
    incident_id: incidentId,
    detection_type: detection.detection_type,
    severity: detection.severity,
    status: "NEW",
    source_ip: detection.source_ip,
    username: detection.username,
    first_detected_at: now.toISOString(),
    last_detected_at: now.toISOString(),
    event_count: detection.event_count,
    evidence: detection.evidence,
    detection_reason: detection.detection_reason,
    recommended_action: detection.recommended_action,
    recommended_action_type: detection.recommended_action_type,
    ai_analysis: null,
  });
  return incidentId;
}

async function analyzeIncidentWithAI(supabase: ReturnType<typeof createClient>, incidentId: string) {
  try {
    const { data: incident } = await supabase
      .from("incidents")
      .select("*")
      .eq("incident_id", incidentId)
      .maybeSingle();
    if (!incident) return;

    const aiResult = await callLLM(incident);
    await supabase
      .from("incidents")
      .update({
        ai_analysis: aiResult,
        severity: aiResult.severity || incident.severity,
        recommended_action: aiResult.recommended_action || incident.recommended_action,
        updated_at: new Date().toISOString(),
      })
      .eq("id", incident.id);
  } catch (err) {
    console.error("AI analysis failed:", err);
  }
}

async function callLLM(incident: Record<string, unknown>): Promise<Record<string, unknown>> {
  const apiKey = Deno.env.get("LLM_API_KEY");
  const model = Deno.env.get("LLM_MODEL") || "gpt-4o-mini";
  const apiUrl = Deno.env.get("LLM_API_URL") || "https://api.openai.com/v1/chat/completions";

  const evidence = (incident.evidence as Record<string, unknown>[]) ?? [];
  const payload = {
    event_type: incident.detection_type,
    source_ip: incident.source_ip,
    username: incident.username,
    failed_attempts: incident.event_count,
    time_window_seconds: 60,
    detection_reason: incident.detection_reason,
    related_events: evidence.slice(0, 10),
  };

  if (!apiKey) {
    return ruleBasedAnalysis(incident, "LLM API key not configured");
  }

  try {
    const systemPrompt = `You are a security analysis engine for an enterprise SIEM system. Analyze the provided security incident evidence and return a JSON object with these exact fields:
- summary: brief one-sentence description of the incident
- severity: one of LOW, MEDIUM, HIGH, CRITICAL
- reasoning: detailed explanation of why this is suspicious
- evidence: array of key evidence points (strings)
- recommended_action: specific recommended response action
- confidence: number between 0 and 1
Return ONLY valid JSON, no markdown.`;

    const response = await fetch(apiUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: JSON.stringify(payload) },
        ],
        temperature: 0.3,
        max_tokens: 500,
      }),
    });

    if (!response.ok) {
      throw new Error(`LLM API returned ${response.status}`);
    }

    const data = await response.json();
    const content = data.choices?.[0]?.message?.content;
    if (!content) throw new Error("Empty LLM response");

    const parsed = JSON.parse(content);
    return validateAIResponse(parsed, incident);
  } catch (err) {
    console.error("LLM call failed, using rule-based fallback:", err);
    return ruleBasedAnalysis(incident, err instanceof Error ? err.message : "LLM unavailable");
  }
}

function validateAIResponse(parsed: Record<string, unknown>, incident: Record<string, unknown>): Record<string, unknown> {
  const validSeverities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
  const severity = validSeverities.includes(parsed.severity as string)
    ? parsed.severity
    : incident.severity;
  return {
    summary: typeof parsed.summary === "string" ? parsed.summary : "Security incident detected",
    severity,
    reasoning: typeof parsed.reasoning === "string" ? parsed.reasoning : String(incident.detection_reason ?? ""),
    evidence: Array.isArray(parsed.evidence) ? parsed.evidence.map(String) : [],
    recommended_action:
      typeof parsed.recommended_action === "string"
        ? parsed.recommended_action
        : String(incident.recommended_action ?? ""),
    confidence: typeof parsed.confidence === "number" ? parsed.confidence : 0.5,
    source: "llm",
  };
}

function ruleBasedAnalysis(incident: Record<string, unknown>, reason: string): Record<string, unknown> {
  return {
    summary: `${incident.detection_type} incident detected involving ${incident.event_count} events from ${incident.source_ip ?? "unknown"}`,
    severity: incident.severity,
    reasoning: String(incident.detection_reason ?? ""),
    evidence: [`Rule-based detection: ${incident.detection_type}`],
    recommended_action: String(incident.recommended_action ?? ""),
    confidence: 0.7,
    source: "rule-based",
    fallback_reason: reason,
  };
}
