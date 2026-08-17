import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.45.0";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

const THRESHOLDS = {
  BRUTE_FORCE_COUNT: 5,
  BRUTE_FORCE_WINDOW_SEC: 60,
  CREDENTIAL_ATTACK_USERS: 3,
  ACCOUNT_TARGET_COUNT: 5,
  COMPROMISE_FAIL_COUNT: 3,
};

function genEventId(): string {
  return "EVT-" + Date.now().toString(36).toUpperCase() + "-" + Math.random().toString(36).slice(2, 8).toUpperCase();
}
function genIncidentId(): string {
  return "INC-" + Date.now().toString(36).toUpperCase() + "-" + Math.random().toString(36).slice(2, 6).toUpperCase();
}
function severityRank(s: string): number {
  return { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }[s] ?? 0;
}
const randomIp = () => `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  try {
    const { scenario } = await req.json();
    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    const results: string[] = [];

    switch (scenario) {
      case "normal_login":
        await generateNormalLogin(supabase, results);
        break;
      case "brute_force":
        await generateBruteForce(supabase, results);
        break;
      case "credential_attack":
        await generateCredentialAttack(supabase, results);
        break;
      case "account_compromise":
        await generateAccountCompromise(supabase, results);
        break;
      case "account_targeting":
        await generateAccountTargeting(supabase, results);
        break;
      default:
        return new Response(JSON.stringify({ error: "Unknown scenario" }), {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
    }

    return new Response(JSON.stringify({ success: true, events: results }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (err) {
    console.error("demo-events error:", err);
    return new Response(
      JSON.stringify({ error: "Demo event generation failed" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});

async function logEvent(
  supabase: ReturnType<typeof createClient>,
  opts: {
    event_type: string;
    username: string;
    login_status: string;
    source_ip: string;
    severity: string;
    detail: string;
  }
): Promise<Record<string, unknown> | null> {
  const now = new Date().toISOString();
  const { data, error } = await supabase
    .from("security_events")
    .insert({
      event_id: genEventId(),
      event_type: opts.event_type,
      username: opts.username,
      login_status: opts.login_status,
      source_ip: opts.source_ip,
      user_agent: "LogSentinel-DemoSimulator/1.0",
      request_id: "req-" + Math.random().toString(36).slice(2, 10),
      severity: opts.severity,
      detail: opts.detail,
      raw: {
        timestamp: now,
        username: opts.username,
        login_status: opts.login_status,
        source_ip: opts.source_ip,
        event_type: opts.event_type,
      },
    })
    .select()
    .maybeSingle();
  if (error) console.error("demo logEvent error:", error);
  return data;
}

async function checkDetection(
  supabase: ReturnType<typeof createClient>,
  sourceIp: string,
  username: string | null,
  loginStatus: string
): Promise<{ detection_type: string; severity: string; source_ip: string; username: string | null; event_count: number; evidence: Record<string, unknown>[]; detection_reason: string; recommended_action: string; recommended_action_type: string } | null> {
  const now = new Date();
  const windowStart = new Date(now.getTime() - THRESHOLDS.BRUTE_FORCE_WINDOW_SEC * 1000).toISOString();

  const { data: ipFails } = await supabase
    .from("security_events")
    .select("event_id, event_type, username, login_status, source_ip, created_at, detail")
    .eq("source_ip", sourceIp)
    .eq("login_status", "FAILED")
    .gte("created_at", windowStart)
    .order("created_at", { ascending: true });

  const ipFailsList = ipFails ?? [];

  if (ipFailsList.length >= THRESHOLDS.BRUTE_FORCE_COUNT) {
    const distinctUsers = new Set(ipFailsList.map((e) => e.username));
    if (distinctUsers.size >= THRESHOLDS.CREDENTIAL_ATTACK_USERS) {
      return {
        detection_type: "CREDENTIAL_ATTACK",
        severity: "CRITICAL",
        source_ip: sourceIp,
        username: null,
        event_count: ipFailsList.length,
        evidence: ipFailsList.slice(-10).map((e) => ({ event_id: e.event_id, timestamp: e.created_at, username: e.username, event_type: e.event_type })),
        detection_reason: `${ipFailsList.length} failed login attempts targeting ${distinctUsers.size} different usernames from IP ${sourceIp} within ${THRESHOLDS.BRUTE_FORCE_WINDOW_SEC}s. Consistent with credential stuffing.`,
        recommended_action: `Temporarily block source IP ${sourceIp} and review targeted accounts.`,
        recommended_action_type: "BLOCK_IP",
      };
    }
    return {
      detection_type: "BRUTE_FORCE",
      severity: "HIGH",
      source_ip: sourceIp,
      username: ipFailsList[0]?.username ?? username,
      event_count: ipFailsList.length,
      evidence: ipFailsList.slice(-10).map((e) => ({ event_id: e.event_id, timestamp: e.created_at, username: e.username, event_type: e.event_type })),
      detection_reason: `${ipFailsList.length} failed login attempts from IP ${sourceIp} within ${THRESHOLDS.BRUTE_FORCE_WINDOW_SEC}s, exceeding brute-force threshold.`,
      recommended_action: `Temporarily block source IP ${sourceIp}.`,
      recommended_action_type: "BLOCK_IP",
    };
  }

  if (loginStatus === "SUCCESS" && ipFails.length >= THRESHOLDS.COMPROMISE_FAIL_COUNT) {
    return {
      detection_type: "SUSPICIOUS_LOGIN",
      severity: "HIGH",
      source_ip: sourceIp,
      username,
      event_count: ipFails.length + 1,
      evidence: [
        ...ipFails.slice(-5).map((e) => ({ event_id: e.event_id, timestamp: e.created_at, username: e.username, event_type: e.event_type })),
        { event_id: "current", timestamp: now.toISOString(), username, event_type: "LOGIN_SUCCESS", source_ip: sourceIp },
      ],
      detection_reason: `${ipFails.length} failed attempts from IP ${sourceIp} followed by successful login for '${username}'. Potential brute-force compromise.`,
      recommended_action: `Require step-up verification for '${username}' and temporarily block IP ${sourceIp}.`,
      recommended_action_type: "BLOCK_IP",
    };
  }

  if (username) {
    const { data: userFails } = await supabase
      .from("security_events")
      .select("event_id, event_type, username, source_ip, created_at")
      .eq("username", username)
      .eq("login_status", "FAILED")
      .gte("created_at", new Date(now.getTime() - 120 * 1000).toISOString())
      .order("created_at", { ascending: true });
    const userFailsList = userFails ?? [];
    if (userFailsList.length >= THRESHOLDS.ACCOUNT_TARGET_COUNT) {
      return {
        detection_type: "ACCOUNT_TARGETING",
        severity: "MEDIUM",
        source_ip: sourceIp,
        username,
        event_count: userFailsList.length,
        evidence: userFailsList.slice(-10).map((e) => ({ event_id: e.event_id, timestamp: e.created_at, username: e.username, event_type: e.event_type, source_ip: e.source_ip })),
        detection_reason: `User '${username}' received ${userFailsList.length} failed login attempts within 120s, indicating targeted access attempts.`,
        recommended_action: `Monitor user '${username}' and consider notifying the account owner.`,
        recommended_action_type: "MONITOR",
      };
    }
  }

  return null;
}

async function createOrUpdateIncident(supabase: ReturnType<typeof createClient>, detection: NonNullable<Awaited<ReturnType<typeof checkDetection>>>, now: Date): Promise<string> {
  let query = supabase
    .from("incidents")
    .select("id, incident_id, event_count, evidence")
    .eq("detection_type", detection.detection_type)
    .neq("status", "RESOLVED")
    .neq("status", "FALSE_POSITIVE")
    .eq("source_ip", detection.source_ip);
  if (detection.username) query = query.eq("username", detection.username);

  const { data: existing } = await query.order("created_at", { ascending: false }).limit(1).maybeSingle();

  if (existing) {
    const mergedEvidence = [...(existing.evidence as Record<string, unknown>[] ?? []), ...detection.evidence].slice(-50);
    await supabase.from("incidents").update({
      severity: severityRank(detection.severity) > 2 ? detection.severity : "MEDIUM",
      last_detected_at: now.toISOString(),
      event_count: (existing.event_count ?? 0) + detection.event_count,
      evidence: mergedEvidence,
      detection_reason: detection.detection_reason,
      recommended_action: detection.recommended_action,
      recommended_action_type: detection.recommended_action_type,
      updated_at: now.toISOString(),
      status: "INVESTIGATING",
    }).eq("id", existing.id);
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

async function generateNormalLogin(supabase: ReturnType<typeof createClient>, results: string[]) {
  const ip = randomIp();
  await logEvent(supabase, {
    event_type: "LOGIN_FAILED",
    username: "jsmith",
    login_status: "FAILED",
    source_ip: ip,
    severity: "LOW",
    detail: "Failed authentication for user 'jsmith' (normal failed login)",
  });
  results.push("Generated 1 normal failed login event");
}

async function generateBruteForce(supabase: ReturnType<typeof createClient>, results: string[]) {
  const ip = randomIp();
  for (let i = 0; i < 10; i++) {
    const ev = await logEvent(supabase, {
      event_type: "LOGIN_FAILED",
      username: "admin",
      login_status: "FAILED",
      source_ip: ip,
      severity: i >= 4 ? "HIGH" : "LOW",
      detail: `Failed authentication for user 'admin' (brute-force attempt ${i + 1}/10)`,
    });
    results.push(`Failed login ${i + 1}/10 from ${ip}`);
    const detection = await checkDetection(supabase, ip, "admin", "FAILED");
    if (detection) {
      const incidentId = await createOrUpdateIncident(supabase, detection, new Date());
      if (ev) await supabase.from("security_events").update({ incident_id: (await supabase.from("incidents").select("id").eq("incident_id", incidentId).maybeSingle()).data?.id }).eq("id", ev.id);
      results.push(`Incident ${incidentId} created: ${detection.detection_type}`);
      break;
    }
    await sleep(200);
  }
}

async function generateCredentialAttack(supabase: ReturnType<typeof createClient>, results: string[]) {
  const ip = randomIp();
  const targets = ["admin", "analyst", "jsmith", "root", "guest", "test"];
  for (let i = 0; i < 10; i++) {
    const username = targets[i % targets.length];
    const ev = await logEvent(supabase, {
      event_type: "LOGIN_FAILED",
      username,
      login_status: "FAILED",
      source_ip: ip,
      severity: i >= 4 ? "HIGH" : "LOW",
      detail: `Failed authentication for user '${username}' (credential stuffing attempt ${i + 1}/10)`,
    });
    results.push(`Failed login ${i + 1}/10 user=${username} from ${ip}`);
    const detection = await checkDetection(supabase, ip, username, "FAILED");
    if (detection) {
      const incidentId = await createOrUpdateIncident(supabase, detection, new Date());
      results.push(`Incident ${incidentId} created: ${detection.detection_type}`);
      break;
    }
    await sleep(200);
  }
}

async function generateAccountCompromise(supabase: ReturnType<typeof createClient>, results: string[]) {
  const ip = randomIp();
  for (let i = 0; i < 5; i++) {
    await logEvent(supabase, {
      event_type: "LOGIN_FAILED",
      username: "admin",
      login_status: "FAILED",
      source_ip: ip,
      severity: "LOW",
      detail: `Failed authentication for user 'admin' (compromise attempt ${i + 1}/5)`,
    });
    results.push(`Failed login ${i + 1}/5 from ${ip}`);
    await sleep(200);
  }
  const ev = await logEvent(supabase, {
    event_type: "LOGIN_SUCCESS",
    username: "admin",
    login_status: "SUCCESS",
    source_ip: ip,
    severity: "INFO",
    detail: "Successful authentication for user 'admin' after repeated failures",
  });
  results.push(`Successful login from ${ip} (compromise)`);
  const detection = await checkDetection(supabase, ip, "admin", "SUCCESS");
  if (detection) {
    const incidentId = await createOrUpdateIncident(supabase, detection, new Date());
    results.push(`Incident ${incidentId} created: ${detection.detection_type}`);
  }
}

async function generateAccountTargeting(supabase: ReturnType<typeof createClient>, results: string[]) {
  const username = "admin";
  for (let i = 0; i < 6; i++) {
    const ip = randomIp();
    await logEvent(supabase, {
      event_type: "LOGIN_FAILED",
      username,
      login_status: "FAILED",
      source_ip: ip,
      severity: "LOW",
      detail: `Failed authentication for user '${username}' from IP ${ip} (targeting attempt ${i + 1}/6)`,
    });
    results.push(`Failed login ${i + 1}/6 user=${username} from ${ip}`);
    await sleep(200);
  }
  const detection = await checkDetection(supabase, randomIp(), username, "FAILED");
  if (detection) {
    const incidentId = await createOrUpdateIncident(supabase, detection, new Date());
    results.push(`Incident ${incidentId} created: ${detection.detection_type}`);
  }
}
