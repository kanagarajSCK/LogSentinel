import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.45.0";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  try {
    const { incident_id } = await req.json();
    if (!incident_id) {
      return new Response(JSON.stringify({ error: "incident_id required" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    const { data: incident } = await supabase
      .from("incidents")
      .select("*")
      .eq("incident_id", incident_id)
      .maybeSingle();

    if (!incident) {
      return new Response(JSON.stringify({ error: "Incident not found" }), {
        status: 404,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

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

    return new Response(JSON.stringify({ success: true, ai_analysis: aiResult }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (err) {
    console.error("ai-analysis error:", err);
    return new Response(
      JSON.stringify({ error: "AI analysis service unavailable" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});

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

    if (!response.ok) throw new Error(`LLM API returned ${response.status}`);

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
