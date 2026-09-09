import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.45.0";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

function genActionId(): string {
  return "ACT-" + Date.now().toString(36).toUpperCase() + "-" + Math.random().toString(36).slice(2, 6).toUpperCase();
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  try {
    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    const url = new URL(req.url);
    const path = url.pathname;
    const body = await req.json().catch(() => ({}));

    // Read the blocklist through the service-role client so the dashboard does
    // not depend on browser REST credentials for security administration.
    if (path.endsWith("/blocked-ips")) {
      const { data, error } = await supabase
        .from("blocked_ips")
        .select("*")
        .order("blocked_at", { ascending: false });
      if (error) throw error;
      return new Response(JSON.stringify({ blocked_ips: data ?? [] }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // Update incident status
    if (path.endsWith("/status")) {
      const { incident_id, status, approved_by } = body as { incident_id: string; status: string; approved_by?: string };
      if (!incident_id || !status) {
        return new Response(JSON.stringify({ error: "incident_id and status required" }), {
          status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      const validStatuses = ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"];
      if (!validStatuses.includes(status)) {
        return new Response(JSON.stringify({ error: "Invalid status" }), {
          status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      const { error } = await supabase
        .from("incidents")
        .update({ status, updated_at: new Date().toISOString() })
        .eq("incident_id", incident_id);
      if (error) throw error;
      return new Response(JSON.stringify({ success: true }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // Approve / reject recommended action
    if (path.endsWith("/action")) {
      const { incident_id, action, approved_by } = body as { incident_id: string; action: "approve" | "reject"; approved_by: string };
      if (!incident_id || !action) {
        return new Response(JSON.stringify({ error: "incident_id and action required" }), {
          status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      const { data: incident } = await supabase
        .from("incidents")
        .select("*")
        .eq("incident_id", incident_id)
        .maybeSingle();

      if (!incident) {
        return new Response(JSON.stringify({ error: "Incident not found" }), {
          status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      const actionId = genActionId();
      const now = new Date().toISOString();

      if (action === "reject") {
        await supabase.from("agent_actions").insert({
          action_id: actionId,
          incident_id: incident.id,
          action_type: incident.recommended_action_type || "REJECT",
          description: incident.recommended_action,
          status: "REJECTED",
          approved_by: approved_by || "analyst",
          approved_at: now,
          result: { rejected: true },
        });
        await supabase.from("incidents").update({ status: "INVESTIGATING", updated_at: now }).eq("id", incident.id);
        return new Response(JSON.stringify({ success: true, action_id: actionId, status: "REJECTED" }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      // Approve: execute the recommended action
      let result: Record<string, unknown> = { approved: true };
      if (incident.recommended_action_type === "BLOCK_IP" && incident.source_ip) {
        const { data: existingBlock } = await supabase
          .from("blocked_ips")
          .select("id")
          .eq("ip", incident.source_ip)
          .eq("is_active", true)
          .maybeSingle();

        if (existingBlock) {
          result = { approved: true, ip_blocked: true, note: "IP was already blocked" };
        } else {
          const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour
          const { error: blockErr } = await supabase.from("blocked_ips").insert({
            ip: incident.source_ip,
            reason: `Blocked due to ${incident.detection_type} incident ${incident.incident_id}`,
            blocked_by: approved_by || "analyst",
            incident_id: incident.id,
            is_active: true,
            expires_at: expiresAt,
          });
          if (blockErr) throw blockErr;
          result = { approved: true, ip_blocked: true, expires_at: expiresAt };
        }
      }

      await supabase.from("agent_actions").insert({
        action_id: actionId,
        incident_id: incident.id,
        action_type: incident.recommended_action_type || "APPROVE",
        description: incident.recommended_action,
        status: "APPROVED",
        approved_by: approved_by || "analyst",
        approved_at: now,
        executed_at: now,
        result,
      });

      await supabase.from("incidents").update({ status: "RESOLVED", updated_at: now }).eq("id", incident.id);

      return new Response(JSON.stringify({ success: true, action_id: actionId, status: "APPROVED", result }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // Clear all history (events, incidents, blocked IPs, agent actions)
    if (path.endsWith("/clear-history")) {
      // Delete in FK-safe order: children before parents
      await supabase.from("security_events").delete().neq("id", "00000000-0000-0000-0000-000000000000");
      await supabase.from("agent_actions").delete().neq("id", "00000000-0000-0000-0000-000000000000");
      await supabase.from("blocked_ips").delete().neq("id", "00000000-0000-0000-0000-000000000000");
      await supabase.from("incidents").delete().neq("id", "00000000-0000-0000-0000-000000000000");
      return new Response(JSON.stringify({ success: true, cleared: true }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // Unblock an IP
    if (path.endsWith("/unblock")) {
      const { ip, approved_by } = body as { ip: string; approved_by?: string };
      if (!ip) {
        return new Response(JSON.stringify({ error: "ip required" }), {
          status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      await supabase.from("blocked_ips").update({ is_active: false }).eq("ip", ip).eq("is_active", true);
      return new Response(JSON.stringify({ success: true, unblocked: ip }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ error: "Unknown endpoint" }), {
      status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (err) {
    console.error("incident-management error:", err);
    return new Response(
      JSON.stringify({ error: "Incident management service unavailable" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
