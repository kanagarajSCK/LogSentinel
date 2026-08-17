export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type IncidentStatus = 'NEW' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';
export type LoginStatus = 'SUCCESS' | 'FAILED' | 'BLOCKED';

export interface SecurityEvent {
  id: string;
  event_id: string;
  event_type: string;
  username: string | null;
  login_status: LoginStatus | null;
  source_ip: string | null;
  user_agent: string | null;
  request_id: string | null;
  severity: string;
  detail: string | null;
  raw: Record<string, unknown> | null;
  incident_id: string | null;
  created_at: string;
}

export interface Incident {
  id: string;
  incident_id: string;
  detection_type: string;
  severity: Severity;
  status: IncidentStatus;
  source_ip: string | null;
  username: string | null;
  first_detected_at: string;
  last_detected_at: string;
  event_count: number;
  evidence: Record<string, unknown>[];
  detection_reason: string | null;
  ai_analysis: AIAnalysis | null;
  recommended_action: string | null;
  recommended_action_type: string | null;
  created_at: string;
  updated_at: string;
}

export interface AIAnalysis {
  summary: string;
  severity: Severity;
  reasoning: string;
  evidence: string[];
  recommended_action: string;
  confidence: number;
  source: 'llm' | 'rule-based';
  fallback_reason?: string;
}

export interface BlockedIP {
  id: string;
  ip: string;
  reason: string | null;
  blocked_by: string | null;
  incident_id: string | null;
  is_active: boolean;
  blocked_at: string;
  expires_at: string | null;
  created_at: string;
}

export interface AgentAction {
  id: string;
  action_id: string;
  incident_id: string;
  action_type: string;
  description: string | null;
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
  approved_by: string | null;
  approved_at: string | null;
  executed_at: string | null;
  result: Record<string, unknown> | null;
  created_at: string;
}

export interface AppUser {
  username: string;
  display_name: string | null;
  role: string | null;
}

export interface DashboardStats {
  totalEvents: number;
  failedLogins: number;
  successfulLogins: number;
  activeIncidents: number;
  highRiskIncidents: number;
}
