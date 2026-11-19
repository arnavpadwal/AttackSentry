import type { Severity, SentryMode } from '@/config/constants';

/* ===== Auth ===== */
export interface User {
  id: string;
  email: string;
  username: string;
  full_name: string | null;
  role: 'admin' | 'analyst' | 'viewer';
  is_active: boolean;
  created_at?: string;
  last_login?: string | null;
}

/* ===== Alerts (detections) ===== */
export interface FrameworkMap {
  family: string;
  nist: { function: string; practice: string };
  iso: { control: string; title: string };
  owasp: { id: string; name: string } | null;
}

export interface Alert {
  id: string;
  incident_id: string | null;
  timestamp: string;
  severity: Severity;
  confidence: number;
  entity_risk: number;
  detection_type: string;
  anomaly_score: number;
  reason: string | null;
  status: string;
  assigned_to: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  dst_port: number | null;
  protocol: number | null;
  group_name: string | null;
  identity: string | null;
  device_type: string | null;
  process_name: string | null;
  subnet: string | null;
  primary_expert: string | null;
  expert_distribution: Record<string, number>;
  expert_probs: Record<string, number>;
  moe_score: number;
  raw_flow: Record<string, unknown>;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  mitre_description: string | null;
  frameworks: FrameworkMap;
}

export interface Incident {
  id: string;
  created_at: string;
  last_seen: string;
  entity: string;
  family: string;
  count: number;
  peak_signal: number;
  severity: Severity;
  status: string;
  resolved_at: string | null;
}

export interface IncidentSummary {
  total: number;
  open: number;
  acknowledged: number;
  resolved: number;
  by_severity: Record<string, number>;
  by_family: Record<string, number>;
}

export interface Playbook {
  id: string;
  detection_id: string | null;
  incident_id: string | null;
  created_at: string;
  attack_summary: string;
  technical_analysis: string | null;
  severity: string;
  confidence: string;
  mitre_attack: { tactic: string; technique: string; description: string };
  steps: PlaybookStep[];
  false_positive_assessment: string | null;
  is_fallback: boolean;
}

export interface PlaybookStep {
  step_id: number;
  title: string;
  description: string;
  action_type: string;
  target: string;
  priority: string;
  auto_executable: boolean;
  command_hint: string | null;
}

export interface AlertFilters {
  severity?: string;
  status?: string;
  expert?: string;
  entity?: string;
  range?: string;
  page?: number;
  page_size?: number;
}

/* ===== Hosts ===== */
export interface Host {
  id: string;
  ip_address: string;
  hostname: string | null;
  group_name: string | null;
  risk_score: number;
  status: string;
  identity: string | null;
  device_type: string | null;
  tags: string[];
  last_seen: string | null;
  baseline_status: string;
  os_info: string | null;
  created_at: string | null;
}

export interface HostDetail extends Host {
  alert_count: number;
  incident_count: number;
  total_bytes_24h: number;
  top_protocols: { protocol: string; bytes: number }[];
}

/* ===== Devices ===== */
export interface Device {
  id: string;
  hostname: string;
  ip: string;
  mac: string;
  os: string;
  fingerprint: string;
  status: 'pending' | 'approved' | 'rejected';
  whitelist: string[];
  blacklist: string[];
  timeout_hours: number | null;
  first_seen: number;
  approved_at: number | null;
  parent_device_id: string | null;
  custom_tag: string | null;
  approval_caveat: string | null;
}

/* ===== Flows (telemetry) ===== */
export interface Flow {
  timestamp: number;
  src_ip: string;
  dst_ip: string;
  dst_port: number;
  protocol: number;
  bytes_in: number;
  bytes_out: number;
}

/* ===== Sentry ===== */
export interface SentryStatus {
  mode: SentryMode;
  baseline_progress_pct: number;
  uptime_seconds: number;
  active_hosts: number;
  flows_processed: number;
  model_versions: Record<string, string>;
  moe_bundle_version: string;
  active_incidents: number;
  llm_healthy: boolean;
}

/* ===== Reports ===== */
export interface ReportResponse {
  title: string;
  generated_at: string;
  sections: { heading: string; body: string }[];
  metrics: Record<string, unknown>;
}

/* ===== Settings ===== */
export interface Settings {
  llm_provider: string;
  llm_base_url: string;
  llm_model: string;
  baseline_hours: number;
  default_alert_threshold: number;
  incident_window_seconds: number;
  suppression_window_seconds: number;
  retention_days: number;
  webhook_url: string;
  webhook_min_severity: 'low' | 'medium' | 'high' | 'critical';
  webhook_secret_configured: boolean;
  response_mode: 'disabled' | 'approval' | 'automatic';
  response_min_severity: 'low' | 'medium' | 'high' | 'critical';
  response_min_confidence: number;
  response_action: 'dynamic' | 'isolate_host' | 'block_ip' | 'rate_limit';
  response_ttl_minutes: number;
  response_auto_resolve: boolean;
}

export interface Mitigation {
  id: string; incident_id: string; entity: string;
  action: 'isolate_host' | 'block_ip' | 'rate_limit';
  mode: 'manual' | 'approval' | 'automatic';
  status: string; reason: string; requested_by: string | null;
  approved_by: string | null; created_at: string; expires_at: string | null;
  executed_at: string | null; provider_message: string | null;
}

export interface Sensor {
  id: string; name: string; sensor_type: string; hostname: string | null;
  ip_address: string | null; status: string; version: string | null;
  last_heartbeat: string | null; flows_per_second: number; total_flows: number;
  network_segments: string[]; created_at: string | null;
}

export interface SuppressionRule {
  id: string; name: string; entity: string | null; subnet: string | null;
  attack_family: string | null; reason: string; is_active: boolean; created_at: string | null;
}

/* ===== Traffic ===== */
export interface TrafficSummary {
  bytes_per_sec: number;
  packets_per_sec: number;
  active_flows: number;
  total_flows_24h: number;
  total_alerts_24h: number;
  critical_24h: number;
  high_24h: number;
  medium_24h: number;
  low_24h: number;
  entities_at_risk: number;
  active_sensors: number;
  threat_level: number;
}

export interface TimeSeries { timestamps: number[]; values: number[]; }

export interface PaginatedResponse<T> {
  items: T[]; total: number; page: number; page_size: number; total_pages: number;
}
