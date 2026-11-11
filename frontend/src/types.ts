export const CLASSES = [
  "BENIGN",
  "BOTNET",
  "BRUTE_FORCE",
  "DDOS",
  "DOS",
  "PORTSCAN",
  "WEB_ATTACK",
] as const;
export type View =
  | "dashboard"
  | "alerts"
  | "traffic"
  | "logs"
  | "response"
  | "forensics"
  | "analytics"
  | "settings";
export type BlockStatus =
  "ACTIVE" | "UNBLOCK_REQUESTED" | "EXPIRY_PENDING" | "EXPIRED" | "UNBLOCKED";
export interface User {
  id: number;
  username: string;
  email: string;
  is_admin: boolean;
}
export interface Detection {
  id: number;
  event_id: string;
  observed_at: string;
  source: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: number;
  label: string;
  confidence: number;
  model_scope: string;
  model_run: string | null;
  model_sha256: string | null;
  sensor_id: string | null;
  decision_action: string;
  decision_reason: string | null;
}
export interface Block {
  id: number;
  block_id: string | null;
  sensor_id: string | null;
  ip: string;
  threat: string;
  mode: string;
  status: BlockStatus;
  blocked_at: string;
  unblock_at: string;
  unblocked_at: string | null;
  command: string[] | null;
}
export interface Stats {
  total_events: number;
  total_attacks: number;
  active_blocked_ips: number;
  active_simulated_blocks: number;
  pending_unblocks: number;
  threat_distribution: Record<string, number>;
  response_mode: string;
}
export interface Analytics {
  window_minutes: number;
  window_start: string;
  window_end: string;
  time_basis: string;
  total_flows: number;
  attack_flows: number;
  buckets: { start: string; end: string; total: number; attacks: number }[];
  protocols: { protocol: number; count: number }[];
  top_sources: { ip: string; count: number }[];
}
export interface Query {
  label: string;
  confidence: string;
  alertOffset: number;
  blockOffset: number;
  blockStatus: BlockStatus;
  minutes: number;
}
export interface DashboardData {
  stats: Stats | null;
  analytics: Analytics | null;
  alerts: Detection[];
  blocks: Block[];
  feed: Detection[];
  cidrs: string[];
  updatedAt: string | null;
}
export interface Notice {
  message: string;
  error: boolean;
}
export interface NewUser {
  username: string;
  email: string;
  password: string;
  is_admin: boolean;
}
