export type CheckStatus = 'PASS' | 'WARNING' | 'FAIL' | 'N/A' | 'WAIVED';

export interface CheckWaiver {
  id: string;
  reason: string;
  owner: string;
  expiresAt: string;
}

export interface SecurityCheck {
  id: string;
  parameter: string;
  category: 'Network & Port' | 'Access Control' | 'Endpoint Protection' | 'System Logging' | 'Kernel & Boot' | 'Cryptographic Posture' | 'Privilege Boundary';
  cis_id: string;
  status: CheckStatus;
  /** Status asli sebelum di-waive (untuk pemulihan). */
  baseStatus?: CheckStatus;
  waiver?: CheckWaiver;
  details: string;
  mitigation: string;
}

export interface ComplianceHistoryPoint {
  timestamp: string;
  score: number;
  passCount: number;
  warnCount: number;
  failCount: number;
  event: string;
}

export interface DeviceInfo {
  id: string;
  /** Version token untuk mencegah browser lama menimpa perubahan yang lebih baru. */
  revision?: number;
  /** Identitas agen/unit yang stabil, bila endpoint didaftarkan oleh agent. */
  agentId?: string;
  name: string;
  hostname: string;
  role: string;
  os: string;
  platformType: 'linux' | 'windows' | 'embedded';
  ip: string;
  mac: string;
  user: string;
  openPorts: number[];
  checks: SecurityCheck[];
  isQuarantined?: boolean;
  history?: ComplianceHistoryPoint[];
}

export interface AuditAgentResult {
  metadata: {
    scanner: string;
    timestamp: string;
    tactical_unit: string;
    standard_baseline: string;
  };
  device_info: {
    hostname: string;
    os: string;
    platform_type: string;
    primary_ip: string;
    mac_address: string;
    active_user: string;
    listening_ports_count: number;
    critical_ports_detected: number;
    ports_list: number[];
  };
  scoring: {
    cyber_readiness_score: number;
    passed_checks: number;
    warning_checks: number;
    failed_checks: number;
    total_checks: number;
  };
  compliance_matrix: Array<{
    parameter: string;
    category: string;
    cis_id: string;
    status: CheckStatus;
    details: string;
  }>;
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  deviceId: string;
  deviceName: string;
  deviceRole: string;
  action: 'HARDENING REMEDIATION' | 'ROLLBACK RESTORATION' | 'BASELINE RECON' | 'TELEMETRY INGESTION' | 'QUARANTINE KILL-SWITCH';
  operator: string;
  preScore: number;
  postScore: number;
  changesSummary: string;
  changesDetails: string[];
  status: 'SUCCESS' | 'WARNING' | 'FAILED';
  storedInDb: boolean;
  deletedAt?: string;
}

export type PlanStatus = 'PLANNED' | 'APPROVED' | 'EXECUTING' | 'VERIFIED' | 'ROLLED_BACK' | 'FAILED';

export interface RemediationPlanItem {
  findingId: string;
  alias: string;
  kind?: 'enforce' | 'advisory';
  title?: string;
  risk: 'LOW' | 'MEDIUM' | 'HIGH';
  reversible: boolean;
  preState?: string;
  postStateExpected?: string;
}

export interface RemediationEvidence {
  stepIndex: number;
  alias: string;
  exitCode: number;
  outputHash: string;
  output?: string;
  verified: boolean;
  advisory?: boolean;
  at?: string;
  rollback?: { exitCode: number; verified: boolean; outputHash: string };
}

export interface RemediationPlan {
  planId: string;
  deviceId: string;
  createdBy: string;
  createdAt: string;
  items: RemediationPlanItem[];
  status: PlanStatus;
  approvedBy?: string;
  approvedAt?: string;
  nonce?: string;
  expiresAt?: number;
  evidenceDeadline?: number;
  signature?: string;
  hasToken?: boolean;
  evidence?: RemediationEvidence[];
  updatedAt?: string;
  requiresConsoleAck?: boolean;
  accessNotes?: string[];
}
