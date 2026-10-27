export type Verdict = "safe" | "unknown" | "suspicious" | "dangerous";

export type RecommendedAction =
  | "BLOCK"
  | "WARN_INTERSTITIAL"
  | "PROCEED_WITH_CAUTION"
  | "ALLOW"
  | "UNABLE_TO_VERIFY";

export type RiskClassification = "SAFE" | "SUSPICIOUS" | "HIGH RISK";

export type RuleSeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type EvidenceType = "confirmed" | "heuristic" | "inconclusive";

export type EvidenceSource = "local_heuristic" | "reputation_list" | "verified_signature";

export interface HttpAnalysis {
  scheme: string;
  is_encrypted: boolean;
  summary: string;
  detailed_explanation: string;
}

export interface TriggeredRule {
  id?: string;
  rule_id: string;
  category: string;
  name: string;
  description: string;
  severity: RuleSeverity;
  penalty: number;
  evidence_type?: EvidenceType;
  source?: EvidenceSource;
  confidence?: string;
}

export interface RiskPolicyConfig {
  block_threshold: number;
  warn_threshold: number;
  allow_override_on_warning: boolean;
}

export interface AnalyzeResponse {
  url: string;
  normalized_url?: string;
  hostname?: string;
  risk_score: number;
  verdict?: Verdict;
  confidence?: string;
  detection_reasons?: string[];
  recommended_action?: RecommendedAction;
  classification: RiskClassification;
  summary: string;
  http_analysis: HttpAnalysis;
  triggered_rules: TriggeredRule[];
  safe_indicators: string[];
  analyzed_at: string;
  engine_version: string;
}

export interface AnalyzeRequest {
  url: string;
}

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  host_restriction: string;
  risk_policy?: RiskPolicyConfig;
}

export interface ScanHistoryItem {
  id: string;
  url: string;
  domain: string;
  risk_score: number;
  verdict: Verdict;
  recommended_action: RecommendedAction;
  timestamp: string;
  detection_reasons: string[];
  eventType?: "scan" | "block" | "blocked" | "warning" | "unknown_publisher";
  ruleName?: string;
}
