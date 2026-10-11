export type RiskClassification = "SAFE" | "SUSPICIOUS" | "HIGH RISK";

export type RuleSeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface HttpAnalysis {
  scheme: string;
  is_encrypted: boolean;
  summary: string;
  detailed_explanation: string;
}

export interface TriggeredRule {
  rule_id: string;
  category: string;
  name: string;
  description: string;
  severity: RuleSeverity;
  penalty: number;
}

export interface AnalyzeResponse {
  url: string;
  risk_score: number;
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
}
