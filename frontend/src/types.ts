// Mirrors the backend `Vulnerability` / `AnalyzeResponse` models (backend/models.py).

export interface Vulnerability {
  cve_id: string
  package: string
  version: string
  ecosystem: string
  cvss: number | null
  severity: string | null // critical | high | medium | low
  epss: number | null
  kev: boolean
  fixed_version: string | null
  summary: string
  aliases: string[]
  osv_url: string | null
}

export interface AnalysisReport {
  narrative: string
  chain_summary: string
  highest_risk_path: string
}

export interface AnalyzeResponse {
  project_id: string
  ecosystem: string | null
  report: AnalysisReport | null
  vulnerabilities: Vulnerability[]
  summary: Record<string, number>
}
