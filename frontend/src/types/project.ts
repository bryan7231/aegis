export type Vulnerability = {
  cve_id: string
  package: string
  version: string
  ecosystem: string
  cvss: number | null
  severity: string | null
  epss: number | null
  kev: boolean
  fixed_version: string | null
  summary: string
  aliases: string[]
  osv_url: string | null
  cwe_ids?: string[]
  attack_vector?: string | null
  attack_complexity?: string | null
  privileges_required?: string | null
  user_interaction?: string | null
  scope?: string | null
}

export type VulnNode = {
  id: string
  source: "dependency" | "code"
  title: string
  description: string | null
  severity: string | null
  cvss: number | null
  cwe_ids: string[]
  remediation: string | null
  centrality_score: number
  // dependency fields
  cve_id: string | null
  package: string | null
  version: string | null
  ecosystem: string | null
  epss: number | null
  kev: boolean
  fixed_version: string | null
  osv_url: string | null
  attack_vector: string | null
  attack_complexity: string | null
  privileges_required: string | null
  user_interaction: string | null
  scope: string | null
  // code finding fields
  file_path: string | null
  line_start: number | null
  line_end: number | null
  vuln_category: string | null
  affected_code: string | null
}

export type VulnEdge = {
  id: string
  source_id: string
  target_id: string
  edge_type: string
  confidence: number
  description: string
}

export type VulnGraph = {
  nodes: VulnNode[]
  edges: VulnEdge[]
}

export type AnalysisReport = {
  narrative: string
  chain_summary: string
  highest_risk_path: string
}

export type AnalysisResult = {
  project_id: string
  status: string             // "analyzing" | "complete"
  ecosystem: string | null
  report: AnalysisReport | null
  vulnerabilities: Vulnerability[]
  graph: VulnGraph | null
  summary: Record<string, number>
}

export type ProjectStatus = 'pending' | 'analyzed'

export type ProjectSummary = {
  vulnerable_packages: number
  attack_paths: number
  fixes_needed: number
}

export type Project = {
  id: string
  name: string
  ecosystem: string
  created_at: string
  status: ProjectStatus
  summary?: ProjectSummary
}

export type CreateProjectRequest = {
  github_url: string
}
