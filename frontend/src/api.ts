import type { AnalyzeResponse } from './types'

const API_BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'

/** Fetch the cached analysis (vulnerability list + report) for a project. */
export async function getAnalysis(projectId: string): Promise<AnalyzeResponse> {
  const res = await fetch(`${API_BASE}/projects/${projectId}/analysis`)
  if (!res.ok) {
    if (res.status === 404) {
      throw new Error('No analysis found for this project. Run "Analyze DB" first.')
    }
    throw new Error(`Failed to load analysis (${res.status})`)
  }
  return res.json()
}
