import type { CreateProjectRequest, Project } from '@/types/project'

const API_BASE = '/api'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...init?.headers,
    },
    ...init,
  })

  if (!response.ok) {
    const message = await response.text().catch(() => response.statusText)
    throw new Error(message || `Request failed (${response.status})`)
  }

  return response.json() as Promise<T>
}

export function createProject(data: CreateProjectRequest): Promise<Project> {
  return request<Project>('/projects', {
    method: 'POST',
    body: JSON.stringify(data),
  })
}

export function listProjects(): Promise<Project[]> {
  return request<Project[]>('/projects')
}
