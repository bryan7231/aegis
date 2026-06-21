import type { AnalysisResult, CreateProjectRequest, Project, VulnGraph } from "@/types/project";

const API_BASE = import.meta.env.VITE_API_URL ?? "";

type TokenGetter = () => Promise<string | null>;
let _getToken: TokenGetter | null = null;

export function configureAuth(fn: TokenGetter) {
  _getToken = fn;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = _getToken ? await _getToken() : null;

  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init?.headers,
    },
  });

  if (!response.ok) {
    const message = await response.text().catch(() => response.statusText);
    throw new Error(message || `Request failed (${response.status})`);
  }

  return response.json() as Promise<T>;
}

export function createProject(data: CreateProjectRequest): Promise<Project> {
  return request<Project>("/projects", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function listProjects(): Promise<Project[]> {
  return request<Project[]>("/projects");
}

export function getProjectVulnerabilities(projectId: string): Promise<AnalysisResult> {
  return request<AnalysisResult>(`/projects/${projectId}/vulnerabilities`);
}

export function getProjectGraph(projectId: string): Promise<VulnGraph> {
  return request<VulnGraph>(`/projects/${projectId}/graph`);
}

export async function deleteProject(projectId: string): Promise<void> {
  await request<unknown>(`/projects/${projectId}`, { method: "DELETE" });
}
