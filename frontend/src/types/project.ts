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

export type CreateProjectFile = {
  filename: string
  content: string
}

export type CreateProjectRequest = {
  name: string
  files: CreateProjectFile[]
}
