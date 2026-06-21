import { useState } from 'react'
import { GitBranch, Loader2 } from 'lucide-react'

import { createProject } from '@/lib/api'
import type { Project } from '@/types/project'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

type NewProjectModalProps = {
  open: boolean
  onOpenChange: (open: boolean) => void
  onCreated: (project: Project) => void
}

function parseGithubUrl(url: string): { owner: string; repo: string } | null {
  const cleaned = url.trim().replace(/\.git$/, '')
  const match = cleaned.match(/github\.com[/:]([\w.-]+)\/([\w.-]+)/)
  if (!match) return null
  return { owner: match[1], repo: match[2] }
}

async function isRepoPublic(owner: string, repo: string): Promise<boolean> {
  try {
    const res = await fetch(`https://api.github.com/repos/${owner}/${repo}`)
    if (!res.ok) return false
    const data = await res.json()
    return data.private === false
  } catch {
    return false
  }
}

export function NewProjectModal({
  open,
  onOpenChange,
  onCreated,
}: NewProjectModalProps) {
  const [repoUrl, setRepoUrl] = useState('')
  const [inputError, setInputError] = useState<string | null>(null)
  const [dialogError, setDialogError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  function resetForm() {
    setRepoUrl('')
    setInputError(null)
    setDialogError(null)
    setSubmitting(false)
  }

  function handleOpenChange(nextOpen: boolean) {
    if (!nextOpen) resetForm()
    onOpenChange(nextOpen)
  }

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault()
    setInputError(null)

    const parsed = parseGithubUrl(repoUrl)
    if (!parsed) {
      setInputError('Please enter a valid GitHub repository URL.')
      return
    }

    setSubmitting(true)

    const isPublic = await isRepoPublic(parsed.owner, parsed.repo)
    if (!isPublic) {
      setInputError('Repository must be public.')
      setDialogError(
        `"${parsed.owner}/${parsed.repo}" is private or doesn't exist. Only public repositories can be scanned.`,
      )
      setSubmitting(false)
      return
    }

    try {
      const project = await createProject({ github_url: repoUrl.trim() })
      onCreated(project)
      handleOpenChange(false)
    } catch (err) {
      setDialogError(
        err instanceof Error ? err.message : 'Failed to create project.',
      )
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <>
      <Dialog open={open} onOpenChange={handleOpenChange}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>New project</DialogTitle>
            <DialogDescription>
              Enter a public GitHub repository URL to scan for vulnerabilities.
            </DialogDescription>
          </DialogHeader>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="space-y-2">
              <Label htmlFor="repo-url">GitHub repository</Label>
              <div className="relative">
                <GitBranch className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground pointer-events-none" />
                <Input
                  id="repo-url"
                  placeholder="https://github.com/owner/repo"
                  value={repoUrl}
                  onChange={(e) => {
                    setRepoUrl(e.target.value)
                    if (inputError) setInputError(null)
                  }}
                  className={`pl-9 ${inputError ? 'border-destructive focus-visible:ring-destructive' : ''}`}
                  autoFocus
                  disabled={submitting}
                />
              </div>
              {inputError && (
                <p className="text-sm text-destructive" role="alert">
                  {inputError}
                </p>
              )}
            </div>

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => handleOpenChange(false)}
                disabled={submitting}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={submitting || !repoUrl.trim()}>
                {submitting ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Checking…
                  </>
                ) : (
                  'Create project'
                )}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog
        open={dialogError !== null}
        onOpenChange={() => setDialogError(null)}
      >
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Repository not accessible</DialogTitle>
            <DialogDescription>{dialogError}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button onClick={() => setDialogError(null)}>OK</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
