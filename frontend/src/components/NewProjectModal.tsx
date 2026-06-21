import { useId, useRef, useState } from 'react'
import { FileUp, Loader2 } from 'lucide-react'

import { createProject } from '@/lib/api'
import {
  detectEcosystem,
  isSupportedLockfile,
  SUPPORTED_LOCKFILES,
} from '@/lib/lockfile'
import type { Project } from '@/types/project'
import { Badge } from '@/components/ui/badge'
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
import { Textarea } from '@/components/ui/textarea'

type NewProjectModalProps = {
  open: boolean
  onOpenChange: (open: boolean) => void
  onCreated: (project: Project) => void
}

type LockfileState = {
  filename: string
  content: string
}

export function NewProjectModal({
  open,
  onOpenChange,
  onCreated,
}: NewProjectModalProps) {
  const nameId = useId()
  const fileId = useId()
  const pasteId = useId()
  const fileInputRef = useRef<HTMLInputElement>(null)

  const [name, setName] = useState('')
  const [lockfile, setLockfile] = useState<LockfileState | null>(null)
  const [pasteFilename, setPasteFilename] = useState('package-lock.json')
  const [pasteContent, setPasteContent] = useState('')
  const [inputMode, setInputMode] = useState<'upload' | 'paste'>('upload')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  const activeFilename =
    inputMode === 'upload' ? lockfile?.filename : pasteFilename.trim()
  const activeContent =
    inputMode === 'upload' ? lockfile?.content : pasteContent.trim()
  const detectedEcosystem = activeFilename
    ? detectEcosystem(activeFilename)
    : null

  function resetForm() {
    setName('')
    setLockfile(null)
    setPasteFilename('package-lock.json')
    setPasteContent('')
    setInputMode('upload')
    setError(null)
    setSubmitting(false)
    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
  }

  function handleOpenChange(nextOpen: boolean) {
    if (!nextOpen) {
      resetForm()
    }
    onOpenChange(nextOpen)
  }

  async function handleFileChange(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    if (!file) return

    if (!isSupportedLockfile(file.name)) {
      setError(
        `Unsupported file. Use one of: ${SUPPORTED_LOCKFILES.join(', ')}`,
      )
      setLockfile(null)
      return
    }

    const content = await file.text()
    setLockfile({ filename: file.name, content })
    setError(null)

    if (!name.trim()) {
      const baseName = file.name.replace(
        /\.(json|lock|yaml|txt|sum)$/i,
        '',
      )
      setName(baseName)
    }
  }

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault()
    setError(null)

    const trimmedName = name.trim()
    if (!trimmedName) {
      setError('Project name is required.')
      return
    }

    if (!activeFilename || !activeContent) {
      setError('Upload or paste a lockfile to continue.')
      return
    }

    if (!isSupportedLockfile(activeFilename)) {
      setError(
        `Unsupported file. Use one of: ${SUPPORTED_LOCKFILES.join(', ')}`,
      )
      return
    }

    setSubmitting(true)

    try {
      const project = await createProject({
        name: trimmedName,
        files: [{ filename: activeFilename, content: activeContent }],
      })
      onCreated(project)
      handleOpenChange(false)
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Failed to create project.',
      )
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>New project</DialogTitle>
          <DialogDescription>
            Name your project and provide a dependency lockfile. We&apos;ll
            auto-detect the ecosystem from the filename.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-5">
          <div className="space-y-2">
            <Label htmlFor={nameId}>Project name</Label>
            <Input
              id={nameId}
              placeholder="my-discord-bot"
              value={name}
              onChange={(event) => setName(event.target.value)}
              autoFocus
            />
          </div>

          <div className="space-y-3">
            <div className="flex items-center justify-between gap-2">
              <Label>Lockfile</Label>
              <div className="flex rounded-md border border-input p-0.5 text-xs">
                <button
                  type="button"
                  className={`rounded px-2.5 py-1 transition-colors ${
                    inputMode === 'upload'
                      ? 'bg-primary text-primary-foreground'
                      : 'text-muted-foreground hover:text-foreground'
                  }`}
                  onClick={() => setInputMode('upload')}
                >
                  Upload
                </button>
                <button
                  type="button"
                  className={`rounded px-2.5 py-1 transition-colors ${
                    inputMode === 'paste'
                      ? 'bg-primary text-primary-foreground'
                      : 'text-muted-foreground hover:text-foreground'
                  }`}
                  onClick={() => setInputMode('paste')}
                >
                  Paste
                </button>
              </div>
            </div>

            {inputMode === 'upload' ? (
              <div className="space-y-2">
                <label
                  htmlFor={fileId}
                  className="flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-input bg-muted/30 px-4 py-8 text-center transition-colors hover:bg-muted/50"
                >
                  <FileUp className="h-8 w-8 text-muted-foreground" />
                  <span className="text-sm font-medium text-foreground">
                    {lockfile
                      ? lockfile.filename
                      : 'Click to upload a lockfile'}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    package-lock.json, yarn.lock, Cargo.lock, and more
                  </span>
                  <Input
                    ref={fileInputRef}
                    id={fileId}
                    type="file"
                    accept=".json,.lock,.yaml,.txt,.sum"
                    className="hidden"
                    onChange={handleFileChange}
                  />
                </label>
              </div>
            ) : (
              <div className="space-y-3">
                <div className="space-y-2">
                  <Label htmlFor={pasteId}>Filename</Label>
                  <Input
                    id={pasteId}
                    placeholder="package-lock.json"
                    value={pasteFilename}
                    onChange={(event) => setPasteFilename(event.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor={`${pasteId}-content`}>File contents</Label>
                  <Textarea
                    id={`${pasteId}-content`}
                    placeholder="Paste your lockfile contents here…"
                    value={pasteContent}
                    onChange={(event) => setPasteContent(event.target.value)}
                    className="min-h-[160px] font-mono text-xs"
                  />
                </div>
              </div>
            )}

            {detectedEcosystem && (
              <div className="flex items-center gap-2 text-sm">
                <span className="text-muted-foreground">Detected:</span>
                <Badge variant="secondary">{detectedEcosystem}</Badge>
              </div>
            )}
          </div>

          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => handleOpenChange(false)}
              disabled={submitting}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={submitting}>
              {submitting ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Creating…
                </>
              ) : (
                'Create project'
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
