import { useEffect, useState } from "react";
import { Plus, Share2, Trash2 } from "lucide-react";
import { Link } from "@tanstack/react-router";
import { UserTab } from "@/components/UserTab";

import { listProjects, deleteProject } from "@/lib/api";
import type { Project, ProjectShare } from "@/types/project";
import { NewProjectModal } from "@/components/NewProjectModal";
import { ShareModal } from "@/components/ShareModal";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";

function formatDate(iso: string) {
  return new Date(iso).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

export function Dashboard() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Project | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [shareTarget, setShareTarget] = useState<Project | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const data = await listProjects();
        if (!cancelled) {
          setProjects(data);
          setLoadError(null);
        }
      } catch (err) {
        if (!cancelled) {
          setLoadError(
            err instanceof Error ? err.message : "Failed to load projects.",
          );
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    load();
    return () => { cancelled = true; };
  }, []);

  function handleProjectCreated(project: Project) {
    setProjects((current) => [project, ...current]);
  }

  function handleSharesChange(projectId: string, shares: ProjectShare[]) {
    setProjects((current) =>
      current.map((p) => (p.id === projectId ? { ...p, shares } : p))
    );
  }

  async function handleDeleteConfirm() {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await deleteProject(deleteTarget.id);
      setProjects((current) => current.filter((p) => p.id !== deleteTarget.id));
      setDeleteTarget(null);
    } catch {
      // keep dialog open on error; user can retry
    } finally {
      setDeleting(false);
    }
  }

  return (
    <>
    <div className="mx-auto flex min-h-svh w-full max-w-5xl flex-col px-6 py-10 text-left">
      <header className="mb-10 flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="text-sm font-medium uppercase tracking-wider text-primary">
            Aegis
          </p>
          <h1 className="mt-1 text-3xl font-semibold tracking-tight text-foreground">
            Projects
          </h1>
          <p className="mt-2 text-sm text-muted-foreground">
            Connect a public GitHub repository to map attack paths across your dependencies.
          </p>
        </div>
        <Button onClick={() => setModalOpen(true)}>
          <Plus className="h-4 w-4" />
          New project
        </Button>
      </header>

      {loading && (
        <p className="text-sm text-muted-foreground">Loading projects…</p>
      )}

      {loadError && (
        <div className="rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3 text-sm text-destructive">
          {loadError}
        </div>
      )}

      {!loading && !loadError && projects.length === 0 && (
        <div className="flex flex-1 flex-col items-center justify-center rounded-xl border border-dashed border-border bg-muted/20 px-6 py-16 text-center">
          <h2 className="text-lg font-medium text-foreground">No projects yet</h2>
          <p className="mt-2 max-w-sm text-sm text-muted-foreground">
            Create your first project by linking a public GitHub repository.
            We&apos;ll scan it for known vulnerabilities and build your attack-path graph.
          </p>
          <Button className="mt-6" onClick={() => setModalOpen(true)}>
            <Plus className="h-4 w-4" />
            New project
          </Button>
        </div>
      )}

      {!loading && projects.length > 0 && (
        <ul className="grid gap-4 sm:grid-cols-2">
          {projects.map((project) => (
            <li key={project.id} className="group relative">
              <Link
                to="/projects/$projectId"
                params={{ projectId: project.id }}
                className="block rounded-xl border border-border bg-card p-5 shadow-sm transition-colors hover:border-primary/40"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <h2 className="truncate font-medium text-foreground">
                      {project.name}
                    </h2>
                    <p className="mt-1 text-xs text-muted-foreground">
                      Created {formatDate(project.created_at)}
                    </p>
                  </div>
                  <div className="flex shrink-0 items-center gap-1.5">
                    {project.is_shared && (
                      <Badge variant="secondary" className="text-xs">Shared</Badge>
                    )}
                    <Badge variant={project.status === "analyzed" ? "default" : "secondary"}>
                      {project.status}
                    </Badge>
                  </div>
                </div>

                <div className="mt-4 flex flex-wrap items-center gap-2">
                  <Badge variant="outline">{project.ecosystem}</Badge>
                  {project.summary && (
                    <span className="text-xs text-muted-foreground">
                      {project.summary.vulnerable_packages} vulns ·{" "}
                      {project.summary.attack_paths} paths
                    </span>
                  )}
                  {!project.is_shared && (project.shares?.length ?? 0) > 0 && (
                    <span className="text-xs text-muted-foreground">
                      · shared with {project.shares!.length}
                    </span>
                  )}
                </div>
              </Link>

              {/* Action buttons — only for owned projects */}
              {!project.is_shared && (
                <div className="absolute right-3 top-3 flex items-center gap-0.5 opacity-0 transition-opacity group-hover:opacity-100">
                  <button
                    onClick={(e) => {
                      e.preventDefault();
                      setShareTarget(project);
                    }}
                    className="rounded-md p-1.5 text-muted-foreground hover:bg-muted hover:text-foreground"
                    aria-label={`Share ${project.name}`}
                  >
                    <Share2 className="h-3.5 w-3.5" />
                  </button>
                  <button
                    onClick={(e) => {
                      e.preventDefault();
                      setDeleteTarget(project);
                    }}
                    className="rounded-md p-1.5 text-muted-foreground hover:bg-destructive/10 hover:text-destructive"
                    aria-label={`Delete ${project.name}`}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}

      <NewProjectModal
        open={modalOpen}
        onOpenChange={setModalOpen}
        onCreated={handleProjectCreated}
      />

      {shareTarget && (
        <ShareModal
          project={shareTarget}
          open={!!shareTarget}
          onOpenChange={(open) => { if (!open) setShareTarget(null); }}
          onSharesChange={(shares) => handleSharesChange(shareTarget.id, shares)}
        />
      )}

      {/* Delete confirmation dialog */}
      <Dialog open={!!deleteTarget} onOpenChange={(open) => { if (!open) setDeleteTarget(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete project?</DialogTitle>
          </DialogHeader>
          <p className="text-sm text-muted-foreground">
            <span className="font-medium text-foreground">{deleteTarget?.name}</span> and all
            its vulnerability data will be permanently removed. This cannot be undone.
          </p>
          <DialogFooter className="mt-2 gap-2">
            <Button variant="outline" onClick={() => setDeleteTarget(null)} disabled={deleting}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleDeleteConfirm} disabled={deleting}>
              {deleting ? "Deleting…" : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
      <UserTab />
    </>
  );
}
