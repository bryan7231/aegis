import { useEffect, useState } from "react";
import { Plus, ShieldAlert } from "lucide-react";
import { UserTab } from "@/components/UserTab";

import { listProjects, deleteProject } from "@/lib/api";
import type { Project, ProjectShare } from "@/types/project";
import { NewProjectModal } from "@/components/NewProjectModal";
import { TiltProjectCard } from "@/components/TiltProjectCard";
import { ShareModal } from "@/components/ShareModal";
import { Button } from "@/components/ui/button";
import logo from "@/assets/logo_white.png";

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Empty,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
  EmptyDescription,
  EmptyContent,
} from "@/components/ui/empty";

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
        if (!cancelled) setLoading(false);
      }
    }

    load();
    return () => {
      cancelled = true;
    };
  }, []);

  function handleProjectCreated(project: Project) {
    setProjects((current) => [project, ...current]);
  }

  function handleSharesChange(projectId: string, shares: ProjectShare[]) {
    setProjects((current) =>
      current.map((p) => (p.id === projectId ? { ...p, shares } : p)),
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
      // keep dialog open on error
    } finally {
      setDeleting(false);
    }
  }

  return (
    <>
      <div className="mx-auto flex min-h-svh w-full max-w-5xl flex-col px-6 py-8 text-left">
        {/* Brand nav */}
        <nav className="mb-10 flex items-center justify-between border-b border-border pb-5">
          <div className="w-30 h-7.5 overflow-hidden relative self-end -mb-2">
            <img
              src={logo}
              alt="Website logo"
              className="absolute right-3.5 top-1/2 -translate-y-1/2 w-[110%] max-w-none h-full object-cover"
            />
          </div>
          <Button onClick={() => setModalOpen(true)} size="sm">
            <Plus className="h-3.5 w-3.5" />
            New project
          </Button>
        </nav>

        {/* Page heading */}
        <div className="mb-8">
          <h1 className="text-3xl font-semibold tracking-tight">Projects</h1>
          <p className="mt-2 text-sm text-muted-foreground">
            Connect a public GitHub repository to map attack paths across your
            dependencies.
          </p>
        </div>

        {loading && (
          <p className="text-sm text-muted-foreground">Loading projects…</p>
        )}

        {loadError && (
          <div className="rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3 text-sm text-destructive">
            {loadError}
          </div>
        )}

        {!loading && !loadError && projects.length === 0 && (
          <Empty className="flex-1 justify-center rounded-xl border border-dashed border-border py-20">
            <EmptyHeader>
              <EmptyMedia
                variant="icon"
                className="bg-linear-to-br from-blue-500/20 to-blue-900/5 border-blue-500/25 text-blue-400"
              >
                <ShieldAlert className="h-5 w-5" />
              </EmptyMedia>
              <EmptyTitle>No projects yet</EmptyTitle>
              <EmptyDescription>
                Create your first project by linking a public GitHub repository.
                We&apos;ll scan it for known vulnerabilities and build your
                attack-path graph.
              </EmptyDescription>
            </EmptyHeader>
            <EmptyContent>
              <Button onClick={() => setModalOpen(true)}>
                <Plus className="h-4 w-4" />
                New project
              </Button>
            </EmptyContent>
          </Empty>
        )}

        {!loading && projects.length > 0 && (
          <ul className="grid gap-4 sm:grid-cols-2">
            {projects.map((project) => (
              <li key={project.id}>
                <TiltProjectCard
                  project={project}
                  setDeleteTarget={setDeleteTarget}
                  setShareTarget={setShareTarget}
                />
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
            onOpenChange={(open) => {
              if (!open) setShareTarget(null);
            }}
            onSharesChange={(shares) =>
              handleSharesChange(shareTarget.id, shares)
            }
          />
        )}

        {/* Delete confirmation dialog */}
        <Dialog
          open={!!deleteTarget}
          onOpenChange={(open) => {
            if (!open) setDeleteTarget(null);
          }}
        >
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Delete project?</DialogTitle>
            </DialogHeader>
            <p className="text-sm text-muted-foreground">
              <span className="font-medium text-foreground">
                {deleteTarget?.name}
              </span>{" "}
              and all its vulnerability data will be permanently removed. This
              cannot be undone.
            </p>
            <DialogFooter className="mt-2 gap-2">
              <Button
                variant="outline"
                onClick={() => setDeleteTarget(null)}
                disabled={deleting}
              >
                Cancel
              </Button>
              <Button
                variant="destructive"
                onClick={handleDeleteConfirm}
                disabled={deleting}
              >
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
