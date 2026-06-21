import { useEffect, useState } from "react";
import { Plus } from "lucide-react";

import { listProjects } from "@/lib/api";
import type { Project } from "@/types/project";
import { NewProjectModal } from "@/components/NewProjectModal";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

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
    return () => {
      cancelled = true;
    };
  }, []);

  function handleProjectCreated(project: Project) {
    setProjects((current) => [project, ...current]);
  }

  return (
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
          <h2 className="text-lg font-medium text-foreground">
            No projects yet
          </h2>
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
            <li
              key={project.id}
              className="rounded-xl border border-border bg-card p-5 shadow-sm transition-colors hover:border-primary/40"
            >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <h2 className="font-medium text-foreground">
                    {project.name}
                  </h2>
                  <p className="mt-1 text-xs text-muted-foreground">
                    Created {formatDate(project.created_at)}
                  </p>
                </div>
                <Badge
                  variant={
                    project.status === "analyzed" ? "default" : "secondary"
                  }
                >
                  {project.status}
                </Badge>
              </div>

              <div className="mt-4 flex flex-wrap items-center gap-2">
                <Badge variant="outline">{project.ecosystem}</Badge>
                {project.summary && (
                  <span className="text-xs text-muted-foreground">
                    {project.summary.vulnerable_packages} vulns ·{" "}
                    {project.summary.attack_paths} paths
                  </span>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}

      <NewProjectModal
        open={modalOpen}
        onOpenChange={setModalOpen}
        onCreated={handleProjectCreated}
      />
    </div>
  );
}
