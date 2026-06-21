import { useRef, useState, type SetStateAction } from "react";
import { useNavigate } from "@tanstack/react-router";
import { ShieldCheck, Trash2, Share2 } from "lucide-react";
import type { Project } from "@/types/project";
import { Badge } from "@/components/ui/badge";

function formatDate(iso: string) {
  return new Date(iso).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

interface Props {
  project: Project;
  setShareTarget: (value: SetStateAction<Project | null>) => void;
  setDeleteTarget: (value: SetStateAction<Project | null>) => void;
}

export function TiltProjectCard({
  project,
  setDeleteTarget,
  setShareTarget,
}: Props) {
  const navigate = useNavigate();
  const wrapperRef = useRef<HTMLDivElement>(null);
  const cardRef = useRef<HTMLDivElement>(null);
  const shimmerRef = useRef<HTMLDivElement>(null);
  const [active, setActive] = useState(false);

  function onMove(e: React.MouseEvent<HTMLDivElement>) {
    if (!wrapperRef.current) return;
    const r = wrapperRef.current.getBoundingClientRect();
    const dx = (e.clientX - r.left) / r.width - 0.5;
    const dy = (e.clientY - r.top) / r.height - 0.5;
    if (cardRef.current) {
      // dy > 0 = cursor in bottom half → positive rotateX → top tilts toward viewer
      cardRef.current.style.transform = `rotateX(${dy * 22}deg) rotateY(${dx * 22}deg)`;
    }
    if (shimmerRef.current) {
      const sx = ((e.clientX - r.left) / r.width) * 100;
      const sy = ((e.clientY - r.top) / r.height) * 100;
      shimmerRef.current.style.background = `radial-gradient(circle at ${sx}% ${sy}%, rgba(255,255,255,0.11) 0%, transparent 58%)`;
    }
  }

  function onEnter() { setActive(true); }
  function onLeave() {
    setActive(false);
    if (cardRef.current) cardRef.current.style.transform = "rotateX(0deg) rotateY(0deg)";
  }

  const isAnalyzed = project.status === "analyzed";

  return (
    <div className="group relative">
      <div
        ref={wrapperRef}
        style={{ perspective: "900px" }}
        onMouseMove={onMove}
        onMouseEnter={onEnter}
        onMouseLeave={onLeave}
      >
        {/* Card is a plain div — useNavigate handles navigation on click.
            No Link ancestor means buttons receive pointer events cleanly. */}
        <div
          ref={cardRef}
          onClick={() => navigate({ to: "/projects/$projectId", params: { projectId: project.id } })}
          style={{
            transition: active
              ? "transform 0.001s linear, box-shadow 0.3s ease"
              : "transform 0.6s cubic-bezier(0.23,1,0.32,1), box-shadow 0.6s ease",
            borderRadius: "16px",
            boxShadow: active
              ? "0 24px 60px rgba(59,130,246,0.14), 0 8px 28px rgba(0,0,0,0.55)"
              : "0 4px 20px rgba(0,0,0,0.35)",
            cursor: "pointer",
          }}
          className="relative bg-card"
        >
          {/* Visual overlays */}
          <div
            style={{
              position: "absolute",
              inset: 0,
              borderRadius: "inherit",
              overflow: "hidden",
              pointerEvents: "none",
            }}
          >
            <div
              style={{
                position: "absolute",
                inset: 0,
                opacity: 0.04,
                mixBlendMode: "screen",
                backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='200' height='200'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='3'/%3E%3C/filter%3E%3Crect width='200' height='200' filter='url(%23n)' opacity='0.7'/%3E%3C/svg%3E")`,
                backgroundRepeat: "repeat",
                backgroundSize: "180px",
              }}
            />
            <div
              style={{
                position: "absolute",
                inset: 0,
                background: `
                  radial-gradient(ellipse at 78% 12%, rgba(59,130,246,0.20) 0%, transparent 52%),
                  radial-gradient(ellipse at 12% 88%, rgba(37,99,235,0.11) 0%, transparent 52%)
                `,
                opacity: active ? 1 : 0.5,
                transition: "opacity 0.4s ease",
              }}
            />
            <div
              ref={shimmerRef}
              style={{
                position: "absolute",
                inset: 0,
                mixBlendMode: "screen",
                opacity: active ? 1 : 0,
                transition: "opacity 0.25s ease",
              }}
            />
            <div
              style={{
                position: "absolute",
                inset: 0,
                background:
                  "linear-gradient(135deg, rgba(255,255,255,0.055) 0%, transparent 50%, rgba(255,255,255,0.018) 100%)",
                opacity: active ? 1 : 0,
                transition: "opacity 0.4s ease",
              }}
            />
          </div>

          {/* Content — no preserve-3d so children are in 2D and receive pointer events normally */}
          <div
            style={{
              position: "relative",
              zIndex: 1,
            }}
            className="p-6 flex flex-col justify-between"
          >
            {/* Tag row */}
            <div className="mb-4 flex items-center gap-2">
              <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-primary/80">
                {project.ecosystem}
              </span>
              <div className="h-px flex-1" style={{ background: "rgba(255,255,255,0.06)" }} />
            </div>

            <div className="flex flex-row justify-between items-center">
              <div>
                <h3 className="mb-1 truncate text-[15px] font-semibold leading-snug text-foreground">
                  {project.name}
                </h3>
                <p className="text-xs text-muted-foreground">
                  Created {formatDate(project.created_at)}
                </p>
              </div>
              <div className="mb-4 flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary ring-1 ring-primary/20">
                <ShieldCheck className="h-5 w-5" />
              </div>
            </div>

            {project.is_shared && project.shared_by_email && (
              <p className="mt-1 text-xs text-muted-foreground">
                Shared with you by{" "}
                <span className="text-foreground/70">{project.shared_by_email}</span>
              </p>
            )}
            {!project.is_shared && project.shares && project.shares.length > 0 && (
              <p className="mt-1 text-xs text-muted-foreground">
                Shared with{" "}
                <span className="text-foreground/70">
                  {project.shares[0].shared_with_email}
                  {project.shares.length > 1 && ` +${project.shares.length - 1} more`}
                </span>
              </p>
            )}

            <div
              style={{ borderTop: "1px solid rgba(255,255,255,0.06)" }}
              className="mt-5 flex items-center justify-between pt-4"
            >
              {project.summary ? (
                <div className="flex gap-4">
                  <div>
                    <p className="text-lg font-semibold leading-none text-foreground">
                      {project.summary.vulnerable_packages}
                    </p>
                    <p className="mt-0.5 text-[10px] tracking-wide text-muted-foreground">
                      vulnerabilities
                    </p>
                  </div>
                  <div>
                    <p className="text-lg font-semibold leading-none text-foreground">
                      {project.summary.attack_paths}
                    </p>
                    <p className="mt-0.5 text-[10px] tracking-wide text-muted-foreground">
                      attack paths
                    </p>
                  </div>
                </div>
              ) : (
                <Badge variant={isAnalyzed ? "default" : "secondary"} className="text-[12px]">
                  {project.status}
                </Badge>
              )}

              {!project.is_shared && (
                <div className="flex items-center gap-4">
                  <button
                    onClick={(e) => { e.stopPropagation(); setShareTarget(project); }}
                    className="rounded-full p-2.5 text-muted-foreground ring-1 ring-white/10 transition-colors hover:bg-primary/10 hover:text-primary"
                    aria-label={`Share ${project.name}`}
                  >
                    <Share2 className="h-3.5 w-3.5" />
                  </button>
                  <button
                    onClick={(e) => { e.stopPropagation(); setDeleteTarget(project); }}
                    className="rounded-full p-2.5 text-muted-foreground hover:bg-destructive/10 hover:text-destructive ring-1 ring-white/10 transition-colors"
                    aria-label={`Delete ${project.name}`}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
