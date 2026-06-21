import { useRef, useState } from "react";
import { Link } from "@tanstack/react-router";
import { ArrowUpRight, ShieldCheck, Trash2 } from "lucide-react";
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
  onDelete: () => void;
}

export function TiltProjectCard({ project, onDelete }: Props) {
  const wrapperRef = useRef<HTMLDivElement>(null);
  const [rot, setRot] = useState({ x: 0, y: 0 });
  const [shimmer, setShimmer] = useState({ x: 50, y: 50 });
  const [active, setActive] = useState(false);

  function onMove(e: React.MouseEvent<HTMLDivElement>) {
    if (!wrapperRef.current) return;
    const r = wrapperRef.current.getBoundingClientRect();
    const dx = (e.clientX - r.left) / r.width - 0.5; // –0.5 … 0.5
    const dy = (e.clientY - r.top) / r.height - 0.5;
    setRot({ x: -dy * 14, y: dx * 14 });
    setShimmer({
      x: ((e.clientX - r.left) / r.width) * 100,
      y: ((e.clientY - r.top) / r.height) * 100,
    });
  }

  function onEnter() {
    setActive(true);
  }
  function onLeave() {
    setActive(false);
    setRot({ x: 0, y: 0 });
  }

  const isAnalyzed = project.status === "analyzed";

  return (
    <div className="group relative">
      {/* Perspective wrapper — mouse events live here */}
      <div
        ref={wrapperRef}
        style={{ perspective: "900px" }}
        onMouseMove={onMove}
        onMouseEnter={onEnter}
        onMouseLeave={onLeave}
      >
        <Link
          to="/projects/$projectId"
          params={{ projectId: project.id }}
          className="block focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring rounded-2xl"
        >
          {/* ── Tilting card ──────────────────────────────────────── */}
          <div
            style={{
              transform: `rotateX(${rot.x}deg) rotateY(${rot.y}deg)`,
              transition: active
                ? "transform 0.001s linear, box-shadow 0.3s ease"
                : "transform 0.6s cubic-bezier(0.23,1,0.32,1), box-shadow 0.6s ease",
              transformStyle: "preserve-3d",
              borderRadius: "16px",
              boxShadow: active
                ? "0 24px 60px rgba(59,130,246,0.14), 0 8px 28px rgba(0,0,0,0.55)"
                : "0 4px 20px rgba(0,0,0,0.35)",
            }}
            className="relative bg-card"
          >
            {/* Visual layers — clipped by this inner overflow wrapper */}
            <div
              style={{
                position: "absolute",
                inset: 0,
                borderRadius: "inherit",
                overflow: "hidden",
                pointerEvents: "none",
              }}
            >
              {/* Noise grain */}
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

              {/* Mesh gradients */}
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

              {/* Cursor shimmer */}
              <div
                style={{
                  position: "absolute",
                  inset: 0,
                  background: `radial-gradient(circle at ${shimmer.x}% ${shimmer.y}%, rgba(255,255,255,0.11) 0%, transparent 58%)`,
                  mixBlendMode: "screen",
                  opacity: active ? 1 : 0,
                  transition: "opacity 0.25s ease",
                }}
              />

              {/* Fixed glare */}
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

            {/* ── Content (3-D floating layer) ─────────────────── */}
            <div
              style={{
                position: "relative",
                zIndex: 1,
                transform: active ? "translateZ(20px)" : "translateZ(0)",
                transition: "transform 0.3s ease",
                transformStyle: "preserve-3d",
              }}
              className="p-6"
            >
              {/* Tag row */}
              <div className="mb-4 flex items-center gap-2">
                <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-primary/80">
                  {project.ecosystem}
                </span>
                <div
                  className="h-px flex-1"
                  style={{ background: "rgba(255,255,255,0.06)" }}
                />
              </div>

              {/* Icon — deepest translateZ */}
              <div
                style={{
                  transform: active ? "translateZ(40px)" : "translateZ(0)",
                  transition: "transform 0.3s ease",
                }}
                className="mb-4 flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary ring-1 ring-primary/20"
              >
                <ShieldCheck className="h-5 w-5" />
              </div>

              {/* Title */}
              <h3
                style={{
                  transform: active ? "translateZ(28px)" : "translateZ(0)",
                  transition: "transform 0.3s ease",
                }}
                className="mb-1 truncate text-[15px] font-semibold leading-snug text-foreground"
              >
                {project.name}
              </h3>

              {/* Date */}
              <p className="text-xs text-muted-foreground">
                Created {formatDate(project.created_at)}
              </p>

              {/* Footer */}
              <div
                style={{
                  transform: active ? "translateZ(16px)" : "translateZ(0)",
                  transition: "transform 0.3s ease",
                  borderTop: "1px solid rgba(255,255,255,0.06)",
                }}
                className="mt-5 flex items-end justify-between pt-4"
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
                  <Badge
                    variant={isAnalyzed ? "default" : "secondary"}
                    className="text-[10px]"
                  >
                    {project.status}
                  </Badge>
                )}

                {/* Arrow button — highest translateZ */}
                <div
                  style={{
                    transform: active
                      ? "translateZ(50px) scale(1.05)"
                      : "translateZ(0) scale(1)",
                    transition: "transform 0.3s ease",
                  }}
                  className="flex h-7 w-7 items-center justify-center rounded-full bg-white/5 text-muted-foreground ring-1 ring-white/10 transition-colors group-hover:bg-primary/10 group-hover:text-primary"
                >
                  <ArrowUpRight className="h-3.5 w-3.5" />
                </div>
              </div>
            </div>
          </div>
        </Link>
      </div>

      {/* Delete — sits on top, outside the Link */}
      <button
        onClick={(e) => {
          e.stopPropagation();
          onDelete();
        }}
        className="absolute right-3 top-3 z-10 rounded-md p-1.5 text-muted-foreground opacity-0 transition-opacity hover:bg-destructive/10 hover:text-destructive group-hover:opacity-100"
        aria-label={`Delete ${project.name}`}
      >
        <Trash2 className="h-3.5 w-3.5" />
      </button>
    </div>
  );
}
