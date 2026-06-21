import { useMemo } from "react";
import type { VulnNode, VulnEdge } from "@/types/project";

// ── Scoring ───────────────────────────────────────────────────────────────────

interface ScoredNode {
  node: VulnNode;
  edgeCount: number;
  score: number;
  components: {
    cvss: number;
    centrality: number;
    epss: number;
    kev: number;
    network: number;
  };
}

const W = { cvss: 0.30, centrality: 0.25, epss: 0.20, kev: 0.15, network: 0.10 };

function scoreNode(node: VulnNode, edgeCount: number): ScoredNode {
  const components = {
    cvss:       ((node.cvss ?? 0) / 10) * W.cvss,
    centrality: node.centrality_score * W.centrality,
    epss:       (node.epss ?? 0) * W.epss,
    kev:        (node.kev ? 1 : 0) * W.kev,
    network:    (node.attack_vector === "Network" ? 1 : 0) * W.network,
  };
  return {
    node,
    edgeCount,
    score: components.cvss + components.centrality + components.epss + components.kev + components.network,
    components,
  };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const SEVERITY_COLOR: Record<string, string> = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#22c55e",
};

function priorityLabel(score: number): { label: string; color: string; bg: string } {
  if (score >= 0.65) return { label: "Fix immediately", color: "text-red-600 dark:text-red-400",    bg: "bg-red-500/10" };
  if (score >= 0.45) return { label: "Fix soon",        color: "text-orange-600 dark:text-orange-400", bg: "bg-orange-500/10" };
  if (score >= 0.25) return { label: "Fix when able",   color: "text-amber-700 dark:text-amber-400",   bg: "bg-amber-500/10" };
  return               { label: "Monitor",             color: "text-green-700 dark:text-green-400",   bg: "bg-green-500/10" };
}

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-red-500/15 text-red-500",
  high:     "bg-orange-500/15 text-orange-600 dark:text-orange-500",
  medium:   "bg-amber-500/15 text-amber-700 dark:text-amber-400",
  low:      "bg-green-500/15 text-green-700 dark:text-green-500",
  unknown:  "bg-muted text-muted-foreground",
};

function nodeSeverity(node: VulnNode): string {
  if (node.severity) return node.severity.toLowerCase();
  if (node.cvss == null) return "unknown";
  if (node.cvss >= 9) return "critical";
  if (node.cvss >= 7) return "high";
  if (node.cvss >= 4) return "medium";
  return "low";
}

// Narrow bar showing a score component's raw contribution (0–W[key]).
function ScoreBar({ value, max, label }: { value: number; max: number; label: string }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0;
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="w-24 shrink-0 text-muted-foreground">{label}</span>
      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted">
        <div
          className="h-full rounded-full bg-primary/60 transition-all"
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="w-8 text-right font-mono text-muted-foreground">
        {Math.round(value * 100)}
      </span>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export function TriageView({ nodes, edges }: { nodes: VulnNode[]; edges: VulnEdge[] }) {
  const scored = useMemo<ScoredNode[]>(() => {
    // Build edge count map
    const counts: Record<string, number> = {};
    for (const e of edges) {
      counts[e.source_id] = (counts[e.source_id] ?? 0) + 1;
      counts[e.target_id] = (counts[e.target_id] ?? 0) + 1;
    }
    return nodes
      .map((n) => scoreNode(n, counts[n.id] ?? 0))
      .sort((a, b) => b.score - a.score);
  }, [nodes, edges]);

  if (scored.length === 0) {
    return (
      <div className="py-16 text-center text-sm text-muted-foreground">
        No vulnerability data to triage yet.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <p className="text-xs text-muted-foreground">
        Ranked by a weighted score: severity (30%) · exploit-chain centrality (25%) ·
        exploitation probability (20%) · active exploitation (15%) · network exposure (10%).
      </p>

      {scored.map(({ node, edgeCount, score, components }, idx) => {
        const tier = nodeSeverity(node);
        const priority = priorityLabel(score);
        const severityColor = SEVERITY_COLOR[tier] ?? "#94a3b8";

        return (
          <div
            key={node.id}
            className="rounded-xl border border-border bg-card p-5 shadow-sm"
          >
            {/* Header row */}
            <div className="flex flex-wrap items-start gap-3">
              {/* Rank */}
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-muted text-xs font-bold text-foreground">
                {idx + 1}
              </div>

              {/* Title + priority */}
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-sm font-semibold text-foreground">
                    {node.cve_id ?? node.title}
                  </span>
                  {node.package && (
                    <span className="font-mono text-xs text-muted-foreground">
                      {node.package}@{node.version}
                    </span>
                  )}
                  {node.file_path && (
                    <span className="font-mono text-xs text-muted-foreground">
                      {node.file_path}
                      {node.line_start != null ? `:${node.line_start}` : ""}
                    </span>
                  )}
                </div>
                <div className="mt-1 flex flex-wrap items-center gap-1.5">
                  <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold ${priority.bg} ${priority.color}`}>
                    {priority.label}
                  </span>
                  {/* Triage score as a subtle percentage */}
                  <span className="text-xs text-muted-foreground">
                    score {Math.round(score * 100)}/100
                  </span>
                </div>
              </div>

              {/* Score arc — simple colored bar */}
              <div className="flex flex-col items-end gap-1">
                <div className="h-2 w-24 overflow-hidden rounded-full bg-muted">
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${Math.round(score * 100)}%`,
                      background: severityColor,
                    }}
                  />
                </div>
              </div>
            </div>

            {/* Badges */}
            <div className="mt-3 flex flex-wrap gap-1.5">
              <span
                className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium capitalize ${SEVERITY_BADGE[tier] ?? SEVERITY_BADGE.unknown}`}
              >
                {tier}
              </span>
              {node.cvss != null && (
                <span className="rounded-full bg-muted px-2 py-0.5 font-mono text-xs font-medium">
                  CVSS {node.cvss.toFixed(1)}
                </span>
              )}
              {node.epss != null && (
                <span className="rounded-full bg-muted px-2 py-0.5 font-mono text-xs font-medium">
                  EPSS {(node.epss * 100).toFixed(1)}%
                </span>
              )}
              {node.kev && (
                <span className="rounded-full bg-red-500/90 px-2 py-0.5 text-xs font-medium text-white">
                  KEV — actively exploited
                </span>
              )}
              {edgeCount > 0 && (
                <span className="rounded-full bg-violet-500/10 px-2 py-0.5 text-xs font-medium text-violet-600 dark:text-violet-400">
                  {edgeCount} exploit chain{edgeCount !== 1 ? "s" : ""}
                </span>
              )}
              {node.attack_vector === "Network" && (
                <span className="rounded-full bg-sky-500/10 px-2 py-0.5 text-xs font-medium text-sky-600 dark:text-sky-400">
                  Network exposed
                </span>
              )}
              {node.source === "code" && node.vuln_category && (
                <span className="rounded-full bg-muted px-2 py-0.5 text-xs font-medium capitalize text-foreground">
                  {node.vuln_category}
                </span>
              )}
            </div>

            {/* Description */}
            {node.description && (
              <p className="mt-3 line-clamp-2 text-xs leading-relaxed text-muted-foreground">
                {node.description}
              </p>
            )}

            {/* Remediation */}
            {node.remediation && (
              <div className="mt-2 flex items-start gap-1.5 text-xs">
                <span className="shrink-0 font-medium text-foreground">Fix:</span>
                <span className="text-muted-foreground">{node.remediation}</span>
              </div>
            )}

            {/* Score breakdown */}
            <details className="mt-4 group">
              <summary className="cursor-pointer list-none text-xs text-muted-foreground hover:text-foreground">
                <span className="group-open:hidden">▶ Score breakdown</span>
                <span className="hidden group-open:inline">▼ Score breakdown</span>
              </summary>
              <div className="mt-2 space-y-1.5 rounded-lg bg-muted/30 px-3 py-2.5">
                <ScoreBar value={components.cvss}       max={W.cvss}       label="Severity (CVSS)" />
                <ScoreBar value={components.centrality} max={W.centrality} label="Chain centrality" />
                <ScoreBar value={components.epss}       max={W.epss}       label="Exploit prob." />
                <ScoreBar value={components.kev}        max={W.kev}        label="Active exploit" />
                <ScoreBar value={components.network}    max={W.network}    label="Network access" />
              </div>
            </details>
          </div>
        );
      })}
    </div>
  );
}
