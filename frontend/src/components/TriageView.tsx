import { useMemo, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Copy, Download, RefreshCw, FileText } from "lucide-react";
import type { VulnNode, VulnEdge, RemediationPlan } from "@/types/project";
import { getRemediationPlan, regenerateRemediationPlan } from "@/lib/api";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";

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

const W = { cvss: 0.3, centrality: 0.25, epss: 0.2, kev: 0.15, network: 0.1 };

function scoreNode(node: VulnNode, edgeCount: number): ScoredNode {
  const components = {
    cvss: ((node.cvss ?? 0) / 10) * W.cvss,
    centrality: node.centrality_score * W.centrality,
    epss: (node.epss ?? 0) * W.epss,
    kev: (node.kev ? 1 : 0) * W.kev,
    network: (node.attack_vector === "Network" ? 1 : 0) * W.network,
  };
  return {
    node,
    edgeCount,
    score: Object.values(components).reduce((a, b) => a + b, 0),
    components,
  };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const SEVERITY_COLOR: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-red-500/15 text-red-500",
  high: "bg-orange-500/15 text-orange-600 dark:text-orange-500",
  medium: "bg-amber-500/15 text-amber-700 dark:text-amber-400",
  low: "bg-green-500/15 text-green-700 dark:text-green-500",
  unknown: "bg-muted text-muted-foreground",
};

function priorityLabel(score: number) {
  if (score >= 0.65)
    return {
      label: "Fix immediately",
      color: "text-red-600 dark:text-red-400",
      bg: "bg-red-500/10",
    };
  if (score >= 0.45)
    return {
      label: "Fix soon",
      color: "text-orange-600 dark:text-orange-400",
      bg: "bg-orange-500/10",
    };
  if (score >= 0.25)
    return {
      label: "Fix when able",
      color: "text-amber-700 dark:text-amber-400",
      bg: "bg-amber-500/10",
    };
  return {
    label: "Monitor",
    color: "text-green-700 dark:text-green-400",
    bg: "bg-green-500/10",
  };
}

function nodeSeverity(node: VulnNode): string {
  if (node.severity) return node.severity.toLowerCase();
  if (node.cvss == null) return "unknown";
  if (node.cvss >= 9) return "critical";
  if (node.cvss >= 7) return "high";
  if (node.cvss >= 4) return "medium";
  return "low";
}

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function isUUID(s: string) {
  return UUID_RE.test(s);
}

function ScoreBar({
  value,
  max,
  label,
}: {
  value: number;
  max: number;
  label: string;
}) {
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

// ── Plan modal ────────────────────────────────────────────────────────────────

function PlanModal({
  open,
  onOpenChange,
  plan,
  loading,
  error,
  nodeTitle,
  onRegenerate,
  regenerating,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  plan: RemediationPlan | null;
  loading: boolean;
  error: string | null;
  nodeTitle: string;
  onRegenerate: () => void;
  regenerating: boolean;
}) {
  const [copied, setCopied] = useState(false);

  function handleCopy() {
    if (!plan) return;
    navigator.clipboard.writeText(plan.plan).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  function handleDownload() {
    if (!plan) return;
    const blob = new Blob([plan.plan], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `remediation-${nodeTitle.replace(/[^a-z0-9]/gi, "-").toLowerCase()}.md`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="flex max-h-[90vh] max-w-3xl flex-col gap-0 p-0">
        <DialogHeader className="flex-row items-center justify-between border-b border-border px-6 py-4">
          <DialogTitle className="text-base font-semibold">
            Fix Plan — <span className="font-mono">{nodeTitle}</span>
          </DialogTitle>
          <div className="flex items-center gap-2">
            {plan?.cached && (
              <span className="rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground">
                cached
              </span>
            )}
            {plan && (
              <>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleCopy}
                  className="h-7 text-xs"
                >
                  <Copy className="mr-1 h-3 w-3" />
                  {copied ? "Copied!" : "Copy"}
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleDownload}
                  className="h-7 text-xs"
                >
                  <Download className="mr-1 h-3 w-3" />
                  .md
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={onRegenerate}
                  disabled={regenerating}
                  className="h-7 text-xs"
                >
                  <RefreshCw
                    className={`mr-1 h-3 w-3 ${regenerating ? "animate-spin" : ""}`}
                  />
                  Regen
                </Button>
              </>
            )}
          </div>
        </DialogHeader>

        <div className="flex-1 overflow-y-auto px-6 py-5">
          {loading && (
            <div className="flex flex-col items-center gap-3 py-16 text-center">
              <span className="inline-block h-5 w-5 animate-spin rounded-full border-2 border-primary border-t-transparent" />
              <p className="text-sm text-muted-foreground">
                Creating your remediation plan…
              </p>
              <p className="text-xs text-muted-foreground">
                This usually takes 15–30 seconds.
              </p>
            </div>
          )}

          {error && !loading && (
            <div className="rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3 text-sm text-destructive">
              {error}
            </div>
          )}

          {plan && !loading && (
            <div
              className="prose prose-sm dark:prose-invert max-w-none
              prose-headings:font-semibold prose-headings:tracking-tight
              prose-h2:mt-6 prose-h2:text-base prose-h2:border-b prose-h2:border-border prose-h2:pb-1
              prose-h3:mt-4 prose-h3:text-sm
              prose-code:rounded prose-code:bg-muted prose-code:px-1 prose-code:py-0.5 prose-code:text-xs prose-code:font-mono prose-code:before:content-none prose-code:after:content-none
              prose-pre:bg-muted prose-pre:rounded-lg prose-pre:text-xs
              prose-li:marker:text-muted-foreground
              prose-a:text-primary
            "
            >
              <ReactMarkdown remarkPlugins={[remarkGfm]}>
                {plan.plan}
              </ReactMarkdown>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ── Triage card ───────────────────────────────────────────────────────────────

function TriageCard({
  scored,
  rank,
  projectId,
}: {
  scored: ScoredNode;
  rank: number;
  projectId?: string;
}) {
  const { node, edgeCount, score, components } = scored;
  const tier = nodeSeverity(node);
  const priority = priorityLabel(score);
  const severityColor = SEVERITY_COLOR[tier] ?? "#94a3b8";
  const canPlan = !!projectId && isUUID(node.id);

  const [modalOpen, setModalOpen] = useState(false);
  const [plan, setPlan] = useState<RemediationPlan | null>(null);
  const [planLoading, setPlanLoading] = useState(false);
  const [planError, setPlanError] = useState<string | null>(null);
  const [regenerating, setRegenerating] = useState(false);

  async function fetchPlan(forceRegen = false) {
    if (!projectId) return;
    setPlanLoading(true);
    setPlanError(null);
    setModalOpen(true);
    try {
      const result = forceRegen
        ? await regenerateRemediationPlan(projectId, node.id)
        : await getRemediationPlan(projectId, node.id);
      setPlan(result);
    } catch (err) {
      setPlanError(
        err instanceof Error ? err.message : "Failed to generate plan.",
      );
    } finally {
      setPlanLoading(false);
      setRegenerating(false);
    }
  }

  async function handleRegenerate() {
    setRegenerating(true);
    setPlan(null);
    await fetchPlan(true);
  }

  const nodeTitle = node.cve_id ?? node.title;

  return (
    <>
      <div className="rounded-xl border border-border bg-card p-5 shadow-sm">
        {/* Header */}
        <div className="flex flex-wrap items-start gap-3">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-muted text-xs font-bold text-foreground">
            {rank}
          </div>

          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-sm font-semibold text-foreground">
                {nodeTitle}
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
              <span
                className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold ${priority.bg} ${priority.color}`}
              >
                {priority.label}
              </span>
              <span className="text-xs text-muted-foreground">
                score {Math.round(score * 100)}/100
              </span>
            </div>
          </div>

          <div className="flex flex-col items-end gap-2">
            <div className="h-2 w-24 overflow-hidden rounded-full bg-muted">
              <div
                className="h-full rounded-full"
                style={{
                  width: `${Math.round(score * 100)}%`,
                  background: severityColor,
                }}
              />
            </div>
            {canPlan && (
              <button
                onClick={() => (plan ? setModalOpen(true) : fetchPlan())}
                className="inline-flex items-center gap-1 rounded-md border border-border bg-background px-2.5 py-1 text-xs font-medium text-foreground shadow-sm transition-colors hover:bg-muted"
              >
                <FileText className="h-3 w-3" />
                {plan ? "View plan" : "Get fix plan"}
              </button>
            )}
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

        {node.description && (
          <p className="mt-3 line-clamp-2 text-xs leading-relaxed text-muted-foreground">
            {node.description}
          </p>
        )}

        {node.remediation && (
          <div className="mt-2 flex items-start gap-1.5 text-xs">
            <span className="shrink-0 font-medium text-foreground">Fix:</span>
            <span className="text-muted-foreground">{node.remediation}</span>
          </div>
        )}

        <details className="mt-4 group">
          <summary className="cursor-pointer list-none text-xs text-muted-foreground hover:text-foreground">
            <span className="group-open:hidden">▶ Score breakdown</span>
            <span className="hidden group-open:inline">▼ Score breakdown</span>
          </summary>
          <div className="mt-2 space-y-1.5 rounded-lg bg-muted/30 px-3 py-2.5">
            <ScoreBar
              value={components.cvss}
              max={W.cvss}
              label="Severity (CVSS)"
            />
            <ScoreBar
              value={components.centrality}
              max={W.centrality}
              label="Chain centrality"
            />
            <ScoreBar
              value={components.epss}
              max={W.epss}
              label="Exploit prob."
            />
            <ScoreBar
              value={components.kev}
              max={W.kev}
              label="Active exploit"
            />
            <ScoreBar
              value={components.network}
              max={W.network}
              label="Network access"
            />
          </div>
        </details>
      </div>

      <PlanModal
        open={modalOpen}
        onOpenChange={setModalOpen}
        plan={plan}
        loading={planLoading}
        error={planError}
        nodeTitle={nodeTitle}
        onRegenerate={handleRegenerate}
        regenerating={regenerating}
      />
    </>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export function TriageView({
  nodes,
  edges,
  projectId,
}: {
  nodes: VulnNode[];
  edges: VulnEdge[];
  projectId?: string;
}) {
  const scored = useMemo<ScoredNode[]>(() => {
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
        Ranked by weighted score: severity (30%) · exploit-chain centrality
        (25%) · exploitation probability (20%) · active exploitation (15%) ·
        network exposure (10%).
      </p>
      {scored.map((s, idx) => (
        <TriageCard
          key={s.node.id}
          scored={s}
          rank={idx + 1}
          projectId={projectId}
        />
      ))}
    </div>
  );
}
