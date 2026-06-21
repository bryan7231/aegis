import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "@tanstack/react-router";
import { ArrowLeft } from "lucide-react";
import { getProjectVulnerabilities } from "@/lib/api";
import type { AnalysisResult, Vulnerability } from "@/types/project";
import { VulnGraphView } from "@/components/VulnGraphView";
import { TriageView } from "@/components/TriageView";

type SortKey = "package" | "cve_id" | "cvss" | "epss" | "kev" | "severity";
type SortDir = "asc" | "desc";
type Tab = "triage" | "vulnerabilities" | "graph";

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-red-500/15 text-red-500",
  high: "bg-orange-500/15 text-orange-600 dark:text-orange-500",
  medium: "bg-amber-500/15 text-amber-700 dark:text-amber-400",
  low: "bg-green-500/15 text-green-700 dark:text-green-500",
  unknown: "bg-muted text-muted-foreground",
};

function severityTier(v: Vulnerability): string {
  if (v.severity) return v.severity;
  if (v.cvss == null) return "unknown";
  if (v.cvss >= 9) return "critical";
  if (v.cvss >= 7) return "high";
  if (v.cvss >= 4) return "medium";
  return "low";
}

function compare(a: Vulnerability, b: Vulnerability, key: SortKey): number {
  switch (key) {
    case "package": return a.package.localeCompare(b.package);
    case "cve_id": return a.cve_id.localeCompare(b.cve_id);
    case "cvss": return (a.cvss ?? -1) - (b.cvss ?? -1);
    case "epss": return (a.epss ?? -1) - (b.epss ?? -1);
    case "kev": return Number(a.kev) - Number(b.kev);
    case "severity":
      return (SEVERITY_RANK[severityTier(a)] ?? 0) - (SEVERITY_RANK[severityTier(b)] ?? 0);
  }
}

const badge = "inline-block rounded-full px-2 py-0.5 text-xs font-medium capitalize leading-snug";
const thBase = "cursor-pointer select-none whitespace-nowrap border-b border-border bg-background px-3 py-2.5 text-left font-medium text-foreground sticky top-0";
const tdBase = "whitespace-nowrap border-b border-border px-3 py-2.5 text-left";
const mono = "font-mono text-[13px] text-foreground";

export function ProjectPage() {
  const { projectId } = useParams({ strict: false }) as { projectId: string };
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sortKey, setSortKey] = useState<SortKey>("cvss");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [tab, setTab] = useState<Tab>("triage");

  useEffect(() => {
    let cancelled = false;
    let pollTimer: ReturnType<typeof setTimeout> | null = null;

    async function load() {
      try {
        const data = await getProjectVulnerabilities(projectId);
        if (cancelled) return;
        setAnalysis(data);
        setLoading(false);
        if (data.status === "analyzing") {
          // Backend is running analysis — poll every 4s until complete.
          pollTimer = setTimeout(load, 4000);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load vulnerabilities.");
          setLoading(false);
        }
      }
    }

    setLoading(true);
    setError(null);
    load();

    return () => {
      cancelled = true;
      if (pollTimer) clearTimeout(pollTimer);
    };
  }, [projectId]);

  const sorted = useMemo(() => {
    if (!analysis) return [];
    const list = [...analysis.vulnerabilities].sort((a, b) => compare(a, b, sortKey));
    return sortDir === "asc" ? list : list.reverse();
  }, [analysis, sortKey, sortDir]);

  function toggleSort(key: SortKey) {
    if (key === sortKey) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortKey(key); setSortDir("desc"); }
  }

  function arrow(key: SortKey) {
    if (key !== sortKey) return "";
    return sortDir === "asc" ? " ▲" : " ▼";
  }

  const hasGraph = analysis?.graph && analysis.graph.nodes.length > 0;
  const codeVulnCount = analysis?.graph?.nodes.filter((n) => n.source === "code").length ?? 0;
  const depVulnCount = analysis?.vulnerabilities.length ?? 0;

  return (
    <div className="mx-auto w-full max-w-7xl px-6 py-8">
      <Link to="/" className="mb-6 inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="h-4 w-4" />
        All projects
      </Link>

      {loading && !analysis && (
        <div className="mt-24 text-center text-sm text-muted-foreground">
          Starting analysis…
        </div>
      )}

      {analysis?.status === "analyzing" && (
        <div className="mt-6 flex items-center gap-3 rounded-lg border border-border bg-muted/30 px-4 py-3 text-sm text-muted-foreground">
          <span className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent" />
          Scanning repository — running OSV lookup, code scan, and building exploit graph…
        </div>
      )}

      {error && (
        <div className="mt-6 rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3 text-sm text-destructive">
          {error}
        </div>
      )}

      {analysis && analysis.status === "complete" && (
        <>
          {/* Page header */}
          <div className="mb-6 flex flex-wrap items-baseline gap-3">
            <h1 className="text-2xl font-semibold tracking-tight">Analysis</h1>
            <span className="text-sm text-muted-foreground">
              {depVulnCount} dep CVEs
              {codeVulnCount > 0 && ` · ${codeVulnCount} code findings`}
              {hasGraph && ` · ${analysis.graph!.edges.length} exploit chains`}
            </span>
          </div>

          {/* Narrative */}
          {analysis.report && (
            <div className="mb-6 rounded-xl border border-border bg-card px-5 py-4 text-sm">
              <p className="font-medium text-foreground">{analysis.report.narrative}</p>
              {analysis.report.highest_risk_path && (
                <p className="mt-2 font-mono text-xs text-muted-foreground">
                  {analysis.report.highest_risk_path}
                </p>
              )}
            </div>
          )}

          {/* Tabs */}
          <div className="mb-5 flex gap-1 border-b border-border">
            {(["triage", "vulnerabilities", "graph"] as Tab[]).map((t) => {
              const labels: Record<Tab, string> = {
                triage: "Triage",
                vulnerabilities: "All CVEs",
                graph: "Exploit Graph",
              };
              const triageCount = hasGraph
                ? analysis.graph!.nodes.length
                : analysis.vulnerabilities.length;
              return (
                <button
                  key={t}
                  onClick={() => setTab(t)}
                  className={[
                    "px-4 py-2 text-sm font-medium transition-colors",
                    tab === t
                      ? "border-b-2 border-primary text-foreground"
                      : "text-muted-foreground hover:text-foreground",
                  ].join(" ")}
                >
                  {labels[t]}
                  {t === "triage" && triageCount > 0 && (
                    <span className="ml-1.5 rounded-full bg-primary/10 px-1.5 py-0.5 text-xs text-primary">
                      {triageCount}
                    </span>
                  )}
                  {t === "graph" && hasGraph && (
                    <span className="ml-1.5 rounded-full bg-primary/10 px-1.5 py-0.5 text-xs text-primary">
                      {analysis.graph!.edges.length} chains
                    </span>
                  )}
                </button>
              );
            })}
          </div>

          {/* Triage tab */}
          {tab === "triage" && (
            <TriageView
              projectId={projectId}
              nodes={
                hasGraph
                  ? analysis.graph!.nodes
                  : analysis.vulnerabilities.map((v) => ({
                      id: v.cve_id + v.package + v.version,
                      source: "dependency" as const,
                      title: v.cve_id,
                      description: v.summary ?? null,
                      severity: v.severity,
                      cvss: v.cvss,
                      cwe_ids: v.cwe_ids ?? [],
                      remediation: v.fixed_version ? `Upgrade to ${v.fixed_version}` : null,
                      centrality_score: 0,
                      cve_id: v.cve_id,
                      package: v.package,
                      version: v.version,
                      ecosystem: v.ecosystem,
                      epss: v.epss,
                      kev: v.kev,
                      fixed_version: v.fixed_version,
                      osv_url: v.osv_url,
                      attack_vector: v.attack_vector ?? null,
                      attack_complexity: v.attack_complexity ?? null,
                      privileges_required: v.privileges_required ?? null,
                      user_interaction: v.user_interaction ?? null,
                      scope: v.scope ?? null,
                      file_path: null,
                      line_start: null,
                      line_end: null,
                      vuln_category: null,
                      affected_code: null,
                    }))
              }
              edges={analysis.graph?.edges ?? []}
            />
          )}

          {/* All CVEs tab */}
          {tab === "vulnerabilities" && (
            <>
              {analysis.vulnerabilities.length === 0 ? (
                <div className="py-16 text-center text-muted-foreground">
                  No known dependency vulnerabilities found.
                </div>
              ) : (
                <div className="overflow-x-auto rounded-lg border border-border">
                  <table className="w-full border-collapse text-sm">
                    <thead>
                      <tr>
                        <th className={thBase} onClick={() => toggleSort("package")}>Package{arrow("package")}</th>
                        <th className={thBase}>Version</th>
                        <th className={thBase} onClick={() => toggleSort("cve_id")}>CVE{arrow("cve_id")}</th>
                        <th className={`${thBase} text-right`} onClick={() => toggleSort("cvss")}>CVSS{arrow("cvss")}</th>
                        <th className={`${thBase} text-right`} onClick={() => toggleSort("epss")}>EPSS{arrow("epss")}</th>
                        <th className={thBase} onClick={() => toggleSort("kev")}>KEV{arrow("kev")}</th>
                        <th className={thBase} onClick={() => toggleSort("severity")}>Severity{arrow("severity")}</th>
                        <th className={thBase}>Fixed in</th>
                      </tr>
                    </thead>
                    <tbody>
                      {sorted.map((v, idx) => {
                        const tier = severityTier(v);
                        return (
                          <tr key={`${v.cve_id}-${v.package}-${v.version}-${idx}`} className="hover:bg-muted/30">
                            <td className={`${tdBase} ${mono}`}>{v.package}</td>
                            <td className={`${tdBase} ${mono} text-muted-foreground`}>{v.version}</td>
                            <td className={tdBase}>
                              {v.osv_url ? (
                                <a href={v.osv_url} target="_blank" rel="noreferrer" className={`${mono} text-primary no-underline hover:underline`}>
                                  {v.cve_id}
                                </a>
                              ) : (
                                <span className={mono}>{v.cve_id}</span>
                              )}
                            </td>
                            <td className={`${tdBase} text-right`}>{v.cvss != null ? v.cvss.toFixed(1) : "—"}</td>
                            <td className={`${tdBase} text-right`}>{v.epss != null ? `${(v.epss * 100).toFixed(1)}%` : "—"}</td>
                            <td className={tdBase}>
                              {v.kev && <span className={`${badge} bg-red-500/90 text-white normal-case`}>KEV</span>}
                            </td>
                            <td className={tdBase}>
                              <span className={`${badge} ${SEVERITY_BADGE[tier] ?? SEVERITY_BADGE.unknown}`}>{tier}</span>
                            </td>
                            <td className={`${tdBase} ${mono} text-muted-foreground`}>{v.fixed_version ?? "—"}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}

          {/* Graph tab */}
          {tab === "graph" && (
            <>
              {!hasGraph ? (
                <div className="py-16 text-center text-muted-foreground">
                  No graph data available. Re-run analysis to generate the exploit chain graph.
                </div>
              ) : (
                <VulnGraphView graph={analysis.graph!} />
              )}
            </>
          )}
        </>
      )}
    </div>
  );
}
