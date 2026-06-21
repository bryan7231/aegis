import { useEffect, useMemo, useState } from "react";
import type { Vulnerability } from "../types";
import { getAnalysis } from "../api";

type SortKey = "package" | "cve_id" | "cvss" | "epss" | "kev" | "severity";
type SortDir = "asc" | "desc";

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
    case "package":
      return a.package.localeCompare(b.package);
    case "cve_id":
      return a.cve_id.localeCompare(b.cve_id);
    case "cvss":
      return (a.cvss ?? -1) - (b.cvss ?? -1);
    case "epss":
      return (a.epss ?? -1) - (b.epss ?? -1);
    case "kev":
      return Number(a.kev) - Number(b.kev);
    case "severity":
      return (
        (SEVERITY_RANK[severityTier(a)] ?? 0) -
        (SEVERITY_RANK[severityTier(b)] ?? 0)
      );
  }
}

const badge = "inline-block rounded-full px-2 py-0.5 text-xs font-medium capitalize leading-snug";
const thBase = "cursor-pointer select-none whitespace-nowrap border-b border-border bg-background px-3 py-2.5 text-left font-medium text-foreground sticky top-0";
const tdBase = "whitespace-nowrap border-b border-border px-3 py-2.5 text-left";
const mono = "font-mono text-[13px] text-foreground";

interface Props {
  projectId: string;
}

export default function VulnerabilitiesPage({ projectId }: Props) {
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sortKey, setSortKey] = useState<SortKey>("cvss");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  useEffect(() => {
    if (!projectId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    getAnalysis(projectId)
      .then((data) => setVulns(data.vulnerabilities))
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [projectId]);

  const sorted = useMemo(() => {
    const list = [...vulns].sort((a, b) => compare(a, b, sortKey));
    return sortDir === "asc" ? list : list.reverse();
  }, [vulns, sortKey, sortDir]);

  function toggleSort(key: SortKey) {
    if (key === sortKey) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("desc");
    }
  }

  function arrow(key: SortKey) {
    if (key !== sortKey) return "";
    return sortDir === "asc" ? " ▲" : " ▼";
  }

  if (loading)
    return <div className="px-8 py-12 text-center text-muted-foreground">Loading vulnerabilities…</div>;
  if (error)
    return <div className="px-8 py-12 text-center text-destructive">{error}</div>;
  if (!vulns.length)
    return (
      <div className="px-8 py-12 text-center text-muted-foreground">No known vulnerabilities found. 🎉</div>
    );

  return (
    <div className="w-full px-8 py-6 text-left max-lg:px-4 max-lg:py-4">
      <div className="mb-4 flex items-baseline gap-3">
        <h2 className="text-lg font-semibold">Vulnerabilities</h2>
        <span className="text-sm text-muted-foreground">{vulns.length} confirmed CVEs</span>
      </div>

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
          {sorted.map((v) => {
            const tier = severityTier(v);
            return (
              <tr key={`${v.cve_id}-${v.package}-${v.version}`} className="hover:bg-muted/30">
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
                <td className={`${tdBase} text-right`}>
                  {v.cvss != null ? v.cvss.toFixed(1) : "—"}
                </td>
                <td className={`${tdBase} text-right`}>
                  {v.epss != null ? `${(v.epss * 100).toFixed(1)}%` : "—"}
                </td>
                <td className={tdBase}>
                  {v.kev ? (
                    <span className={`${badge} bg-red-500/90 text-white normal-case`}>KEV</span>
                  ) : ""}
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
  );
}
