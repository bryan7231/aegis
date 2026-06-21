import { useEffect, useRef, useState } from "react";
import * as d3 from "d3";
import type { VulnNode, VulnEdge, VulnGraph } from "@/types/project";
import { X } from "lucide-react";

// ── colour helpers ────────────────────────────────────────────────────────────

const SEVERITY_COLOR: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

const EDGE_COLOR: Record<string, string> = {
  dependency_chain: "#6366f1",
  data_flow: "#ec4899",
  privilege_escalation: "#f97316",
  cwe_chain: "#8b5cf6",
  lateral_movement: "#14b8a6",
};

function nodeColor(n: VulnNode): string {
  const tier = n.severity?.toLowerCase() ?? "unknown";
  return SEVERITY_COLOR[tier] ?? "#94a3b8";
}

function nodeRadius(n: VulnNode): number {
  const base = n.source === "code" ? 10 : 12;
  return base + n.centrality_score * 10;
}

// ── D3 simulation types ───────────────────────────────────────────────────────

interface SimNode extends d3.SimulationNodeDatum {
  id: string;
  data: VulnNode;
}

interface SimLink extends d3.SimulationLinkDatum<SimNode> {
  data: VulnEdge;
}

// ── Detail panel ──────────────────────────────────────────────────────────────

function DetailPanel({ node, onClose }: { node: VulnNode; onClose: () => void }) {
  const badge = "inline-block rounded-full px-2 py-0.5 text-xs font-medium capitalize";

  return (
    <div className="flex h-full flex-col overflow-hidden rounded-xl border border-border bg-card shadow-lg">
      <div className="flex items-start justify-between gap-2 border-b border-border px-4 py-3">
        <div className="min-w-0">
          <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            {node.source === "code" ? "Code Finding" : "Dependency CVE"}
          </p>
          <h3 className="mt-0.5 truncate text-sm font-semibold text-foreground">
            {node.title}
          </h3>
        </div>
        <button
          onClick={onClose}
          className="shrink-0 rounded-md p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="flex-1 space-y-4 overflow-y-auto px-4 py-3 text-sm">
        {/* Severity / CVSS / EPSS row */}
        <div className="flex flex-wrap gap-2">
          {node.severity && (
            <span
              className={badge}
              style={{
                background: `${nodeColor(node)}20`,
                color: nodeColor(node),
              }}
            >
              {node.severity}
            </span>
          )}
          {node.cvss != null && (
            <span className="rounded-full bg-muted px-2 py-0.5 text-xs font-mono font-medium">
              CVSS {node.cvss.toFixed(1)}
            </span>
          )}
          {node.epss != null && (
            <span className="rounded-full bg-muted px-2 py-0.5 text-xs font-mono font-medium">
              EPSS {(node.epss * 100).toFixed(1)}%
            </span>
          )}
          {node.kev && (
            <span className="rounded-full bg-red-500/90 px-2 py-0.5 text-xs font-medium text-white">
              KEV
            </span>
          )}
          {node.centrality_score > 0 && (
            <span className="rounded-full bg-violet-500/10 px-2 py-0.5 text-xs font-medium text-violet-600 dark:text-violet-400">
              centrality {node.centrality_score.toFixed(2)}
            </span>
          )}
        </div>

        {/* Description */}
        {node.description && (
          <div>
            <p className="mb-1 text-xs font-medium text-muted-foreground">Description</p>
            <p className="text-xs leading-relaxed text-foreground">{node.description}</p>
          </div>
        )}

        {/* Dependency-specific */}
        {node.source === "dependency" && (
          <>
            {node.package && (
              <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                <span className="text-muted-foreground">Package</span>
                <span className="font-mono">{node.package}@{node.version}</span>
                <span className="text-muted-foreground">Ecosystem</span>
                <span className="font-mono">{node.ecosystem}</span>
                {node.fixed_version && (
                  <>
                    <span className="text-muted-foreground">Fix</span>
                    <span className="font-mono text-green-600 dark:text-green-400">
                      {node.fixed_version}
                    </span>
                  </>
                )}
                {node.attack_vector && (
                  <>
                    <span className="text-muted-foreground">Attack vector</span>
                    <span>{node.attack_vector}</span>
                  </>
                )}
                {node.privileges_required && (
                  <>
                    <span className="text-muted-foreground">Privileges req.</span>
                    <span>{node.privileges_required}</span>
                  </>
                )}
                {node.scope && (
                  <>
                    <span className="text-muted-foreground">Scope</span>
                    <span>{node.scope}</span>
                  </>
                )}
              </div>
            )}
            {node.osv_url && (
              <a
                href={node.osv_url}
                target="_blank"
                rel="noreferrer"
                className="text-xs text-primary underline-offset-2 hover:underline"
              >
                View on OSV →
              </a>
            )}
          </>
        )}

        {/* Code-finding-specific */}
        {node.source === "code" && (
          <>
            {node.file_path && (
              <div>
                <p className="mb-1 text-xs font-medium text-muted-foreground">Location</p>
                <p className="rounded-md bg-muted px-2.5 py-1.5 font-mono text-xs">
                  {node.file_path}
                  {node.line_start != null && (
                    <span className="text-muted-foreground">
                      :{node.line_start}
                      {node.line_end != null && node.line_end !== node.line_start
                        ? `–${node.line_end}`
                        : ""}
                    </span>
                  )}
                </p>
              </div>
            )}
            {node.vuln_category && (
              <div className="grid grid-cols-2 gap-x-4 text-xs">
                <span className="text-muted-foreground">Category</span>
                <span className="capitalize">{node.vuln_category}</span>
              </div>
            )}
            {node.affected_code && (
              <div>
                <p className="mb-1 text-xs font-medium text-muted-foreground">Affected code</p>
                <pre className="overflow-x-auto rounded-md bg-muted px-2.5 py-1.5 font-mono text-xs leading-relaxed whitespace-pre-wrap break-all">
                  {node.affected_code}
                </pre>
              </div>
            )}
          </>
        )}

        {/* CWEs */}
        {node.cwe_ids?.length > 0 && (
          <div>
            <p className="mb-1 text-xs font-medium text-muted-foreground">CWE</p>
            <div className="flex flex-wrap gap-1">
              {node.cwe_ids.map((c) => (
                <span key={c} className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
                  {c}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Remediation */}
        {node.remediation && (
          <div>
            <p className="mb-1 text-xs font-medium text-muted-foreground">Remediation</p>
            <p className="text-xs leading-relaxed text-foreground">{node.remediation}</p>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Legend ────────────────────────────────────────────────────────────────────

function Legend() {
  return (
    <div className="absolute bottom-3 left-3 rounded-lg border border-border bg-card/90 px-3 py-2 text-xs backdrop-blur-sm">
      <p className="mb-1.5 font-medium text-foreground">Edge types</p>
      <div className="space-y-1">
        {Object.entries(EDGE_COLOR).map(([type, color]) => (
          <div key={type} className="flex items-center gap-1.5">
            <span className="h-0.5 w-4 rounded-full" style={{ background: color }} />
            <span className="capitalize text-muted-foreground">
              {type.replace(/_/g, " ")}
            </span>
          </div>
        ))}
      </div>
      <p className="mt-2 mb-1 font-medium text-foreground">Node size</p>
      <p className="text-muted-foreground">Larger = more chains through it</p>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export function VulnGraphView({ graph }: { graph: VulnGraph }) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [selectedNode, setSelectedNode] = useState<VulnNode | null>(null);

  useEffect(() => {
    if (!svgRef.current || graph.nodes.length === 0) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const width = svgRef.current.clientWidth;
    const height = svgRef.current.clientHeight;

    // Zoom / pan container
    const root = svg.append("g");

    svg.call(
      d3.zoom<SVGSVGElement, unknown>()
        .scaleExtent([0.2, 4])
        .on("zoom", (event) => root.attr("transform", event.transform))
    );

    // Build sim data
    const nodeMap = new Map<string, SimNode>();
    const simNodes: SimNode[] = graph.nodes.map((n) => {
      const sn: SimNode = { id: n.id, data: n };
      nodeMap.set(n.id, sn);
      return sn;
    });

    const simLinks: SimLink[] = graph.edges
      .map((e) => {
        const source = nodeMap.get(e.source_id);
        const target = nodeMap.get(e.target_id);
        if (!source || !target) return null;
        return { source, target, data: e } as SimLink;
      })
      .filter((l): l is SimLink => l !== null);

    // Arrow markers per edge type
    const defs = svg.append("defs");
    Object.entries(EDGE_COLOR).forEach(([type, color]) => {
      defs.append("marker")
        .attr("id", `arrow-${type}`)
        .attr("viewBox", "0 -4 8 8")
        .attr("refX", 8)
        .attr("refY", 0)
        .attr("markerWidth", 6)
        .attr("markerHeight", 6)
        .attr("orient", "auto")
        .append("path")
        .attr("d", "M0,-4L8,0L0,4")
        .attr("fill", color);
    });

    // Links
    const link = root.append("g")
      .selectAll<SVGLineElement, SimLink>("line")
      .data(simLinks)
      .join("line")
      .attr("stroke", (d) => EDGE_COLOR[d.data.edge_type] ?? "#94a3b8")
      .attr("stroke-opacity", 0.6)
      .attr("stroke-width", (d) => 1 + d.data.confidence * 2)
      .attr("marker-end", (d) => `url(#arrow-${d.data.edge_type})`);

    // Node groups
    const node = root.append("g")
      .selectAll<SVGGElement, SimNode>("g")
      .data(simNodes)
      .join("g")
      .style("cursor", "pointer")
      .call(
        d3.drag<SVGGElement, SimNode>()
          .on("start", (event, d) => {
            if (!event.active) sim.alphaTarget(0.3).restart();
            d.fx = d.x; d.fy = d.y;
          })
          .on("drag", (event, d) => { d.fx = event.x; d.fy = event.y; })
          .on("end", (event, d) => {
            if (!event.active) sim.alphaTarget(0);
            d.fx = null; d.fy = null;
          })
      )
      .on("click", (_event, d) => {
        setSelectedNode((prev) => prev?.id === d.id ? null : d.data);
      });

    // Circle
    node.append("circle")
      .attr("r", (d) => nodeRadius(d.data))
      .attr("fill", (d) => nodeColor(d.data))
      .attr("fill-opacity", 0.85)
      .attr("stroke", (d) => nodeColor(d.data))
      .attr("stroke-width", 1.5);

    // Source indicator (code nodes get a dashed stroke)
    node.filter((d) => d.data.source === "code")
      .select("circle")
      .attr("stroke-dasharray", "3,2")
      .attr("stroke-width", 2);

    // Label
    node.append("text")
      .attr("dy", (d) => nodeRadius(d.data) + 11)
      .attr("text-anchor", "middle")
      .attr("font-size", 10)
      .attr("fill", "currentColor")
      .attr("class", "text-foreground")
      .text((d) => {
        const label = d.data.package ?? d.data.file_path?.split("/").pop() ?? d.data.title;
        return label.length > 18 ? label.slice(0, 17) + "…" : label;
      });

    // Simulation
    const sim = d3.forceSimulation(simNodes)
      .force("link", d3.forceLink<SimNode, SimLink>(simLinks).id((d) => d.id).distance(120))
      .force("charge", d3.forceManyBody().strength(-300))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide<SimNode>().radius((d) => nodeRadius(d.data) + 14))
      .on("tick", () => {
        link
          .attr("x1", (d) => (d.source as SimNode).x ?? 0)
          .attr("y1", (d) => (d.source as SimNode).y ?? 0)
          .attr("x2", (d) => (d.target as SimNode).x ?? 0)
          .attr("y2", (d) => (d.target as SimNode).y ?? 0);
        node.attr("transform", (d) => `translate(${d.x ?? 0},${d.y ?? 0})`);
      });

    return () => { sim.stop(); };
  }, [graph]);

  if (graph.nodes.length === 0) {
    return (
      <div className="flex h-64 items-center justify-center text-sm text-muted-foreground">
        No graph data — run an analysis first.
      </div>
    );
  }

  return (
    <div className="relative flex h-[calc(100vh-220px)] min-h-[480px] gap-3">
      <div className="relative flex-1 overflow-hidden rounded-xl border border-border bg-card">
        <svg ref={svgRef} className="h-full w-full" />
        <Legend />
        <div className="absolute right-3 top-3 rounded-md bg-card/80 px-2 py-1 text-xs text-muted-foreground backdrop-blur-sm">
          {graph.nodes.length} nodes · {graph.edges.length} edges · scroll to zoom · drag to pan
        </div>
      </div>

      {selectedNode && (
        <div className="w-72 shrink-0">
          <DetailPanel node={selectedNode} onClose={() => setSelectedNode(null)} />
        </div>
      )}
    </div>
  );
}
