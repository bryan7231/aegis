import { useEffect, useRef, useState } from "react";
import * as d3 from "d3";
import type { VulnNode, VulnEdge, VulnGraph } from "@/types/project";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";

// ── Constants ─────────────────────────────────────────────────────────────────

const NODE_W = 148;
const NODE_H = 44;
const NODE_RX = 7;
const ACCENT_W = 3;

// ── Colour helpers ────────────────────────────────────────────────────────────

const SEVERITY_COLOR: Record<string, string> = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#22c55e",
  unknown:  "#52525b",
};

// Dark gradient fills: [dark tint, nearly-black]
const SEVERITY_GRAD: Record<string, [string, string]> = {
  critical: ["rgba(127,29,29,0.90)", "rgba(15,15,15,0.98)"],
  high:     ["rgba(124,45,18,0.90)", "rgba(15,15,15,0.98)"],
  medium:   ["rgba(113,63,18,0.90)", "rgba(15,15,15,0.98)"],
  low:      ["rgba(20,83,45,0.90)",  "rgba(15,15,15,0.98)"],
  unknown:  ["rgba(39,39,42,0.92)",  "rgba(15,15,15,0.98)"],
};

const EDGE_COLOR: Record<string, string> = {
  dependency_chain:     "#a5b4fc",
  data_flow:            "#f9a8d4",
  privilege_escalation: "#fdba74",
  cwe_chain:            "#c4b5fd",
  lateral_movement:     "#5eead4",
};

function nodeSeverity(n: VulnNode): string {
  const s = n.severity?.toLowerCase() ?? "unknown";
  return s in SEVERITY_COLOR ? s : "unknown";
}

function nodeAccentColor(n: VulnNode): string {
  return SEVERITY_COLOR[nodeSeverity(n)] ?? SEVERITY_COLOR.unknown;
}

// Returns the point on the edge of a rectangle (cx, cy, w=NODE_W, h=NODE_H)
// in the direction (dx, dy) from center.
function rectEdge(cx: number, cy: number, dx: number, dy: number): [number, number] {
  if (dx === 0 && dy === 0) return [cx, cy];
  const len = Math.hypot(dx, dy);
  const ux = dx / len;
  const uy = dy / len;
  const halfW = NODE_W / 2 + 2;
  const halfH = NODE_H / 2 + 2;
  const tx = ux !== 0 ? halfW / Math.abs(ux) : Infinity;
  const ty = uy !== 0 ? halfH / Math.abs(uy) : Infinity;
  const t = Math.min(tx, ty);
  return [cx + ux * t, cy + uy * t];
}

function truncate(s: string, max: number) {
  return s.length > max ? s.slice(0, max - 1) + "…" : s;
}

// ── D3 simulation types ───────────────────────────────────────────────────────

interface SimNode extends d3.SimulationNodeDatum {
  id: string;
  data: VulnNode;
}

interface SimLink extends d3.SimulationLinkDatum<SimNode> {
  data: VulnEdge;
}

// ── Detail Sheet ──────────────────────────────────────────────────────────────

function NodeDetailContent({ node }: { node: VulnNode }) {
  const sev = nodeSeverity(node);
  const accentColor = nodeAccentColor(node);

  return (
    <div className="flex-1 overflow-y-auto px-5 py-4 text-sm space-y-4">
      {/* Severity + scores */}
      <div className="flex flex-wrap gap-1.5">
        {node.severity && (
          <span
            className="inline-block rounded-full px-2 py-0.5 text-xs font-medium capitalize"
            style={{ background: `${accentColor}22`, color: accentColor }}
          >
            {sev}
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
          <span className="rounded-full bg-white/8 px-2 py-0.5 text-xs font-medium text-white/60">
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

      {/* Dependency-specific fields */}
      {node.source === "dependency" && node.package && (
        <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
          <span className="text-muted-foreground">Package</span>
          <span className="font-mono">{node.package}@{node.version}</span>
          <span className="text-muted-foreground">Ecosystem</span>
          <span className="font-mono">{node.ecosystem}</span>
          {node.fixed_version && (
            <>
              <span className="text-muted-foreground">Fix</span>
              <span className="font-mono text-green-400">{node.fixed_version}</span>
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
      {node.source === "dependency" && node.osv_url && (
        <a
          href={node.osv_url}
          target="_blank"
          rel="noreferrer"
          className="text-xs text-primary underline-offset-2 hover:underline"
        >
          View on OSV →
        </a>
      )}

      {/* Code-finding fields */}
      {node.source === "code" && node.file_path && (
        <div>
          <p className="mb-1 text-xs font-medium text-muted-foreground">Location</p>
          <p className="rounded-md bg-muted px-2.5 py-1.5 font-mono text-xs">
            {node.file_path}
            {node.line_start != null && (
              <span className="text-muted-foreground">
                :{node.line_start}
                {node.line_end != null && node.line_end !== node.line_start
                  ? `–${node.line_end}` : ""}
              </span>
            )}
          </p>
        </div>
      )}
      {node.source === "code" && node.vuln_category && (
        <div className="grid grid-cols-2 gap-x-4 text-xs">
          <span className="text-muted-foreground">Category</span>
          <span className="capitalize">{node.vuln_category}</span>
        </div>
      )}
      {node.source === "code" && node.affected_code && (
        <div>
          <p className="mb-1 text-xs font-medium text-muted-foreground">Affected code</p>
          <pre className="overflow-x-auto rounded-md bg-muted px-2.5 py-1.5 font-mono text-xs leading-relaxed whitespace-pre-wrap break-all">
            {node.affected_code}
          </pre>
        </div>
      )}

      {/* CWEs */}
      {node.cwe_ids?.length > 0 && (
        <div>
          <p className="mb-1 text-xs font-medium text-muted-foreground">CWE</p>
          <div className="flex flex-wrap gap-1">
            {node.cwe_ids.map((c) => (
              <span key={c} className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">{c}</span>
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
  );
}

// ── Legend ────────────────────────────────────────────────────────────────────

function Legend() {
  return (
    <div className="absolute bottom-3 left-3 rounded-lg border border-border bg-card/90 px-3 py-2.5 text-xs backdrop-blur-sm">
      <p className="mb-2 font-medium text-foreground">Edge types</p>
      <div className="space-y-1.5">
        {Object.entries(EDGE_COLOR).map(([type, color]) => (
          <div key={type} className="flex items-center gap-2">
            <span
              className="h-px w-5 rounded-full"
              style={{ background: color, boxShadow: `0 0 4px ${color}` }}
            />
            <span className="capitalize text-muted-foreground">
              {type.replace(/_/g, " ")}
            </span>
          </div>
        ))}
      </div>
      <div className="mt-3 border-t border-border pt-2.5 space-y-1">
        <p className="font-medium text-foreground">Nodes</p>
        <p className="text-muted-foreground">Left bar = severity</p>
        <p className="text-muted-foreground">Dashed = code finding</p>
      </div>
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

    const root = svg.append("g");

    svg.call(
      d3.zoom<SVGSVGElement, unknown>()
        .scaleExtent([0.15, 4])
        .on("zoom", (event) => root.attr("transform", event.transform)),
    );

    // ── Defs: gradients + arrow markers ──────────────────────────────────────

    const defs = svg.append("defs");

    // Per-severity linear gradient fills
    Object.entries(SEVERITY_GRAD).forEach(([sev, [from, to]]) => {
      const lg = defs.append("linearGradient")
        .attr("id", `node-grad-${sev}`)
        .attr("x1", "0%").attr("y1", "0%")
        .attr("x2", "100%").attr("y2", "0%");
      lg.append("stop").attr("offset", "0%").attr("stop-color", from);
      lg.append("stop").attr("offset", "100%").attr("stop-color", to);
    });

    // Arrow markers per edge type
    Object.entries(EDGE_COLOR).forEach(([type, color]) => {
      defs.append("marker")
        .attr("id", `arrow-${type}`)
        .attr("viewBox", "0 -4 8 8")
        .attr("refX", 1)
        .attr("refY", 0)
        .attr("markerWidth", 5)
        .attr("markerHeight", 5)
        .attr("orient", "auto")
        .append("path")
        .attr("d", "M0,-4L8,0L0,4")
        .attr("fill", color)
        .attr("opacity", 0.8);
    });

    // ── Sim data ──────────────────────────────────────────────────────────────

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

    // ── Links ─────────────────────────────────────────────────────────────────

    const link = root.append("g")
      .selectAll<SVGLineElement, SimLink>("line")
      .data(simLinks)
      .join("line")
      .attr("stroke", (d) => EDGE_COLOR[d.data.edge_type] ?? "#52525b")
      .attr("stroke-opacity", 0.55)
      .attr("stroke-width", (d) => 1 + d.data.confidence * 1.5)
      .attr("marker-end", (d) => `url(#arrow-${d.data.edge_type})`);

    // ── Nodes ─────────────────────────────────────────────────────────────────

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
          }),
      )
      .on("click", (_event, d) => {
        setSelectedNode((prev) => prev?.id === d.id ? null : d.data);
      });

    // Background rect (gradient fill)
    node.append("rect")
      .attr("x", -NODE_W / 2).attr("y", -NODE_H / 2)
      .attr("width", NODE_W).attr("height", NODE_H)
      .attr("rx", NODE_RX)
      .attr("fill", (d) => `url(#node-grad-${nodeSeverity(d.data)})`)
      .attr("stroke", (d) => nodeAccentColor(d.data))
      .attr("stroke-opacity", 0.3)
      .attr("stroke-width", 1);

    // Dashed border for code findings
    node.filter((d) => d.data.source === "code")
      .select("rect")
      .attr("stroke-dasharray", "4,3")
      .attr("stroke-opacity", 0.5);

    // Left accent bar
    node.append("rect")
      .attr("x", -NODE_W / 2)
      .attr("y", -NODE_H / 2)
      .attr("width", ACCENT_W)
      .attr("height", NODE_H)
      .attr("rx", NODE_RX)
      .attr("fill", (d) => nodeAccentColor(d.data))
      .attr("opacity", 0.85);

    // KEV glow ring
    node.filter((d) => !!d.data.kev)
      .append("rect")
      .attr("x", -NODE_W / 2 - 3).attr("y", -NODE_H / 2 - 3)
      .attr("width", NODE_W + 6).attr("height", NODE_H + 6)
      .attr("rx", NODE_RX + 3)
      .attr("fill", "none")
      .attr("stroke", "#ef4444")
      .attr("stroke-width", 1)
      .attr("stroke-opacity", 0.25);

    const TEXT_X = -NODE_W / 2 + ACCENT_W + 8;

    // Primary label (CVE ID or title)
    node.append("text")
      .attr("x", TEXT_X)
      .attr("y", -4)
      .attr("text-anchor", "start")
      .attr("dominant-baseline", "middle")
      .attr("font-size", 10)
      .attr("font-weight", "600")
      .attr("fill", "#fafafa")
      .attr("font-family", "'Poppins', system-ui, sans-serif")
      .text((d) => truncate(d.data.cve_id ?? d.data.title, 17));

    // Sub-label (package or file)
    node.append("text")
      .attr("x", TEXT_X)
      .attr("y", 10)
      .attr("text-anchor", "start")
      .attr("dominant-baseline", "middle")
      .attr("font-size", 8.5)
      .attr("fill", "#737373")
      .attr("font-family", "'Poppins', system-ui, sans-serif")
      .text((d) => truncate(
        d.data.package ?? d.data.file_path?.split("/").pop() ?? "",
        20,
      ));

    // ── Simulation ────────────────────────────────────────────────────────────

    const sim = d3.forceSimulation(simNodes)
      .force("link", d3.forceLink<SimNode, SimLink>(simLinks).id((d) => d.id).distance(180))
      .force("charge", d3.forceManyBody().strength(-420))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide<SimNode>().radius(Math.hypot(NODE_W / 2, NODE_H / 2) + 10))
      .on("tick", () => {
        link
          .attr("x1", (d) => {
            const s = d.source as SimNode, t = d.target as SimNode;
            return rectEdge(s.x ?? 0, s.y ?? 0, (t.x ?? 0) - (s.x ?? 0), (t.y ?? 0) - (s.y ?? 0))[0];
          })
          .attr("y1", (d) => {
            const s = d.source as SimNode, t = d.target as SimNode;
            return rectEdge(s.x ?? 0, s.y ?? 0, (t.x ?? 0) - (s.x ?? 0), (t.y ?? 0) - (s.y ?? 0))[1];
          })
          .attr("x2", (d) => {
            const s = d.source as SimNode, t = d.target as SimNode;
            return rectEdge(t.x ?? 0, t.y ?? 0, (s.x ?? 0) - (t.x ?? 0), (s.y ?? 0) - (t.y ?? 0))[0];
          })
          .attr("y2", (d) => {
            const s = d.source as SimNode, t = d.target as SimNode;
            return rectEdge(t.x ?? 0, t.y ?? 0, (s.x ?? 0) - (t.x ?? 0), (s.y ?? 0) - (t.y ?? 0))[1];
          });
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
    <>
      <div className="relative h-[calc(100vh-220px)] min-h-120 overflow-hidden rounded-xl border border-border bg-card">
        <svg ref={svgRef} className="h-full w-full" />
        <Legend />
        <div className="absolute right-3 top-3 rounded-md bg-card/80 px-2.5 py-1 text-xs text-muted-foreground backdrop-blur-sm ring-1 ring-white/5">
          {graph.nodes.length} nodes · {graph.edges.length} edges · scroll to zoom · drag to pan
        </div>
      </div>

      <Sheet open={!!selectedNode} onOpenChange={(open) => { if (!open) setSelectedNode(null); }}>
        <SheetContent side="right" className="flex w-80 flex-col gap-0 p-0">
          {selectedNode && (
            <>
              <SheetHeader>
                <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
                  {selectedNode.source === "code" ? "Code Finding" : "Dependency CVE"}
                </p>
                <SheetTitle className="font-mono text-sm leading-snug">
                  {selectedNode.title}
                </SheetTitle>
              </SheetHeader>
              <NodeDetailContent node={selectedNode} />
            </>
          )}
        </SheetContent>
      </Sheet>
    </>
  );
}
