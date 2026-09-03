import { useMemo } from "react";
import type {
  AttackChainStep, AttackChainEdge, AttackChainStepStatus,
} from "../api";

/**
 * P7-C2 — compact SVG DAG for attack-chain views (AD / Cloud / Web).
 *
 * The chain views used to render steps as a linear timeline. That works
 * for a mostly-linear chain but hides the branching that a real chain
 * has (SMB null-session unlocks several leaves; cloud pivot forks
 * between IAM abuse + KMS reach). This component renders the same
 * `steps + edges` payload as a layered DAG so the branching is
 * visible at a glance:
 *
 *   * layer index = longest depends_on chain to a node → nodes stack
 *     left-to-right by dependency depth
 *   * within a layer, nodes are stacked vertically in step-id order
 *     so the layout is stable across renders
 *   * each node is a circle colored by status (proven / pending /
 *     blocked / skipped) matching the timeline's palette
 *   * edges are drawn as curved paths from source-right to target-
 *     left with an arrowhead marker so the direction is obvious
 *
 * Clicking a node fires `onSelect(id)` — the parent `ChainView` scrolls
 * the corresponding step card into view. Purely additive: the timeline
 * below is unchanged.
 */
const STATUS_META: Record<AttackChainStepStatus, { color: string; label: string }> = {
  proven:  { color: "#16a34a", label: "proven" },
  pending: { color: "#d97706", label: "pending" },
  blocked: { color: "#dc2626", label: "blocked" },
  skipped: { color: "#8892a0", label: "skipped" },
};

const NODE_R = 14;         // node radius
const COL_W = 130;          // horizontal spacing per layer
const ROW_H = 56;           // vertical spacing per row within a layer
const PAD_X = 22;
const PAD_Y = 22;

interface LayoutNode {
  id: string;
  title: string;
  status: AttackChainStepStatus;
  layer: number;
  row: number;
  x: number;
  y: number;
}

function computeLayers(steps: AttackChainStep[]): Map<string, number> {
  // Longest-path layering: layer(v) = 1 + max(layer(u) for u in deps).
  // Steps with no deps land in layer 0. Handles unreachable-in-graph
  // steps gracefully (they stay in layer 0 too).
  const byId = new Map(steps.map((s) => [s.id, s]));
  const layer = new Map<string, number>();
  const visiting = new Set<string>();

  const resolve = (id: string): number => {
    if (layer.has(id)) return layer.get(id)!;
    if (visiting.has(id)) return 0;              // cycle guard — treat as root
    const s = byId.get(id);
    if (!s || s.depends_on.length === 0) {
      layer.set(id, 0);
      return 0;
    }
    visiting.add(id);
    let best = 0;
    for (const dep of s.depends_on) {
      if (!byId.has(dep)) continue;              // dropped by server-side filter
      best = Math.max(best, resolve(dep) + 1);
    }
    visiting.delete(id);
    layer.set(id, best);
    return best;
  };
  for (const s of steps) resolve(s.id);
  return layer;
}

function layout(steps: AttackChainStep[]): { nodes: LayoutNode[]; width: number; height: number } {
  const layerOf = computeLayers(steps);
  // Bucket by layer, preserve declared step order within each layer.
  const buckets = new Map<number, AttackChainStep[]>();
  for (const s of steps) {
    const l = layerOf.get(s.id) ?? 0;
    if (!buckets.has(l)) buckets.set(l, []);
    buckets.get(l)!.push(s);
  }
  const maxLayer = Math.max(0, ...buckets.keys());
  const maxRow = Math.max(0, ...[...buckets.values()].map((b) => b.length - 1));

  const nodes: LayoutNode[] = [];
  for (const [l, group] of buckets) {
    // Vertical centering per layer around the tallest layer.
    const groupH = (group.length - 1) * ROW_H;
    const tallest = maxRow * ROW_H;
    const yOffset = (tallest - groupH) / 2;
    group.forEach((s, i) => {
      nodes.push({
        id: s.id,
        title: s.title,
        status: s.status,
        layer: l,
        row: i,
        x: PAD_X + NODE_R + l * COL_W,
        y: PAD_Y + NODE_R + yOffset + i * ROW_H,
      });
    });
  }
  const width  = PAD_X * 2 + NODE_R * 2 + maxLayer * COL_W;
  const height = PAD_Y * 2 + NODE_R * 2 + maxRow * ROW_H;
  return { nodes, width, height };
}

function edgePath(from: LayoutNode, to: LayoutNode): string {
  // Cubic bezier from source-right → target-left. Horizontal handle
  // proportional to the layer gap so wider hops arc more gently.
  const x1 = from.x + NODE_R, y1 = from.y;
  const x2 = to.x - NODE_R,   y2 = to.y;
  const handle = Math.max(24, (x2 - x1) * 0.45);
  return `M ${x1} ${y1} C ${x1 + handle} ${y1}, ${x2 - handle} ${y2}, ${x2} ${y2}`;
}

export function ChainGraph(
  { steps, edges, onSelect }:
  { steps: AttackChainStep[]; edges: AttackChainEdge[]; onSelect?: (id: string) => void }
) {
  const { nodes, width, height } = useMemo(() => layout(steps), [steps]);
  const nodeMap = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);
  // Number the nodes in declared step order so a chip in the graph
  // matches "step N" in the timeline below.
  const numberOf = useMemo(() => {
    const m = new Map<string, number>();
    steps.forEach((s, i) => m.set(s.id, i + 1));
    return m;
  }, [steps]);

  if (steps.length === 0) return null;

  const arrowId = "chaingraph-arrow";
  return (
    <div className="chain-graph-wrap">
      <svg className="chain-graph" viewBox={`0 0 ${width} ${height}`}
           width="100%" height={height + 8}
           preserveAspectRatio="xMidYMid meet"
           role="img" aria-label="attack chain dependency graph">
        <defs>
          <marker id={arrowId} viewBox="0 0 8 8" refX="7" refY="4"
                  markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M 0 0 L 8 4 L 0 8 z" fill="var(--muted)" />
          </marker>
        </defs>
        {/* Edges first so nodes render on top. */}
        {edges.map((e) => {
          const a = nodeMap.get(e.from);
          const b = nodeMap.get(e.to);
          if (!a || !b) return null;
          return (
            <path key={`${e.from}->${e.to}`}
                  d={edgePath(a, b)}
                  className="chain-edge"
                  markerEnd={`url(#${arrowId})`} />
          );
        })}
        {/* Nodes. */}
        {nodes.map((n) => {
          const meta = STATUS_META[n.status];
          const num = numberOf.get(n.id) || "?";
          return (
            <g key={n.id}
               className="chain-node"
               transform={`translate(${n.x}, ${n.y})`}
               onClick={() => onSelect?.(n.id)}
               onKeyDown={(ev) => {
                 // Nodes are role=button + tabIndex=0, so the focus ring
                 // lands on them naturally. Wire Enter + Space to fire
                 // the same handler as click — otherwise a keyboard user
                 // can tab TO a step but never activate it.
                 if (ev.key === "Enter" || ev.key === " ") {
                   ev.preventDefault();
                   onSelect?.(n.id);
                 }
               }}
               tabIndex={0}
               role="button"
               aria-label={`${n.title} — ${meta.label}`}>
              <title>{`${n.title} · ${meta.label}`}</title>
              <circle r={NODE_R} fill={meta.color}
                      stroke="var(--surface)" strokeWidth={3} />
              <text textAnchor="middle" dominantBaseline="central"
                    fontSize={11} fontWeight={700} fill="#fff"
                    fontFamily="var(--mono)">
                {n.status === "proven" ? "✓" : num}
              </text>
              <text x={0} y={NODE_R + 12} textAnchor="middle"
                    className="chain-node-label"
                    fontSize={10} fill="var(--text)">
                {n.title.length > 18 ? n.title.slice(0, 16) + "…" : n.title}
              </text>
            </g>
          );
        })}
      </svg>
      <div className="chain-graph-legend muted">
        {(["proven", "pending", "blocked", "skipped"] as AttackChainStepStatus[]).map((k) => (
          <span key={k} className="chain-legend-item">
            <span className="chain-legend-dot"
                  style={{ background: STATUS_META[k].color }} />
            {STATUS_META[k].label}
          </span>
        ))}
      </div>
    </div>
  );
}
