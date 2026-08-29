import { useCallback, useEffect, useRef, useState } from "react";
import { getJSON } from "../api";

// The maps the report writes as .svg files, served live instead. Same generators
// (recce/report/netmap.py), so what you see here is what lands in the deliverable.
type MapView = { id: string; label: string; blurb: string; available: boolean };
type ViewsResp = { views: MapView[]; hosts: number };

const TITLES: Record<string, string> = {
  architecture: "Architecture",
  overview: "Overview",
  full: "Every host",
  tiered: "Tiers",
  reachability: "Reachability",
  ad: "AD tier-0",
  attackpath: "Attack path",
};

// attackpath comes from a different endpoint (act/attackpath) but belongs in the
// same tab — an operator thinking "show me the environment" means this too.
const ATTACKPATH: MapView = {
  id: "attackpath", label: "attackpath",
  blurb: "projected chain from foothold to domain", available: true,
};

const ZOOM_MIN = 0.25, ZOOM_MAX = 6, ZOOM_STEP = 1.15;

export function Topology() {
  const [views, setViews] = useState<MapView[] | null>(null);
  const [hosts, setHosts] = useState(0);
  const [view, setView] = useState("architecture");
  const [svg, setSvg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Pan/zoom lives here rather than in CSS so Reset is exact and the download
  // always emits the untransformed source.
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const drag = useRef<{ x: number; y: number; px: number; py: number } | null>(null);

  const url = view === "attackpath" ? "/api/attackpath.svg" : `/api/netmap.svg?view=${view}`;

  useEffect(() => {
    getJSON<ViewsResp>("/api/netmap/views")
      .then((r) => { setViews([...r.views, ATTACKPATH]); setHosts(r.hosts); })
      .catch((e) => setErr(String(e)));
  }, []);

  const load = useCallback(() => {
    setLoading(true); setErr(null);
    fetch(url)
      .then((r) => r.ok ? r.text() : r.text().then((t) => { throw new Error(t || `${r.status}`); }))
      .then(setSvg)
      .catch((e) => setErr(String(e)))
      .finally(() => setLoading(false));
  }, [url]);

  useEffect(() => { load(); }, [load]);

  const reset = () => { setZoom(1); setPan({ x: 0, y: 0 }); };
  useEffect(() => { reset(); }, [view]);

  const onWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    setZoom((z) => Math.min(ZOOM_MAX, Math.max(ZOOM_MIN,
      e.deltaY < 0 ? z * ZOOM_STEP : z / ZOOM_STEP)));
  };
  const onDown = (e: React.MouseEvent) => {
    drag.current = { x: e.clientX, y: e.clientY, px: pan.x, py: pan.y };
  };
  const onMove = (e: React.MouseEvent) => {
    const d = drag.current;
    if (!d) return;
    setPan({ x: d.px + (e.clientX - d.x), y: d.py + (e.clientY - d.y) });
  };
  const onUp = () => { drag.current = null; };

  // Blank-but-valid SVG is what the API returns when a view has no data — treat
  // it as "nothing to draw" rather than rendering a 1x1 dot.
  const isEmpty = !!svg && svg.length < 200;

  if (err && !views) return <div className="err">{err}</div>;
  if (!views) return <div className="loading">Loading maps…</div>;

  return (
    <div className="topo-view">
      <section className="panel">
        <div className="panel-h">
          <span>Topology</span>
          <span className="muted">{hosts} live host{hosts === 1 ? "" : "s"}</span>
        </div>

        <div className="topo-bar">
          <div className="topo-views">
            {views.map((v) => (
              <button
                key={v.id}
                className={`topo-tab${v.id === view ? " on" : ""}`}
                disabled={!v.available}
                title={v.available ? v.blurb : `${v.blurb} — no data yet`}
                onClick={() => setView(v.id)}
              >{TITLES[v.id] ?? v.id}</button>
            ))}
          </div>
          <div className="topo-tools">
            <button onClick={() => setZoom((z) => Math.min(ZOOM_MAX, z * ZOOM_STEP))} title="Zoom in">+</button>
            <button onClick={() => setZoom((z) => Math.max(ZOOM_MIN, z / ZOOM_STEP))} title="Zoom out">−</button>
            <button onClick={reset} title="Reset view">Reset</button>
            <span className="topo-zoom">{Math.round(zoom * 100)}%</span>
            <button onClick={load} title="Redraw from the current datastore">Refresh</button>
            <a href={url} target="_blank" rel="noreferrer" title="Open the raw SVG">Open ↗</a>
          </div>
        </div>

        <p className="topo-blurb muted">
          {views.find((v) => v.id === view)?.blurb}
          {" — "}drag to pan, scroll to zoom. Same generator the report uses.
        </p>

        {err && <div className="err">{err}</div>}
        {loading && <div className="loading">Rendering…</div>}
        {!loading && isEmpty && (
          <div className="empty">
            Nothing to draw for this view yet.
            {view === "ad" && " Import BloodHound data (recce ad) to populate the AD tier-0 map."}
            {view === "reachability" && " Reachability needs hosts with overlapping segments or routes."}
            {view === "attackpath" && " No attack path projected yet — findings and access are what build it."}
          </div>
        )}
        {!loading && !isEmpty && svg && (
          <div
            className="topo-canvas"
            onWheel={onWheel}
            onMouseDown={onDown}
            onMouseMove={onMove}
            onMouseUp={onUp}
            onMouseLeave={onUp}
          >
            <div
              className="topo-stage"
              style={{ transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})` }}
              // The SVG is generated server-side by recce's own netmap module from
              // the engagement datastore — not third-party or user-submitted markup.
              dangerouslySetInnerHTML={{ __html: svg }}
            />
          </div>
        )}
      </section>
    </div>
  );
}
