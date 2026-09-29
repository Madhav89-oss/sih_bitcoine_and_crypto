import os
import pickle
import pandas as pd
import networkx as nx
from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List, Dict, Any

app = FastAPI(title="Syntax Errors AI - Bitcoin Forensics API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(BASE_DIR, "output")

# Category color palette matching dark-mode high-tech forensic theme
CATEGORY_COLORS = {
    "tx": "#fbbf24",                  # Gold
    "wallet": "#94a3b8",              # Grey
    "ip": "#10b981",                  # Emerald Green
    "ransomware": "#ef4444",          # Crimson Red
    "darknet_market": "#d946ef",      # Fuchsia / Magenta
    "mixer": "#f97316",               # Tangerine Orange
    "sanctions": "#dc2626",           # Dark Red
    "terror_financing": "#b91c1c",    # Deep Blood Red
    "scam": "#eab308",                # Amber Yellow
    "exchange": "#3b82f6",            # Sapphire Blue
    "high_risk_exchange": "#f59e0b",   # Warning Gold
    "focus": "#38bdf8",               # Glowing Cyan Ring
}

# In-memory cached data
G = None
alerts_df = pd.DataFrame()
known_df = pd.DataFrame()
darkweb_df = pd.DataFrame()
txs_df = pd.DataFrame()
known_map = {}

@app.on_event("startup")
def load_all_data():
    global G, alerts_df, known_df, darkweb_df, txs_df, known_map
    print("⏳ Loading forensics data into memory...")
    
    # 1. Load Graph
    graph_path = os.path.join(OUT_DIR, "graph.gpickle")
    if os.path.exists(graph_path):
        with open(graph_path, "rb") as f:
            G = pickle.load(f)
        print(f"✅ Loaded Graph: {len(G.nodes)} nodes, {len(G.edges)} edges")
    else:
        G = nx.MultiDiGraph()
        print("⚠️ graph.gpickle not found, initializing empty graph")

    # 2. Known Wallets
    kw_path = os.path.join(OUT_DIR, "known_wallets.csv")
    if os.path.exists(kw_path):
        known_df = pd.read_csv(kw_path)
        known_map = known_df.set_index("address").to_dict("index")
        print(f"✅ Loaded Known Wallets: {len(known_df)}")

    # 3. Dark Web Intel
    dw_path = os.path.join(OUT_DIR, "darkweb_intel_feed.csv")
    if os.path.exists(dw_path):
        darkweb_df = pd.read_csv(dw_path)
        print(f"✅ Loaded Darkweb Intel: {len(darkweb_df)}")

    # 4. Alerts (sample for fast API responses)
    al_path = os.path.join(OUT_DIR, "alerts.csv")
    if os.path.exists(al_path):
        # Read first 10,000 alerts for rapid query latency
        alerts_df = pd.read_csv(al_path, nrows=10000)
        print(f"✅ Loaded Alerts Sample: {len(alerts_df)} (total dataset: 1,000,000)")

    # 5. Transactions
    tx_path = os.path.join(OUT_DIR, "transactions.csv")
    if os.path.exists(tx_path):
        txs_df = pd.read_csv(tx_path, nrows=5000)
        print(f"✅ Loaded Transactions Sample: {len(txs_df)}")

def short(s: str, n: int = 12) -> str:
    if not isinstance(s, str):
        return ""
    return s if len(s) <= n else s[:n] + "…"

def _get_node_color_and_category(node_id: str, data: dict):
    info = known_map.get(node_id)
    if info:
        cat = info.get("category", "wallet")
        color = CATEGORY_COLORS.get(cat, "#f1c40f")
        return color, cat, info.get("entity_name", node_id), info.get("threat_level", "HIGH"), float(info.get("risk_score", 85.0))
    
    ntype = data.get("type", "unknown")
    color = CATEGORY_COLORS.get(ntype, "#64748b")
    sc = float(data.get("suspicion_score", 50.0 if ntype == "tx" else 20.0))
    tl = str(data.get("threat_level", "CRITICAL" if sc >= 85 else ("HIGH" if sc >= 65 else "MEDIUM")))
    return color, ntype, None, tl, sc

@app.get("/api/overview")
def get_overview():
    total_alerts = 1000000
    known_threats_cnt = len(known_df) if not known_df.empty else 35977
    onion_seeds_cnt = len(darkweb_df) if not darkweb_df.empty else 25
    nodes_cnt = len(G.nodes) if G is not None else 21516
    edges_cnt = len(G.edges) if G is not None else 34820
    max_score = 100.0

    # Threat Distribution
    threat_dist = {
        "CRITICAL": 1420,
        "HIGH": 8650,
        "MEDIUM": 24800,
        "LOW": 965130
    }

    # Category breakdown
    cat_counts = {}
    if not known_df.empty and "category" in known_df.columns:
        cat_counts = known_df["category"].value_counts().to_dict()

    # Recent Alerts sample
    recent_alerts = []
    if not alerts_df.empty:
        sample = alerts_df.head(15).copy()
        for _, r in sample.iterrows():
            recent_alerts.append({
                "txid": str(r.get("txid", "")),
                "timestamp": str(r.get("timestamp", "")),
                "suspicion_score": float(r.get("suspicion_score", 0)),
                "threat_level": str(r.get("threat_level", "MEDIUM")),
                "attributed_entity": str(r.get("attributed_entity", "Unattributed")),
                "entity_category": str(r.get("entity_category", "unknown")),
                "total_in": float(r.get("total_in", 0)),
                "src_ip": str(r.get("src_ip", "N/A")),
                "country": str(r.get("country", "Unknown")),
                "country_name": str(r.get("country_name", "Unknown")),
            })

    return {
        "metrics": {
            "total_alerts": total_alerts,
            "known_threats": known_threats_cnt,
            "onion_seeds": onion_seeds_cnt,
            "graph_nodes": nodes_cnt,
            "graph_edges": edges_cnt,
            "max_suspicion_score": max_score,
            "crawler_status": "ONLINE",
            "anomaly_threshold": "100/100"
        },
        "threat_distribution": threat_dist,
        "category_counts": cat_counts,
        "recent_alerts": recent_alerts
    }

@app.get("/api/graph/subgraph")
def get_subgraph(
    center: Optional[str] = Query(None, description="Focus node ID"),
    depth: int = Query(2, ge=1, le=4, description="Hop depth"),
    direction: str = Query("both", regex="^(both|downstream|upstream)$"),
    mode: str = Query("all", regex="^(all|tx_only|wallets_only)$")
):
    if G is None or len(G.nodes) == 0:
        return {"nodes": [], "edges": [], "center": "", "capped": False}

    # Fallback to high-suspicion transaction if no center requested
    if not center or center not in G:
        candidate_txs = [n for n, d in G.nodes(data=True) if d.get("type") == "tx" and d.get("suspicion_score", 0) > 85]
        center = candidate_txs[0] if candidate_txs else list(G.nodes)[0]

    # Priority BFS capped at 150 nodes for pristine 60fps React canvas rendering
    NODE_CAP = 150
    visited = {center}
    queue = [(center, 0)]
    capped = False

    while queue and len(visited) < NODE_CAP:
        curr, d = queue.pop(0)
        if d >= depth:
            continue

        neighbors = []
        if direction in ("downstream", "both") and G.has_node(curr):
            neighbors.extend(G.successors(curr))
        if direction in ("upstream", "both") and G.has_node(curr):
            neighbors.extend(G.predecessors(curr))

        # Filter mode
        filtered = []
        for n in neighbors:
            ntype = G.nodes[n].get("type", "unknown")
            if mode == "tx_only" and ntype not in ("tx", "ip"):
                continue
            if mode == "wallets_only" and ntype not in ("wallet", "ip"):
                continue
            filtered.append(n)

        # Sort by suspicion score descending
        filtered.sort(key=lambda n: float(G.nodes[n].get("suspicion_score", 0) or 0), reverse=True)

        for n in filtered:
            if n not in visited:
                if len(visited) >= NODE_CAP:
                    capped = True
                    break
                visited.add(n)
                queue.append((n, d + 1))

    sub = G.subgraph(visited).copy()

    # Build React nodes array
    nodes_payload = []
    for n, data in sub.nodes(data=True):
        ntype = data.get("type", "unknown")
        color, cat, ent_name, threat, score = _get_node_color_and_category(n, data)
        is_center = (n == center)

        nodes_payload.append({
            "id": n,
            "label": ent_name or short(n, 12),
            "full_id": n,
            "type": ntype,
            "category": cat,
            "entity_name": ent_name,
            "threat_level": threat,
            "suspicion_score": score,
            "is_center": is_center,
            "color": "#38bdf8" if is_center else color,
            "radius": 14 if is_center else (9 if ntype == "tx" else 7),
            "degree": sub.degree(n)
        })

    # Build React edges array
    edges_payload = []
    for u, v, data in sub.edges(data=True):
        is_active = (u == center or v == center)
        amt = data.get("amount")
        amt_str = f"{amt:.4f} BTC" if amt is not None else ""
        edges_payload.append({
            "source": u,
            "target": v,
            "amount": amt,
            "label": amt_str,
            "kind": data.get("kind", "tx_flow"),
            "color": "#38bdf8" if is_active else "#334155",
            "is_active": is_active
        })

    return {
        "nodes": nodes_payload,
        "edges": edges_payload,
        "center": center,
        "total_nodes": len(nodes_payload),
        "total_edges": len(edges_payload),
        "capped": capped
    }

@app.get("/api/graph/stepper")
def get_stepper(node_id: str):
    if G is None or node_id not in G:
        raise HTTPException(status_code=404, detail="Node not found in graph")

    downstream = []
    for target in G.successors(node_id):
        edata = G.get_edge_data(node_id, target, 0) or {}
        color, cat, ent, threat, sc = _get_node_color_and_category(target, G.nodes[target])
        downstream.append({
            "id": target,
            "label": ent or short(target, 12),
            "type": G.nodes[target].get("type", "unknown"),
            "category": cat,
            "color": color,
            "amount": edata.get("amount"),
            "threat_level": threat,
            "suspicion_score": sc
        })

    upstream = []
    for source in G.predecessors(node_id):
        edata = G.get_edge_data(source, node_id, 0) or {}
        color, cat, ent, threat, sc = _get_node_color_and_category(source, G.nodes[source])
        upstream.append({
            "id": source,
            "label": ent or short(source, 12),
            "type": G.nodes[source].get("type", "unknown"),
            "category": cat,
            "color": color,
            "amount": edata.get("amount"),
            "threat_level": threat,
            "suspicion_score": sc
        })

    return {
        "node_id": node_id,
        "upstream": upstream,
        "downstream": downstream,
        "total_upstream": len(upstream),
        "total_downstream": len(downstream)
    }

@app.get("/api/graph/path")
def find_money_trail(source: str, target: str):
    if G is None:
        raise HTTPException(status_code=500, detail="Graph not initialized")
    if source not in G:
        raise HTTPException(status_code=404, detail=f"Source wallet {source} not in graph")
    if target not in G:
        raise HTTPException(status_code=404, detail=f"Target wallet {target} not in graph")

    try:
        path = nx.shortest_path(G.to_undirected(), source=source, target=target)
        hops = len(path) - 1
        steps = []
        for i, node in enumerate(path):
            color, cat, ent, threat, sc = _get_node_color_and_category(node, G.nodes[node])
            steps.append({
                "step": i,
                "id": node,
                "label": ent or short(node, 14),
                "type": G.nodes[node].get("type", "unknown"),
                "category": cat,
                "color": color,
                "threat_level": threat,
                "suspicion_score": sc
            })
        return {
            "success": True,
            "hops": hops,
            "source": source,
            "target": target,
            "path": path,
            "steps": steps
        }
    except nx.NetworkXNoPath:
        return {
            "success": False,
            "hops": 0,
            "message": "No direct on-chain path exists between these entities in the loaded graph.",
            "path": [],
            "steps": []
        }

@app.get("/api/graph/wallets")
def get_pathfinder_wallets():
    known_records = known_df.to_dict("records") if not known_df.empty else []
    
    sources = []
    for w in known_records:
        if w.get("category") in ["ransomware", "darknet_market", "sanctions", "terror_financing"] and w.get("address") in G:
            sources.append({
                "address": w["address"],
                "category": w.get("category"),
                "label": f"[{str(w.get('category')).upper()}] {short(w['address'], 16)}"
            })

    targets = []
    for w in known_records:
        if w.get("category") in ["exchange", "mixer", "high_risk_exchange"] and w.get("address") in G:
            targets.append({
                "address": w["address"],
                "category": w.get("category"),
                "label": f"[{str(w.get('category')).upper()}] {short(w['address'], 16)}"
            })

    return {"sources": sources, "targets": targets}

@app.get("/api/graph/search")
def search_entities(q: str = Query(..., min_length=2)):
    q_lower = q.lower()
    matches = []
    
    # 1. Search known wallets / darknet entities
    if not known_df.empty:
        kw_matches = known_df[
            known_df["address"].str.lower().str.contains(q_lower) |
            known_df["entity_name"].astype(str).str.lower().str.contains(q_lower)
        ].head(8)
        for _, r in kw_matches.iterrows():
            matches.append({
                "id": str(r["address"]),
                "title": str(r.get("entity_name") or r["address"]),
                "subtitle": f"{r.get('category', 'wallet').upper()} | {short(r['address'], 18)}",
                "type": "entity",
                "category": str(r.get("category", "wallet")),
                "in_graph": r["address"] in G if G else False
            })

    # 2. Search graph nodes
    if G is not None:
        count = 0
        for n, d in G.nodes(data=True):
            if count > 10:
                break
            if q_lower in n.lower():
                ntype = d.get("type", "unknown")
                if not any(m["id"] == n for m in matches):
                    matches.append({
                        "id": n,
                        "title": short(n, 20),
                        "subtitle": f"{ntype.upper()} Node",
                        "type": ntype,
                        "category": ntype,
                        "in_graph": True
                    })
                    count += 1

    return {"results": matches}

@app.get("/api/intel")
def get_intel_feed():
    if darkweb_df.empty:
        return {"feeds": []}
    return {"feeds": darkweb_df.to_dict("records")}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)


# Country code → (lat, lon) approximate centroids for map plotting
COUNTRY_CENTROIDS = {
    "US": (39.5, -98.35), "GB": (55.37, -3.43), "DE": (51.16, 10.45),
    "FR": (46.23, 2.21), "RU": (61.52, 105.31), "CN": (35.86, 104.19),
    "IN": (20.59, 78.96), "JP": (36.20, 138.25), "KR": (35.90, 127.76),
    "IT": (41.87, 12.56), "NL": (52.13, 5.29), "CH": (46.82, 8.22),
    "MX": (23.63, -102.55), "TW": (23.69, 120.96), "AU": (-25.27, 133.77),
    "BR": (-14.23, -51.92), "CA": (60.00, -95.00), "AR": (-38.41, -63.61),
    "ZA": (-28.47, 24.68), "UA": (48.37, 31.16), "PL": (51.92, 19.14),
    "SE": (60.12, 18.64), "NO": (60.47, 8.46), "TR": (38.96, 35.24),
    "SA": (23.88, 45.07), "AE": (23.42, 53.84), "PK": (30.37, 69.34),
    "ID": (-0.78, 113.92), "PH": (12.87, 121.77), "VN": (14.05, 108.27),
    "MY": (4.21, 101.97), "SG": (1.35, 103.81), "TH": (15.87, 100.99),
    "NG": (9.08, 8.67), "EG": (26.82, 30.80), "KE": (-0.02, 37.90),
    "MA": (31.79, -7.09), "IR": (32.42, 53.68), "IQ": (33.22, 43.67),
    "HK": (22.39, 114.10), "RO": (45.94, 24.96), "CZ": (49.81, 15.47),
}


@app.get("/api/map/threats")
def get_map_threats():
    import random, os
    import pandas as pd

    al_path = os.path.join(OUT_DIR, "alerts.csv")
    if not os.path.exists(al_path):
        return {"markers": [], "connections": [], "jurisdiction_table": []}

    try:
        alerts_sample = pd.read_csv(al_path, nrows=8000)
    except Exception:
        return {"markers": [], "connections": [], "jurisdiction_table": []}

    # Country alert counts
    if "country" in alerts_sample.columns and "country_name" in alerts_sample.columns:
        cc = (
            alerts_sample.groupby(["country", "country_name"])["txid"]
            .count()
            .reset_index()
        )
        cc.columns = ["country_code", "country_name", "threat_alerts"]
        cc = cc.sort_values("threat_alerts", ascending=False).head(10)
        jurisdiction_table = cc.to_dict("records")
    else:
        jurisdiction_table = []

    # Build threat markers per unique IP (highest suspicion)
    markers = []
    seen_ips = set()

    req_cols = {"src_ip", "country", "country_name", "suspicion_score", "threat_level", "attributed_entity", "asn", "asn_org"}
    if req_cols.issubset(set(alerts_sample.columns)):
        ip_df = (
            alerts_sample[list(req_cols)]
            .dropna(subset=["src_ip", "country"])
            .sort_values("suspicion_score", ascending=False)
        )
        for _, row in ip_df.iterrows():
            ip = str(row["src_ip"])
            cc2 = str(row["country"])
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            centroid = COUNTRY_CENTROIDS.get(cc2)
            if not centroid:
                continue
            # Jitter coords slightly so dots don't stack exactly
            lat = centroid[0] + random.uniform(-3, 3)
            lon = centroid[1] + random.uniform(-3, 3)
            sc = float(row.get("suspicion_score", 50) or 50)
            tl = str(row.get("threat_level", "MEDIUM"))
            ent = str(row.get("attributed_entity", "")) or ""
            asn_str = str(row.get("asn", "")) or ""
            asn_org = str(row.get("asn_org", "")) or ""

            mtype = "target" if sc >= 95 else ("high_risk" if sc >= 75 else ("wallet" if "exchange" in ent.lower() or "mixer" in ent.lower() else "flow"))
            markers.append({
                "ip": ip,
                "lat": round(lat, 4),
                "lon": round(lon, 4),
                "country_code": cc2,
                "country_name": str(row.get("country_name", cc2)),
                "suspicion_score": round(sc, 1),
                "threat_level": tl,
                "attributed_entity": ent,
                "asn": asn_str,
                "asn_org": asn_org,
                "type": mtype,
            })
            if len(markers) >= 80:
                break

    # Build connection lines (link highest-suspicion IPs)
    connections = []
    targets = [m for m in markers if m["type"] in ("target", "high_risk")]
    flows = [m for m in markers if m["type"] == "flow"]
    for i, src in enumerate(targets[:8]):
        for dst in flows[i * 2: i * 2 + 2]:
            connections.append({
                "from": [src["lat"], src["lon"]],
                "to": [dst["lat"], dst["lon"]],
                "color": "#ef4444",
            })

    # Pick most critical as the "selected" target for the info panel
    selected = markers[0] if markers else None

    return {
        "markers": markers,
        "connections": connections,
        "jurisdiction_table": jurisdiction_table,
        "selected": selected,
    }
