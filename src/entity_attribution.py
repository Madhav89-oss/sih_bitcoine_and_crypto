"""
Entity attribution ("whose wallet is this?") and Threat Intelligence layer.

Combines:
1. Common-Input-Ownership Heuristic (CIOH):
   All input addresses on a single transaction are co-signed and merged into one cluster.
2. Change-Address Heuristic:
   Identifies change outputs returned to the sender across transaction hops.
3. Multi-Hop Threat Intelligence Propagation:
   Propagates darknet, ransomware, mixer, sanctions, and terror financing tags
   from known/tagged seeds across the co-controlled cluster with hop-decayed confidence.
"""
import pandas as pd


class UnionFind:
    def __init__(self):
        self.parent = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


def _is_likely_change(row, output_idx: int) -> bool:
    """Heuristic: exactly 2 outputs, not round amount, smaller output amount."""
    if row["n_outputs"] != 2:
        return False
    amt = row["output_amounts"][output_idx]
    other_idx = 1 - output_idx
    other_amt = row["output_amounts"][other_idx]
    is_round = round(amt, 3) == round(amt, 8) and (amt * 1000) == int(amt * 1000)
    return (not is_round) and amt < other_amt


def build_ciohc_clusters(df: pd.DataFrame) -> dict:
    """Returns {wallet_address: cluster_id} using CIOH + change-address heuristics."""
    uf = UnionFind()

    for _, row in df.iterrows():
        inputs = row["input_addresses"]
        for addr in inputs:
            uf.find(addr)
        for i in range(1, len(inputs)):
            uf.union(inputs[0], inputs[i])

        if inputs:
            anchor = inputs[0]
            for i, out_addr in enumerate(row["output_addresses"]):
                if _is_likely_change(row, i):
                    uf.union(anchor, out_addr)

    return {addr: uf.find(addr) for addr in uf.parent}


def load_known_wallets(path: str) -> pd.DataFrame:
    try:
        return pd.read_csv(path)
    except FileNotFoundError:
        return pd.DataFrame(columns=[
            "address", "entity_name", "category", "threat_level", "risk_score",
            "confidence", "source", "onion_source", "first_seen", "last_seen"
        ])


def attribute_clusters(clusters: dict, known_wallets: pd.DataFrame) -> pd.DataFrame:
    """
    clusters: {address: cluster_id} from build_ciohc_clusters
    known_wallets: DataFrame with threat intel columns

    Returns a per-wallet attribution table: address, cluster_id, cluster_size,
    attributed_entity, category, threat_level, risk_score, confidence, evidence, onion_source.
    """
    known_map = known_wallets.set_index("address").to_dict("index") if len(known_wallets) else {}

    cluster_tags = {}
    cluster_members = {}
    for addr, cid in clusters.items():
        cluster_members.setdefault(cid, []).append(addr)
        if addr in known_map:
            cluster_tags.setdefault(cid, []).append((addr, known_map[addr]))

    rows = []
    for addr, cid in clusters.items():
        members = cluster_members[cid]
        tags = cluster_tags.get(cid, [])
        if tags:
            # highest-risk / highest-confidence tag wins
            best_addr, best_tag = max(
                tags,
                key=lambda t: (float(t[1].get("risk_score", 0)), float(t[1].get("confidence", 0)))
            )
            is_direct = (addr == best_addr)
            confidence = float(best_tag.get("confidence", 0.9)) if is_direct else round(float(best_tag.get("confidence", 0.9)) * 0.85, 2)
            
            rows.append({
                "address": addr,
                "cluster_id": cid,
                "cluster_size": len(members),
                "attributed_entity": best_tag.get("entity_name"),
                "category": best_tag.get("category"),
                "threat_level": best_tag.get("threat_level", "HIGH"),
                "risk_score": best_tag.get("risk_score", 85),
                "confidence": confidence,
                "onion_source": best_tag.get("onion_source", ""),
                "evidence": (
                    f"Direct hit: matches known intelligence record for {best_tag.get('entity_name')} ({best_tag.get('source', 'Threat DB')})"
                    if is_direct
                    else f"CIOH Cluster link: co-spends with {best_tag.get('category')} seed {best_addr[:14]}… in cluster of {len(members)} wallets"
                ),
            })
        else:
            rows.append({
                "address": addr,
                "cluster_id": cid,
                "cluster_size": len(members),
                "attributed_entity": None,
                "category": None,
                "threat_level": "LOW",
                "risk_score": 10,
                "confidence": None,
                "onion_source": None,
                "evidence": None,
            })
    return pd.DataFrame(rows)


if __name__ == "__main__":
    from ingest import load_csv
    df = load_csv("../output/transactions.csv")
    clusters = build_ciohc_clusters(df)
    known = load_known_wallets("../output/known_wallets.csv")
    attribution = attribute_clusters(clusters, known)
    n_attributed = attribution["attributed_entity"].notna().sum()
    print(f"{len(clusters)} wallets in {attribution['cluster_id'].nunique()} CIOH clusters")
    print(f"{n_attributed} wallets attributed to a known entity")
