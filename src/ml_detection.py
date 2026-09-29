"""
AI/ML detection layer.

1. IsolationForest -> unsupervised anomaly score per transaction (0-100, higher = more suspicious)
2. Louvain community detection on the undirected wallet-wallet projection -> entity clusters
   (wallets that transact closely together get grouped, surfacing custodial/mixing groups)
"""
import community as community_louvain  # python-louvain
import networkx as nx
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


def run_anomaly_detection(feat_df: pd.DataFrame, feature_cols: list, contamination: float = 0.06):
    X = feat_df[feature_cols].replace([np.inf, -np.inf], 0).fillna(0).values
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=300, contamination=contamination, random_state=42, n_jobs=-1
    )
    model.fit(Xs)

    raw_scores = model.decision_function(Xs)  # higher = more normal
    preds = model.predict(Xs)  # -1 anomaly, 1 normal

    # convert to an intuitive 0-100 "suspicion score", higher = more suspicious
    norm = (raw_scores.max() - raw_scores) / (raw_scores.max() - raw_scores.min() + 1e-12)
    suspicion = (norm * 100).round(1)

    feat_df = feat_df.copy()
    feat_df["is_anomaly"] = (preds == -1)
    feat_df["suspicion_score"] = suspicion
    return feat_df, model, scaler, Xs


def build_wallet_projection(G: nx.MultiDiGraph) -> nx.Graph:
    """Collapse tx nodes: connect wallets that co-occur as input+output on the same tx."""
    W = nx.Graph()
    tx_nodes = [n for n, d in G.nodes(data=True) if d.get("type") == "tx"]
    for tx in tx_nodes:
        inputs = [u for u, _, d in G.in_edges(tx, data=True) if d.get("kind") == "input"]
        outputs = [v for _, v, d in G.out_edges(tx, data=True) if d.get("kind") == "output"]
        for a in inputs:
            for b in outputs:
                if a != b:
                    if W.has_edge(a, b):
                        W[a][b]["weight"] += 1
                    else:
                        W.add_edge(a, b, weight=1)
    return W


def run_entity_clustering(G: nx.MultiDiGraph):
    W = build_wallet_projection(G)
    if W.number_of_edges() == 0:
        return {}, W
    partition = community_louvain.best_partition(W, weight="weight", random_state=42)
    return partition, W


if __name__ == "__main__":
    from ingest import load_csv
    from graph_builder import build_graph
    from features import build_features

    df = load_csv("../output/transactions.csv")
    G = build_graph(df)
    feat_df, cols = build_features(df, G)
    feat_df, model, scaler, Xs = run_anomaly_detection(feat_df, cols)
    print(feat_df["is_anomaly"].sum(), "anomalies flagged out of", len(feat_df))

    partition, W = run_entity_clustering(G)
    n_clusters = len(set(partition.values())) if partition else 0
    print(f"{n_clusters} wallet clusters found across {W.number_of_nodes()} wallets")
