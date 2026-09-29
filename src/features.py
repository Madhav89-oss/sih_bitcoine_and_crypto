"""
Feature engineering layer.
Builds a per-transaction feature matrix combining:
  - raw transaction shape features (fan-in/out, amounts, fee ratio)
  - temporal features (time since last tx from same src_ip / wallet)
  - graph link-analysis features (degree, IP fan-out, betweenness proxy, flow concentration)
"""
import networkx as nx
import numpy as np
import pandas as pd


def _output_equality_score(amounts):
    """0 = very unequal outputs, 1 = near-identical outputs (mixing signature)."""
    if len(amounts) < 2:
        return 0.0
    arr = np.array(amounts)
    if arr.mean() == 0:
        return 0.0
    cv = arr.std() / (arr.mean() + 1e-12)  # coefficient of variation
    return float(max(0.0, 1.0 - cv))


def build_features(df: pd.DataFrame, G: nx.MultiDiGraph) -> tuple:
    df = df.copy()
    df["fee_ratio"] = df["fee"] / (df["total_in"] + 1e-12)
    df["change_ratio"] = df["total_out"] / (df["total_in"] + 1e-12)
    df["output_equality"] = df["output_amounts"].apply(_output_equality_score)
    df["fanout_ratio"] = df["n_outputs"] / (df["n_inputs"] + 1e-12)

    # time since previous tx broadcast from the same src_ip (rapid-layering / bot signature)
    df = df.sort_values("timestamp")
    df["prev_ts_same_ip"] = df.groupby("src_ip")["timestamp"].shift(1)
    df["seconds_since_prev_ip_tx"] = (
        (df["timestamp"] - df["prev_ts_same_ip"]).dt.total_seconds()
    )
    df["seconds_since_prev_ip_tx"] = df["seconds_since_prev_ip_tx"].fillna(
        df["seconds_since_prev_ip_tx"].median()
    )

    # graph-derived: distinct wallets seen broadcasting from this tx's src_ip
    ip_wallet_fanout = {}
    for _, row in df.iterrows():
        ip = row["src_ip"]
        wallets = set(row["input_addresses"])
        ip_wallet_fanout.setdefault(ip, set()).update(wallets)
    df["ip_distinct_wallets"] = df["src_ip"].map(lambda ip: len(ip_wallet_fanout.get(ip, set())))

    # Network analysis link features (Praescient / i2 methodology)
    df["tx_degree"] = df["txid"].map(lambda t: G.degree(t) if t in G else 0)
    df["tx_in_degree"] = df["txid"].map(lambda t: G.in_degree(t) if t in G else 0)
    df["tx_out_degree"] = df["txid"].map(lambda t: G.out_degree(t) if t in G else 0)

    feature_cols = [
        "n_inputs", "n_outputs", "total_in", "total_out", "fee_ratio",
        "change_ratio", "output_equality", "fanout_ratio",
        "seconds_since_prev_ip_tx", "ip_distinct_wallets", "tx_degree",
        "tx_in_degree", "tx_out_degree",
    ]
    return df, feature_cols


if __name__ == "__main__":
    from ingest import load_csv
    from graph_builder import build_graph
    df = load_csv("../output/transactions.csv")
    G = build_graph(df)
    feat_df, cols = build_features(df, G)
    print(feat_df[cols].describe())
