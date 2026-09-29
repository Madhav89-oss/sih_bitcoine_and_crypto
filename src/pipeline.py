"""
End-to-end offline pipeline. Run this once to produce alerts.csv, graph.gpickle,
and attribution models for the dashboard to consume.

    python3 pipeline.py --input ../output/transactions.csv --outdir ../output
"""
import argparse
import os
import pickle

import pandas as pd

from ingest import load_csv
from graph_builder import build_graph, graph_summary
from features import build_features
from ml_detection import run_anomaly_detection, run_entity_clustering
from explain import explain_alerts
from entity_attribution import build_ciohc_clusters, load_known_wallets, attribute_clusters


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=None)
    ap.add_argument("--outdir", default=None)
    ap.add_argument("--known_wallets", default=None,
                     help="Path to a known-address tag CSV. Defaults to <outdir>/known_wallets.csv if present.")
    ap.add_argument("--contamination", type=float, default=0.06)
    ap.add_argument("--max_explain", type=int, default=120,
                     help="Only run SHAP on the top-N highest-suspicion alerts (speed).")
    args = ap.parse_args()

    # Determine default outdir and input paths
    if not args.outdir:
        if os.path.isdir("output"):
            args.outdir = "output"
        elif os.path.isdir("../output"):
            args.outdir = "../output"
        else:
            args.outdir = "output"

    if not args.input:
        default_in = os.path.join(args.outdir, "transactions.csv")
        if os.path.exists(default_in):
            args.input = default_in
        elif os.path.exists("output/transactions.csv"):
            args.input = "output/transactions.csv"
        elif os.path.exists("../output/transactions.csv"):
            args.input = "../output/transactions.csv"
        else:
            args.input = default_in

    print("[1/7] Ingesting...")
    df = load_csv(args.input)

    print("[2/7] Building entity/transaction graph...")
    G = build_graph(df)
    print("   ", graph_summary(G))

    print("[3/7] Engineering features...")
    feat_df, feature_cols = build_features(df, G)

    print("[4/7] Running anomaly detection (Isolation Forest)...")
    feat_df, model, scaler, Xs = run_anomaly_detection(feat_df, feature_cols, args.contamination)
    print(f"    {feat_df['is_anomaly'].sum()} transactions flagged")

    print("[5/7] Running entity clustering (Louvain on wallet projection)...")
    partition, W = run_entity_clustering(G)
    n_clusters = len(set(partition.values())) if partition else 0
    print(f"    {n_clusters} wallet clusters across {W.number_of_nodes()} wallets")

    print("[6/7] Running entity attribution (CIOH clustering + Dark Web / Threat Intel)...")
    known_path = args.known_wallets or os.path.join(args.outdir, "known_wallets.csv")
    ciohc_clusters = build_ciohc_clusters(df)
    known_wallets = load_known_wallets(known_path)
    attribution = attribute_clusters(ciohc_clusters, known_wallets)
    attribution_map = attribution.set_index("address")[
        ["attributed_entity", "category", "threat_level", "risk_score", "confidence", "evidence", "onion_source"]
    ].to_dict("index")
    n_attributed = attribution["attributed_entity"].notna().sum()
    print(f"    {len(known_wallets)} threat intelligence tags loaded from {known_path}")
    print(f"    {n_attributed} wallets attributed to a known entity")

    print("[7/7] Generating explanations for flagged alerts (SHAP + Heuristic)...")
    # Separate top-N alerts for deep SHAP explanation, while keeping ALL flagged alerts
    anomalies_df = feat_df[feat_df["is_anomaly"]].copy()
    if anomalies_df.empty:
        anomalies_df = feat_df.sort_values("suspicion_score", ascending=False).head(500).copy()

    top_flagged = anomalies_df.sort_values("suspicion_score", ascending=False).head(args.max_explain)
    explain_input = anomalies_df.copy()
    explain_input["is_anomaly"] = explain_input.index.isin(top_flagged.index)
    shap_alerts = explain_alerts(explain_input, feature_cols, model, scaler, background_size=50)

    # For the remaining anomalies beyond top-N, provide fast feature-attribution reason
    if len(anomalies_df) > len(top_flagged):
        remaining_idx = anomalies_df.index.difference(top_flagged.index)
        rem_df = anomalies_df.loc[remaining_idx].copy()
        rem_reasons = []
        for _, r in rem_df.iterrows():
            r_parts = []
            if r.get("output_equality", 0) > 0.7:
                r_parts.append(f"output equality mixing signature = {r['output_equality']:.2f}")
            if r.get("seconds_since_prev_ip_tx", 999) < 60:
                r_parts.append(f"rapid IP broadcast delta = {r['seconds_since_prev_ip_tx']:.1f}s")
            if r.get("ip_distinct_wallets", 0) > 5:
                r_parts.append(f"high IP wallet fan-out = {int(r['ip_distinct_wallets'])} wallets")
            if r.get("fanout_ratio", 0) > 3 or r.get("fanout_ratio", 0) < 0.3:
                r_parts.append(f"fan-out ratio = {r['fanout_ratio']:.2f}")
            if not r_parts:
                r_parts.append(f"statistical outlier score = {r['suspicion_score']:.1f}")
            rem_reasons.append("; ".join(r_parts[:3]))
        rem_df["reason"] = rem_reasons
        alerts = pd.concat([shap_alerts, rem_df]).sort_values("suspicion_score", ascending=False)
    else:
        alerts = shap_alerts

    # attach Louvain cluster id + entity attribution for each alert's first input wallet
    def first_wallet(row):
        addrs = row.get("input_addresses")
        if isinstance(addrs, list) and addrs:
            return addrs[0]
        if isinstance(addrs, str) and addrs:
            return addrs.split("|")[0].strip()
        return None

    if not alerts.empty:
        alerts["_first_wallet"] = alerts.apply(first_wallet, axis=1)
        alerts["wallet_cluster"] = alerts["_first_wallet"].map(lambda w: partition.get(w, -1))
        alerts["attributed_entity"] = alerts["_first_wallet"].map(
            lambda w: attribution_map.get(w, {}).get("attributed_entity")
        )
        alerts["entity_category"] = alerts["_first_wallet"].map(
            lambda w: attribution_map.get(w, {}).get("category")
        )
        alerts["threat_level"] = alerts["_first_wallet"].map(
            lambda w: attribution_map.get(w, {}).get("threat_level", "LOW")
        )
        alerts["risk_score"] = alerts["_first_wallet"].map(
            lambda w: attribution_map.get(w, {}).get("risk_score", 10)
        )
        alerts["onion_source"] = alerts["_first_wallet"].map(
            lambda w: attribution_map.get(w, {}).get("onion_source")
        )
        alerts["attribution_evidence"] = alerts["_first_wallet"].map(
            lambda w: attribution_map.get(w, {}).get("evidence")
        )
        alerts = alerts.drop(columns=["_first_wallet"])

    # Ensure list columns are serialized cleanly for CSV connections
    for col in ["input_addresses", "output_addresses", "input_amounts", "output_amounts"]:
        if col in alerts.columns:
            alerts[col] = alerts[col].apply(lambda x: "|".join(str(i) for i in x) if isinstance(x, (list, tuple)) else str(x or ""))

    alerts_out = alerts.sort_values("suspicion_score", ascending=False)
    export_cols = [
        "txid", "timestamp", "src_ip", "country", "country_name", "asn", "asn_org",
        "n_inputs", "n_outputs", "total_in", "fee", "suspicion_score", "wallet_cluster",
        "attributed_entity", "entity_category", "threat_level", "risk_score",
        "onion_source", "attribution_evidence", "reason",
        "input_addresses", "output_addresses", "input_amounts", "output_amounts", "script_type"
    ]
    export_cols = [c for c in export_cols if c in alerts_out.columns]
    alerts_out[export_cols].to_csv(f"{args.outdir}/alerts.csv", index=False)

    with open(f"{args.outdir}/graph.gpickle", "wb") as f:
        pickle.dump(G, f)

    feat_df.to_pickle(f"{args.outdir}/feat_df.pkl")
    with open(f"{args.outdir}/partition.pkl", "wb") as f:
        pickle.dump(partition, f)
    attribution.to_pickle(f"{args.outdir}/attribution.pkl")

    print(f"\n✅ Pipeline complete. Wrote {len(alerts_out)} ranked alerts -> {args.outdir}/alerts.csv")


if __name__ == "__main__":
    main()
