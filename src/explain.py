"""
Explainability layer.
Uses SHAP (permutation explainer over the IsolationForest decision function) to attribute
each alert's suspicion score to specific features, then renders a human-readable reason string.
"""
import numpy as np
import pandas as pd
import shap

FEATURE_LABELS = {
    "n_inputs": "input count",
    "n_outputs": "output count",
    "total_in": "total value in",
    "total_out": "total value out",
    "fee_ratio": "fee-to-value ratio",
    "change_ratio": "output/input ratio",
    "output_equality": "output-splitting equality (mixing signature)",
    "fanout_ratio": "output/input fan-out ratio",
    "seconds_since_prev_ip_tx": "time since prior broadcast from same IP",
    "ip_distinct_wallets": "distinct wallets seen from this IP",
    "tx_degree": "transaction graph total degree",
    "tx_in_degree": "transaction in-degree (fan-in)",
    "tx_out_degree": "transaction out-degree (fan-out)",
}


def explain_alerts(feat_df: pd.DataFrame, feature_cols: list, model, scaler,
                    top_k_features: int = 3, background_size: int = 100):
    alerts = feat_df[feat_df["is_anomaly"]].copy()
    if alerts.empty:
        return alerts

    X_all = feat_df[feature_cols].replace([np.inf, -np.inf], 0).fillna(0).values
    Xs_all = scaler.transform(X_all)
    background = shap.sample(Xs_all, min(background_size, len(Xs_all)), random_state=42)

    explainer = shap.Explainer(model.decision_function, background)

    idx = alerts.index
    Xs_alerts = scaler.transform(alerts[feature_cols].replace([np.inf, -np.inf], 0).fillna(0).values)
    shap_values = explainer(Xs_alerts)

    reasons = []
    for i, row_idx in enumerate(idx):
        contribs = shap_values.values[i]
        order = np.argsort(contribs)[:top_k_features]
        parts = []
        for j in order:
            fname = feature_cols[j]
            fval = alerts.loc[row_idx, fname]
            label = FEATURE_LABELS.get(fname, fname)
            parts.append(f"{label} = {fval:.4g} (contribution {contribs[j]:.3f})")
        reasons.append("; ".join(parts))

    alerts["reason"] = reasons
    return alerts
