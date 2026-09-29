# 🛡️ AI-Powered Bitcoin Forensics & Dark Web Intelligence

An offline blockchain intelligence and forensic monitoring platform integrating:
1. **Dark Web Threat Intelligence & Categorization System (SIH 2026 / Syntax Errors AI)**
2. **Praescient / IBM i2 Network Link Analysis & Money Laundering Pattern Tracing**
3. **Unsupervised ML Anomaly Detection (Isolation Forest) & Graph Community Clustering (Louvain)**
4. **Explainable AI (SHAP Permutation Explainer)**
5. **Entity Attribution (CIOH + Multi-Hop Threat Intelligence Propagation)**

---

## 📽️ Referenced Architectures

- **[Video 1: Cryptocurrency Tracking System SIH 2026 \| Dark Web Intelligence AI](https://www.youtube.com/watch?v=a8S-Cw9E0jg)**
  - Dark web intelligence feeds & autonomous Tor onion scraping simulation
  - Illicit categorization: **Darknet Markets, Ransomware Syndicates, Mixers/Tumblers, Sanctions (OFAC), Terrorist Financing, Scams/Fraud, High-Risk Exchanges**
  - Threat Level scoring (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and Risk Scores (0–100)
  - Formal Law Enforcement Forensic Dossier & Intelligence Package export (JSON / Markdown)

- **[Video 2: Identifying Cryptocurrency Money Laundering Patterns Using Network Analysis (Praescient Analytics)](https://www.youtube.com/watch?v=QNRd8Z-ZKn0)**
  - Advanced money laundering topology recognition:
    - **Peeling Chains**: Micro-peeling with cash-out to exchanges
    - **CoinJoin / Mixing Tumblers**: Equal-split privacy transactions
    - **Rapid Multi-hop Layering**: High-speed wallet hops via automated scripts
    - **IP Fan-out / Proxy Clusters**: High-density wallet broadcasting from single Tor/proxy nodes
    - **U-Turn / Roundtripping**: Cyclical loop transactions to simulate wash volume or obscure source
    - **Consolidation / Fan-in Funnel**: Aggregating victim/illicit payments into central treasuries
  - Link Analysis: Multi-hop directional tracing, graph centrality metrics, shortest-path flow tracer to cash-out points

---

## 📁 Repository Layout

```
bitcoin-forensics/
├── data/
│   └── generate_synthetic_data.py   # synthetic transactions + laundering patterns + dark web intel feed
├── src/
│   ├── ingest.py                    # CSV parsing & normalization
│   ├── geoip_enrich.py              # offline GeoIP lookups (MaxMind GeoLite2)
│   ├── graph_builder.py             # wallet ↔ tx ↔ ip multi-directed entity graph
│   ├── features.py                  # per-tx + network link analysis features
│   ├── ml_detection.py              # Isolation Forest + Louvain community clustering
│   ├── entity_attribution.py        # CIOH clustering + multi-hop threat propagation
│   ├── explain.py                   # SHAP explainability layer
│   └── pipeline.py                  # end-to-end runner
├── dashboard/
│   └── app.py                       # 4-tab Streamlit investigator dashboard
├── output/                          # generated datasets, threat feeds, alerts & graph
└── requirements.txt
```

---

## 🚀 Quickstart

```bash
# 1. Activate environment
source venv/bin/activate  # or .venv/bin/activate

# 2. Generate dataset with Dark Web Intelligence & Laundering Patterns
cd data
python3 generate_synthetic_data.py --n_normal 5000 --n_anomalous 300 --out ../output/transactions.csv

# 3. Run the detection pipeline
cd ../src
python3 pipeline.py --input ../output/transactions.csv --outdir ../output --max_explain 120

# 4. Launch the investigator dashboard
cd ../dashboard
streamlit run app.py
```

---

## 📊 Dashboard Modules

1. **🚨 Live Alerts & Anomaly Monitor**: Real-time ranked suspicion scoring (0–100), SHAP feature contributions, threat badges, and GeoIP filtering.
2. **🕵️ Dark Web Threat Intelligence**: Searchable Tor hidden service intercepts, threat actor profiles, risk meters, and 1-click pivot to graph trace.
3. **🕸️ Praescient Link Analysis & Laundering Patterns**: Multi-hop interactive link visualizer, category color coding, and Shortest-Path Money Trail Finder to cash-out exchanges.
4. **📑 Forensic Case Dossier Export**: Generate and download compliant case intelligence reports in Markdown and JSON.
