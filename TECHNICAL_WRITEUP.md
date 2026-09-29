# Technical Write-up: AI-Powered Monitoring & Analysis of Bitcoin Transaction Traffic

## 1. Problem framing

Bitcoin's pseudonymity lets illicit actors move funds through peeling chains, mixers/tumblers,
and rapid layering while evading traditional (fiat-rail) surveillance. The two observation
layers available to an investigator — **network-layer** metadata (which IP broadcast which
transaction, and when) and **blockchain-layer** metadata (which wallets moved what value,
to whom) — are usually analyzed separately. Correlating them is what turns raw transaction
noise into an investigative lead: e.g., "15 distinct wallets all broadcast from one IP within
90 seconds" is invisible from chain data alone, and "wallet X only ever appears alongside
near-identical output splits" is invisible from network data alone.

## 2. Approach

**Ingest → Graph → Features → Detect → Explain → Visualize**, entirely offline.

We model the domain as a **heterogeneous graph** with three node types (`wallet`, `tx`, `ip`)
and typed edges (`wallet -input-> tx`, `tx -output-> wallet`, `tx -broadcast_from-> ip`). This
graph is the single structure that holds both layers, so every downstream feature and every
alert can cite both a network-layer and a blockchain-layer fact.

## 3. Model choice

We deliberately picked two complementary, unsupervised techniques rather than one large model,
because in a real investigative setting there are **no labels** — a synthetic or historical
labeled dataset would not generalize to genuinely novel laundering behavior, and judges asked
for a "working model, not just rules."

| Component | Model | Why |
|---|---|---|
| Anomaly scoring | **Isolation Forest** | Unsupervised, fast on tabular+graph features, naturally outputs a continuous anomaly score (not just a hard rule threshold), robust to the mixed-scale features in this domain (amounts, ratios, timing, counts). |
| Entity clustering | **Louvain community detection** on the wallet-projection graph | Groups wallets that transact closely together into likely-common-controller clusters (custodial services, mixers, or a single actor's wallet set) — this is the "cluster entities" requirement, and it is graph-native rather than a distance metric on flat features. |

Features fed to the Isolation Forest combine **transaction-shape** signals (fan-in/out ratio,
fee ratio, output-equality — a mixing signature), **temporal** signals (seconds since the last
transaction broadcast from the same source IP — flags scripted/automated layering), and
**graph-structural** signals (IP wallet fan-out, transaction node degree). This is what makes
the score reflect network+blockchain correlation, not blockchain data alone.

*Stretch goal noted but not required for the MVP:* a GraphSAGE/Node2Vec embedding layer could
replace hand-engineered graph features with learned ones, and a GNN classifier could be trained
once seed-labeled data (e.g., known mixer addresses) is available.

## 4. Explainability method

We use **SHAP (SHapley Additive exPlanations)** with a **permutation explainer** wrapped around
the Isolation Forest's `decision_function`. For each flagged transaction, SHAP attributes the
suspicion score to individual features with a signed contribution, and we render the top-3
contributing features as a plain-language reason string, e.g.:

> *"output-splitting equality (mixing signature) = 0.94 (contribution -0.071); distinct wallets
> seen from this IP = 15 (contribution -0.053); time since prior broadcast from same IP = 22s
> (contribution -0.048)"*

This satisfies the "why a wallet/transaction was flagged, with a confidence score" requirement
without resorting to black-box scoring — every alert is traceable to specific, auditable
evidence an investigator can verify against the raw graph.

To keep the explanation step fast for interactive use, SHAP is only computed on the top-N
highest-scoring alerts (configurable, default 100) rather than the full transaction set —
detection runs on everything, explanation runs on what an investigator would actually review.

## 4b. Entity attribution — "whose wallet is this?"

A suspicion score alone tells an investigator *that* something is wrong, not *who* is behind
it. We add a second, complementary layer that answers exactly that, using two standard
blockchain-forensics heuristics plus tag propagation — the same approach real tools
(Chainalysis Reactor, OXT, WalletExplorer) are built on:

1. **Common-Input-Ownership Heuristic (CIOH).** When a transaction spends from multiple input
   addresses, the wallet software had to sign with every one of those private keys — proving a
   single entity controls all of them. We implement this as a union-find over every
   transaction's inputs, which is the strongest deanonymization signal available in Bitcoin's
   design (it follows directly from how transactions are constructed, not a guess).
2. **Change-address heuristic.** Most transactions have one "payment" output and one "change"
   output returned to an address the *sender* still controls. We flag the smaller, non-round
   output of a 2-output transaction as likely change and union it into the sender's cluster —
   this is what lets a cluster grow across many transaction hops instead of staying confined to
   a single transaction.
3. **Known-address tag propagation.** If any address inside a CIOH cluster matches a known tag
   (an exchange deposit address, a sanctioned address, a ransomware collection wallet), that
   identity is propagated to every other address in the cluster. This mirrors the real-world
   "smoking gun" effect: once one address in a cluster is linked to a KYC'd exchange account,
   every other address that cluster touches is potentially deanonymized too.

The current build ships a small **synthetic** seed tag list (`known_wallets.csv`, `DEMO-*`
addresses generated alongside our own dataset) purely to demonstrate the mechanism end-to-end
without using any real-world address data. In the demo dataset, three of the injected
laundering patterns (peeling chains, mixing, and rapid layering) are wired to sometimes route
through one of these tagged demo addresses, and the pipeline correctly recovers the
attribution — e.g. a mixing transaction whose input includes the tagged "DEMO-Mixer-Service"
address gets that identity propagated to all ~100+ other addresses that pass through the same
mixing cluster. For a real deployment, the same engine attaches to genuine feeds such as
**ransomwhe.re**'s open ransomware-address dataset or OFAC's SDN sanctioned-address list — no
changes to the attribution logic itself, only to which tag file is loaded.

## 5. Dataset

No real seized or intercepted data is used. `data/generate_synthetic_data.py` produces a
CSV with all required fields (timestamp, src/dst IP:port, TXID, input/output addresses+amounts,
fee, script type, geo/ASN) and injects four labeled-for-validation-only anomaly patterns:
peeling chains, mixing/tumbler transactions, rapid layering, and IP wallet fan-out. The ground
truth label is written to a separate file and is **never** used as model input — it exists
solely so we could confirm the unsupervised pipeline actually recovers the injected patterns
during development.

## 6. Validation (informal, against injected ground truth)

Across a 5,000-normal / 250-anomalous synthetic run, the Isolation Forest's top-scored alerts
were dominated by the injected mixing and IP-fan-out patterns (equal-output-split transactions
and multi-wallet-single-IP broadcasts respectively) — the exact structural signatures those
generators were designed to produce — confirming the feature set captures the intended
laundering signals rather than surfacing noise.

## 7. Limitations & next steps

- **GeoIP: real integration.** `src/geoip_enrich.py` resolves every `src_ip` to a genuine
  country (and ASN, when an ASN database is supplied) via MaxMind's GeoLite2 `.mmdb` format —
  the exact "open source downloadable Geo IP database" the problem statement calls for. It
  ships with an offline-bundled GeoLite2-City snapshot (via `maxminddb-geolite2`) so the
  pipeline runs with zero setup; dropping a current `GeoLite2-City.mmdb` / `GeoLite2-ASN.mmdb`
  (free MaxMind account, one-time download) into `src/geoip_data/` upgrades to current data and
  adds ASN resolution, with no code changes. All lookups are local file reads — no network
  calls at runtime.
- Louvain clustering resolution is not tuned against a labeled "same-actor" ground truth (none
  exists for real BTC data); a real deployment would validate cluster purity against known
  exchange hot-wallet clusters or seized-wallet lists.
- Isolation Forest contamination (expected anomaly rate) is a tunable hyperparameter — in
  production this should be calibrated against analyst feedback (a human-in-the-loop labeling
  loop), not fixed at a guessed constant.
