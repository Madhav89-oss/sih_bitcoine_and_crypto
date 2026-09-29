"""
Synthetic Bitcoin P2P + transaction metadata generator.

Produces a CSV with the minimum required fields:
timestamp, src_ip, dst_ip, src_port, dst_port, txid,
input_addresses, output_addresses, input_amounts, output_amounts,
fee, script_type, asn, asn_org, country, country_name

Also writes:
- ground_truth.csv (which rows are anomalous + which pattern)
- known_wallets.csv (rich Dark Web & Threat Intelligence feed with 50+ threat entities)
- darkweb_intel_feed.csv (simulated Tor onion scrapes, threat actor forum postings, risk levels)

Usage:
    python3 generate_synthetic_data.py --n_normal 5000 --n_anomalous 300 --out ../output/transactions.csv
"""
import argparse
import csv
import ipaddress
import os
import random
import sys
import uuid
from datetime import datetime, timedelta

def _get_geoip_reader():
    try:
        import maxminddb
        _src_mmdb = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "geoip_data", "GeoLite2-City.mmdb"))
        if os.path.exists(_src_mmdb):
            return maxminddb.open_database(_src_mmdb)
        import geolite2
        db_path = geolite2.geolite2_database()
        if db_path:
            return maxminddb.open_database(db_path)
    except Exception:
        pass
    return None


class GeoIPResolver:
    def __init__(self):
        self.reader = _get_geoip_reader()

    def lookup(self, ip: str) -> dict:
        res = {"latitude": None, "longitude": None, "country_iso": None, "country_name": None}
        if self.reader is not None:
            try:
                rec = self.reader.get(ip)
                if rec:
                    country = rec.get("country", {}) or rec.get("registered_country", {})
                    res["country_iso"] = country.get("iso_code")
                    res["country_name"] = (country.get("names") or {}).get("en")
                    loc = rec.get("location", {})
                    res["latitude"] = loc.get("latitude")
                    res["longitude"] = loc.get("longitude")
            except Exception:
                pass
        return res


random.seed(42)

SCRIPT_TYPES = ["P2PKH", "P2SH", "P2WPKH", "P2WSH", "P2TR"]

_ENRICHER = GeoIPResolver()


def rand_ip():
    """Random *globally routable* IPv4 so real GeoIP lookups resolve."""
    while True:
        candidate = ipaddress.IPv4Address(random.randint(1, 0xFFFFFFFE))
        if candidate.is_global:
            return str(candidate)


def rand_addr():
    return "bc1q" + uuid.uuid4().hex[:34]


def rand_txid():
    return uuid.uuid4().hex + uuid.uuid4().hex[:32]


def rand_onion():
    chars = "abcdefghijklmnopqrstuvwxyz234567"
    return "".join(random.choice(chars) for _ in range(16)) + ".onion"


def base_row(ts, src_ip, dst_ip, txid, inputs, outputs, in_amts, out_amts, fee, script_type):
    geo = _ENRICHER.lookup(src_ip)
    return {
        "timestamp": ts.isoformat(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(1024, 65535),
        "dst_port": 8333,
        "txid": txid,
        "input_addresses": "|".join(inputs),
        "output_addresses": "|".join(outputs),
        "input_amounts": "|".join(f"{a:.8f}" for a in in_amts),
        "output_amounts": "|".join(f"{a:.8f}" for a in out_amts),
        "fee": f"{fee:.8f}",
        "script_type": script_type,
        "asn": geo.get("asn", ""),
        "asn_org": geo.get("asn_org", ""),
        "country": geo.get("country_iso", ""),
        "country_name": geo.get("country_name", ""),
    }


def gen_normal_tx(ts, wallet_pool, ip_pool):
    n_in = random.choice([1, 1, 1, 2])
    n_out = random.choice([1, 2, 2])
    inputs = random.sample(wallet_pool, n_in)
    outputs = [rand_addr() for _ in range(n_out)]
    total_in = round(random.uniform(0.001, 3.0), 8)
    fee = round(total_in * random.uniform(0.0005, 0.003), 8)
    remaining = total_in - fee
    splits = sorted([random.random() for _ in range(n_out - 1)]) + [1.0]
    prev = 0.0
    out_amts = []
    for s in splits:
        out_amts.append(round(remaining * (s - prev), 8))
        prev = s
    return base_row(
        ts, random.choice(ip_pool), random.choice(ip_pool), rand_txid(),
        inputs, outputs, [total_in], out_amts, fee, random.choice(SCRIPT_TYPES)
    )


def gen_peeling_chain(ts, ip_pool, length=6, known_exchange_addr=None):
    """One wallet peels off small amounts repeatedly to a change address, chained."""
    rows = []
    current_wallet = rand_addr()
    remaining = round(random.uniform(2.0, 8.0), 8)
    single_ip = random.choice(ip_pool)
    t = ts
    for i in range(length):
        peel = round(remaining * random.uniform(0.03, 0.08), 8)
        is_last_hop = (i == length - 1)
        if is_last_hop and known_exchange_addr and random.random() < 0.7:
            change_wallet = known_exchange_addr
        else:
            change_wallet = rand_addr()
        fee = round(remaining * 0.0008, 8)
        out_amts = [peel, remaining - peel - fee]
        rows.append(base_row(
            t, single_ip, random.choice(ip_pool), rand_txid(),
            [current_wallet], [rand_addr(), change_wallet],
            [remaining], out_amts, fee, "P2WPKH"
        ))
        remaining = out_amts[1]
        current_wallet = change_wallet
        t += timedelta(seconds=random.randint(20, 90))
    return rows


def gen_mixing_pattern(ts, ip_pool, n_participants=8, known_mixer_addr=None):
    """Many-in / many-out with near-equal output splitting (tumbler / CoinJoin style)."""
    inputs = [rand_addr() for _ in range(n_participants)]
    if known_mixer_addr and random.random() < 0.6:
        inputs[0] = known_mixer_addr
    outputs = [rand_addr() for _ in range(n_participants)]
    equal_amt = round(random.uniform(0.05, 0.2), 8)
    in_amts = [equal_amt + round(random.uniform(-0.001, 0.001), 8) for _ in inputs]
    out_amts = [equal_amt for _ in outputs]
    fee = round(sum(in_amts) * 0.001, 8)
    single_ip = random.choice(ip_pool)
    return [base_row(
        ts, single_ip, single_ip, rand_txid(),
        inputs, outputs, in_amts, out_amts, fee, "P2WSH"
    )]


def gen_rapid_layering(ts, ip_pool, hops=5, known_ransomware_addr=None):
    """Funds hop through wallets within seconds/minutes, single IP each hop."""
    rows = []
    wallet = known_ransomware_addr if (known_ransomware_addr and random.random() < 0.6) else rand_addr()
    amt = round(random.uniform(1.0, 5.0), 8)
    t = ts
    src_ip = random.choice(ip_pool)
    for _ in range(hops):
        next_wallet = rand_addr()
        fee = round(amt * 0.0009, 8)
        rows.append(base_row(
            t, src_ip, src_ip, rand_txid(),
            [wallet], [next_wallet], [amt], [amt - fee], fee, "P2WPKH"
        ))
        wallet = next_wallet
        amt -= fee
        t += timedelta(seconds=random.randint(15, 45))
    return rows


def gen_ip_fanout_cluster(ts, n_wallets=15):
    """Many distinct wallets all broadcasting from the SAME src_ip/ASN within a short window."""
    rows = []
    single_ip = rand_ip()
    t = ts
    for _ in range(n_wallets):
        wallet = rand_addr()
        out = rand_addr()
        amt = round(random.uniform(0.01, 0.5), 8)
        fee = round(amt * 0.001, 8)
        rows.append(base_row(
            t, single_ip, rand_ip(), rand_txid(),
            [wallet], [out], [amt], [amt - fee], fee, random.choice(SCRIPT_TYPES)
        ))
        t += timedelta(seconds=random.randint(5, 30))
    return rows


def gen_uturn_roundtripping(ts, ip_pool, hops=4, known_entity_addr=None):
    """
    Praescient / i2 Link Analysis pattern: U-Turn / Roundtripping.
    Funds leave wallet A, bounce through B, C, D, and return back to A or an allied wallet
    to simulate fake volume or obscure ownership.
    """
    rows = []
    origin_wallet = known_entity_addr if known_entity_addr else rand_addr()
    current_wallet = origin_wallet
    amt = round(random.uniform(2.5, 10.0), 8)
    t = ts
    single_ip = random.choice(ip_pool)

    for i in range(hops):
        is_last = (i == hops - 1)
        next_wallet = origin_wallet if is_last else rand_addr()
        fee = round(amt * 0.001, 8)
        rows.append(base_row(
            t, single_ip, random.choice(ip_pool), rand_txid(),
            [current_wallet], [next_wallet], [amt], [amt - fee], fee, "P2WPKH"
        ))
        current_wallet = next_wallet
        amt -= fee
        t += timedelta(seconds=random.randint(30, 120))
    return rows


def gen_fanin_consolidation(ts, ip_pool, n_feeders=10, known_destination_addr=None):
    """
    Consolidation / Fan-in Funnel (Darknet / Ransomware victim payouts to Treasury).
    Multiple feeder addresses send payments into one single aggregator wallet.
    """
    rows = []
    destination = known_destination_addr if known_destination_addr else rand_addr()
    single_ip = random.choice(ip_pool)
    t = ts
    for _ in range(n_feeders):
        feeder = rand_addr()
        amt = round(random.uniform(0.1, 0.8), 8)
        fee = round(amt * 0.0012, 8)
        rows.append(base_row(
            t, single_ip, random.choice(ip_pool), rand_txid(),
            [feeder], [destination], [amt], [amt - fee], fee, "P2WPKH"
        ))
        t += timedelta(seconds=random.randint(10, 60))
    return rows


def build_darkweb_threat_intelligence_catalog():
    """
    Builds a rich threat intelligence & dark web entity database matching real-world
    SIH 2026 Dark Web Intelligence AI & Law Enforcement Watchlist categories.
    """
    entities_spec = [
        # Ransomware Groups
        ("LockBit 3.0 Ransomware Syndicate", "ransomware", "CRITICAL", 98, "Ransomwhe.re Darknet Feed", 0.95),
        ("BlackCat / ALPHV Ransomware Group", "ransomware", "CRITICAL", 96, "FBI Cyber Threat Feed", 0.94),
        ("Conti Ransomware Locker", "ransomware", "HIGH", 92, "LEA Watchlist", 0.92),
        ("Hive Ransomware Collector", "ransomware", "CRITICAL", 95, "CISA Threat Advisory", 0.93),
        ("DarkSide / BlackMatter Ransomware", "ransomware", "HIGH", 90, "Dark Web Intelligence Report", 0.91),
        ("Clop Ransomware Group Treasury", "ransomware", "CRITICAL", 97, "Ransomwhe.re Darknet Feed", 0.96),

        # Darknet Markets
        ("Hydra Market Vendor Vault", "darknet_market", "CRITICAL", 99, "Tor Onion Crawler (Hydra Scrape)", 0.98),
        ("Silk Road 3.0 Narcotics Escrow", "darknet_market", "HIGH", 93, "Darknet Forum Scraper", 0.92),
        ("Bohemia Darknet Market Escrow", "darknet_market", "CRITICAL", 96, "Tor Onion Crawler", 0.95),
        ("Russian Market Carding Payout", "darknet_market", "HIGH", 91, "Genesis/Carding Intel Feed", 0.90),
        ("ASAP Market Automated Deposit", "darknet_market", "HIGH", 89, "Deep Web Monitor", 0.89),
        ("Mega Darknet Market Treasury", "darknet_market", "CRITICAL", 97, "Darknet Onion Intel", 0.96),

        # Mixers & Tumblers
        ("Tornado Cash Multi-Chain Relayer", "mixer", "CRITICAL", 98, "OFAC Sanctions & Chainalysis Feed", 0.99),
        ("Sinbad.io Bitcoin Tumbler Pool", "mixer", "CRITICAL", 97, "OFAC Specially Designated Nationals", 0.98),
        ("Blender.io Obfuscation Engine", "mixer", "CRITICAL", 96, "US Treasury OFAC List", 0.97),
        ("ChipMixer Micro-Split Pool", "mixer", "CRITICAL", 95, "Europol Action Feed", 0.96),
        ("Wasabi CoinJoin Coordinator Hub", "mixer", "HIGH", 85, "P2P Network Probe", 0.88),
        ("YoMix Automated Tumbler Pool", "mixer", "HIGH", 90, "Dark Web Privacy Feed", 0.91),

        # Terrorist & Illicit Financing
        ("Al-Qassam Brigades Cryptopool", "terror_financing", "CRITICAL", 100, "Counter-Terrorism Finance Taskforce", 0.99),
        ("ISIS-Khurasan Crypto Procurement", "terror_financing", "CRITICAL", 99, "UN Sanctions Committee Report", 0.98),
        ("Hamas Virtual Asset Campaign", "terror_financing", "CRITICAL", 98, "National Bureau for Counter Financing", 0.97),

        # Sanctions & State-Sponsored Actors (OFAC)
        ("Lazarus Group (DPRK Cyber Syndicate)", "sanctions", "CRITICAL", 100, "OFAC SDN List & CISA", 0.99),
        ("Garantex Europe Sanctioned OTC", "sanctions", "HIGH", 94, "OFAC Treasury Sanctions", 0.95),
        ("Bitzlato Criminal Exchange Node", "sanctions", "HIGH", 92, "FinCEN Enforcement Action", 0.93),
        ("SUEX OTC Sanctioned Money Laundering Hub", "sanctions", "HIGH", 93, "OFAC SDN List", 0.94),
        ("Chatex Sanctioned Crypto Broker", "sanctions", "HIGH", 90, "OFAC SDN List", 0.91),

        # Scams & Fraud Networks
        ("PlusToken Ponzi Scheme Reserve", "scam", "HIGH", 92, "Chain Forensic Audit", 0.93),
        ("Pig-Butchering Fraud Network Alpha", "scam", "CRITICAL", 95, "Global Anti-Scam Watchlist", 0.94),
        ("BitConnect Recovery Scam Vault", "scam", "MEDIUM", 78, "Community Fraud Alert", 0.85),
        ("OneCoin Illicit Liquidation Wallet", "scam", "HIGH", 88, "SEC Fraud Enforcement", 0.90),

        # High-Risk / No-KYC Exchanges & P2P Escrows
        ("Anonymous Instant Swap DEX Gateway", "high_risk_exchange", "HIGH", 82, "Risk Intelligence Engine", 0.86),
        ("No-KYC P2P Russian Escrow Hub", "high_risk_exchange", "HIGH", 85, "Dark Web P2P Monitor", 0.88),
        ("Bulletproof Crypto Swap Service", "high_risk_exchange", "HIGH", 84, "Darknet Gateway Monitor", 0.87),

        # Legitimate / Compliant Exchanges (for cash-out identification)
        ("Binance Institutional Custody", "exchange", "LOW", 10, "Exchange Public Attribution", 0.99),
        ("Coinbase Prime Deposit Vault", "exchange", "LOW", 8, "Exchange Public Attribution", 0.99),
        ("Kraken Global Cold Reserve", "exchange", "LOW", 12, "Exchange Public Attribution", 0.98),
        ("Bitstamp Liquidity Hot Wallet", "exchange", "LOW", 15, "Exchange Public Attribution", 0.97),
    ]

    known_wallets = []
    darkweb_intel_feed = []

    start_time = datetime(2026, 1, 15)

    for (name, cat, threat_lvl, risk_score, source, conf) in entities_spec:
        addr = rand_addr()
        onion = rand_onion() if cat in ["darknet_market", "ransomware", "mixer", "terror_financing", "scam"] else ""
        first_seen = (start_time + timedelta(days=random.randint(0, 100))).strftime("%Y-%m-%d")
        last_seen = datetime(2026, 6, random.randint(15, 30)).strftime("%Y-%m-%d")

        known_wallets.append({
            "address": addr,
            "entity_name": name,
            "category": cat,
            "threat_level": threat_lvl,
            "risk_score": risk_score,
            "confidence": conf,
            "source": source,
            "onion_source": onion,
            "first_seen": first_seen,
            "last_seen": last_seen,
        })

        if onion:
            darkweb_intel_feed.append({
                "feed_id": f"INTEL-{uuid.uuid4().hex[:8].upper()}",
                "target_entity": name,
                "category": cat,
                "threat_level": threat_lvl,
                "risk_score": risk_score,
                "bitcoin_address": addr,
                "onion_url": f"http://{onion}",
                "intercept_date": last_seen,
                "intel_summary": f"Autonomous Tor scraper extracted BTC deposit wallet for {name} from hidden service {onion}.",
                "source_credibility": f"{int(conf * 100)}%",
            })

    return known_wallets, darkweb_intel_feed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n_normal", type=int, default=5000)
    ap.add_argument("--n_anomalous", type=int, default=300)
    ap.add_argument("--out", type=str, default=None)
    ap.add_argument("--truth_out", type=str, default=None)
    ap.add_argument("--known_wallets_out", type=str, default=None)
    ap.add_argument("--intel_feed_out", type=str, default=None)
    args = ap.parse_args()

    # Determine default output directory
    if args.out:
        out_path = os.path.abspath(args.out)
        out_dir = os.path.dirname(out_path)
    else:
        # Check if running from root or data/
        if os.path.isdir("output"):
            out_dir = os.path.abspath("output")
        elif os.path.isdir("../output"):
            out_dir = os.path.abspath("../output")
        else:
            out_dir = os.path.abspath("output")
        out_path = os.path.join(out_dir, "transactions.csv")
        args.out = out_path

    if not args.truth_out:
        args.truth_out = os.path.join(out_dir, "ground_truth.csv")
    if not args.known_wallets_out:
        args.known_wallets_out = os.path.join(out_dir, "known_wallets.csv")
    if not args.intel_feed_out:
        args.intel_feed_out = os.path.join(out_dir, "darkweb_intel_feed.csv")

    for path in [args.out, args.truth_out, args.known_wallets_out, args.intel_feed_out]:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    start = datetime(2026, 6, 1)
    wallet_pool = [rand_addr() for _ in range(1800)]
    ip_pool = [rand_ip() for _ in range(500)]

    known_wallets, darkweb_intel_feed = build_darkweb_threat_intelligence_catalog()

    # Create convenient lookup maps by category
    exchanges = [w["address"] for w in known_wallets if w["category"] == "exchange"]
    mixers = [w["address"] for w in known_wallets if w["category"] == "mixer"]
    ransomware = [w["address"] for w in known_wallets if w["category"] == "ransomware"]
    darknet_markets = [w["address"] for w in known_wallets if w["category"] == "darknet_market"]
    sanctions = [w["address"] for w in known_wallets if w["category"] == "sanctions"]
    terror = [w["address"] for w in known_wallets if w["category"] == "terror_financing"]

    rows = []
    truth = []  # (txid, is_anomalous, pattern)

    for _ in range(args.n_normal):
        ts = start + timedelta(seconds=random.randint(0, 60 * 60 * 24 * 30))
        r = gen_normal_tx(ts, wallet_pool, ip_pool)
        rows.append(r)
        truth.append((r["txid"], 0, "normal"))

    # Injected Laundering Patterns (Covering Video 1 & Video 2 concepts)
    patterns = [
        "peeling",
        "mixing",
        "layering",
        "ip_fanout",
        "uturn_roundtripping",
        "fanin_consolidation",
    ]
    n_each = args.n_anomalous // len(patterns)

    for pattern in patterns:
        for _ in range(n_each):
            ts = start + timedelta(seconds=random.randint(0, 60 * 60 * 24 * 30))
            if pattern == "peeling":
                exch = random.choice(exchanges) if exchanges else None
                new_rows = gen_peeling_chain(ts, ip_pool, known_exchange_addr=exch)
            elif pattern == "mixing":
                mix = random.choice(mixers) if mixers else None
                new_rows = gen_mixing_pattern(ts, ip_pool, known_mixer_addr=mix)
            elif pattern == "layering":
                rans = random.choice(ransomware + sanctions + terror) if (ransomware or sanctions) else None
                new_rows = gen_rapid_layering(ts, ip_pool, known_ransomware_addr=rans)
            elif pattern == "uturn_roundtripping":
                sanct = random.choice(sanctions + darknet_markets) if sanctions else None
                new_rows = gen_uturn_roundtripping(ts, ip_pool, known_entity_addr=sanct)
            elif pattern == "fanin_consolidation":
                dest = random.choice(darknet_markets + ransomware) if darknet_markets else None
                new_rows = gen_fanin_consolidation(ts, ip_pool, known_destination_addr=dest)
            else:
                new_rows = gen_ip_fanout_cluster(ts)

            rows.extend(new_rows)
            for r in new_rows:
                truth.append((r["txid"], 1, pattern))

    random.shuffle(rows)

    fieldnames = list(rows[0].keys())
    with open(args.out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    with open(args.truth_out, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["txid", "is_anomalous", "pattern"])
        writer.writerows(truth)

    known_fields = ["address", "entity_name", "category", "threat_level", "risk_score", "confidence", "source", "onion_source", "first_seen", "last_seen"]
    with open(args.known_wallets_out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=known_fields)
        writer.writeheader()
        writer.writerows(known_wallets)

    intel_fields = ["feed_id", "target_entity", "category", "threat_level", "risk_score", "bitcoin_address", "onion_url", "intercept_date", "intel_summary", "source_credibility"]
    with open(args.intel_feed_out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=intel_fields)
        writer.writeheader()
        writer.writerows(darkweb_intel_feed)

    print(f"✅ Wrote {len(rows)} transactions to {args.out}")
    print(f"✅ Wrote ground truth ({sum(t[1] for t in truth)} anomalous) to {args.truth_out}")
    print(f"✅ Wrote {len(known_wallets)} threat intelligence tags to {args.known_wallets_out}")
    print(f"✅ Wrote {len(darkweb_intel_feed)} dark web intel records to {args.intel_feed_out}")


if __name__ == "__main__":
    main()
