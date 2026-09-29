#!/usr/bin/env python3
"""
High-Performance 1,000,000 Transaction & Alert CSV Dataset Generator
Generates a comprehensive, realistic forensic dataset containing:
- 1,000,000 transactions
- Full suspiciousness score distribution (0.0 to 100.0)
- Threat intelligence attributions (Dark Web, Mixers, Ransomware, OFAC)
- Explainable AI (SHAP) feature contribution reason strings
- Complete multi-hop input/output addresses and amounts
- Network layer metadata (GeoIP, ASN, ISP)
"""
import os
import sys
import time
import random
import hashlib
from datetime import datetime, timedelta

def main():
    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "output"))
    os.makedirs(out_dir, exist_ok=True)
    out_csv = os.path.join(out_dir, "alerts.csv")
    out_txs = os.path.join(out_dir, "transactions_1m.csv")
    
    print(f"🚀 Starting high-performance generation of 1,000,000 records...")
    t0 = time.time()
    
    random.seed(42)

    # 1. Threat Entities Catalog
    THREAT_ENTITIES = [
        {"name": "Blender.io Obfuscation Engine", "cat": "mixer", "threat": "CRITICAL", "risk": 96, "onion": "dwoecbpmbjpi6hn5.onion", "ev": "Direct hit: matches known intelligence record for Blender.io Obfuscation Engine (US Treasury OFAC List)"},
        {"name": "Sinbad.io Bitcoin Tumbler Pool", "cat": "mixer", "threat": "CRITICAL", "risk": 97, "onion": "i5ldqyun5uvyr2qf.onion", "ev": "Direct hit: matches known intelligence record for Sinbad.io Bitcoin Tumbler Pool (OFAC SDN List)"},
        {"name": "ChipMixer Micro-Split Pool", "cat": "mixer", "threat": "CRITICAL", "risk": 95, "onion": "xkhktgbtyzmepgth.onion", "ev": "Direct hit: matches known intelligence record for ChipMixer Micro-Split Pool (Europol Action Feed)"},
        {"name": "Wasabi CoinJoin Coordinator Hub", "cat": "mixer", "threat": "HIGH", "risk": 85, "onion": "w3xeva27g3x5j3lr.onion", "ev": "Direct hit: matches known intelligence record for Wasabi CoinJoin Coordinator Hub (P2P Network Probe)"},
        {"name": "YoMix Automated Tumbler Pool", "cat": "mixer", "threat": "HIGH", "risk": 90, "onion": "53rupfr4p5yvb7ul.onion", "ev": "Direct hit: matches known intelligence record for YoMix Automated Tumbler Pool (Dark Web Privacy Feed)"},
        {"name": "LockBit 3.0 Ransomware Syndicate", "cat": "ransomware", "threat": "CRITICAL", "risk": 98, "onion": "atgiqhgjrsnvnq7q.onion", "ev": "Direct hit: matches known intelligence record for LockBit 3.0 Ransomware Syndicate (Ransomwhe.re Feed)"},
        {"name": "BlackCat / ALPHV Ransomware Group", "cat": "ransomware", "threat": "CRITICAL", "risk": 96, "onion": "3rcaviqk43ahejcx.onion", "ev": "Direct hit: matches known intelligence record for BlackCat / ALPHV (FBI Cyber Threat Feed)"},
        {"name": "Conti Ransomware Locker", "cat": "ransomware", "threat": "HIGH", "risk": 92, "onion": "3ictxcwnpgw2jpkl.onion", "ev": "Direct hit: matches known intelligence record for Conti Ransomware Locker (LEA Watchlist)"},
        {"name": "Clop Ransomware Group Treasury", "cat": "ransomware", "threat": "CRITICAL", "risk": 97, "onion": "wu3hymqc3amx3evu.onion", "ev": "Direct hit: matches known intelligence record for Clop Ransomware Group (Ransomwhe.re Darknet Feed)"},
        {"name": "Hydra Market Vendor Vault", "cat": "darknet_market", "threat": "CRITICAL", "risk": 99, "onion": "tt2uzsim2yltzats.onion", "ev": "Direct hit: matches known intelligence record for Hydra Market Vendor Vault (Tor Onion Crawler)"},
        {"name": "Silk Road 3.0 Narcotics Escrow", "cat": "darknet_market", "threat": "HIGH", "risk": 93, "onion": "u544n6kfsvfptomj.onion", "ev": "Direct hit: matches known intelligence record for Silk Road 3.0 Narcotics Escrow (Darknet Forum Scraper)"},
        {"name": "Bohemia Darknet Market Escrow", "cat": "darknet_market", "threat": "CRITICAL", "risk": 96, "onion": "p6e52my7zpjag3ol.onion", "ev": "Direct hit: matches known intelligence record for Bohemia Darknet Market (Tor Onion Crawler)"},
        {"name": "Russian Market Carding Payout", "cat": "darknet_market", "threat": "HIGH", "risk": 91, "onion": "dph5i5u434k64qpr.onion", "ev": "Direct hit: matches known intelligence record for Russian Market Carding Payout (Genesis Feed)"},
        {"name": "Tornado Cash Multi-Chain Relayer", "cat": "mixer", "threat": "CRITICAL", "risk": 98, "onion": "7or37byvzk5ibzbf.onion", "ev": "Direct hit: matches known intelligence record for Tornado Cash Relayer (OFAC Sanctions List)"},
        {"name": "Al-Qassam Brigades Cryptopool", "cat": "terror_financing", "threat": "CRITICAL", "risk": 100, "onion": "wqvrramfp27p674b.onion", "ev": "Direct hit: matches known intelligence record for Al-Qassam Brigades (Counter-Terrorism Taskforce)"},
        {"name": "Chatex Sanctioned Crypto Broker", "cat": "sanctions", "threat": "HIGH", "risk": 90, "onion": "", "ev": "Direct hit: matches known intelligence record for Chatex Sanctioned Broker (OFAC SDN List)"},
        {"name": "Garantex High-Risk Exchange", "cat": "high_risk_exchange", "threat": "CRITICAL", "risk": 97, "onion": "", "ev": "Direct hit: matches known intelligence record for Garantex (OFAC Specially Designated Nationals)"},
    ]

    # 2. GeoIP & Network Nodes
    GEO_POOLS = [
        {"ip": "94.196.46.9", "iso": "GB", "name": "United Kingdom", "asn": "2856", "org": "British Telecommunications PLC"},
        {"ip": "33.232.172.105", "iso": "US", "name": "United States", "asn": "15169", "org": "Google LLC"},
        {"ip": "62.171.237.204", "iso": "GB", "name": "United Kingdom", "asn": "5413", "org": "M247 Ltd"},
        {"ip": "224.243.234.177", "iso": "DE", "name": "Germany", "asn": "24940", "org": "Hetzner Online GmbH"},
        {"ip": "121.20.193.33", "iso": "CN", "name": "China", "asn": "4134", "org": "CHINANET-BACKBONE"},
        {"ip": "58.87.138.143", "iso": "JP", "name": "Japan", "asn": "2516", "org": "KDDI Corporation"},
        {"ip": "27.61.189.93", "iso": "IN", "name": "India", "asn": "55836", "org": "Reliance Jio Infocomm Ltd"},
        {"ip": "167.202.212.22", "iso": "NL", "name": "Netherlands", "asn": "49981", "org": "WorldStream B.V."},
        {"ip": "151.42.132.106", "iso": "IT", "name": "Italy", "asn": "30722", "org": "Vodafone Italia S.p.A."},
        {"ip": "206.23.123.79", "iso": "US", "name": "United States", "asn": "16509", "org": "Amazon.com Inc"},
        {"ip": "145.62.77.227", "iso": "DE", "name": "Germany", "asn": "3320", "org": "Deutsche Telekom AG"},
        {"ip": "108.18.172.233", "iso": "US", "name": "United States", "asn": "701", "org": "Verizon Communications"},
        {"ip": "57.133.195.208", "iso": "BE", "name": "Belgium", "asn": "5432", "org": "Proximus NV"},
        {"ip": "195.15.244.111", "iso": "CH", "name": "Switzerland", "asn": "3303", "org": "Swisscom AG"},
        {"ip": "56.37.103.185", "iso": "US", "name": "United States", "asn": "13335", "org": "Cloudflare Inc"},
        {"ip": "165.229.165.172", "iso": "KR", "name": "Republic of Korea", "asn": "9318", "org": "SK Broadband"},
        {"ip": "67.218.192.68", "iso": "US", "name": "United States", "asn": "7922", "org": "Comcast Cable Communications"},
        {"ip": "105.61.255.189", "iso": "KE", "name": "Kenya", "asn": "36914", "org": "Safaricom PLC"},
        {"ip": "104.10.192.123", "iso": "US", "name": "United States", "asn": "7018", "org": "AT&T Services Inc"},
        {"ip": "15.154.234.76", "iso": "US", "name": "United States", "asn": "16509", "org": "Amazon.com Inc"},
        {"ip": "97.35.253.248", "iso": "US", "name": "United States", "asn": "20115", "org": "Charter Communications"},
        {"ip": "102.63.28.152", "iso": "ZA", "name": "South Africa", "asn": "37457", "org": "MTN SA"},
        {"ip": "1.169.231.32", "iso": "TW", "name": "Taiwan", "asn": "3462", "org": "Data Communication Business Group"},
        {"ip": "187.2.101.119", "iso": "BR", "name": "Brazil", "asn": "28573", "org": "Claro Telecom Participacoes S.A."},
        {"ip": "86.220.137.8", "iso": "FR", "name": "France", "asn": "3215", "org": "Orange SA"},
        {"ip": "176.43.97.197", "iso": "TR", "name": "Turkey", "asn": "47331", "org": "Turkcell Iletisim Hizmetleri"},
        {"ip": "124.105.222.226", "iso": "PH", "name": "Philippines", "asn": "9299", "org": "Philippine Long Distance Telephone"},
        {"ip": "87.26.168.119", "iso": "IT", "name": "Italy", "asn": "1267", "org": "Wind Tre S.p.A."},
        {"ip": "137.74.5.229", "iso": "PL", "name": "Poland", "asn": "16276", "org": "OVH SAS Poland"},
        {"ip": "160.160.77.197", "iso": "MA", "name": "Morocco", "asn": "6713", "org": "Maroc Telecom"},
        {"ip": "189.156.102.180", "iso": "MX", "name": "Mexico", "asn": "8151", "org": "Uninet S.A. de C.V."},
    ]

    SCRIPT_TYPES = ["P2WPKH", "P2SH", "P2TR", "P2PKH", "P2WSH"]

    # Pre-generate 1,000 reusable wallet addresses
    wallet_pool = ["bc1q" + hashlib.md5(f"wallet_{i}".encode()).hexdigest() + hashlib.sha1(f"w_{i}".encode()).hexdigest()[:10] for i in range(1200)]

    # Header
    HEADER = "txid,timestamp,src_ip,country,country_name,asn,asn_org,n_inputs,n_outputs,total_in,fee,suspicion_score,wallet_cluster,attributed_entity,entity_category,threat_level,risk_score,onion_source,attribution_evidence,reason,input_addresses,output_addresses,input_amounts,output_amounts,script_type\n"

    base_time = datetime(2026, 6, 1, 0, 0, 0)
    total_records = 1000000
    chunk_size = 50000

    print(f"📊 Generating {total_records:,} records in chunks of {chunk_size:,}...")

    # Distribution plan across 1M:
    # 0 - 25: ~500,000 normal records (peer-to-peer commerce, low fee)
    # 25 - 50: ~350,000 standard variance (routine exchange transfers, batches)
    # 50 - 75: ~100,000 anomalous (peeling chains, high fan-out, velocity spikes)
    # 75 - 95: ~35,000 high suspicion (automated layering, CoinJoin, unverified mixers)
    # 95 - 100: ~15,000 critical threats (direct OFAC sanctions, ransomware, darknet vaults)

    # We will write directly to both alerts.csv and transactions_1m.csv
    with open(out_csv, "w", encoding="utf-8", buffering=1024*1024*8) as f_alerts, \
         open(out_txs, "w", encoding="utf-8", buffering=1024*1024*8) as f_txs:
        
        f_alerts.write(HEADER)
        f_txs.write(HEADER)

        records_written = 0

        # Preserve the top famous benchmark alerts at the very top for seamless continuity!
        top_anchors = [
            ("7347c8cdbe674db8bb56d5939b9e5d21b1799c2d558546dba69e235dcbc8d07c", "2026-06-17 00:20:39", "94.196.46.9", "GB", "United Kingdom", "2856", "British Telecommunications", 8, 8, 0.71090187, 0.0007109, 100.0, 267, "Blender.io Obfuscation Engine", "mixer", "CRITICAL", 96, "dwoecbpmbjpi6hn5.onion", "Direct hit: matches known intelligence record for Blender.io Obfuscation Engine (US Treasury OFAC List)", "input count = 8 (contribution -0.057); transaction out-degree (fan-out) = 9 (contribution -0.042); distinct wallets seen from this IP = 44 (contribution -0.041)", "|".join(wallet_pool[:8]), "|".join(wallet_pool[8:16]), "|".join(["0.0888"]*8), "|".join(["0.0888"]*8), "P2WPKH"),
            ("3b6ac13c2fd148c9a0079f38669ca9d57683ffdd828d4eb4874cae4b0ff85a8a", "2026-06-16 11:08:37", "33.232.172.105", "US", "United States", "15169", "Google LLC", 8, 8, 0.75920674, 0.00075921, 98.3, 1808, "", "", "LOW", 10, "", "", "input count = 8 (contribution -0.053); transaction out-degree (fan-out) = 9 (contribution -0.040); time since prior broadcast from same IP = 8.424e+05 (contribution -0.034)", "|".join(wallet_pool[16:24]), "|".join(wallet_pool[24:32]), "|".join(["0.0949"]*8), "|".join(["0.0949"]*8), "P2WPKH"),
            ("003d056ad6ad4d9886a891070b1cc3fe3909f6748d044af198f24db590b3613a", "2026-06-14 00:12:15", "94.196.46.9", "GB", "United Kingdom", "2856", "British Telecommunications", 8, 8, 0.83390872, 0.00083391, 98.1, 267, "Blender.io Obfuscation Engine", "mixer", "CRITICAL", 96, "dwoecbpmbjpi6hn5.onion", "Direct hit: matches known intelligence record for Blender.io Obfuscation Engine (US Treasury OFAC List)", "input count = 8 (contribution -0.057); distinct wallets seen from this IP = 44 (contribution -0.042); transaction out-degree (fan-out) = 9 (contribution -0.041)", "|".join(wallet_pool[32:40]), "|".join(wallet_pool[40:48]), "|".join(["0.1042"]*8), "|".join(["0.1042"]*8), "P2WPKH"),
            ("04a8f674eec04f4da01ab1306cfb49b56f5bd7ae27074680a98d41ef7412210a", "2026-06-15 00:46:50", "62.171.237.204", "GB", "United Kingdom", "5413", "M247 Ltd", 8, 8, 1.57352598, 0.00157353, 97.7, 1724, "", "", "LOW", 10, "", "", "input count = 8 (contribution -0.053); time since prior broadcast from same IP = 1.061e+06 (contribution -0.047); transaction out-degree (fan-out) = 9 (contribution -0.040)", "|".join(wallet_pool[48:56]), "|".join(wallet_pool[56:64]), "|".join(["0.1966"]*8), "|".join(["0.1966"]*8), "P2WPKH"),
            ("c7f82a4bf49048c58cac5206ec010eddb3275bd911614625b34217e3b70e90ad", "2026-06-23 19:27:12", "224.243.234.177", "DE", "Germany", "24940", "Hetzner Online GmbH", 8, 8, 0.48194232, 0.00048194, 97.5, 2327, "YoMix Automated Tumbler Pool", "mixer", "HIGH", 90, "53rupfr4p5yvb7ul.onion", "Direct hit: matches known intelligence record for YoMix Automated Tumbler Pool (Dark Web Privacy Feed)", "input count = 8 (contribution -0.055); transaction out-degree (fan-out) = 9 (contribution -0.042); transaction graph total degree = 17 (contribution -0.035)", "|".join(wallet_pool[64:72]), "|".join(wallet_pool[72:80]), "|".join(["0.0602"]*8), "|".join(["0.0602"]*8), "P2WPKH"),
            ("c7771d3b27fc45d895eb425f220ec2346fb9c0e808484362981999d07214bd7a", "2026-06-08 11:24:25", "121.20.193.33", "CN", "China", "4134", "CHINANET", 8, 8, 0.55916266, 0.00055916, 97.0, 1146, "Wasabi CoinJoin Coordinator Hub", "mixer", "HIGH", 85, "w3xeva27g3x5j3lr.onion", "Direct hit: matches known intelligence record for Wasabi CoinJoin Coordinator Hub (P2P Network Probe)", "input count = 8 (contribution -0.060); transaction out-degree (fan-out) = 9 (contribution -0.045); transaction graph total degree = 17 (contribution -0.039)", "|".join(wallet_pool[80:88]), "|".join(wallet_pool[88:96]), "|".join(["0.0698"]*8), "|".join(["0.0698"]*8), "P2WPKH"),
            ("36b2824ffc7141e590432bd7837d839fd794c699543d48c29eadcddbc48fa078", "2026-06-22 20:50:20", "58.87.138.143", "JP", "Japan", "2516", "KDDI Corporation", 8, 8, 1.26829282, 0.00126829, 96.7, 77, "ChipMixer Micro-Split Pool", "mixer", "CRITICAL", 95, "xkhktgbtyzmepgth.onion", "Direct hit: matches known intelligence record for ChipMixer Micro-Split Pool (Europol Action Feed)", "input count = 8 (contribution -0.062); transaction out-degree (fan-out) = 9 (contribution -0.045); transaction graph total degree = 17 (contribution -0.040)", "|".join(wallet_pool[96:104]), "|".join(wallet_pool[104:112]), "|".join(["0.1585"]*8), "|".join(["0.1585"]*8), "P2WPKH"),
        ]

        top_lines = []
        for a in top_anchors:
            line = f"{a[0]},{a[1]},{a[2]},{a[3]},{a[4]},{a[5]},{a[6]},{a[7]},{a[8]},{a[9]:.8f},{a[10]:.8f},{a[11]:.1f},{a[12]},{a[13]},{a[14]},{a[15]},{a[16]},{a[17]},{a[18]},{a[19]},{a[20]},{a[21]},{a[22]},{a[23]},{a[24]}\n"
            top_lines.append(line)
        
        f_alerts.writelines(top_lines)
        f_txs.writelines(top_lines)
        records_written += len(top_anchors)

        # Batch generator
        lines_buffer = []

        while records_written < total_records:
            # Determine profile tier
            r_val = random.random()
            
            # Timestamp uniformly spread over 30 days
            sec_offset = random.randint(0, 30 * 86400)
            row_ts = (base_time + timedelta(seconds=sec_offset)).strftime("%Y-%m-%d %H:%M:%S")

            # Geo profile
            geo = random.choice(GEO_POOLS)
            script_t = random.choice(SCRIPT_TYPES)

            # Random 64-char transaction hash
            tx_hash = hashlib.sha256(f"tx_{records_written}_{r_val}".encode()).hexdigest()

            if r_val < 0.015:
                # 1.5% CRITICAL THREATS (Score: 95.0 - 100.0)
                score = round(random.uniform(95.0, 99.9), 1)
                entity = random.choice(THREAT_ENTITIES)
                threat = entity["threat"]
                category = entity["cat"]
                risk = entity["risk"]
                entity_name = entity["name"]
                onion = entity["onion"]
                ev = entity["ev"]

                n_in = random.choice([4, 6, 8, 10])
                n_out = n_in
                tot_val = round(random.uniform(0.5, 8.5), 4)
                fee = round(tot_val * random.uniform(0.0005, 0.0015), 6)
                cluster = random.randint(10, 2500)

                w_in_list = random.sample(wallet_pool, n_in)
                w_out_list = random.sample(wallet_pool, n_out)
                in_split = round(tot_val / n_in, 4)
                out_split = round((tot_val - fee) / n_out, 4)

                in_addrs = "|".join(w_in_list)
                out_addrs = "|".join(w_out_list)
                in_amts = "|".join([str(in_split)] * n_in)
                out_amts = "|".join([str(out_split)] * n_out)

                reasons = [
                    f"output-splitting equality (mixing signature) = {random.uniform(0.94, 0.99):.2f} (contribution -0.065); input count = {n_in} (contribution -0.058); distinct wallets seen from this IP = {random.randint(25, 55)} (contribution -0.044)",
                    f"input count = {n_in} (contribution -0.061); transaction out-degree (fan-out) = {n_out+1} (contribution -0.046); transaction graph total degree = {n_in+n_out+1} (contribution -0.040)",
                    f"high multi-party input/output splitting = {n_in}x{n_out} (contribution -0.063); automated proxy cluster velocity = {random.randint(12, 45)}s (contribution -0.042)"
                ]
                reason = random.choice(reasons)

            elif r_val < 0.050:
                # 3.5% HIGH SUSPICION (Score: 75.0 - 94.9)
                score = round(random.uniform(75.0, 94.9), 1)
                is_named = (random.random() < 0.6)
                if is_named:
                    entity = random.choice(THREAT_ENTITIES)
                    threat = entity["threat"]
                    category = entity["cat"]
                    risk = entity["risk"]
                    entity_name = entity["name"]
                    onion = entity["onion"]
                    ev = entity["ev"]
                else:
                    threat = "HIGH"
                    category = random.choice(["mixer", "layering_ring", "peeling_hub"])
                    risk = random.randint(75, 88)
                    entity_name = ""
                    onion = ""
                    ev = ""

                n_in = random.choice([2, 4, 8])
                n_out = random.choice([2, 4, 8])
                tot_val = round(random.uniform(0.2, 5.0), 4)
                fee = round(tot_val * random.uniform(0.0006, 0.002), 6)
                cluster = random.randint(10, 2500)

                w_in_list = random.sample(wallet_pool, n_in)
                w_out_list = random.sample(wallet_pool, n_out)
                in_addrs = "|".join(w_in_list)
                out_addrs = "|".join(w_out_list)
                in_amts = "|".join([str(round(tot_val / n_in, 4))] * n_in)
                out_amts = "|".join([str(round((tot_val - fee) / n_out, 4))] * n_out)

                reason = f"transaction out-degree (fan-out) = {n_out+1} (contribution -0.045); distinct wallets seen from this IP = {random.randint(15, 35)} (contribution -0.038); time since prior broadcast = {random.randint(100, 900)}s (contribution -0.031)"

            elif r_val < 0.150:
                # 10% MEDIUM ANOMALIES (Score: 50.0 - 74.9)
                score = round(random.uniform(50.0, 74.9), 1)
                threat = "MEDIUM"
                category = random.choice(["rapid_layering", "peeling_chain", "unverified_cluster", ""])
                risk = random.randint(40, 65)
                entity_name = ""
                onion = ""
                ev = ""

                n_in = random.choice([1, 2, 3])
                n_out = random.choice([1, 2, 3])
                tot_val = round(random.uniform(0.05, 3.0), 4)
                fee = round(tot_val * random.uniform(0.0008, 0.003), 6)
                cluster = random.randint(1, 2500)

                w_in_list = random.sample(wallet_pool, n_in)
                w_out_list = random.sample(wallet_pool, n_out)
                in_addrs = "|".join(w_in_list)
                out_addrs = "|".join(w_out_list)
                in_amts = "|".join([str(round(tot_val / n_in, 4))] * n_in)
                out_amts = "|".join([str(round((tot_val - fee) / n_out, 4))] * n_out)

                reason = f"time since prior broadcast from same IP = {random.randint(1000, 8000)}s (contribution -0.052); output/input fan-out ratio = {n_out/n_in:.2f} (contribution -0.031); fee-to-value ratio = {fee/tot_val:.5f} (contribution -0.024)"

            elif r_val < 0.500:
                # 35% LOW VARIANCE / ROUTINE BATCHES (Score: 25.0 - 49.9)
                score = round(random.uniform(25.0, 49.9), 1)
                threat = "LOW"
                category = ""
                risk = random.randint(15, 35)
                entity_name = ""
                onion = ""
                ev = ""

                n_in = random.choice([1, 2])
                n_out = random.choice([1, 2])
                tot_val = round(random.uniform(0.01, 1.5), 4)
                fee = round(tot_val * random.uniform(0.0003, 0.001), 6)
                cluster = random.randint(1, 2500)

                w_in_list = random.sample(wallet_pool, n_in)
                w_out_list = random.sample(wallet_pool, n_out)
                in_addrs = "|".join(w_in_list)
                out_addrs = "|".join(w_out_list)
                in_amts = "|".join([str(round(tot_val / n_in, 4))] * n_in)
                out_amts = "|".join([str(round((tot_val - fee) / n_out, 4))] * n_out)

                reason = f"standard multi-output payment; normal broadcast velocity (contribution -0.012); baseline wallet activity"

            else:
                # 50% NORMAL COMMERCE / PEER-TO-PEER (Score: 0.0 - 24.9)
                score = round(random.uniform(0.0, 24.9), 1)
                threat = "LOW"
                category = ""
                risk = random.randint(1, 10)
                entity_name = ""
                onion = ""
                ev = ""

                n_in = 1
                n_out = random.choice([1, 2])
                tot_val = round(random.uniform(0.001, 0.8), 4)
                fee = round(tot_val * random.uniform(0.0002, 0.0008), 6)
                cluster = random.randint(1, 2500)

                w_in_list = random.sample(wallet_pool, n_in)
                w_out_list = random.sample(wallet_pool, n_out)
                in_addrs = "|".join(w_in_list)
                out_addrs = "|".join(w_out_list)
                in_amts = str(tot_val)
                out_amts = "|".join([str(round((tot_val - fee) / n_out, 4))] * n_out)

                reason = "nominal transaction flow; standard single-user broadcast; zero anomaly indicators"

            line = f"{tx_hash},{row_ts},{geo['ip']},{geo['iso']},{geo['name']},{geo['asn']},{geo['org']},{n_in},{n_out},{tot_val:.8f},{fee:.8f},{score:.1f},{cluster},{entity_name},{category},{threat},{risk},{onion},{ev},{reason},{in_addrs},{out_addrs},{in_amts},{out_amts},{script_t}\n"
            lines_buffer.append(line)
            records_written += 1

            if len(lines_buffer) >= chunk_size:
                f_alerts.writelines(lines_buffer)
                f_txs.writelines(lines_buffer)
                lines_buffer = []
                print(f"   ⏳ Written {records_written:,} / {total_records:,} records ({records_written/total_records*100:.0f}%)...")

        if lines_buffer:
            f_alerts.writelines(lines_buffer)
            f_txs.writelines(lines_buffer)

    t1 = time.time()
    size_mb = os.path.getsize(out_csv) / (1024 * 1024)
    print(f"\n✅ SUCCESS! 1,000,000 transaction & alert records generated in {t1 - t0:.2f} seconds!")
    print(f"📁 alerts.csv: {out_csv} ({size_mb:.2f} MB)")
    print(f"📁 transactions_1m.csv: {out_txs} ({size_mb:.2f} MB)")

if __name__ == "__main__":
    main()
