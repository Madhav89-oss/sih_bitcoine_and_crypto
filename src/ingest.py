"""
Ingestion layer.
Parses CSV (and optionally JSON/XML — CSV is the primary demo path) transaction
metadata into a normalized pandas DataFrame ready for graph building.
"""
import pandas as pd


REQUIRED_COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "txid",
    "input_addresses", "output_addresses", "input_amounts", "output_amounts",
    "fee", "script_type",
]


def load_csv(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["input_addresses"] = df["input_addresses"].astype(str).str.split("|")
    df["output_addresses"] = df["output_addresses"].astype(str).str.split("|")
    df["input_amounts"] = df["input_amounts"].astype(str).str.split("|").apply(
        lambda xs: [float(x) for x in xs]
    )
    df["output_amounts"] = df["output_amounts"].astype(str).str.split("|").apply(
        lambda xs: [float(x) for x in xs]
    )
    df["n_inputs"] = df["input_addresses"].apply(len)
    df["n_outputs"] = df["output_addresses"].apply(len)
    df["total_in"] = df["input_amounts"].apply(sum)
    df["total_out"] = df["output_amounts"].apply(sum)
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df


if __name__ == "__main__":
    import sys
    df = load_csv(sys.argv[1] if len(sys.argv) > 1 else "../output/transactions.csv")
    print(df.shape)
    print(df.head(3))
