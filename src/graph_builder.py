"""
Entity/transaction graph builder.

Node types:  wallet, tx, ip
Edge types:  wallet -> tx   (input, spends from)
             tx -> wallet   (output, pays to)
             tx -> ip       (broadcast source)
"""
import networkx as nx
import pandas as pd


def build_graph(df: pd.DataFrame) -> nx.MultiDiGraph:
    G = nx.MultiDiGraph()

    for _, row in df.iterrows():
        txid = row["txid"]
        G.add_node(txid, type="tx", timestamp=row["timestamp"], fee=row["fee"],
                   script_type=row["script_type"])

        ip = row["src_ip"]
        G.add_node(ip, type="ip", asn=row.get("asn"), country=row.get("country"))
        G.add_edge(txid, ip, kind="broadcast_from")

        for addr, amt in zip(row["input_addresses"], row["input_amounts"]):
            G.add_node(addr, type="wallet")
            G.add_edge(addr, txid, kind="input", amount=amt)

        for addr, amt in zip(row["output_addresses"], row["output_amounts"]):
            G.add_node(addr, type="wallet")
            G.add_edge(txid, addr, kind="output", amount=amt)

    return G


def graph_summary(G: nx.MultiDiGraph) -> dict:
    types = {}
    for _, data in G.nodes(data=True):
        t = data.get("type", "unknown")
        types[t] = types.get(t, 0) + 1
    return {
        "nodes": G.number_of_nodes(),
        "edges": G.number_of_edges(),
        "by_type": types,
    }


if __name__ == "__main__":
    from ingest import load_csv
    df = load_csv("../output/transactions.csv")
    G = build_graph(df)
    print(graph_summary(G))
