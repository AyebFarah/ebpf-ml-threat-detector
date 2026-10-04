import pandas as pd

from detection.layer2.baseline import graph_stats
from detection.layer2.builder import build_graph

EVENT = dict(event_id=1, timestamp="t", dst_ip="93.184.216.34", dst_port=443, exec_id="e1",
             parent_exec_id="e0", process_pid=4242, process_name="/usr/bin/curl",
             query_name="example.com", sni=None)
EMPTY_FILES = pd.DataFrame({"event_id": [], "path": []})


def test_single_event_graph_shape():
    g = build_graph(pd.DataFrame([EVENT]), EMPTY_FILES, label=0)
    assert g.x.shape[0] == 5                   # host, process, parent, ip, domain
    assert g.edge_index.shape[1] == 10         # 5 undirected edges, stored both ways
    assert float(g.y) == 0.0


def test_file_activity_adds_node_and_edge():
    files = pd.DataFrame({"event_id": [1], "path": ["/root/.ssh/authorized_keys"]})
    g = build_graph(pd.DataFrame([EVENT]), files, label=1)
    assert g.x.shape[0] == 6 and g.edge_index.shape[1] == 12


def test_empty_window_still_has_host_node():
    g = build_graph(pd.DataFrame(columns=list(EVENT)), EMPTY_FILES, label=0)
    assert g.x.shape[0] == 1 and g.edge_index.shape[1] == 0
    assert graph_stats(g)["n_components"] == 1

def test_inbound_flows_make_port_nodes():
    flows = pd.DataFrame({"flow_id": [1, 2, 3], "src_ip": ["10.0.0.5"] * 3,
                          "dst_ip": ["10.0.0.9"] * 3, "dst_port": [22, 80, 443],
                          "direction": ["inbound"] * 3})
    g = build_graph(pd.DataFrame(columns=list(EVENT)), EMPTY_FILES, 1, flows=flows)
    assert g.x.shape[0] == 5                 # host, 1 attacker ip, 3 ports
    assert g.edge_index.shape[1] == 12       # 6 undirected edges, stored both ways

def test_dns_queries_make_domain_nodes():
    dns = pd.DataFrame({"query_name": ["a1b2c3.evil.com", "d4e5f6.evil.com"]})
    g = build_graph(pd.DataFrame(columns=list(EVENT)), EMPTY_FILES, 1, dns=dns)
    assert g.x.shape[0] == 3 and g.edge_index.shape[1] == 4