# Layer 2: Graph Based Detection

## 1. Purpose

Layer 1 describes each 15 second host window as one row of about 90 numbers.
Layer 2 describes the same window as a graph, so it can express relationships
(which process contacted which IP, which port, which domain) that counts and
ratios cannot. The research question is whether graph structure adds detection
value beyond the Layer 1 feature vector.

Unit of work: one host level time window is one graph and one binary label
(0 benign, 1 attack).

## 2. Design rule: reuse, do not duplicate

The layer2 package only adds graph construction, graph models, and their
training and evaluation. Everything else is imported from shared modules:

database path and random seed     detection.config
window rows and labels            detection.data.extract
run level split                   detection.data.split
model saving and loading          detection.artifacts
metrics and thresholds            detection.evaluation.metrics
alerts and replay                 detection.inference, detection.replay
entropy and external IP helpers   observation.features.utils

Layer 2 models are stored under entity type host_graph:

models/host_graph/graphsage/default/
models/host_graph/lightgbm/graph_stats/     (the ablation baseline)

## 3. Graph definition (schema version g2)

Node kinds: host, process, remote_ip, domain, file, port.

Node features (11 numbers): one hot node kind (6), log of event count,
is external, name entropy, log of name length, well known port ratio.

Edges are undirected (stored in both directions):

host to process            a process produced a connection
parent process to process  process lineage
process to remote_ip       tcp_connect
process to domain          DNS or TLS SNI context
domain to remote_ip        resolution matched to a connection
remote_ip to port          raw TCP flow, port on the local side
port to host               raw TCP flow
host to domain             raw DNS query
process to file            sensitive file access

Every graph contains the host node, so no graph is empty.

## 4. Evidence sources

Layer 1 windows list their evidence in feature_windows.contributing_event_ids.
The list mixes integers (correlated_events ids) and strings such as
flow_raw_149469 (tcp_flows_raw ids). About 80 percent of the ids are raw flows.
Inbound attack traffic appears only in raw flows, because the victim never
issues a tcp_connect for it.

DNS raw events are not listed in the windows, so they are selected by the
window time range.

Lesson from graph schema g1: reading only correlated_events produced empty
graphs for 39.7 percent of windows and identical inputs for attacks and near
misses (for example dns_tunneling and dev_dns_burst). Adding raw flows and raw
DNS reduced empty windows to 0.2 percent. Always check the empty window share
after building.

## 5. Pipeline

graph-build      builds one graph per host window, saves a frozen snapshot
(.pt tensors, .csv index, .json manifest) in datasets/graphs
graph-train      trains the graph statistics baseline or a GNN
graph-evaluate   scores the held out test runs
graph-compare    Layer 1 vs baseline vs GNN on identical test windows
graph-replay     replays one run and prints alerts with time to first alert

The split uses the same function and seed as Layer 1, so test runs are
identical, and graph-compare warns if they ever differ. The decision threshold
is tuned on validation only.

## 6. Models

Graph statistics baseline: LightGBM on 18 structural numbers (node counts by
kind, density, degree, fan out, port hit counts, domain entropy). It goes
through the existing BaseDetectionModel contract unchanged.

GraphSAGE and GCN: two message passing layers, then mean, max and log sum
pooling, then a small classifier. The log sum pooling is required: mean and max
pooling are blind to graph size, and node counts (for example the number of
domains) are a primary signal.

## 7. Results (run of 2026 09 29, before the pooling fix)

test windows 3954, test runs 22

                        pr_auc  precision  recall  false_positive_rate
layer1_lightgbm        0.862      0.681   0.917                0.084
graph_stats_baseline   0.952      0.535   1.000                0.171
layer2_graphsage       0.895      0.602   0.969                0.126

Findings:
1. The baseline ranks best. Structural counts carry strong signal.
2. Layer 1 raises the fewest false alarms.
3. GraphSAGE failed on dns_tunneling (detection 0.0) because its pooling could
   not see node counts. See section 6.
4. admin_backup_rsync (0.991) and ssh_retry_storm (0.326) fool every model
   including Layer 1. They are documented hard cases.
5. git_workflow is a Layer 2 weakness (0.371 baseline, 0.600 GraphSAGE against
   0.000 for Layer 1).

## 8. Limitations

1. The validation set holds 77 attack windows from two families, so threshold
   tuning is unstable. Results should be reported over several seeds.
2. dev_dns_burst and ops_log_collection have one run each. They were used only
   for training, so generalization to them is untested.
3. Attack traffic uses private lab addresses while browsing uses public ones.
   The near miss scenarios protect against this shortcut, so read the per
   scenario false positive table and not only the overall score.
4. Replay scores a frozen snapshot. A live version would call build_graph on
   the last 15 seconds of events.

## 9. How to run

python -m pytest -q detection/tests/unit/test_layer2_builder.py
python -m detection.cli graph-build
python -m detection.cli graph-train --baseline
python -m detection.cli graph-train --model graphsage
python -m detection.cli graph-compare
python -m detection.cli graph-replay --run-id 61 --model graphsage --speed 5

If graph-build fails, stop. Later commands silently reuse the previous snapshot.