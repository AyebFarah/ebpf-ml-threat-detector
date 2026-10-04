# Layer 1 Validation and Model Selection

## 1. Purpose

This document closes out the Layer 1 validation phase of the detection pipeline
(`detection/`). It records what was tested, what was found, which model was
selected as the current `default` variant and which limitations remain open for the next phase.

Layer 1 is the tabular, tree based classifier that scores each `host` window
from `feature_windows` as benign or attack. This phase answers five questions:

1. Is the underlying data sound enough to train on?
2. Does the chosen model work on runs it has never seen?
3. Does it work on entire attack families it has never seen?
4. Is it learning real network behavior, or a lab specific shortcut?
5. Does it behave correctly, live, window by window, including on a bad path
   such as an operator interrupting a replay?

## 2. Dataset Used

All experiments in this phase ran against:

```text
/ebpf-ml-threat-detector/observation/database/merged_observations.db
entity_type = "host"
16100 rows, 88 runs
```

`detection.data.validate.validate()` flagged three structural properties of
this dataset that shaped every later step:

* Six feature columns have zero variance at host level: `http_status_4xx_ratio`,
  `http_status_5xx_ratio`, `shell_spawn_count`, `sudo_exec_count`,
  `pkexec_count`, `su_exec_count`. No privilege escalation or persistence
  attack scenario has been collected yet, so these columns carry no signal.
  Layer 1, as validated here, only demonstrates network behavior detection.
* Two `(label:scenario)` categories have exactly one run
  (`0:dev_dns_burst`, `0:ops_log_collection`). `group_stratified_split`
  places single run categories in train only: no test metric says anything
  about generalization to them.
* Ten categories have only two or three runs each. These appear in both train
  and test but are too scarce to reliably appear in val as well. This is the
  reason `detection.evaluation.generalization` exists as a separate, dedicated
  protocol rather than relying on the ordinary train/val/test split for these
  categories.

## 3. Split Design

`detection.data.split.group_stratified_split` splits by `run_id`, never by
row, because sliding feature windows overlap (15 second window, 5 second
stride), so neighboring rows from the same run are near duplicates. Splitting
by row would leak information from test into train.

Resulting split for this phase:

| split | windows | runs |
|---|---|---|
| train | 10815 | 55 |
| val   | 1331  | 11 |
| test  | 3954  | 22 |

Val is deliberately not stratified by category: its only jobs are early
stopping and threshold tuning, and it is too small (77 attack windows) to
trust for ranking models or reporting headline numbers. All comparative
numbers in this document are read from test (650 attack windows, 3304
benign windows).

## 4. Algorithms Trained and Rejected on Basic Sanity Grounds

All nine registered algorithms were trained under the identical split. Three
were rejected immediately, before any deeper comparison, because they fail a
basic sanity check on their own:

| model | disqualifying test metric | reading |
|---|---|---|
| `hdbscan` | false positive rate 0.4625 | nearly half of all benign windows flagged |
| `residual_regression` | recall 0.0123 | misses 99 percent of attacks |
| `rules` | Matthews correlation coefficient minus 0.1297 | worse than random guessing |

`isolation_forest`, added to the registry later in this phase, also falls
into this tier on PR AUC alone (0.2649 on test) and is not treated as a
contender.

## 5. Comparison of Remaining Candidates

The built in ranking command was run against the test split, with the
reasoning for that choice recorded in Section 6:

```bash
python -m detection.cli compare --entity-type host --metric pr_auc --split test
```

Result:

```text
[compare] ranking by pr_auc on test
  1. lightgbm                     0.8616
  2. logistic_regression          0.8570
  3. xgboost                      0.6650
  4. xgbod                        0.6494
  5. random_forest                0.6043
  6. hdbscan                      0.2687
  7. isolation_forest             0.2649
  8. residual_regression          0.1757
  9. rules                        0.1508
```

Full test metrics for the four PR AUC contenders:

| model | PR AUC | recall | precision | false positive rate |
|---|---|---|---|---|
| lightgbm | 0.8616 | 0.9169 | 0.6811 | 0.0844 |
| logistic_regression | 0.8570 | 0.9985 | 0.5748 | 0.1453 |
| xgboost | 0.6650 | 0.9446 | 0.6710 | 0.0911 |
| random_forest | 0.6043 | 1.0000 | 0.7012 | 0.0838 |

## 6. Why PR AUC on the Test Split Was Chosen as the Ranking Metric

Three separate choices, each justified on its own:

**PR AUC over ROC AUC or accuracy.** Test is imbalanced (3304 benign against
650 attack, roughly 5 to 1). ROC AUC treats the large benign class and small
attack class symmetrically and can look strong even when the model produces
many false alarms relative to true attacks. PR AUC measures precision against
recall directly, which is the tradeoff a live detector is judged on. Plain
accuracy is worse still: a model that labels everything benign already scores
about 83 percent accuracy from class imbalance alone, without catching a
single attack.

**Test over val.** Val has only 77 attack windows across 11 runs, too few to
rank nine algorithms against each other reliably. Test has 650 attack windows
across 22 runs.

**Test over train.** Train scores measure memorization, not generalization.
`random_forest` scored a perfect 1.0000 across every metric on train, then
dropped to 0.6043 PR AUC on test, a gap of roughly 0.4 that is invisible if
only train is inspected.

## 7. The Near Miss Tie Breaker

PR AUC alone leaves `lightgbm` (0.8616) and `logistic_regression` (0.8570)
too close to separate safely. `detection.evaluation.evaluate`'s per scenario
false positive breakdown resolves this:

| scenario | lightgbm | logistic_regression | xgboost | random_forest | xgbod |
|---|---|---|---|---|---|
| `ops_health_check` | 0.000 | 1.000 | 0.000 | 0.000 | 0.497 |
| `port_scan` (detection rate) | 1.000 | 1.000 | 0.000 | 1.000 | 1.000 |
| `ssh_retry_storm` | 0.326 | 0.223 | 0.326 | 0.326 | 0.326 |
| `admin_backup_rsync` | 0.991 | 0.991 | 0.991 | 0.991 | 0.991 |

`logistic_regression` flags every single `ops_health_check` window, a
routine benign scenario, as an attack. `xgboost` misses every single
`port_scan` window in test. Both are disqualified by one catastrophic,
scenario specific failure that the aggregate PR AUC number completely hides.
`admin_backup_rsync` fails at almost exactly the same rate across every
model, which is the first sign that this particular false positive is a
shared data problem, not a model choice problem.

## 8. Final Decision: LightGBM

LightGBM is selected as the Layer 1 model:

* Highest PR AUC among candidates with no disqualifying near miss failure.
* Smallest relative train to test gap of the top two (`logistic_regression`
  hit 0.9985 recall and 1.0 precision-adjacent scores on train before
  dropping sharply on `ops_health_check`, while LightGBM's train score,
  0.9517 recall, was not a perfect memorized fit).
* Confirmed independently twice: once by manual reading of individual
  `evaluate` logs, once by the `compare --split test` ranking.
* Already saved as the `default` variant at
  `models/host/lightgbm/default/`, requiring no promotion step.

`xgbod` (a hybrid unsupervised plus supervised approach, Zhao and
Hryniewicki 2018) was tried and did not beat the plain supervised baseline
(PR AUC 0.6494 against 0.8616), while adding two extra fitted detectors
(Isolation Forest, Local Outlier Factor) that must be saved and loaded
alongside the boosted model. This negative result is itself informative: it
shows the labeled attack data already gives the supervised models enough
signal that an unsupervised outlier layer adds redundancy rather than new
information, for this dataset as currently collected.

## 9. The xgbod Training Stall, Explained

`xgbod`'s training log showed:

```text
[0]     validation_0-aucpr:0.71692
[30]    validation_0-aucpr:0.71692
```

Round 0 and round 30 report the identical validation score, so the 30
rounds `early_stopping_rounds` requires before giving up all changed
nothing. This happened because `xgbod`'s own printed feature importance
showed one feature, `private_dst_ip_count`, carrying about 90 percent of
the decision weight. When one feature already separates most rows almost
perfectly, the first tree or two saturate the predictions and later trees
have almost nothing left to correct, so the ranking measured by `aucpr`
stops moving. This is the same single feature dominance seen in every other
model in this phase, made unusually visible here because the ensemble gave
up training after only a handful of rounds.


## 10. Feature Importance: How It Is Calculated and What It Revealed

`BaseDetectionModel.feature_importance()` is optional per model. LightGBM's
`Booster` supports two distinct importance types, and they tell different
stories:

* **Split importance**: how many times a feature was chosen as a splitting
  rule across every tree. Spreads out relatively evenly across many useful
  features.
* **Gain importance** (used here): the sum of training objective improvement
  contributed every time a feature was used for a split. Rewards one large,
  decisive cut heavily, even if that feature is rarely used afterward.

The printed importances from training,

```text
private_dst_ip_count: 122516.3
max_flow_duration_sec: 11302.3
dns_query_count: 5099.3
```

show a ten to one ratio between the top feature and the next, which is a
gain style signature: `private_dst_ip_count` is very likely used near the
top of most trees to make one large separation, with every following split
only cleaning up the remainder.


## 11. Generalization: Leave One Category Out

```bash
python -m detection.cli generalization --entity-type host --model lightgbm
```

For each `(label, scenario)` category, every run of that category is removed
from training entirely, the model is refit from scratch on everything else,
a threshold is tuned on a small validation slice of the remaining classes,
and the held out category is scored on its own. This is a materially harder
test than the ordinary test split: the test split only holds out specific
runs, while other runs of the same family remain in training.

### Attack families: detection rate when fully held out

| family | held out detection rate | in sample test detection rate |
|---|---|---|
| `c2_beacon` | 1.000 | 1.000 |
| `network_discovery` | 0.217 | 0.842 |
| `port_scan` | 0.021 | 1.000 |
| `lateral_movement_ssh` | 0.001 | 1.000 |
| `dns_tunneling` | 0.000 | 1.000 |
| `data_exfiltration` | 0.000 | 1.000 |
| `ssh_bruteforce` | 0.000 | 0.844 |

Only `c2_beacon` survives being fully held out. Every other attack family
collapses toward zero detection once no example of that family remains in
training. This is the single most important finding of this phase: the
strong test split scores reported in Section 5 measure recognizing a
slightly different instance of an already trained on pattern, not learning
attack behavior that transfers to a genuinely unseen family. `c2_beacon`
likely survives because regular, fixed interval beaconing is separable using
generic timing features (`interarrival_mean_ms`, `interarrival_p95_ms`) that
do not depend on any scenario specific numeric range.

### Benign and near miss scenarios: false positive rate when fully held out

| scenario | held out false positive rate | in sample false positive rate |
|---|---|---|
| `ops_health_check` | 1.000 | 0.000 |
| `ssh_retry_storm` | 0.949 | 0.326 |
| `admin_backup_rsync` | 0.907 | 0.991 |
| `admin_nmap_inventory` | 0.667 | 0.000 |
| `git_workflow` | 0.286 | 0.000 |
| `ops_log_collection` | 0.386 | not tested in sample (single run category) |
| `security_vuln_scan_light` | 0.161 | 0.120 |

`ops_health_check` is the clearest single example: with at least one of its
runs present in training the model correctly scores it as entirely benign
(0.000). Remove every run of it and the model flags all of it as an attack
(1.000). This is not the model learning "health checks are benign," it is
the model memorizing the specific numeric ranges of the runs it has seen and
flagging anything numerically outside those ranges as suspicious.

### Interpretation

Taken together, the attack side and the benign side of this table describe
the same underlying mechanism. The model appears closer to memorizing a
typical `private_dst_ip_count` (and related count feature) range per
scenario than learning a general behavioral rule. This explains both why an
unseen benign scenario gets wrongly flagged and why an unseen attack family
gets wrongly cleared: neither has a memorized range to match against yet.

A secondary, separate limitation: several held out categories have very
little data (`data_exfiltration` 26 windows, `port_scan` 47 windows,
`lateral_movement_ssh` only 3 windows in its one test run). A detection rate
computed over 26 to 47 windows is noisy on its own, independent of the
shortcut question, and more runs per family are needed before trusting a
generalization number for these categories in isolation.

## 12. Replay: Live, Window by Window Confirmation

Three runs, all drawn only from the `default` variant's `test_run_ids`
(never trained or threshold tuned on), were replayed:

```bash
python -m detection.cli replay --run-id 59 --entity-type host --model lightgbm --speed 5 --output experiments/logs/alerts_attack_run59.jsonl
python -m detection.cli replay --run-id 20 --entity-type host --model lightgbm --speed 5 --output experiments/logs/alerts_benign_run20.jsonl
python -m detection.cli replay --run-id 70 --entity-type host --model lightgbm --speed 5 --output experiments/logs/alerts_nearmiss_run70.jsonl
```

| run | scenario         | label | result                                                          |
|-----|------------------|---|-----------------------------------------------------------------|
| 59  | `port_scan`      | attack | 6 of 6 alerts correct before interruption, first alert at 15.0s |
| 20  | `light_browsing` | benign | 0 alerts across all 92 windows                                  |
| 70  | `admin_nmap_inventory` | near miss | 0 alerts across all 63 windows                                  |

A near miss run, `admin_nmap_inventory` (run 70), was replayed to
completion and produced zero alerts across all 63 windows, differing from
its held out generalization false positive rate of 0.667. This is expected
and not a contradiction: the `default` variant model was trained with
`admin_nmap_inventory` runs present in training (only one of its two total
runs was held out during the separate generalization experiment), so its
in sample behavior on this scenario is clean, consistent with the near miss
table's "in sample" column pattern seen throughout Section 11.

## 13. Open Limitations Carried Into the Next Phase

1. **The private IP shortcut is unresolved.** `admin_backup_rsync` fails at
   essentially the same rate (0.991 in sample, 0.907 held out) across every
   model tried in Section 5, meaning it lives in the data or feature layer,
   not in model choice. The ablation experiment (drop
   `private_dst_ip_count` and related private/external features, retrain,
   rerun both `evaluate` and `generalization`) is queued but not yet run.
2. **Layer 1, as validated, covers network behavior only.** No privilege
   escalation or persistence scenario has been collected, so the six zero
   variance privilege and HTTP error features remain untested.
3. **Generalization to unseen attack families is currently weak**, outside
   of `c2_beacon`. This is the primary finding to carry forward: the
   ablation in point 1 is the first planned experiment to test whether
   removing the dominant count feature exposes usable signal in the
   remaining features or whether more label diversity is needed instead.
4. **Several attack families have too few runs for a trustworthy held out
   number** (`data_exfiltration`, `port_scan`, `lateral_movement_ssh`,
   `dns_tunneling`, `network_discovery`). Additional attack lab collection
   runs for these families are recommended before re running
   `generalization` a second time.
5. **Near miss benign scenarios currently rely on few runs each**, so a
   held out generalization number for them is also noisy: broadening the
   variety of hosts and target ranges used by scenarios such as
   `ops_health_check` and `ssh_retry_storm` is recommended alongside more
   run volume.

## 14. Commands Reference for This Phase

```bash
# Dataset check
python -m detection.cli validate --entity-type host

# Train and evaluate the chosen model
python -m detection.cli train --entity-type host --model lightgbm --validate --show-split --full-metrics
python -m detection.cli evaluate --entity-type host --models lightgbm

# Compare all algorithms, ranked on the test split
python -m detection.cli compare --entity-type host --metric pr_auc --split test

# Leave one category out generalization
python -m detection.cli generalization --entity-type host --model lightgbm

# Feature importance, once the stub fix above is applied
python -m detection.cli importance --entity-type host --models lightgbm

# Replay, restricted to test split run ids only
python -m detection.cli replay --run-id <id> --entity-type host --model lightgbm --speed 5 --output experiments/logs/<name>.jsonl
```

## 15. Status

Layer 1 model selection is complete: LightGBM is the `default` variant,
selected on PR AUC on the test split, confirmed by the near miss check, and
confirmed a second time by the tool's own `compare` ranking. The phase's central finding, generalization to
unseen attack families is weak outside of `c2_beacon`, and is most likely
explained by a single dominant feature (`private_dst_ip_count`), is
documented and queued as the first task of the next phase, ahead of any
further model comparison work.