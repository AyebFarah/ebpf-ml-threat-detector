# Detection pipeline report
generated: 2026-09-28T14:00:13.915542+00:00
entity type: host, model: lightgbm, variant: default
threshold: 0.790

* train: ROC AUC=0.9999708990841581, PR AUC=0.9999486395176537, precision=1.000, recall=0.952
* val: ROC AUC=0.9996168106215954, PR AUC=0.9876789876789878, precision=0.963, recall=1.000
* test: ROC AUC=0.9682114918979325, PR AUC=0.8616400825432579, precision=0.681, recall=0.917

## Latency
* 9.5125 ms per window (105 windows per second)