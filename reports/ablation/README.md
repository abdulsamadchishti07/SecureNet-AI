# Port sensitivity experiment

Paired RF/XGBoost runs use identical sampled training rows and full frozen validation/test sets.
Transforms and class weights use training rows only. No serving artifacts are replaced.

| Condition | Model | Features | Test macro F1 | Test benign FPR |
| --- | --- | ---: | ---: | ---: |
| full | random_forest | 20 | 98.698811% | 0.164314% |
| full | xgboost | 20 | 99.187736% | 0.076300% |
| no_source_port | random_forest | 19 | 98.939774% | 0.168747% |
| no_source_port | xgboost | 19 | 99.432345% | 0.126323% |
| no_ports | random_forest | 18 | 96.818318% | 0.310266% |
| no_ports | xgboost | 18 | 97.055299% | 0.251695% |

These previously inspected partitions share endpoints/campaigns. This exploratory comparison
does not establish independent generalization, original-capture parity, or response readiness.
Full metrics, per-class results, provenance, transforms and deltas: [port_ablation.json](port_ablation.json).
Exact sampled training row IDs are in training_sample.json. No fitted experimental models are saved.
