# Campaign-Disjoint Lab Ablation

Zero shared endpoint pairs verified across train (14), calibration (14), and evaluation (14).

| Condition | Model | Features | Eval Macro F1 | Eval Benign FPR |
| --- | --- | ---: | ---: | ---: |
| full | random_forest | 20 | 100.0000% | 0.0000% |
| full | xgboost | 20 | 100.0000% | 0.0000% |
| no_source_port | random_forest | 19 | 100.0000% | 0.0000% |
| no_source_port | xgboost | 19 | 100.0000% | 0.0000% |
| no_ports | random_forest | 18 | 100.0000% | 0.0000% |
| no_ports | xgboost | 18 | 100.0000% | 0.0000% |
