# Validity review and revised priorities

Reviewed: 2026-11-07 (Asia/Karachi), following the user's methodological critique.

**Current scores are preliminary connection-held-out, within-capture results.
They do not demonstrate campaign-independent detection or deployment readiness.**
Correcting pre-split SMOTE/scaler leakage was necessary, but it did not resolve
correlation between attack flows. This review overrides any optimistic reading
of the earlier headline results or implementation-completion notes.

## Confirmed split weakness

The split key includes both endpoint ports. This keeps one bidirectional
connection together, but ephemeral source ports separate many flows from the same
attacking host/tool run. A stronger audit joined retained raw row IDs to source
IP endpoints and counted unordered endpoint pairs across partitions:

| Family | Retained rows | Five-tuple groups | Endpoint pairs | Pairs shared across partitions |
| --- | ---: | ---: | ---: | ---: |
| Tuesday FTP | 3,984 | 3,973 | 1 | 1 |
| Tuesday SSH | 2,988 | 2,979 | 1 | 1 |
| Wednesday GoldenEye | 7,647 | 7,574 | 1 | 1 |
| Wednesday Hulk | 159,049 | 14,108 | 1 | 1 |
| Wednesday Slowhttptest | 5,108 | 4,215 | 1 | 1 |
| Wednesday Slowloris | 5,679 | 3,869 | 1 | 1 |
| Thursday web brute force | 1,365 | 1,363 | 1 | 1 |
| Thursday XSS | 673 | 673 | 1 | 1 |

Every retained row in these families belongs to a pair represented on both sides
of the split. This confirms missing endpoint independence. It does not, by itself,
prove how much of a score comes from memorization or establish exact campaign IDs.
Thursday PORTSCAN also shares all 12 of its endpoint pairs across partitions.
See [machine-readable findings](../../reports/validity_review/findings.json).

Simply removing source port from the split key is not a complete solution. These
families have only one observed endpoint pair each, so a pair-disjoint split cannot
retain that same family's examples in training, validation and test. Independent
campaign/host data or a narrower evaluation question is required. Do not silently
fall back to row splitting when a meaningful split lacks class coverage.

`Src Port` remains an input feature. No source-port ablation has been run. The
effect size is unknown. Plan paired full-feature, drop-source-port and drop-both-
ports ablations on frozen, defensible partitions; an ablation on the old split is
only an internal shortcut diagnostic, not evidence of campaign generalization.

## Deployment architecture and Monday exposure

The four per-day classifiers are experimental baselines. Day is not an observable
attack property, and the current sniffer's `--predict` only uses Friday. No four-
model ensemble was deployed. A live design needs one justified target taxonomy
and serving policy, with joint cross-day duplicate/campaign handling.

Running a hypothetical OR ensemble on Monday's existing common cohort flags
3,357 unique rows out of 189,279 (1.7736%). Individual counts are 57 Friday,
3,154 Thursday, 147 Wednesday, zero Tuesday; summed events are 3,358 because one
row is flagged by more than one model. This measurement assumes the source BENIGN
labels and the previously documented restricted cohort. Alerts/minute additionally
depend on flow rate, aggregation and suppression; a network-independent volume
claim is unsupported. These counts do not establish attack recall or a winner.

## Label semantics, web scope and provenance

The 2022 reprocessing authors describe Attempted labels as intended attack traffic
that may lack malicious behavior, and recommend a benign mapping when uncertain.
Our unconditional merge into attack families was not justified for a detector
whose verdict is interpreted as malicious activity. Resolve exact release and
target semantics before further tuning. See the authors'
[dataset guidance](https://intrusion-detection.distrinet-research.be/CNS2022/Dataset_Download.html).

The labels, Attempted Category and additional fields are consistent with a
reprocessed CICIDS2017 family. This is an inference, not a checksum-verified
identification of the local release. The 2022 authors also document PCAP repairs,
label rules, and extractor changes; source ports appear in some labelling rules.
See [their dataset documentation](https://intrusion-detection.distrinet-research.be/CNS2022/CICIDS2017.html)
and [extractor changes](https://intrusion-detection.distrinet-research.be/CNS2022/Tools_Documentation.html).

Flow statistics omit HTTP payload semantics. Current evidence does not support
robust XSS versus web brute-force claims, but does not prove all flow-level web
detection impossible. Suspend subtype claims. Coarse WEB_ATTACK is a possible
experiment after label review; collapsing classes alone cannot repair missing
information or nonmalicious Attempted targets. Exclude unsupported web coverage
from deployment if independent evidence cannot support it.

## Extraction and runtime defects

- Matching columns and formula checks do not establish feature parity. The
  extractor intentionally emits torn-down TCP flows after a five-second grace,
  drops single-packet/nonpositive-duration flows and has other reference departures.
- No PCAP/PCAPNG files were found in the workspace or `aaa.zip`. No original-
  capture replay was performed. Identify the matching capture/release, repairs,
  labels and extractor commit before claiming CSV reproduction. Original
  unrepaired captures may not reproduce a repaired/regenerated release.
- A negative predictor input raises ValueError; the sniffer callback has no
  per-flow inference error boundary. Invalid flows should be counted/flagged and
  skipped without accepting corrupt values or silently masking model failures.
  The present extractor derives its IAT mean from positive duration, so a negative
  IAT from that path was not demonstrated; the uncaught invalid-input path exists.
- Prediction label decoding is per row and should be vectorized. No throughput
  benchmark of that overhead has been performed.
- `joblib.load` is pickle-based and runs before metadata validation. Pickle
  artifacts require a trusted source; a checksum stored in an attacker-replaceable
  file or inside the pickle is not an authentication boundary. Review protected
  manifests/signatures, format migration and separation of capture privileges from
  inference. See [scikit-learn persistence guidance](https://scikit-learn.org/stable/model_persistence.html).

## Revised work order

1. Mark current scientific and serving claims provisional; freeze existing
   results as evidence. No more headline-score optimization on these test sets.
2. Establish data provenance, label semantics and independent campaign availability.
   Define a unified detector's supported targets and evaluation question.
3. Obtain matching PCAPs and run a differential replay against the pinned reference
   exporter. Match flows, compare feature values/tolerances and quantify unmatched
   records. Synthetic packet tests remain regression checks, not parity proof.
4. Design campaign/host-separated evaluation with honest class-coverage limits;
   collect independent lab campaigns where the dataset cannot support that design.
5. Run port ablations and bounded web-scope experiments under that design, then
   train a unified candidate with untouched independent evaluation data.
6. Before live trials, isolate per-flow errors, vectorize inference, secure model
   artifacts and define one serving/alert policy. Runtime hardening can proceed
   independently while captures are being obtained.
7. Quarantine legacy leaky root artifacts with checksums; replace obsolete SMOTE
   instructions; consolidate Friday-specific compatibility paths. Preserve data
   and historical evidence rather than deleting or rewriting the old results.

Only inspection, endpoint-overlap/ensemble measurements and documentation were
performed during this review. Source-port ablations, label changes, differential
replay, retraining, runtime fixes and artifact migration are not completed work.
