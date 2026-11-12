# Capture-time replay and response sensitivity

Implemented 2026-11-12 (Asia/Karachi). These tools provide experimental evidence;
independent calibration and enforcement readiness remain open.

`observed_at` remains event creation time in UTC. Extracted flows additionally carry
integer `flow_start_usec`, `flow_end_usec` and `flow_emitted_usec` epoch microseconds.
They become `capture_start`, `capture_time` and `capture_available_at` on detection
events. Model input remains exactly the original 20 features. The API validates
optional capture timestamps and their ordering, persists them in the existing
payload JSON, and returns them in HTTP/WebSocket alerts. Existing rows and legacy
delivery fingerprints retain their previous interpretation; no migration is needed.
Missing capture metadata stays absent, rather than being invented from observation
time. A lone externally supplied capture time is accepted as metadata, but replay
policy evaluation requires all three timestamps.

The policy's default `monotonic` mode uses consumer processing time as before.
Select event time only for offline response replay:

```bash
.venv/bin/python -m sniffer.main -r runtime/response_demo_offline.pcap \
  --predict --respond --clock-mode event_time \
  --alert-log runtime/my-capture-replay.jsonl
```

Event-time windows use **feature availability**, `capture_available_at`, so a flow
cannot contribute evidence before it is finalized. Replacement SYNs, timeouts and
TCP grace expiration carry the timestamp that triggered emission. EOF flush uses
the highest timestamp seen in the capture, including excluded packets. EOF can
finalize incomplete flows earlier than a continuing live capture would; it is not
a simulated wait for the normal timeout. Grace sweeps still occur at packet/tick
boundaries, so sparse captures can delay finalization beyond the configured grace.

Availability must never move backward. The policy permits equal timestamps and
rejects earlier arrivals with `late_capture_event`, without adding evidence.
BENIGN, low-score and unsupported-class events advance the watermark and expire
old evidence too. An exact window boundary is inclusive. Events missing complete
capture metadata produce `capture_time_unavailable` and cannot become candidates.
Packet reordering is counted; the extractor retains its existing first-packet
orientation and flow-start semantics rather than repairing historical captures.

The runtime firewall simulator deliberately keeps processing-monotonic lifetimes.
Fast replay of a long capture does not accelerate its 900-second lifetime. Audit
records identify both clocks. Use policy sensitivity results for evidence-window
analysis; runtime `already_simulated` suppression is a different measurement.
No host firewall commands execute.

Run the sensitivity analysis on an audit file:

```bash
.venv/bin/python -m sniffer.calibration --events runtime/my-capture-replay.jsonl \
  --confidence 0.9 0.99 --min-flows 2 3 4 --window 10 60 \
  --output reports/response/my-calibration.json
```

Output refuses to overwrite reports. Events are evaluated in their original
arrival order. Lifecycle records are skipped; duplicate detection IDs and incomplete
capture metadata are rejected. Results include decision counts, repeated candidate
events, first candidate sources, late arrivals, missing candidate sources and
delay from the first attack-labelled flow start to the first candidate after that
onset. Candidates before onset are counted separately and cannot hide a missed
attack source. This is policy eligibility, without firewall state or execution.

Without `--truth`, attack labels come from model predictions. They are not ground
truth: false-block rate, true recall and calibration quality cannot be inferred.
`--truth labels.json` accepts a complete JSON mapping of event UUIDs to the seven
labels. Its provenance must be established separately. Per-event truth enables
benign-triggered candidate counts; a source-level false-block probability still
requires labelled source/time exposure intervals. Earliest captured attack-flow
time may be later than the actual attack onset.

Current defaults remain score >=0.90, three source/model/class flows within 60
seconds. Scores are not calibrated correctness probabilities. WEB_ATTACK and
historical scopes remain alert-only. Neither sensitivity curves nor correlated
flows justify enabling prevention.

A defensible next calibration run needs independently labelled benign exposure
and separate attack campaigns, recorded capture/exporter provenance, a separate
calibration cohort, and a frozen policy evaluated once on held-out lab traffic.
Measure false proposals, missed attack sources, alert volume, packet/extractor
exclusions and latency including flow finalization. Bound false alarms using the
actual observed benign exposure rather than the current three-flow demo.

See [Sprint 4](SPRINT_4.md), [the execution plan](SPRINT_3_TO_5_PLAN.md) and
[the validity review](<ML Engine/VALIDITY_REVIEW.md>).
