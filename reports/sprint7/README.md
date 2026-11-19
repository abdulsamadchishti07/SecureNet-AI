# Sprint 7/8 live verification evidence

Implementation and isolated 3-vector strict acceptance (`exit 0`, `status: ok`) passed.

- [Verification record](verification.json): 474 default tests passed (one opt-in
  skip), ten browser workflows passed, installed model hashes verified separately.
- [Live lab report](multi_attack_lab.json): all three vectors mitigated with
  real kernel TCP/ICMP drops and exact-ID unblock recovery: `PORTSCAN` (**0.605420s**,
  ML model), `BRUTE_FORCE` (**1.015394s**, `rule:auth_burst`), and `DOS`
  (**3.480821s**, `rule:service_flood`). Raw ML `event.label` predictions are
  preserved without label substitution. Watchdog, DB reconciliation and SIGTERM
  recovery passed.
- Notifications: actual SMTP and webhook exchanges used disposable loopback
  receivers. External delivery remains unconfigured and unverified. Flood limits,
  failures, queue bounds and action eligibility have regression coverage.
- [Defense dossier](../../docs/FYP_DEFENSE.md), [slides](../../docs/FYP_SLIDES.md)
  and [figure hashes](../../docs/assets/fyp/manifest.json).

The JSON records include source hashes. The default lab output is overwritten
on rerun; use `--output runtime/new-run.json` to preserve this evidence.
Regenerate presentation figures only after choosing the report to present.
Historical metrics, installed models, private credentials and the main DB were
preserved. These results do not establish real-world attack recall or a latency SLA.
