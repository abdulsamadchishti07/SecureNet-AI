# Sprint 7 evidence — November 18, 2026

Implementation verification passed; live multi-vector detection acceptance remains open.

- [Verification record](verification.json): 471 default tests passed (one opt-in
  skip), ten browser workflows passed, installed model hashes verified separately.
- [Live lab report](multi_attack_lab.json): PORTSCAN blocked, TCP/ICMP drops and
  exact-ID unblock verified; observed mitigation confirmation **1.710407s**.
  BRUTE_FORCE and DOS were missed within their eight-second windows. Strict mode
  exited **2**, as intended for detection gaps. Watchdog, DB reconciliation and
  SIGTERM recovery passed.
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
