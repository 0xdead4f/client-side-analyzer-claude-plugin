---
name: csa-report
description: "Run Phase 4 (Reporting). Requires validated-finding.md from prior /csa-solve. Usage: /csa-report"
---

# Client-Side Analysis — Report Only

Requires `./security-review/validated-finding.md` to exist.

1. Invoke **report-generator** agent on all `./security-review/` files.
2. Output `./security-review/REPORT.md`.
3. Print finding counts and severity breakdown.
