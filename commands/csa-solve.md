---
name: csa-solve
description: "Run Phase 2 (Creative Solvers) + Phase 3 (Validation). Requires entry-point.md from prior /csa-recon. Usage: /csa-solve"
---

# Client-Side Analysis — Solve + Validate

Requires `./security-review/entry-point.md` to exist (from a prior `/csa-recon` run).

1. Read `./security-review/entry-point.md`. Parse every row.
2. For EACH entry point, spawn one **creative-solver** subagent (see /csa command for full solver prompt).
3. After all solvers complete, invoke **validation-gate** to classify findings.
4. Print summary of validated results.
5. Suggest `/csa-report` to generate the final report.
