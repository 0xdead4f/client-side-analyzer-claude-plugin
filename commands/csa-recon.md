---
name: csa-recon
description: "Run only Phase 1 (Recon). Usage: /csa-recon [target-directory]. Produces entry-point.md, endpoint.md, feature-flag.md."
---

# Client-Side Analysis — Recon Only

Run only Phase 1. Useful for inspecting recon output before committing to solvers.

1. Create `./security-review/` if needed.
2. Spawn all 3 recon subagents in parallel:
   - **source-identifier** → `./security-review/entry-point.md`
   - **route-scanner** → `./security-review/endpoint.md`
   - **feature-flag-hunter** → `./security-review/feature-flag.md`
3. Wait for ALL to complete (since we're not proceeding to Phase 2, no rush).
4. Print summary: number of entry points, endpoints, and feature flags found.
5. Suggest `/csa-solve` to proceed to Phase 2.
