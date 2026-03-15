---
name: csa
description: "Run full client-side analysis pipeline. Usage: /csa [target-directory-or-url]. Recon → per-source solving → validation → report."
---

# Client-Side Analysis — Full Pipeline

You are orchestrating a multi-phase client-side security analysis for bug bounty.

## Pre-flight

1. Identify the target:
   - A directory path containing JavaScript source files (already cloned/downloaded)
   - A URL (fetch the page, extract all `<script src>` references, fetch each JS file, save to a working dir)
2. Create `./security-review/` directory if it doesn't exist.
3. Verify JS files are accessible. List them. If minified, note it — the agents can still work with minified code but accuracy drops.

## Phase 1 — Recon

Spawn ALL 3 subagents in parallel:

### Critical path (blocks Phase 2):
- **source-identifier** → `./security-review/entry-point.md`
  - "Scan all JS files in [target]. For every controllable entry point, output one row: source type, parameter/listener name, file:line, the immediate function it enters, and the nearest sink it flows toward. Table format. No explanations. No code blocks unless the flow is non-obvious (max 3 lines of code per entry). This is a checklist — each row will spawn its own solver."

### Intel lane (async, does NOT block Phase 2):
- **route-scanner** → `./security-review/endpoint.md`
- **feature-flag-hunter** → `./security-review/feature-flag.md`

**CRITICAL**: The moment `source-identifier` completes, proceed to Phase 2 immediately. Do NOT wait for the intel lane agents. Their files are supplementary — solvers read them if available, skip if not.

## Phase 2 — Creative Solvers

Read `./security-review/entry-point.md`. Parse the checklist. For EACH row (each individual source), spawn one **creative-solver** subagent:

- "You are testing ONE specific source:
  Source: [source-type] — [param/listener name]
  Location: [file:line]  
  Flows toward: [nearest sink]
  
  Supplementary intel (read if files exist, skip if not):
  - ./security-review/endpoint.md (known routes/API endpoints)
  - ./security-review/feature-flag.md (hidden features)
  
  Your job: Can this source reach a dangerous sink and be weaponized? Try creatively. Load vuln-class skills as needed when you hit specific patterns or obstacles.
  
  Output:
  - Validated exploitable bug → APPEND to ./security-review/finding.md using the finding template
  - Chainable primitive (not exploitable alone but useful in chains) → APPEND to ./security-review/gadget.md using the gadget template
  - Nothing useful → do not write anything, just return 'NO_FINDING' to the orchestrator"

Each solver runs independently. They all write to the same finding.md and gadget.md (append-only).

## Phase 3 — Validation Gate

After ALL solvers complete, invoke the **validation-gate** agent:

- "Read ./security-review/finding.md and ./security-review/gadget.md.
  For each finding: Is this actually exploitable in a real bug bounty context? Does it have real user impact?
  For gadgets: Can any combination of gadgets chain into something exploitable?
  
  Classify every item:
  - EXPLOITABLE: Real vuln, real impact, worth submitting. Assign severity (Critical/High/Medium/Low).
  - INFORMATIVE: Real behavior but no meaningful impact (log injection, telemetry manipulation, etc). Keep for completeness.
  - GADGET INVENTORY: Standalone primitives. Note which other gadgets they could chain with.
  - DISCARD: False positive or unreachable in practice. Remove from report.
  
  Write validated results to ./security-review/validated-finding.md"

## Phase 4 — Report

Invoke **report-generator**:
- "Read all files in ./security-review/. Generate ./security-review/REPORT.md. Structure: executive summary, exploitable findings (ranked by severity with full reproduction steps), informative findings, gadget inventory, and methodology notes."

## Output to User

Present:
- Count of exploitable findings by severity
- Count of informative findings  
- Count of gadgets in inventory
- Path to REPORT.md
