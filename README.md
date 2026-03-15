# client-side-analysis

Client-side vulnerability analysis plugin for bug bounty hunting. Multi-agent pipeline that finds, tests, validates, and reports client-side bugs in JavaScript applications.

## Architecture

```
/csa [target]
  │
  ├── source-identifier (CRITICAL PATH — blocks Phase 2)
  │     └── entry-point.md (flat checklist: one row per controllable source)
  │
  ├── route-scanner (ASYNC INTEL — does not block)
  │     └── endpoint.md
  │
  └── feature-flag-hunter (ASYNC INTEL — does not block)
        └── feature-flag.md

  ↓ fires immediately when source-identifier completes

  creative-solver × N (one per entry point row)
  │  ├── loads vuln-class skills on demand (xss, proto-pollution, etc.)
  │  ├── finding.md (append-only)
  │  └── gadget.md (append-only)

  ↓ after all solvers complete

  validation-gate (opus model)
  │  ├── Exploitable → severity-ranked
  │  ├── Informative → log injection, telemetry, self-XSS
  │  ├── Gadget inventory → chain potential noted
  │  └── Discarded → false positives removed

  ↓

  report-generator → REPORT.md
```

## Commands

| Command | What it does |
|---------|-------------|
| `/csa [target]` | Full pipeline: recon → solve → validate → report |
| `/csa-recon [target]` | Recon only — produces entry-point.md, endpoint.md, feature-flag.md |
| `/csa-solve` | Solve + validate only — requires prior `/csa-recon` |
| `/csa-report` | Report only — requires prior `/csa-solve` |

## Agents

| Agent | Role | Model | Blocking? |
|-------|------|-------|-----------|
| source-identifier | Find all controllable entry points | sonnet | Yes — critical path |
| route-scanner | Extract routes and API endpoints | sonnet | No — async intel |
| feature-flag-hunter | Find hidden features and activation methods | sonnet | No — async intel |
| creative-solver | Test one source for exploitability | sonnet | N/A — spawned per source |
| validation-gate | Verify findings against bug bounty standards | opus | Yes — quality gate |
| report-generator | Produce final REPORT.md | sonnet | Yes — final step |

## Skills (loaded on demand by solvers)

| Skill | Trigger |
|-------|---------|
| xss | innerHTML, document.write, eval, jQuery.html() |
| prototype-pollution | deep merge, Object.assign, recursive copy |
| open-redirect | location.assign, window.open, href assignment |
| csrf | state-changing fetch/XHR without CSRF tokens |
| postmessage-abuse | addEventListener('message') handlers |
| dom-clobbering | document.X / window.X named access |
| css-injection | dynamic style assignment, style tag injection |
| cspt | user input in fetch/XHR path, REST slug injection |

## Output files

All output goes to `./security-review/`:

| File | Written by | Purpose |
|------|-----------|---------|
| entry-point.md | source-identifier | Flat checklist of all sources |
| endpoint.md | route-scanner | Routes and API endpoints |
| feature-flag.md | feature-flag-hunter | Hidden features and gates |
| finding.md | creative-solvers | Raw findings (append-only) |
| gadget.md | creative-solvers | Chainable primitives (append-only) |
| validated-finding.md | validation-gate | Classified and verified results |
| REPORT.md | report-generator | Final bug bounty report |

## Installation

```
/plugin install client-side-analysis
```

Or manually:
```
cp -r client-side-analysis/ .claude/plugins/
```

## Token management

- **Source-identifier**: Compact table output only. No code blocks unless flow is ambiguous (max 3 lines). This keeps Phase 1 output small.
- **Intel agents**: Table format, deduplicated. Their output is supplementary — solvers read it if available.
- **Solvers**: Each runs in its own context window. Output is append-only to shared files. `NO_FINDING` return for dead ends (zero token waste on the output file).
- **Validation gate**: Runs on opus for quality. This is where reasoning budget matters most.
- **Report generator**: Reads all files, produces structured markdown. Runs on sonnet — the hard thinking is already done.
