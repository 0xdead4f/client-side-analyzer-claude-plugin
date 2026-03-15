---
name: cspt
description: "Client-Side Path Traversal detection and exploitation (CSPT2CSRF, CSPT2XSS). Load when a solver finds user input reflected in the path portion of fetch/XHR URLs, REST-style API calls with user-controlled slugs, or SPA route parameters used in API requests."
---

# Client-Side Path Traversal (CSPT) Skill

Emerging vuln class. PortSwigger Top 10 2025 nomination. First publicized by Philippe Harewood on Facebook's bug bounty. Systematized by Doyensec (Maxence Schmitt) at OWASP AppSec Lisbon 2024.

## What is CSPT

User input injected into the **path** of a client-side HTTP request (fetch/XHR), allowing `../` traversal to hit unintended API endpoints. Unlike server-side path traversal (file access), CSPT reroutes API requests — the browser sends cookies and auth headers automatically.

## Why it matters for bug bounty
- Resurrects CSRF on modern apps with anti-CSRF tokens (CSPT2CSRF)
- Can chain to XSS if the rerouted endpoint returns HTML-injectable content
- Bypasses SameSite cookie protections (request originates from same site)
- Works on modern single-page applications with REST APIs

## Source identification

### URL parameters in API paths
```javascript
// VULNERABLE: user input in fetch path
fetch(`/api/articles/${articleId}/metadata`)
// If articleId = "../users/admin" → fetch("/api/users/admin/metadata")
```

### Framework route params
- React Router: `useParams()` value used in subsequent API call
- Vue Router: `$route.params.id` in fetch URL
- Angular: `ActivatedRoute.params` in HTTP client call

### Types of CSPT sources (from Doyensec whitepaper)
- **DOM-based**: URL param, hash, postMessage → directly into fetch path
- **Reflected**: Server reflects user input into page JS that constructs fetch URL
- **Stored**: Database value (e.g., username, file name) used in API path

## Sink identification

A sink is any API endpoint reachable via the CSPT that performs a useful action.

### CSPT2CSRF sinks
The rerouted request hits a state-changing endpoint. The frontend adds auth tokens automatically.
- `DELETE /api/users/{id}` → account deletion
- `POST /api/settings` → settings change
- `PATCH /api/users/me` → profile modification

### CSPT2XSS sinks
The rerouted response is rendered as HTML.
- API endpoint returns user-controlled JSON that gets `.innerHTML`'d
- File download endpoint returns attacker-uploaded content
- Error messages reflected into DOM

### Key CVEs
- **CVE-2023-45316**: CSPT2CSRF with POST sink in Mattermost
- **CVE-2023-6458**: CSPT2CSRF with GET sink in Mattermost
- **CVE-2023-5123**: CSPT2CSRF in Grafana JSON API plugin

## Exploitation techniques

### Basic traversal
```
articleId = ../../../api/admin/deleteUser?id=victim
```
Resulting fetch: `/api/articles/../../../api/admin/deleteUser?id=victim/metadata`
Normalized: `/api/admin/deleteUser?id=victim/metadata`

### Suffix handling
The path often has a suffix appended (e.g., `/metadata`). Bypass:
- `?` to start query string: `../target?` → suffix becomes query param
- `#` to start fragment: `../target#` → suffix becomes fragment (not sent to server)
- URL encoding: `%3F` for `?`, `%23` for `#`

### Encoding bypass for WAFs (Doyensec research)
Different encoding functions handle `/` and `.` differently:
- `encodeURI()`: does NOT encode `/` — traversal works directly
- `encodeURIComponent()`: DOES encode `/` — need double encoding `%252F`
- None of them encode `.` — `..` always passes

### Chaining CSPT with file upload (Doyensec Mattermost exploit)
1. Upload a JSON file with manipulated content to the target app
2. Use CSPT GET sink to fetch the uploaded file instead of the intended API
3. The frontend processes the attacker's JSON as if it came from the real API
4. If the JSON has an `id` field used in a subsequent state-changing request → CSPT2CSRF chain

### Chaining CSPT with Open Redirect
If target has an open redirect: `/redirect?url=https://evil.com`
CSPT payload: `../redirect?url=https://evil.com`
The fetch follows the redirect → attacker controls the full response.

## Bug bounty severity context
- CSPT2CSRF on account deletion / password change: **High**
- CSPT2CSRF on settings modification: **Medium**
- CSPT2XSS via response rendering: **High** (if stored/no interaction)
- CSPT source only (no exploitable sink found): **Informative** — still document as gadget

## Detection approach for this plugin
When source-identifier finds user input in a fetch/XHR path:
1. Check if `../` sequences are possible (encoding, sanitization)
2. Map all API endpoints from route-scanner output
3. For each endpoint: is it reachable via traversal from the CSPT source?
4. Match HTTP method + body constraints of the source with potential sinks
5. Check if file upload exists (enables response forgery)

## Key references
- Doyensec CSPT2CSRF whitepaper: https://www.doyensec.com/resources/Doyensec_CSPT2CSRF_Whitepaper.pdf
- Doyensec blog: https://blog.doyensec.com/2024/07/02/cspt2csrf.html
- Doyensec CSPT resources collection: https://blog.doyensec.com/2025/03/27/cspt-resources.html
- Doyensec file upload bypass: "Bypassing File Upload Restrictions To Exploit CSPT" (Jan 2025)
- PortSwigger Burp extension: https://portswigger.net/bappstore/eefe20568a894635b500ad13fdc8a683
- PayloadsAllTheThings: https://swisskyrepo.github.io/PayloadsAllTheThings/Client%20Side%20Path%20Traversal/
- Renwa bug bounty writeups (Opera, Reverb): https://medium.com/@renwa/client-side-path-traversal-cspt-bug-bounty-reports-and-techniques-8ee6cd2e7ca1
- Jorian Woltjer practical guide: https://book.jorianwoltjer.com/web/client-side/client-side-path-traversal-cspt
