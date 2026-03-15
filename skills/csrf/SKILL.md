---
name: csrf
description: "Client-side CSRF patterns, including CSPT2CSRF. Load when a solver finds state-changing requests that may lack proper token validation, or when CSPT source is identified and state-changing sinks exist."
---

# Client-Side CSRF Skill

## Traditional CSRF indicators
- `fetch()` / `XMLHttpRequest` making POST/PUT/DELETE/PATCH without CSRF token header
- `credentials: 'include'` or `withCredentials: true` — cookies sent cross-origin
- CSRF token from predictable location (meta tag, cookie) without per-request validation
- CORS misconfiguration: `Access-Control-Allow-Origin: *` with credentials

## What's NOT CSRF
- GET requests (unless they cause state change — rare)
- Requests with non-simple Content-Type (`application/json`) without CORS allowing it — preflight blocks
- Bearer token auth from localStorage — not auto-sent by browser
- Requests with custom headers (X-Requested-With) — preflight blocks unless CORS allows

## CSPT2CSRF — the modern CSRF resurrection (Doyensec research)

Traditional CSRF is "dead" on modern apps with SameSite cookies and CSRF tokens. But CSPT2CSRF resurrects it because the rerouted request comes from the same origin — SameSite cookies are included, and the frontend automatically attaches CSRF tokens.

### How it works
1. Find a CSPT source (user input in fetch path)
2. The frontend constructs an API call with the CSPT-ed path
3. Frontend attaches auth cookies + CSRF tokens automatically (it thinks it's a legitimate request)
4. The traversed path hits a state-changing endpoint instead of the intended one
5. Server processes the request as legitimate because tokens are correct

### CVE examples
- **CVE-2023-45316**: CSPT2CSRF POST sink in Mattermost
  - Source: `/<team>/channels/channelname?telem_action=controlled&telem_run_id=../../../../../../api/v4/caches/invalidate`
- **CVE-2023-6458**: CSPT2CSRF GET sink in Mattermost
- **CVE-2023-5123**: CSPT2CSRF in Grafana JSON API plugin

### Constraints of CSPT2CSRF
- Cannot change HTTP method (bound to source's method)
- Cannot change headers (frontend sets them)
- Cannot always control body (bound to source's body structure)
- Host is fixed (same-origin)
- Need to match sink's expected parameters

### Chaining GET + POST sinks
If only a GET CSPT source exists but target has POST state-changing endpoints:
1. Find GET CSPT → reroute to file upload/download feature
2. Upload JSON with manipulated fields
3. GET CSPT fetches attacker's uploaded JSON
4. Frontend processes the JSON, triggers another request with attacker's data
5. Second request hits POST state-changing endpoint

## PoC approach

### Standard CSRF PoC (no CSPT)
```html
<form method="POST" action="https://target.com/api/settings">
  <input name="email" value="attacker@evil.com">
  <input type="submit">
</form>
<script>document.forms[0].submit();</script>
```

### JSON body trick
For endpoints accepting `application/json`, try `text/plain` Content-Type with JSON body — many servers parse JSON regardless of Content-Type:
```html
<form method="POST" action="https://target.com/api/settings" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","x":"' value='"}'>
</form>
```

## Bug bounty severity
| Action | Severity |
|--------|----------|
| Password/email change | **High** |
| Account deletion | **High** |
| Admin action (role change, user management) | **Critical** |
| Profile update | **Medium** |
| Settings change (non-security) | **Low** |
| Theme/language change | **Informative** |

Reduce by one level if: requires user to be in specific state, requires multiple clicks, or requires uncommon browser configuration.

## Key references
- Doyensec CSPT2CSRF whitepaper: https://www.doyensec.com/resources/Doyensec_CSPT2CSRF_Whitepaper.pdf
- Doyensec blog: https://blog.doyensec.com/2024/07/02/cspt2csrf.html
- OWASP Client-Side CSRF: https://owasp.org/www-community/attacks/csrf
