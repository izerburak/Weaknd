# Zyxel EX3301: client-side bypass of the WiFi password complexity check

**Source:** Zarino Zappia, 25 January 2025 — https://zarino.co.uk/post/bypass-password-complexity-zyxel/
**Original method:** a user called "Hello1024", on the Three broadband community forum (reposted by zarino).
**Device: Zyxel EX3301 (Hyperoptic deployment) — SAME MODEL AS OUR TARGET.**

## Problem
The admin interface enforces a minimum complexity on the WiFi password (lowercase-only diceware
passphrases, ones without digits/symbols, are rejected).

## Bypass technique (in the browser, not on the device)
1. Log into the admin UI (192.168.1.1), uncheck the "Random password" box in the WiFi settings.
2. Browser DevTools → pretty-print the loaded `app.js`.
3. Find the `checkPasswordStrenth` function, set a breakpoint on its first line.
4. Type the password you want into the form; the breakpoint pauses execution when the field loses focus.
5. In the console, manually override the value the check will accept (the `t` variable), then resume.
6. Pressing "Save" re-runs the check, so repeat the override.

## Security takeaway (the demo's didactic message)
- The complexity check **runs in the browser (JS)** → the user can change the outcome without touching the device.
- The author didn't test server-side re-validation; if there isn't any, the restriction is
  **purely cosmetic**.
- **Lesson:** client-side policy enforcement is NOT a security control. Any client-side-only
  validation (password strength, input validation, an auth gate) can be bypassed. This is a clear
  example of why attack surface mapping needs to "look behind the UI".

## Use in weaknd / the demo
- Didactic slide: "In Stage 2 we read the UI's JS, not the UI." A live mini-demo is possible
  (a `checkPasswordStrenth` breakpoint in DevTools) — since we have the EX3301, it's fully reproducible.
- Additional idea for the `weaknd` surface module: a simple scanner that pulls the mgmt page's
  JS and flags client-side-only validation patterns (checkPassword*, validate* functions).
