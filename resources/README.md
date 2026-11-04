# resources/ — demo resources

External sources we collected to say "this isn't made up, it's documented" during the judge demo.
All of them overlap with our active target (**Zyxel EX3301-T0 / gateway 192.168.153.1**).

| File | Topic | Role in the demo |
|---|---|---|
| [zyxel-cve-2023-28770-lfi-serial-derive.md](zyxel-cve-2023-28770-lfi-serial-derive.md) | Unauth LFI → serial number → supervisor password derivation → SSH RCE | **Main attack chain** (the "deterministic" way to get into SSH) |
| [zyxel-client-side-pw-complexity-bypass.md](zyxel-client-side-pw-complexity-bypass.md) | Browser-side bypass of the WiFi password complexity check on the EX3301 | Didactic example of "client-side validation ≠ security" |

## Why these sources matter (demo narrative)
1. **The EX3301-T0 is our device** — the zarino write-up targets the exact same model (Hyperoptic EX3301).
2. The CVE-2023-28770 chain shows a **non-brute-force** way to get into SSH: we prove the
   determinism of the vulnerability ("we didn't crack it, we computed it"). This is the derive
   branch of the `weaknd` creds module.
3. Users on forums asking Zyxel staff to "generate the password from the serial number" → social
   proof that the algorithm really exists (confirms the CVE).

Related internal notes: memory `cpe-root-password-pattern`, `odido-zyxel-lifemote-case-study`.
