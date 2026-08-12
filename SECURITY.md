# Security Policy

RISKX is a security tool; its own security posture is treated as a critical asset (spec §25).

## Reporting a Vulnerability

- **Do not** open a public issue for security vulnerabilities.
- Email: security@risks-research-placeholder.invalid *(will be replaced once a real
  security contact is established; currently the project is in research phase)*.

If a real security contact address is not yet available, file a vulnerability via the
GitHub "Report a vulnerability" flow: <https://github.com/RajaMuhammadAwais/RISKX/security>.

## Scope of This Policy

| In scope                                  | Out of scope (for now)         |
| ----------------------------------------- | ------------------------------ |
| The `riskx` CLI and bundled engines       | Third-party vulnerability feeds themselves (report to NVD/CISA/OSV) |
| Configuration parsing, storage, output    | Test labs and intentionally vulnerable fixtures |
| Plugins loaded from the `plugins/` dir    | Unvetted external plugins      |
| Documentation about RISKX's own behavior  | Other RajaMuhammadAwais repos  |

## What We Commit To

1. Triage within 5 business days where feasible.
2. No retaliation against good-faith researchers.
3. Published fix + CVE acknowledgment when the vulnerability is confirmed and fixed.
4. All vulnerability data sources (NVD, CISA KEV, OSV, EPSS) are external; issues in
   those feeds should be reported to the respective organizations directly.

## Safe Use of RISKX

- RISKX operates in **PASSIVE mode by default** (§8). No active validation occurs
  without an explicit `--mode` flag and a confirmation prompt.
- Never run RISKX (or any RISKX active/validation command) against systems you do not
  own or have explicit written authorization to assess.
- Findings are **evidence-based observations**, not confirmed exploitation.
