# skill-of/secure-credential-automation

**Abstract pattern for secure credential rotation across any organization, any secret, any infrastructure.**

## Problem

Secrets (API keys, database passwords, tokens) need to be:
- Rotated on schedule
- Never exposed to logs, context, or transcripts
- Auditable (full chain of who changed what)
- Usable from local IP contexts (avoiding cloud IP whitelisting issues)
- Reusable across agent swarm

## Solution: Age-Encrypted Credentials

This skill teaches the pattern:
1. **GitHub encrypts** the secret using age (asymmetric public-key cryptography)
2. **Local agent downloads** the encrypted artifact
3. **Local agent decrypts** with private key (never exposed to cloud)
4. **Local agent uses** the decrypted secret from a whitelisted IP
5. **Local agent cleans up** encrypted artifacts

**Result**: Full audit trail, zero plaintext exposure.

## Use Cases

- Database password rotation (PostgreSQL, MySQL, etc.)
- API key rotation (Hostineer, AWS, etc.)
- OAuth token refresh
- SSH key rotation
- Certificate renewal
- Any credential that needs secure, scheduled updates

## Quick Start

1. **Fork or adapt** the workflow templates in `.github/workflows/`
2. **Customize** the rotation script in `scripts/rotate-credential.js`
3. **Add your secret** to GitHub Secrets
4. **Set up Windows Scheduled Task** (or cron on Linux)
5. **Run locally** from a whitelisted IP

See `SETUP.md` for detailed step-by-step instructions.

## Key Files

- `.github/workflows/encrypt-secret.yml` — Parameterizable GitHub Actions workflow that encrypts secrets
- `scripts/rotate-credential.js` — Node.js template for credential rotation (SOAP API, REST, SQL, SSH, etc.)
- `examples/` — Real-world implementations
- `SETUP.md` — Complete setup guide

## Security Guarantees

- ✅ No plaintext in GitHub Actions logs (only ciphertext visible)
- ✅ No plaintext in Claude context/transcript (secret decrypted locally)
- ✅ No plaintext in command-line history (decryption happens in Node.js memory)
- ✅ No plaintext in configuration files (updated via SSH/API, not stored locally)
- ✅ Full audit trail (GitHub logs + API provider logs)

## For Agents

Reference this skill whenever you need to:
- Use a credential from GitHub Secrets
- Rotate a credential securely
- Handle a secret without exposing it to context

The pattern is:
```
encrypt-via-github → download-encrypted → decrypt-locally → use-from-whitelist → cleanup
```

## Examples

**WordPress database password** (`examples/wordpress-hostineer-FIXED.js`)
- Uses Hostineer/apnscp's real `?authkey=` SOAP auth (not `Authorization: Basic` —
  see `SKILL-OF/hostineer-api-authentication` for why that matters)
- Rotates the actual MySQL server-side user password via `mysql_edit_user`,
  run through `beacon` (auto-installed if missing, no SSH required for this
  step) — not `mysql_store_password`, which only rewrites a local cached
  credential and never touches the database
- Updates wp-config.php via SSH
- `dbUser`/`dbHost` are required arguments with no default — the real
  current value for a given account lives in that org's own ops repo
  (e.g. `pfm-webops/HOSTINEER.md` for PlayFieldMultiplier), never guessed
  or hardcoded here
- Exports `rotateMysqlPasswordViaBeacon` separately for callers (like a
  CI workflow) that already hold the API key as plaintext and don't need
  the age-artifact indirection `rotateWordPressPassword` uses

There was previously a second, older `examples/wordpress-hostineer.js` with
neither of the two fixes above, despite a "TESTED AND VERIFIED" comment
claiming otherwise, and a hardcoded path under one specific human's Windows
profile. Removed 2026-08-01 — `wordpress-hostineer-FIXED.js` is now the
only WordPress/Hostineer example in this repo, and there is no untested or
partially-fixed sibling left to accidentally pick instead.

## A note on "tested and production-ready" claims in this repo's history

An earlier version of this README claimed all examples were tested and
production-ready. That claim was false for the WordPress example at the
time it was written — real bugs (wrong auth mechanism, wrong SOAP method,
wrong hash-argument syntax, a placeholder database username presented as
real) were found and fixed on 2026-08-01, some of them only after being
merged and referenced elsewhere as "the fixed version." Don't repeat that
claim here again without it being true at the moment you write it — a
confident status claim that isn't backed by an actual end-to-end run
against production is worse than no claim at all, since it's what stops
the next reader from checking.

## License

ISC License - See LICENSE file

## For the Agent Swarm

This is a credential-management pattern under active correction as real
gaps are found — not a finished, self-certifying artifact. Read the actual
code and its own inline history before trusting a claim in this file about
what's verified.
