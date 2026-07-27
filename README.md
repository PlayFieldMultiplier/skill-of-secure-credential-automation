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
- `examples/` — Real-world implementations (WordPress, generic DB, API endpoints)
- `SETUP.md` — Complete setup guide
- `PROTOCOL.md` — Technical protocol details

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

**WordPress database password** (`examples/wordpress-rotation.js`)
- Encrypts Hostineer API key via GitHub
- Calls SOAP API to rotate MySQL password
- Updates wp-config.php via SSH
- Runs on 90-day schedule

**Generic database password** (`examples/generic-db-rotation.js`)
- Works with PostgreSQL, MySQL, MariaDB
- Connects directly to database
- Executes ALTER USER password command
- Updates config file

**API key rotation** (`examples/api-key-rotation.js`)
- Generic pattern for any REST API
- Submits old key for revocation
- Creates new key
- Updates application config

## Testing

All examples have been tested and are production-ready. See `examples/README.md` for verification status.

## License

ISC License - See LICENSE file

## For the Agent Swarm

This is a verified, auditable pattern for credential management. All agents should reference this skill when handling secrets.
