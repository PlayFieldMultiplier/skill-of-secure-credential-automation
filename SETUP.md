# Setup: Secure Credential Automation

## 5-Minute Setup

### 1. Generate Age Keypair (One-time)
```bash
age-keygen -o ~/.age-key
age-keygen -y ~/.age-key  # Save the public key
```

### 2. Add Secret to GitHub
```bash
gh secret set MY_SECRET --repo your-org/your-repo -b "$(cat ~/.secret-file)"
```

### 3. Create Encryption Workflow
Copy `.github/workflows/encrypt-secret.yml` and customize:
- Change `MY_SECRET` to your secret name
- Change `CLAUDE_PUBKEY` to your age public key
- Change artifact name

### 4. Create Rotation Script
Copy `scripts/rotate-credential.js` and customize for your use case:
- Implement `rotateCredential()` for your API/database/service
- Implement `verifyRotation()` to confirm success
- Update configuration paths and endpoints

### 5. Test Locally
```bash
node scripts/rotate-credential.js --dry-run
```

### 6. Schedule Execution

**Windows**:
```powershell
schtasks /create /tn My-Credential-Rotation `
  /tr "node.exe `"C:\path\to\script.js`"" `
  /sc monthly /d 1 /st 02:00
```

**Linux**:
```bash
0 2 1 * * /usr/bin/node /path/to/script.js
```

Done! Your credential is now encrypted, rotated, and auditable.

---

## Full Documentation

See:
- `PROTOCOL.md` — Technical deep-dive
- `examples/README.md` — Real-world examples (WordPress, database, API)
- `scripts/rotate-credential.js` — Detailed template with customization points
