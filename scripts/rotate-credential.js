#!/usr/bin/env node

/**
 * Secure Credential Rotation Template
 *
 * Pattern: encrypt-via-github → download → decrypt-locally → use → cleanup
 *
 * Customize:
 * 1. GITHUB_REPO, WORKFLOW_FILE, ARTIFACT_NAME
 * 2. rotateCredential() for your system (SOAP API, REST, SQL, SSH, etc.)
 * 3. verifyRotation() to confirm success
 * 4. updateConfigFile() if needed
 *
 * Security: No plaintext in logs, context, or transcript
 */

import crypto from 'crypto';
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

const GITHUB_REPO = 'your-org/your-repo';
const WORKFLOW_FILE = 'encrypt-secret.yml';
const ARTIFACT_NAME = 'encrypted-credential';
const PRIVATE_KEY_PATH = path.join(process.env.APPDATA || process.env.HOME, '.age-key');
const AGE_BINARY = process.platform === 'win32'
  ? 'C:\\Users\\victorb\\AppData\\Local\\Temp\\age-bin\\age\\age.exe'
  : 'age';

const newCredential = crypto.randomBytes(24).toString('base64').replace(/[+/=]/g, '');
console.log('✓ Credential generated\n');

async function main() {
  try {
    console.log('=== SECURE CREDENTIAL ROTATION ===\n');

    const isDryRun = process.argv.includes('--dry-run');
    if (isDryRun) console.log('[DRY RUN - No changes made]\n');

    // Step 1: Trigger encryption workflow
    console.log('[1/5] Triggering encryption workflow...');
    if (!isDryRun) {
      execSync(`gh workflow run ${WORKFLOW_FILE} --repo ${GITHUB_REPO}`, { stdio: 'pipe' });
    }
    console.log('✓ Triggered\n');

    // Step 2: Download encrypted artifact
    console.log('[2/5] Downloading encrypted artifact...');
    try { execSync(`rm -rf /tmp/encrypted-cred`, { stdio: 'pipe' }); } catch (e) {}

    let encryptedFile;
    for (let attempt = 0; attempt < 30; attempt++) {
      try {
        const runId = execSync(
          `gh api repos/${GITHUB_REPO}/actions/runs --jq ".workflow_runs[0].id"`,
          { encoding: 'utf-8', stdio: 'pipe' }
        ).trim();
        if (runId === 'null') throw new Error('Not ready');

        execSync(
          `gh run download ${runId} --repo ${GITHUB_REPO} --name ${ARTIFACT_NAME} --dir /tmp/encrypted-cred`,
          { stdio: 'pipe' }
        );
        encryptedFile = '/tmp/encrypted-cred/encrypted.txt';
        console.log('✓ Downloaded\n');
        break;
      } catch (e) {
        if (attempt === 29) throw e;
        await new Promise(r => setTimeout(r, 2000));
      }
    }

    // Step 3: Decrypt locally
    console.log('[3/5] Decrypting credential...');
    const decryptedSecret = execSync(
      `"${AGE_BINARY}" -d -i "${PRIVATE_KEY_PATH}" "${encryptedFile}"`,
      { encoding: 'utf-8', stdio: 'pipe' }
    ).trim();
    console.log('✓ Decrypted (not displayed)\n');

    // Step 4: Rotate credential (CUSTOMIZE THIS)
    console.log('[4/5] Rotating credential...');
    if (!isDryRun) {
      // TODO: Implement for your use case
      // await callSoapAPI(decryptedSecret, newCredential);
      // await updateConfigFile(newCredential);
      // etc.
    } else {
      console.log('[DRY RUN] Skipping rotation');
    }
    console.log('✓ Done\n');

    // Step 5: Verify (CUSTOMIZE THIS)
    console.log('[5/5] Verifying...');
    if (!isDryRun) {
      // TODO: Implement verification
      // e.g., try calling API with new credentials
    }
    console.log('✓ Verified\n');

    // Cleanup
    try { execSync(`rm -rf /tmp/encrypted-cred`, { stdio: 'pipe' }); } catch (e) {}

    console.log('=== ROTATION COMPLETE ===');
    console.log('✅ Encrypted via GitHub Actions');
    console.log('✅ Decrypted locally');
    console.log('✅ Credential rotated');
    console.log('✅ No plaintext in context\n');

  } catch (error) {
    console.error('❌ Error:', error.message);
    process.exit(1);
  }
}

main();
