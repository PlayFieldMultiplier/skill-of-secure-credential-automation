#!/usr/bin/env node

/**
 * WordPress Hostineer Password Rotation — FIXED VERSION
 *
 * Security fixes applied:
 * ✅ #1: Password never appears in a shell command string. It travels only
 *   through execSync's `input` option (stdin), which Node does not include
 *   in thrown-error messages — unlike a heredoc embedded in the command
 *   text itself, which still leaks on failure. The remote script text
 *   (fixed, no secret material) is the only thing passed as a command arg.
 * ✅ #2: Try/finally guarantees cleanup even on error
 * ✅ #3: Atomic file creation with correct permissions
 * ✅ #4: Dynamic age binary lookup with helpful error messaging
 * ✅ #5: API key never appears in a shell command string. The secret enters
 *   only a curl config file (guaranteed-cleanup temp file, same pattern as
 *   the SSH key below) that only curl itself reads, referenced by path only.
 *
 * ✅ #6 (found and fixed 2026-08-01): this file's auth mechanism was wrong,
 *   not just its secret-handling. It previously sent the API key as HTTP
 *   Basic auth (`Authorization: Basic base64("api:" + apiKey)`) — that is
 *   NOT how apnscp/Hostineer's SOAP API authenticates. Confirmed by reading
 *   the vendor's own reference client (`apisnetworks/Beacon/Client.php`):
 *   the real mechanism is an `?authkey=<key>` query parameter appended to
 *   the endpoint URL. Verified live and current (2026-08-01) via
 *   PlayFieldMultiplier/pfm-webops's own `.github/workflows/test-api-key.yml`,
 *   which calls the real endpoint with this mechanism and gets a clean
 *   response — Basic auth gets a 401 no matter how fresh/valid the key is.
 *   Fixed here the same way as the header used to be handled: the key goes
 *   into the curl config file's `url =` directive (never the command-line
 *   string execSync tracks), not a header, since there is no header for
 *   this API — the query-string *is* the auth.
 */

import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import crypto from 'crypto';

// Find age binary dynamically instead of hardcoding path
function findAgeBinary() {
  const possiblePaths = [
    'age', // First try PATH
    path.join(process.env.APPDATA || '', '..', 'Local', 'Temp', 'age-bin', 'age', 'age.exe'),
    path.join(process.env.APPDATA || '', '..', 'Local', 'Temp', 'age-bin', 'age'), // Unix-style on Windows git-bash
    path.join(process.env.ProgramFiles || '', 'age', 'age.exe'),
  ];

  for (const binPath of possiblePaths) {
    try {
      execSync(`"${binPath}" --version`, { stdio: 'pipe' });
      return binPath;
    } catch (e) {
      // Try next path
    }
  }

  throw new Error(
    `Cannot find 'age' binary. Tried: ${possiblePaths.join(', ')}. ` +
    `Install age or set it in PATH.`
  );
}

const AGE_BINARY = findAgeBinary();
const HOSTINEER_ENDPOINT = 'https://falcon.hostineer.com:2083/soap';

/**
 * Rotate WordPress database password via Hostineer SOAP API
 * @param {string} encryptedArtifactPath - Path to age-encrypted artifact from GitHub
 * @param {string} privateKeyPath - Path to age private key
 * @param {string} sshKey - SSH private key for wp-config.php access
 * @param {string} remoteHost - SSH target (user@host)
 * @param {string} wpConfigPath - Remote path to wp-config.php
 */
async function rotateWordPressPassword(
  encryptedArtifactPath,
  privateKeyPath,
  sshKey,
  remoteHost,
  wpConfigPath
) {
  // Generate new password (cryptographically secure)
  const newPassword = crypto.randomBytes(16).toString('hex');

  // Decrypt API key from artifact
  let apiKey;
  try {
    const encryptedData = fs.readFileSync(encryptedArtifactPath);
    const decrypted = execSync(
      `"${AGE_BINARY}" --decrypt -i "${privateKeyPath}"`,
      { input: encryptedData, encoding: 'utf-8' }
    );
    apiKey = decrypted.trim();
  } catch (e) {
    throw new Error(`Failed to decrypt API key: ${e.message}`);
  }

  // Step 1: Call Hostineer SOAP API to rotate password
  // Uses heredoc to pass password safely, never plaintext in command line
  const soapRequest = `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <mysql_store_password>
      <username>staging_pfm</username>
      <password>${escapeXml(newPassword)}</password>
    </mysql_store_password>
  </soap:Body>
</soap:Envelope>`;

  // apnscp/Hostineer's real auth is `?authkey=<key>` on the URL, not a
  // header — so the URL itself (with the key embedded) goes into the curl
  // config file's `url =` directive, never the command line. This mirrors
  // the SSH-key temp-file pattern below: curl reads its target from
  // -K/--config, the SOAP body still comes via stdin (--data-binary @-),
  // and the secret never becomes part of the string execSync tracks as
  // "the command".
  let curlConfigPath;
  try {
    const endpointWithAuth = `${HOSTINEER_ENDPOINT}?authkey=${encodeURIComponent(apiKey)}`;
    curlConfigPath = path.join(process.env.TEMP || '/tmp', `curl-cfg-${Date.now()}`);
    const fd = fs.openSync(curlConfigPath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
    try {
      fs.writeSync(fd,
        `url = "${endpointWithAuth}"\n` +
        `header = "Content-Type: application/soap+xml"\n`
      );
    } finally {
      fs.closeSync(fd);
    }

    let response;
    try {
      response = execSync(
        `curl -s -X POST -K "${curlConfigPath}" --data-binary @-`,
        { input: soapRequest, encoding: 'utf-8', maxBuffer: 10 * 1024 * 1024 }
      );
    } catch (e) {
      // Deliberately not including e.message here: curl's own stderr on a
      // network/HTTP failure could echo request context, and the config
      // file path (safe) is the only thing in the command itself — but
      // staying conservative costs nothing and this is exactly the class
      // of bug this whole fix is about.
      throw new Error('Failed to rotate password via SOAP API (curl invocation failed)');
    }

    if (!response.includes('mysql_store_passwordResponse')) {
      throw new Error('SOAP API returned an unexpected response (body withheld from error to avoid leaking anything it may have echoed back)');
    }
  } finally {
    if (curlConfigPath) {
      try {
        fs.unlinkSync(curlConfigPath);
      } catch (e) {
        console.error(`Warning: Failed to delete curl config at ${curlConfigPath}: ${e.message}`);
      }
    }
  }

  // Step 2: Update wp-config.php via SSH
  // Use try/finally to GUARANTEE cleanup even on error
  let sshKeyPath;
  try {
    // Write SSH key with atomic permissions (never world-readable window)
    sshKeyPath = path.join(process.env.TEMP || '/tmp', `ssh-key-${Date.now()}`);

    // Create with correct permissions from the start (atomic operation)
    const fd = fs.openSync(sshKeyPath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
    try {
      fs.writeSync(fd, sshKey);
    } finally {
      fs.closeSync(fd);
    }

    // Update wp-config.php using ssh. The remote script below contains no
    // secret material — it's a fixed argument string, safe to interpolate.
    // The password itself never appears in it: the remote side reads it
    // from its own stdin (`NEWPW="$(cat)"`), which ssh forwards from this
    // process's stdin. Node's execSync only ever captures the `command`
    // string in a thrown error, never the `input` buffer — so even on SSH
    // failure, the plaintext password is not present in any error/log.
    const remoteScript =
      `set -e; cd "$(dirname "${wpConfigPath}")"; ` +
      `cp wp-config.php wp-config.php.backup; ` +
      `NEWPW="$(cat)"; ` +
      `sed -i "s/define('DB_PASSWORD', '[^']*')/define('DB_PASSWORD', '$NEWPW')/" wp-config.php`;

    const updateCommand =
      `ssh -i "${sshKeyPath}" -o StrictHostKeyChecking=no "${remoteHost}" ` +
      `'${escapeShell(remoteScript)}'`;

    execSync(updateCommand, { input: newPassword, encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] });
  } finally {
    // GUARANTEED cleanup: this runs even if ssh fails
    if (sshKeyPath) {
      try {
        fs.unlinkSync(sshKeyPath);
      } catch (e) {
        console.error(`Warning: Failed to delete SSH key at ${sshKeyPath}: ${e.message}`);
      }
    }
  }

  // Step 3: Verify WordPress is online
  try {
    const response = execSync('curl -s -o /dev/null -w "%{http_code}" https://staging-pfm.victorb.net/', { encoding: 'utf-8' });
    if (response.trim() !== '200') {
      throw new Error(`WordPress returned HTTP ${response}, expected 200`);
    }
  } catch (e) {
    throw new Error(`Failed to verify WordPress: ${e.message}`);
  }

  // Never log the plaintext password — the caller gets it via the return
  // value only, in-memory, and decides what to do with it from there.
  console.log('✓ Password rotated successfully');
  return { success: true, password: newPassword };
}

// Helper: Escape XML special characters
function escapeXml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

// Helper: Escape for shell (single quotes)
function escapeShell(str) {
  return String(str).replace(/'/g, "'\\''");
}

// Main
const isMainModule = process.argv[1] === new URL(import.meta.url).pathname;
if (isMainModule) {
  const encryptedPath = process.argv[2] || './encrypted-hostineer-password';
  const keyPath = process.argv[3] || path.join(process.env.APPDATA || '', '.claude-age-key');
  const sshKeyPath = process.argv[4] || path.join(process.env.HOME || process.env.USERPROFILE || '', '.ssh', 'pfm_victorb_net');
  const remoteHost = process.argv[5] || 'pfm#victorb.net@victorb.net';
  const wpConfigPath = process.argv[6] || '/var/www/staging.pfm.victorb.net/wp-config.php';

  rotateWordPressPassword(
    encryptedPath,
    keyPath,
    fs.readFileSync(sshKeyPath, 'utf-8'),
    remoteHost,
    wpConfigPath
  ).catch(err => {
    console.error(`ERROR: ${err.message}`);
    process.exit(1);
  });
}

export { rotateWordPressPassword };
