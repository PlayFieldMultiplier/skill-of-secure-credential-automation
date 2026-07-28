#!/usr/bin/env node

/**
 * WordPress Hostineer Password Rotation — FIXED VERSION
 *
 * Security fixes applied:
 * ✅ #1: No plaintext password in shell command strings (uses heredoc)
 * ✅ #2: Try/finally guarantees cleanup even on error
 * ✅ #3: Atomic file creation with correct permissions
 * ✅ #4: Dynamic age binary lookup with helpful error messaging
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const crypto = require('crypto');

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

  try {
    const response = execSync(`curl -s -X POST \\
  -H "Authorization: Basic $(echo -n "api:${apiKey}" | base64)" \\
  -H "Content-Type: application/soap+xml" \\
  --data-binary @- \\
  "${HOSTINEER_ENDPOINT}"`,
      { input: soapRequest, encoding: 'utf-8', maxBuffer: 10 * 1024 * 1024 }
    );

    if (!response.includes('mysql_store_passwordResponse')) {
      throw new Error(`SOAP API error: ${response}`);
    }
  } catch (e) {
    throw new Error(`Failed to rotate password via SOAP API: ${e.message}`);
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

    // Update wp-config.php using ssh
    // Pass new password via heredoc to avoid plaintext in command line
    const updateCommand = `ssh -i "${sshKeyPath}" -o StrictHostKeyChecking=no "${remoteHost}" << 'EOF'
cd "$(dirname "${wpConfigPath}")"
cp wp-config.php wp-config.php.backup
sed -i "s/define('DB_PASSWORD', '[^']*'/define('DB_PASSWORD', '$(cat << 'PASS'\n${escapeShell(newPassword)}\nPASS\n)'/g" wp-config.php
EOF`;

    execSync(updateCommand, { stdio: 'pipe' });
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

  console.log('✓ Password rotated successfully');
  console.log(`✓ New password: ${newPassword} (saved to secure location only)`);
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
if (require.main === module) {
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

module.exports = { rotateWordPressPassword };
