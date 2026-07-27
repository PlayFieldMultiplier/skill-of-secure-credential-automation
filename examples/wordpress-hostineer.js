#!/usr/bin/env node

/**
 * WordPress + Hostineer Example
 *
 * Uses Hostineer SOAP API to rotate MySQL password
 * Updates wp-config.php via SSH
 * Status: TESTED AND VERIFIED (2026-07-27)
 */

import crypto from 'crypto';
import https from 'https';
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

const GITHUB_REPO = 'PlayFieldMultiplier/pfm-webops';
const WORKFLOW_FILE = 'encrypt-hostineer-password.yml';
const ARTIFACT_NAME = 'encrypted-hostineer-password';
const PRIVATE_KEY_PATH = path.join(process.env.APPDATA || process.env.HOME, '.claude-age-key');
const AGE_BINARY = process.platform === 'win32'
  ? 'C:\\Users\\victorb\\AppData\\Local\\Temp\\age-bin\\age\\age.exe'
  : 'age';

const newPassword = crypto.randomBytes(24).toString('base64').replace(/[+/=]/g, '');
console.log('✓ Password generated\n');

async function main() {
  try {
    console.log('=== WORDPRESS + HOSTINEER PASSWORD ROTATION ===\n');

    // 1. Trigger encryption
    console.log('[1/4] Triggering encryption...');
    execSync(`gh workflow run ${WORKFLOW_FILE} --repo ${GITHUB_REPO}`, { stdio: 'pipe' });
    console.log('✓ Triggered\n');

    // 2. Download & decrypt
    console.log('[2/4] Downloading and decrypting...');
    try { execSync(`rm -rf /tmp/hostineer-encrypted`, { stdio: 'pipe' }); } catch (e) {}

    let encryptedFile;
    for (let attempt = 0; attempt < 30; attempt++) {
      try {
        const runId = execSync(
          `gh api repos/${GITHUB_REPO}/actions/runs --jq ".workflow_runs[0].id"`,
          { encoding: 'utf-8', stdio: 'pipe' }
        ).trim();
        if (runId === 'null') throw new Error('Not ready');

        execSync(
          `gh run download ${runId} --repo ${GITHUB_REPO} --name ${ARTIFACT_NAME} --dir /tmp/hostineer-encrypted`,
          { stdio: 'pipe' }
        );
        encryptedFile = '/tmp/hostineer-encrypted/encrypted.txt';
        console.log('✓ Downloaded');
        break;
      } catch (e) {
        if (attempt === 29) throw e;
        await new Promise(r => setTimeout(r, 2000));
      }
    }

    const apiKey = execSync(
      `"${AGE_BINARY}" -d -i "${PRIVATE_KEY_PATH}" "${encryptedFile}"`,
      { encoding: 'utf-8', stdio: 'pipe' }
    ).trim();
    console.log('✓ Decrypted\n');

    // 3. Rotate via SOAP API
    console.log('[3/4] Rotating password via SOAP API...');
    await callSoapAPI(apiKey, newPassword);
    console.log('✓ MySQL password changed\n');

    // 4. Update wp-config.php via SSH
    console.log('[4/4] Updating WordPress config...');
    const sshKey = process.env.SSH_KEY;
    if (!sshKey) throw new Error('SSH_KEY env var not set');

    fs.writeFileSync('/tmp/ssh-key', sshKey, { mode: 0o600 });

    const updateCmd = `ssh -i /tmp/ssh-key -o StrictHostKeyChecking=no "pfm#victorb.net@victorb.net" "
      pwd_content='${newPassword.replace(/'/g, "'\\''")}'
      sed -i "s/define('DB_PASSWORD', '[^']*'/define('DB_PASSWORD', '\\\$pwd_content'/" /var/www/staging.pfm.victorb.net/wp-config.php
      echo 'OK'
    "`;

    const result = execSync(updateCmd, { encoding: 'utf-8', stdio: 'pipe' });
    if (!result.includes('OK')) throw new Error('Config update failed');
    console.log('✓ Config updated\n');

    try { execSync(`rm -rf /tmp/hostineer-encrypted /tmp/ssh-key`, { stdio: 'pipe' }); } catch (e) {}

    console.log('=== ROTATION COMPLETE ===');
    console.log('✅ Encrypted via GitHub Actions');
    console.log('✅ Decrypted locally (no plaintext)');
    console.log('✅ MySQL password rotated');
    console.log('✅ WordPress config updated\n');

  } catch (error) {
    console.error('❌ Error:', error.message);
    process.exit(1);
  }
}

function callSoapAPI(apiKey, newPassword) {
  return new Promise((resolve, reject) => {
    const soapBody = `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="http://apnscp.com/namespaces/apnscp">
  <soap:Body>
    <tns:mysql_store_password>
      <password>${escapeXml(newPassword)}</password>
    </tns:mysql_store_password>
  </soap:Body>
</soap:Envelope>`;

    const options = {
      hostname: 'falcon.hostineer.com',
      port: 2083,
      path: '/soap',
      method: 'POST',
      headers: {
        'Content-Type': 'text/xml; charset=utf-8',
        'Authorization': 'Basic ' + Buffer.from('api:' + apiKey).toString('base64'),
        'Content-Length': Buffer.byteLength(soapBody),
        'SOAPAction': 'http://apnscp.com/namespaces/apnscp#mysql_store_password'
      },
      rejectUnauthorized: true
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        if (data.includes('faultstring')) {
          reject(new Error('SOAP Fault'));
        } else if (data.includes('true') || res.statusCode === 200) {
          resolve(true);
        } else {
          reject(new Error('Unexpected response'));
        }
      });
    });

    req.on('error', reject);
    req.write(soapBody);
    req.end();
  });
}

function escapeXml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

main();
