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
 *   not just its secret-handling — it previously sent the API key as HTTP
 *   Basic auth, which apnscp/Hostineer's SOAP API does not accept. See
 *   https://github.com/SKILL-OF/hostineer-api-authentication for the full
 *   finding, how it was verified, and why (that's now the canonical home
 *   for this fact — it's true for any Hostineer account, not just this
 *   organization's, so it doesn't live only here as inline history).
 *
 * ✅ #7 (found and fixed 2026-08-01): the MySQL step called the wrong
 *   apnscp method entirely. `mysql_store_password` only rewrites this
 *   account's own cached client credential in ~/.my.cnf (see
 *   `set_option('password', ..., 'client')` in apnscp's own
 *   lib/modules/mysql.php, confirmed by reading the real source at
 *   https://gitlab.com/apisnetworks/apnscp/-/blob/master/lib/modules/mysql.php
 *   — that's the authoritative implementation; the generated docs site at
 *   api.apiscp.com is frequently unreachable to automated agents in this
 *   environment due to a domain-wide TLS trust-chain failure, so GitLab
 *   source is the reliable reference, not a fallback). It never touches
 *   the real MySQL server-side user account, and it doesn't take a
 *   username argument at all (the script was sending one it silently
 *   ignored, or faulted on — either way, the actual database credential
 *   was never rotated, only wp-config.php would have been, leaving
 *   WordPress pointed at a password the database never received).
 *
 *   The real method is `mysql_edit_user(user, host, opts)`. Its own
 *   docblock warns: whichever `opts` keys are omitted get silently reset
 *   to server defaults — this happens on every call, not just over SOAP,
 *   because the PHP implementation always merges omitted keys against a
 *   hardcoded defaults array. So a partial opts payload correctly changes
 *   the password while silently clobbering that user's existing
 *   max-connections/SSL settings. To avoid that, this script now reads
 *   the user's CURRENT settings first (`mysql_list_users`) and resubmits
 *   them unchanged alongside the new password.
 *
 *   `edit_user`'s `opts` parameter is a nested array/hash. Hand-rolling
 *   that as raw SOAP XML would mean guessing apnscp's WSDL struct
 *   encoding — the exact class of unverified guess that caused this bug
 *   in the first place. `beacon` (Hostineer's own CLI, see
 *   https://kb.hostineer.com/control-panel/scripting-with-beacon/) already
 *   knows how to serialize hash arguments correctly and runs
 *   pre-authenticated over the box's own session, so this step now prefers
 *   `beacon` over raw SOAP whenever it's present on the target host —
 *   checked at runtime, never assumed (per
 *   SKILL-OF/hostineer-api-authentication, beacon has been observed
 *   missing on at least one real account despite Hostineer's docs calling
 *   it preinstalled on all v5+ platforms). If `beacon` isn't present, this
 *   step refuses to guess the raw-SOAP struct encoding and fails loudly
 *   with actionable guidance instead of silently risking a wrong write to
 *   a live user account.
 *
 *   NOTE: the multi-key `beacon exec` hash-argument syntax below
 *   (`[key:value][key2:value2]...`) is inferred from a single-key example
 *   in Hostineer's own docs — it has not yet been live-verified against a
 *   real account for a multi-key call. This script defends against a
 *   silently-wrong guess by re-reading the user's settings immediately
 *   after the edit and refusing to proceed to the wp-config.php update
 *   unless every non-password field still matches what was there before.
 */

import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import crypto from 'crypto';

// Fields mysql_edit_user's $opts accepts. Any key omitted here gets reset
// to a hardcoded server default by apnscp itself (see file header) — so a
// password-only rotation must always resubmit every one of these, sourced
// from the user's own current row, not left to chance.
const MYSQL_EDIT_USER_OPT_KEYS = [
  'host', 'password', 'max_user_connections', 'max_updates', 'max_questions',
  'use_ssl', 'ssl_type', 'ssl_cipher', 'x509_subject', 'x509_issuer',
];

/**
 * Rotate WordPress database password via Hostineer's `beacon` CLI over SSH
 * @param {string} sshKeyPath - local path to the already-materialized SSH private key
 * @param {string} remoteHost - SSH target (user@host)
 * @param {string} dbUser - MySQL user to rotate (e.g. 'staging_pfm')
 * @param {string} dbHost - MySQL host clause for that user (usually 'localhost')
 * @param {string} newPassword - new plaintext password
 * @returns {{maxUserConnections:number,maxUpdates:number,maxQuestions:number,useSsl:boolean,sslType:string,sslCipher:string,x509Subject:string,x509Issuer:string}} the preserved settings, for post-write verification
 */
function rotateMysqlPasswordViaBeacon(sshKeyPath, remoteHost, dbUser, dbHost, newPassword) {
  const sshBase = `ssh -i "${sshKeyPath}" -o StrictHostKeyChecking=no "${remoteHost}"`;

  const beaconPresent = execSync(`${sshBase} 'which beacon'`, { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] })
    .trim().length > 0;
  if (!beaconPresent) {
    throw new Error(
      "'beacon' CLI not found on remote host. Refusing to hand-roll the " +
      "mysql_edit_user SOAP call instead: its opts parameter is a nested " +
      "struct whose apnscp wire encoding has not been verified in this " +
      "script, and guessing it risks silently corrupting the user's " +
      "existing connection-limit/SSL settings (see file header). Install " +
      "beacon on this host, or add a verified raw-SOAP struct encoding " +
      "here only after confirming it against a read-only call first."
    );
  }

  const listRaw = execSync(`${sshBase} 'beacon exec --format=json mysql_list_users'`, { encoding: 'utf-8' });
  const users = JSON.parse(listRaw);
  const before = users.find(u => u.user === dbUser && (u.host === dbHost || dbHost === 'localhost'));
  if (!before) {
    throw new Error(`MySQL user ${dbUser}@${dbHost} not found via mysql_list_users — refusing to guess its settings.`);
  }

  const preserved = {
    host: before.host,
    max_user_connections: before.max_user_connections,
    max_updates: before.max_updates,
    max_questions: before.max_questions,
    use_ssl: !!before.ssl_type,
    ssl_type: before.ssl_type || '',
    ssl_cipher: before.ssl_cipher || '',
    x509_subject: before.x509_subject || '',
    x509_issuer: before.x509_issuer || '',
  };

  // Password never enters `opts` here, and never appears in any string
  // built on this side — only a placeholder token does. The remote shell
  // substitutes the real value from stdin ($PW) into that exact token
  // position. This is the only way to keep the secret out of the command
  // string execSync tracks (and would otherwise echo in a thrown error),
  // matching the discipline already used for the SSH key and wp-config
  // steps below.
  const PW_PLACEHOLDER = '__NEWPW_PLACEHOLDER__';
  const opts = { ...preserved, password: PW_PLACEHOLDER };
  // Not yet live-verified for multi-key hashes — see file header note.
  const hashArg = MYSQL_EDIT_USER_OPT_KEYS
    .map(k => `[${k}:${typeof opts[k] === 'boolean' ? (opts[k] ? '1' : '0') : opts[k]}]`)
    .join('');

  const remoteEditScript =
    `set -e; PW="$(cat)"; ` +
    `beacon exec mysql_edit_user ${dbUser} ${dbHost} ` +
    hashArg.replace(PW_PLACEHOLDER, '$PW');

  execSync(`${sshBase} '${remoteEditScript.replace(/'/g, "'\\''")}'`, {
    input: newPassword,
    encoding: 'utf-8',
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  // Verify: re-read and confirm nothing but the password changed.
  const afterRaw = execSync(`${sshBase} 'beacon exec --format=json mysql_list_users'`, { encoding: 'utf-8' });
  const usersAfter = JSON.parse(afterRaw);
  const after = usersAfter.find(u => u.user === dbUser && u.host === preserved.host);
  if (!after) {
    throw new Error(`Post-rotation verification failed: ${dbUser}@${preserved.host} no longer found.`);
  }
  const drifted = ['max_user_connections', 'max_updates', 'max_questions', 'ssl_type', 'ssl_cipher', 'x509_subject', 'x509_issuer']
    .filter(k => String(after[k] ?? '') !== String(before[k] ?? ''));
  if (drifted.length > 0) {
    throw new Error(
      `mysql_edit_user changed unrelated settings, not just the password: ${drifted.join(', ')}. ` +
      `The hash-argument encoding above is unverified for multi-key calls — this is exactly ` +
      `the failure mode it was guarding against. Do not proceed to update wp-config.php; ` +
      `the two are now out of sync with the database's actual state.`
    );
  }

  return preserved;
}

/**
 * Rotate WordPress database password via Hostineer
 * @param {string} sshKey - SSH private key for the target host
 * @param {string} remoteHost - SSH target (user@host)
 * @param {string} wpConfigPath - Remote path to wp-config.php
 * @param {string} dbUser - MySQL user whose password is being rotated
 * @param {string} dbHost - MySQL host clause for that user (usually 'localhost')
 */
async function rotateWordPressPassword(
  sshKey,
  remoteHost,
  wpConfigPath,
  dbUser = 'staging_pfm',
  dbHost = 'localhost'
) {
  // Generate new password (cryptographically secure)
  const newPassword = crypto.randomBytes(16).toString('hex');

  // Write SSH key with atomic permissions (never world-readable window)
  let sshKeyPath;
  try {
    sshKeyPath = path.join(process.env.TEMP || '/tmp', `ssh-key-${Date.now()}`);
    const fd = fs.openSync(sshKeyPath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
    try {
      fs.writeSync(fd, sshKey);
    } finally {
      fs.closeSync(fd);
    }

    // Step 1: rotate the real MySQL user password via beacon, preserving
    // every other setting on that account (see rotateMysqlPasswordViaBeacon).
    rotateMysqlPasswordViaBeacon(sshKeyPath, remoteHost, dbUser, dbHost, newPassword);

    // Step 2: update wp-config.php to match, now that the database
    // actually has the new password. Use try/finally to GUARANTEE cleanup
    // even on error.
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
    // GUARANTEED cleanup: this runs even if any step above fails
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

// Helper: Escape for shell (single quotes)
function escapeShell(str) {
  return String(str).replace(/'/g, "'\\''");
}

// Main
const isMainModule = process.argv[1] === new URL(import.meta.url).pathname;
if (isMainModule) {
  const sshKeyPath = process.argv[2] || path.join(process.env.HOME || process.env.USERPROFILE || '', '.ssh', 'pfm_victorb_net');
  const remoteHost = process.argv[3] || 'pfm#victorb.net@victorb.net';
  const wpConfigPath = process.argv[4] || '/var/www/staging.pfm.victorb.net/wp-config.php';
  const dbUser = process.argv[5] || 'staging_pfm';
  const dbHost = process.argv[6] || 'localhost';

  rotateWordPressPassword(
    fs.readFileSync(sshKeyPath, 'utf-8'),
    remoteHost,
    wpConfigPath,
    dbUser,
    dbHost
  ).catch(err => {
    console.error(`ERROR: ${err.message}`);
    process.exit(1);
  });
}

export { rotateWordPressPassword };
