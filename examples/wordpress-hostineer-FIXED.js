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
 *   api.apnscp.com (and its api.apiscp.com alias) is unreachable from at
 *   least one real agent-fetch tool via a domain-wide TLS trust-chain
 *   failure, so GitLab source is the reliable reference, not a fallback).
 *   It never touches the real MySQL server-side user account, and it
 *   doesn't take a username argument at all (the script was sending one
 *   it silently ignored, or faulted on — either way, the actual database
 *   credential was never rotated, only wp-config.php would have been,
 *   leaving WordPress pointed at a password the database never received).
 *
 *   The real method is `mysql_edit_user(user, host, opts)`. Its own
 *   docblock warns: whichever `opts` keys are omitted get silently reset
 *   to server defaults — this happens on every call, not just over SOAP,
 *   because the PHP implementation always merges omitted keys against a
 *   hardcoded defaults array. So a partial opts payload correctly changes
 *   the password while silently clobbering that user's existing
 *   max-connections/SSL settings. To avoid that, this script reads the
 *   user's CURRENT settings first (`mysql_list_users`) and resubmits them
 *   unchanged alongside the new password.
 *
 * ✅ #8 (found and fixed 2026-08-01, same day as #7): the first version of
 *   this fix ran `beacon` over SSH into the target host, which assumes an
 *   SSH key for that specific account — not every agent/machine running
 *   this script has one, even though every one of them has (or can get)
 *   the Hostineer API key. That's a real regression: it should not have
 *   traded "guessing a struct encoding" for "requires a credential most
 *   callers won't have." beacon itself doesn't need SSH at all — it
 *   supports full remote operation via `--endpoint`/`--key`/`--keyfile`,
 *   authenticating with the same API key this whole file already handles
 *   (confirmed directly in apisnetworks/beacon's own README). So this now
 *   runs `beacon` locally, wherever this script executes, against the
 *   account's API key — see `findOrInstallBeacon()` and
 *   `rotateMysqlPasswordViaBeacon()`. `beacon` doesn't need to be
 *   preinstalled: it ships as a single ~10MB self-contained
 *   `beacon.phar` (bundles its own PHP deps), downloaded straight from
 *   https://github.com/apisnetworks/beacon if not already present —
 *   the only real requirement is a PHP7.4+/8.x runtime.
 *
 *   Also corrected the hash/array argument syntax for `beacon exec`: it's
 *   ONE bracket with comma-separated `key:value` pairs
 *   (`[host:x,password:y,...]`), confirmed directly against beacon's own
 *   README example (`[imap:1,smtp:1]`) — the first version of this fix
 *   guessed one bracket per key (`[host:x][password:y]...`), which was
 *   wrong. The post-write re-read/diff check below is what would have
 *   caught that wrong guess before it clobbered a live account's settings
 *   — it stays in place as a general safeguard, not because the syntax is
 *   still unverified.
 *
 *   Known limitation, not fully solved: beacon's CLI has no file/stdin
 *   channel for an arbitrary `exec` argument value (only its own API key,
 *   via `--keyfile`), so the new password is briefly present in this
 *   process's own argv for the duration of the `mysql_edit_user` call —
 *   visible to `ps` on a shared, multi-tenant machine. Only run this on a
 *   trusted, single-tenant CI runner or agent machine.
 */

import fs from 'fs';
import path from 'path';
import { execSync, execFileSync } from 'child_process';
import crypto from 'crypto';

// Fields mysql_edit_user's $opts accepts. Any key omitted here gets reset
// to a hardcoded server default by apnscp itself (see file header) — so a
// password-only rotation must always resubmit every one of these, sourced
// from the user's own current row, not left to chance.
const MYSQL_EDIT_USER_OPT_KEYS = [
  'host', 'password', 'max_user_connections', 'max_updates', 'max_questions',
  'use_ssl', 'ssl_type', 'ssl_cipher', 'x509_subject', 'x509_issuer',
];

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

const BEACON_PHAR_URL = 'https://raw.githubusercontent.com/apisnetworks/beacon/master/beacon.phar';
const BEACON_CACHE_PATH = path.join(process.env.APPDATA || process.env.HOME || '/tmp', '.cache', 'beacon', 'beacon.phar');

/**
 * Find a local `beacon` install, or fetch beacon.phar (a single self-contained
 * file, ~10MB, bundles all its own PHP deps) straight from its own GitHub
 * repo if nothing is found. This runs on whatever machine executes this
 * script — beacon supports full remote operation via --endpoint/--key (see
 * SKILL-OF/hostineer-api-authentication), so nothing here needs SSH access
 * to the Hostineer account at all.
 * @returns {string[]} the argv prefix to invoke beacon, e.g. ['php', '/path/to/beacon.phar']
 */
function findOrInstallBeacon() {
  try {
    execSync('beacon --version', { stdio: 'pipe' });
    return ['beacon'];
  } catch (e) {
    // not on PATH, fall through
  }
  if (fs.existsSync(BEACON_CACHE_PATH)) {
    return ['php', BEACON_CACHE_PATH];
  }
  fs.mkdirSync(path.dirname(BEACON_CACHE_PATH), { recursive: true });
  execSync(`curl -sL -o "${BEACON_CACHE_PATH}" "${BEACON_PHAR_URL}"`, { stdio: 'pipe' });
  const size = fs.statSync(BEACON_CACHE_PATH).size;
  if (size < 1_000_000) {
    // A real beacon.phar is ~10MB; anything much smaller is a download
    // failure (e.g. a GitHub error page), not a valid PHAR.
    fs.unlinkSync(BEACON_CACHE_PATH);
    throw new Error(`Downloaded beacon.phar looks wrong (${size} bytes) -- refusing to use it.`);
  }
  return ['php', BEACON_CACHE_PATH];
}

/**
 * Rotate WordPress database password via Hostineer's `beacon` CLI, run
 * locally against the account's API key (no SSH — see findOrInstallBeacon).
 * @param {string} apiKey - the Hostineer/apnscp API key (authkey)
 * @param {string} endpoint - the SOAP endpoint, e.g. https://falcon.hostineer.com:2083/soap
 * @param {string} dbUser - MySQL user to rotate (real current value: check pfm-webops/HOSTINEER.md)
 * @param {string} dbHost - MySQL host clause for that user (usually 'localhost')
 * @param {string} newPassword - new plaintext password
 * @returns {object} the preserved settings, for post-write verification
 */
function rotateMysqlPasswordViaBeacon(apiKey, endpoint, dbUser, dbHost, newPassword) {
  const beaconCmd = findOrInstallBeacon();

  // beacon's own --keyfile flag keeps the API key out of argv (a file
  // containing nothing but the key, per beacon's own README) -- same
  // atomic-permissions/guaranteed-cleanup discipline as the SSH key below.
  let keyfilePath;
  try {
    keyfilePath = path.join(process.env.TEMP || '/tmp', `beacon-key-${Date.now()}`);
    const fd = fs.openSync(keyfilePath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
    try {
      fs.writeSync(fd, apiKey);
    } finally {
      fs.closeSync(fd);
    }

    const base = [...beaconCmd, 'exec', `--keyfile=${keyfilePath}`, `--endpoint=${endpoint}`, '--format=json'];

    // mysql_list_users's real shape (confirmed 2026-08-01 against production
    // -- NOT a flat array of {user, host, ...} objects, which was the
    // original, wrong assumption here): a nested object keyed by username,
    // then by host, e.g. {"someuser": {"localhost": {ssl_type: "", ...}}}.
    // There is no `host` field inside the innermost object -- the host is
    // the key path itself, not a value to read back out.
    const listRaw = execFileSync(base[0], [...base.slice(1), 'mysql_list_users'], { encoding: 'utf-8' });
    const users = JSON.parse(listRaw);
    const userEntry = users[dbUser];
    const before = userEntry && userEntry[dbHost];
    if (!before) {
      throw new Error(`MySQL user ${dbUser}@${dbHost} not found via mysql_list_users — refusing to guess its settings.`);
    }

    const preserved = {
      host: dbHost,
      max_user_connections: before.max_user_connections,
      max_updates: before.max_updates,
      max_questions: before.max_questions,
      use_ssl: !!before.ssl_type,
      ssl_type: before.ssl_type || '',
      ssl_cipher: before.ssl_cipher || '',
      x509_subject: before.x509_subject || '',
      x509_issuer: before.x509_issuer || '',
    };

    // Hash/array arguments to `beacon exec` are ONE bracket with
    // comma-separated key:value pairs (confirmed directly against
    // apisnetworks/beacon's own README: `[imap:1,smtp:1]`), not one
    // bracket per key — that earlier guess was wrong and is exactly why
    // this script re-verifies unrelated fields after the write below.
    //
    // ✅ #9 (found and fixed 2026-08-01, the actual reason the site stayed
    //   down all week despite every earlier "fix"): beacon's bracket-hash
    //   parser silently drops the ENTIRE array — not just the empty key —
    //   when any value is an empty string (a bare `key:` with nothing
    //   before the next `,`/`]`). ssl_type/ssl_cipher/x509_subject/
    //   x509_issuer default to `''` on this account, so every real call
    //   this account ever made hit this: apnscp received an empty $opts,
    //   changed nothing, and still returned `true` (ALTER USER with no
    //   IDENTIFIED BY clause and unchanged limits succeeds trivially).
    //   Verified directly against production: the identical call with
    //   empty-string keys omitted actually changed both max_user_connections
    //   and the password hash; with them included, neither ever changed,
    //   across multiple fresh-password attempts. Fix: never emit a
    //   `key:` with an empty value — omit that key instead (apnscp's own
    //   defaults for these fields are already `''`, so omitting is
    //   equivalent to sending it, without tripping the parser bug).
    const opts = { ...preserved, password: newPassword };
    const hashArg = '[' + MYSQL_EDIT_USER_OPT_KEYS
      .filter(k => {
        const v = opts[k];
        return !(typeof v === 'string' && v === '');
      })
      .map(k => `${k}:${typeof opts[k] === 'boolean' ? (opts[k] ? '1' : '0') : opts[k]}`)
      .join(',') + ']';

    // NOTE ON EXPOSURE: unlike the API key (via --keyfile) and the SSH key
    // and wp-config password below (both via stdin), beacon's own CLI has
    // no file/stdin channel for an arbitrary `exec` argument value — the
    // new password must be passed as a real CLI argument here, so it is
    // briefly visible in this process's argv (e.g. to `ps` on a shared,
    // multi-tenant machine) for the duration of this one call. That is an
    // inherent limitation of beacon's CLI design, not something this
    // script can fully engineer around. Only run this on a trusted,
    // single-tenant CI runner or agent machine, not a shared box. The
    // thrown-error message below deliberately omits `e.message`/`e.output`
        // so a failure doesn't compound the exposure via logs.
    try {
      execFileSync(base[0], [...base.slice(1), 'mysql_edit_user', dbUser, dbHost, hashArg], { stdio: 'pipe' });
    } catch (e) {
      throw new Error('mysql_edit_user call failed (details withheld -- see NOTE ON EXPOSURE above for why)');
    }

    // Verify: re-read and confirm nothing but the password changed.
    const afterRaw = execFileSync(base[0], [...base.slice(1), 'mysql_list_users'], { encoding: 'utf-8' });
    const usersAfter = JSON.parse(afterRaw);
    const after = usersAfter[dbUser] && usersAfter[dbUser][preserved.host];
    if (!after) {
      throw new Error(`Post-rotation verification failed: ${dbUser}@${preserved.host} no longer found.`);
    }
    const drifted = ['max_user_connections', 'max_updates', 'max_questions', 'ssl_type', 'ssl_cipher', 'x509_subject', 'x509_issuer']
      .filter(k => String(after[k] ?? '') !== String(before[k] ?? ''));
    if (drifted.length > 0) {
      throw new Error(
        `mysql_edit_user changed unrelated settings, not just the password: ${drifted.join(', ')}. ` +
        `Do not proceed to update wp-config.php; the two are now out of sync with the database's actual state.`
      );
    }

    return preserved;
  } finally {
    if (keyfilePath) {
      try {
        fs.unlinkSync(keyfilePath);
      } catch (e) {
        console.error(`Warning: Failed to delete beacon keyfile at ${keyfilePath}: ${e.message}`);
      }
    }
  }
}

/**
 * Rotate WordPress database password via Hostineer
 * @param {string} encryptedArtifactPath - Path to age-encrypted Hostineer API key artifact from GitHub
 * @param {string} privateKeyPath - Path to age private key
 * @param {string} endpoint - Hostineer SOAP endpoint, e.g. https://falcon.hostineer.com:2083/soap
 * @param {string} sshKey - SSH private key for the target host (still needed for the wp-config.php file edit)
 * @param {string} remoteHost - SSH target (user@host)
 * @param {string} wpConfigPath - Remote path to wp-config.php
 * @param {string} dbUser - MySQL user whose password is being rotated. No default on purpose:
 *   this org's real current value lives in pfm-webops/HOSTINEER.md, which
 *   also explicitly warns not to treat it as permanent across rebuilds --
 *   a hardcoded default here would just relocate that same staleness risk
 *   (this file previously defaulted to 'staging_pfm', which was never the
 *   real value at all -- see pfm-webops/HOSTINEER.md's actual
 *   'DB user and DB name are both rgon_stagingpfmvictorbnet').
 * @param {string} dbHost - MySQL host clause for that user (usually 'localhost'). Also no default, same reason.
 */
async function rotateWordPressPassword(
  encryptedArtifactPath,
  privateKeyPath,
  endpoint,
  sshKey,
  remoteHost,
  wpConfigPath,
  dbUser,
  dbHost
) {
  if (!dbUser || !dbHost) {
    throw new Error(
      "dbUser and dbHost are required, with no default -- check pfm-webops/HOSTINEER.md " +
      "(or the equivalent instance doc for whatever site this is) for the real current " +
      "values before running this. This file previously defaulted dbUser to a " +
      "plausible-looking guess ('staging_pfm') that was never the real value at all -- " +
      "caught before it ran against production, but only by luck of it being noticed."
    );
  }

  // Generate new password (cryptographically secure)
  const newPassword = crypto.randomBytes(16).toString('hex');

  // Decrypt the Hostineer API key -- needed for the beacon-based MySQL
  // step below, which runs locally against this key and never touches SSH.
  let apiKey;
  try {
    const ageBinary = findAgeBinary();
    const encryptedData = fs.readFileSync(encryptedArtifactPath);
    const decrypted = execFileSync(
      ageBinary, ['--decrypt', '-i', privateKeyPath],
      { input: encryptedData, encoding: 'utf-8' }
    );
    apiKey = decrypted.trim();
  } catch (e) {
    throw new Error(`Failed to decrypt API key: ${e.message}`);
  }

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

    // Step 1: rotate the real MySQL user password via beacon, run locally
    // against the API key (no SSH needed for this step) -- preserving
    // every other setting on that account (see rotateMysqlPasswordViaBeacon).
    rotateMysqlPasswordViaBeacon(apiKey, endpoint, dbUser, dbHost, newPassword);

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
  const encryptedPath = process.argv[2] || './encrypted-hostineer-password';
  const keyPath = process.argv[3] || path.join(process.env.APPDATA || '', '.claude-age-key');
  const endpoint = process.argv[4] || 'https://falcon.hostineer.com:2083/soap';
  const sshKeyPath = process.argv[5] || path.join(process.env.HOME || process.env.USERPROFILE || '', '.ssh', 'pfm_victorb_net');
  const remoteHost = process.argv[6] || 'pfm#victorb.net@victorb.net';
  const wpConfigPath = process.argv[7] || '/var/www/staging.pfm.victorb.net/wp-config.php';
  // No fallback default here on purpose -- see rotateWordPressPassword's
  // own check. Pass the real current value explicitly (check
  // pfm-webops/HOSTINEER.md, or the equivalent instance doc).
  const dbUser = process.argv[8];
  const dbHost = process.argv[9] || 'localhost';

  rotateWordPressPassword(
    encryptedPath,
    keyPath,
    endpoint,
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

// rotateMysqlPasswordViaBeacon is exported separately from
// rotateWordPressPassword because not every caller has (or needs) the
// age-encrypted-artifact indirection: a GitHub Actions workflow already
// holds the API key as plaintext in its own `secrets.*` context and would
// gain nothing from an unnecessary encrypt/decrypt round-trip just to
// call this. Import this directly and pass the key you already have.
export { rotateWordPressPassword, rotateMysqlPasswordViaBeacon, findOrInstallBeacon };
