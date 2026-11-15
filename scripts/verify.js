// Verify the web-vault will be able to decrypt: use the REAL Bitwarden SDK.
const crypto = require('crypto');
const https = require('https');
const qs = require('querystring');
const { PureCrypto } = require('@bitwarden/sdk-internal');

const BASE_URL = process.env.BASE_URL;
const EMAIL = process.env.WARDEN_EMAIL;
const PASSWORD = process.env.WARDEN_MASTER_PASSWORD;
const ITER = 600000;

const emailLower = EMAIL.toLowerCase();
const masterKey = crypto.pbkdf2Sync(Buffer.from(PASSWORD), Buffer.from(emailLower), ITER, 32, 'sha256');
const masterPasswordHash = crypto.pbkdf2Sync(masterKey, Buffer.from(PASSWORD), 1, 32, 'sha256').toString('base64');

const body = qs.stringify({
  grant_type: 'password', username: EMAIL, password: masterPasswordHash,
  scope: 'api offline_access', client_id: 'web', deviceType: '10',
  deviceIdentifier: 'verify-' + crypto.randomUUID(), deviceName: 'verify',
});
const u = new URL(BASE_URL.replace(/\/$/, '') + '/identity/connect/token');
const req = https.request({ hostname: u.hostname, port: 443, path: u.pathname, method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) } }, (res) => {
  let d = '';
  res.on('data', (c) => (d += c));
  res.on('end', () => {
    console.log('LOGIN STATUS', res.statusCode);
    if (res.statusCode !== 200) { console.log(d.slice(0, 400)); process.exit(2); }
    const j = JSON.parse(d);
    const kdf = { pBKDF2: { iterations: ITER } };
    let ok = true;
    try {
      // 1. Unwrap user symmetric key exactly as web-vault (MasterKeyWrappedUserKey)
      const mpu = j.UserDecryptionOptions.MasterPasswordUnlock;
      const userKeyBytes = PureCrypto.decrypt_user_key_with_master_password(mpu.MasterKeyWrappedUserKey, PASSWORD, mpu.Salt, kdf);
      console.log('SDK unwrap MasterKeyWrappedUserKey -> len', userKeyBytes.length);
      // 2. Decrypt the top-level Key too
      const userKeyBytes2 = PureCrypto.decrypt_user_key_with_master_password(j.Key, PASSWORD, mpu.Salt, kdf);
      console.log('SDK unwrap top Key -> len', userKeyBytes2.length);
      ok = userKeyBytes.length === 64 && userKeyBytes2.length === 64;
      console.log(ok ? '::notice::SDK OK - web-vault can unwrap user key (64 bytes)' : '::error::unexpected user key length');
    } catch (e) {
      ok = false;
      console.log('::error::SDK decrypt failed: ' + (e.message || e));
    }
    process.exit(ok ? 0 : 5);
  });
});
req.on('error', (e) => { console.log('ERR', e.message); process.exit(3); });
req.write(body);
req.end();
