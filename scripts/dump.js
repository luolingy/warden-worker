// Full login response dump for debugging web-vault "No key provided".
const crypto = require('crypto');
const https = require('https');
const qs = require('querystring');

const BASE_URL = process.env.BASE_URL;
const EMAIL = process.env.WARDEN_EMAIL;
const PASSWORD = process.env.WARDEN_MASTER_PASSWORD;
const ITER = 600000;

const emailLower = EMAIL.toLowerCase();
const masterKey = crypto.pbkdf2Sync(Buffer.from(PASSWORD), Buffer.from(emailLower), ITER, 32, 'sha256');
const masterPasswordHash = crypto.pbkdf2Sync(masterKey, Buffer.from(PASSWORD), 1, 32, 'sha256').toString('base64');

const body = qs.stringify({
  grant_type: 'password',
  username: EMAIL,
  password: masterPasswordHash,
  scope: 'api offline_access',
  client_id: 'web',
  deviceType: '10',
  deviceIdentifier: 'dump-' + crypto.randomUUID(),
  deviceName: 'dump',
});

const u = new URL(BASE_URL.replace(/\/$/, '') + '/identity/connect/token');
const req = https.request(
  { hostname: u.hostname, port: 443, path: u.pathname, method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) } },
  (res) => {
    let d = '';
    res.on('data', (c) => (d += c));
    res.on('end', () => {
      console.log('LOGIN STATUS', res.statusCode);
      let j;
      try { j = JSON.parse(d); } catch (e) { console.log('RAW', d); process.exit(1); }
      const keys = Object.keys(j);
      console.log('TOP-LEVEL FIELDS:', keys.join(', '));
      console.log('Top Key length:', (j.Key || '').length, '| Top PrivateKey length:', (j.PrivateKey || '').length);
      console.log('Kdf:', j.Kdf, 'KdfIterations:', j.KdfIterations);
      console.log('UserDecryptionOptions:', JSON.stringify(j.UserDecryptionOptions || null));
      console.log('AccountKeys.publicKeyEncryptionKeyPair.wrappedPrivateKey len:', (j.AccountKeys && j.AccountKeys.publicKeyEncryptionKeyPair && j.AccountKeys.publicKeyEncryptionKeyPair.wrappedPrivateKey || '').length);
      console.log('AccountKeys.publicKeyEncryptionKeyPair.publicKey len:', (j.AccountKeys && j.AccountKeys.publicKeyEncryptionKeyPair && j.AccountKeys.publicKeyEncryptionKeyPair.publicKey || '').length);
      // full key list of AccountKeys / UDO
      if (j.AccountKeys) console.log('AccountKeys keys:', Object.keys(j.AccountKeys).join(','));
      if (j.UserDecryptionOptions) console.log('UDO keys:', Object.keys(j.UserDecryptionOptions).join(','));
      process.exit(0);
    });
  }
);
req.on('error', (e) => { console.log('ERR', e.message); process.exit(3); });
req.write(body);
req.end();
