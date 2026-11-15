// Verify login against the Warden worker using the master password.
// Derives masterPasswordHash the same way Bitwarden does, then calls /identity/connect/token.
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
console.log('masterPasswordHash =', masterPasswordHash);

const body = qs.stringify({
  grant_type: 'password',
  username: EMAIL,
  password: masterPasswordHash,
  scope: 'api offline_access',
  client_id: 'web',
  deviceType: '10',
  deviceIdentifier: 'verify-script-' + crypto.randomUUID(),
  deviceName: 'verify',
});

const u = new URL(BASE_URL.replace(/\/$/, '') + '/identity/connect/token');
const req = https.request(
  { hostname: u.hostname, port: 443, path: u.pathname, method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) } },
  (res) => {
    let d = '';
    res.on('data', (c) => (d += c));
    res.on('end', () => {
      console.log('LOGIN STATUS', res.statusCode);
      console.log(d.slice(0, 800));
      if (res.statusCode !== 200) process.exit(2);
      const j = JSON.parse(d);
      console.log('Got token?', !!j.access_token, 'Key len', (j.Key || '').length, 'PrivateKey len', (j.PrivateKey || '').length);
      process.exit(0);
    });
  }
);
req.on('error', (e) => { console.log('ERR', e.message); process.exit(3); });
req.write(body);
req.end();
