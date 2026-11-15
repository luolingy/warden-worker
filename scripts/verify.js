// Verify login AND client-side decryption (the exact step web-vault does:
// derive master key -> stretch -> unwrap user symmetric key -> unwrap private key).
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

function hkdfExpand(prk, info, length) {
  const hashLen = 32;
  const n = Math.ceil(length / hashLen);
  let okm = Buffer.alloc(0); let t = Buffer.alloc(0);
  for (let i = 1; i <= n; i++) {
    t = crypto.createHmac('sha256', prk).update(Buffer.concat([t, Buffer.from(info), Buffer.from([i])])).digest();
    okm = Buffer.concat([okm, t]);
  }
  return okm.slice(0, length);
}

// Parse and decrypt a Bitwarden EncString (encType 2 = AesCbc256_HmacSha256_B64)
function decryptType2(encString, encKey, macKey) {
  const parts = encString.split('.');
  const type = parseInt(parts[0], 10);
  if (type !== 2) throw new Error('expected encType 2, got ' + type);
  const [dataB64, macB64] = parts[1].split('|');
  const data = Buffer.from(dataB64, 'base64');
  const mac = Buffer.from(macB64, 'base64');
  const iv = data.subarray(0, 16);
  const ct = data.subarray(16);
  const expectMac = crypto.createHmac('sha256', macKey).update(Buffer.concat([iv, ct])).digest();
  if (!crypto.timingSafeEqual(mac, expectMac)) throw new Error('MAC mismatch');
  const d = crypto.createDecipheriv('aes-256-cbc', encKey, iv);
  return Buffer.concat([d.update(ct), d.final()]);
}

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
    try {
      // stretch master key
      const encKey = hkdfExpand(masterKey, 'enc', 32);
      const macKey = hkdfExpand(masterKey, 'mac', 32);
      const userSymKey = decryptType2(j.Key, encKey, macKey);
      console.log('Decrypted userSymKey length:', userSymKey.length, '(expect 64)');
      // derive enc/mac from userSymKey to decrypt private key
      const userEnc = userSymKey.subarray(0, 32);
      const userMac = userSymKey.subarray(32, 64);
      const priv = decryptType2(j.PrivateKey, userEnc, userMac);
      console.log('Decrypted privateKey DER length:', priv.length, '(expect ~1218)');
      const ok = userSymKey.length === 64 && priv.length > 1000;
      console.log(ok ? '::notice::E2E OK: userKey + privateKey decrypt correctly' : '::error::E2E decrypt produced bad sizes');
      process.exit(ok ? 0 : 4);
    } catch (e) {
      console.log('::error::decrypt failed: ' + e.message);
      console.log('Key prefix:', (j.Key || '').slice(0, 4));
      process.exit(5);
    }
  });
});
req.on('error', (e) => { console.log('ERR', e.message); process.exit(3); });
req.write(body);
req.end();
