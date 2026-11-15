// Register a Bitwarden-compatible account on the Warden worker.
// Reads BASE_URL, WARDEN_EMAIL, WARDEN_MASTER_PASSWORD from env.
const crypto = require('crypto');
const https = require('https');

const BASE_URL = process.env.BASE_URL;
const EMAIL = process.env.WARDEN_EMAIL;
const PASSWORD = process.env.WARDEN_MASTER_PASSWORD;
const KDF_ITERATIONS = 600000;

if (!BASE_URL || !EMAIL || !PASSWORD) {
  console.error('Missing BASE_URL / WARDEN_EMAIL / WARDEN_MASTER_PASSWORD');
  process.exit(1);
}

const emailLower = EMAIL.toLowerCase();
const b64 = (buf) => Buffer.from(buf).toString('base64');

function pbkdf2(password, salt, iterations, keylenBytes) {
  return crypto.pbkdf2Sync(Buffer.from(password), Buffer.from(salt), iterations, keylenBytes, 'sha256');
}

function encryptToB64(encKey, plaintext) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', encKey, iv);
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  return b64(Buffer.concat([iv, ct]));
}

// HKDF-Expand (RFC 5869), SHA-256
function hkdfExpand(prk, info, length) {
  const hashLen = 32;
  const n = Math.ceil(length / hashLen);
  let okm = Buffer.alloc(0);
  let t = Buffer.alloc(0);
  for (let i = 1; i <= n; i++) {
    t = crypto.createHmac('sha256', prk).update(Buffer.concat([t, Buffer.from(info), Buffer.from([i])])).digest();
    okm = Buffer.concat([okm, t]);
  }
  return okm.slice(0, length);
}

const masterKey = pbkdf2(PASSWORD, emailLower, KDF_ITERATIONS, 32);
const masterPasswordHash = b64(pbkdf2(masterKey, PASSWORD, 1, 32));

const encKey = hkdfExpand(masterKey, 'enc', 32);
const macKey = hkdfExpand(masterKey, 'mac', 32);

const userSymKey = crypto.randomBytes(64);
const protectedUserSymKey = encryptToB64(encKey, userSymKey);

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'der' },
  privateKeyEncoding: { type: 'pkcs8', format: 'der' },
});

const payload = {
  name: null,
  email: EMAIL,
  masterPasswordHash,
  masterPasswordHint: null,
  userSymmetricKey: protectedUserSymKey,
  userAsymmetricKeys: { publicKey: b64(publicKey), encryptedPrivateKey: encryptToB64(encKey, privateKey) },
  kdf: 0,
  kdfIterations: KDF_ITERATIONS,
};

const body = JSON.stringify(payload);
const url = BASE_URL.replace(/\/$/, '') + '/identity/accounts/register/finish';
console.log('POST', url);

const u = new URL(url);
const req = https.request(
  { hostname: u.hostname, port: u.port || 443, path: u.pathname + u.search, method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } },
  (res) => {
    let d = '';
    res.on('data', (c) => (d += c));
    res.on('end', () => {
      console.log('STATUS', res.statusCode);
      console.log(d);
      process.exit(res.statusCode >= 200 && res.statusCode < 300 ? 0 : 2);
    });
  }
);
req.on('error', (e) => { console.log('ERR', e.message); process.exit(3); });
req.write(body);
req.end();
