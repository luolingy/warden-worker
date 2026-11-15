// Register a Bitwarden-compatible account on the Warden worker (encType 2 = AesCbc256_HmacSha256).
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

// Bitwarden EncString, encType 2 (AesCbc256_HmacSha256_B64): "2.<b64(iv|ct)>|<b64(mac)>"
function encryptType2(encKey, macKey, plaintext) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', encKey, iv);
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  const mac = crypto.createHmac('sha256', macKey).update(Buffer.concat([iv, ct])).digest();
  return '2.' + b64(Buffer.concat([iv, ct])) + '|' + b64(mac);
}

// Master key + auth hash
const masterKey = pbkdf2(PASSWORD, emailLower, KDF_ITERATIONS, 32);
const masterPasswordHash = b64(pbkdf2(masterKey, PASSWORD, 1, 32));

// Stretch master key -> encKey/macKey (32+32) via HKDF-Expand
const encKey = hkdfExpand(masterKey, 'enc', 32);
const macKey = hkdfExpand(masterKey, 'mac', 32);

// User symmetric key = 64 random bytes (enc+mac)
const userSymKey = crypto.randomBytes(64);
const protectedUserSymKey = encryptType2(encKey, macKey, userSymKey);

// RSA 2048 keypair; encrypt private key as encType 2
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'der' },
  privateKeyEncoding: { type: 'pkcs8', format: 'der' },
});
const publicKeyB64 = b64(publicKey);
// Private key must be encrypted with the USER SYMMETRIC KEY (its enc/mac halves),
// not the master-stretched key. Client decrypts it using the unwrapped userSymKey.
const userEncKey = userSymKey.subarray(0, 32);
const userMacKey = userSymKey.subarray(32, 64);
const encryptedPrivateKey = encryptType2(userEncKey, userMacKey, privateKey);

const payload = {
  name: null,
  email: EMAIL,
  masterPasswordHash,
  masterPasswordHint: null,
  userSymmetricKey: protectedUserSymKey,
  userAsymmetricKeys: { publicKey: publicKeyB64, encryptedPrivateKey },
  kdf: 0,
  kdfIterations: KDF_ITERATIONS,
};

const body = JSON.stringify(payload);
const url = BASE_URL.replace(/\/$/, '') + '/identity/accounts/register/finish';
console.log('POST', url);
console.log('userSymmetricKey prefix:', protectedUserSymKey.slice(0, 4));
console.log('encryptedPrivateKey prefix:', encryptedPrivateKey.slice(0, 4));

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
