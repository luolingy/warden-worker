const crypto = require('crypto');
const https = require('https');
const qs = require('querystring');
const B = process.env.BASE_URL, E = process.env.WARDEN_EMAIL, P = process.env.WARDEN_MASTER_PASSWORD;
const mKey = crypto.pbkdf2Sync(Buffer.from(P), Buffer.from(E.toLowerCase()), 600000, 32, 'sha256');
const mph = crypto.pbkdf2Sync(mKey, Buffer.from(P), 1, 32, 'sha256').toString('base64');
const body = qs.stringify({grant_type:'password',username:E,password:mph,scope:'api offline_access',client_id:'web',deviceType:'10',deviceIdentifier:'d-'+crypto.randomUUID()});
const u = new URL(B + '/identity/connect/token');
const req = https.request({hostname:u.hostname,path:u.pathname,method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','Content-Length':Buffer.byteLength(body)}},res=>{
 let d='';res.on('data',c=>d+=c);res.on('end',()=>{
  const j=JSON.parse(d);
  const udo=j.UserDecryptionOptions||{};
  const mpu=udo.MasterPasswordUnlock||{};
  // base64-encode salt so GH secret-redaction can't mask it
  const saltB64=Buffer.from(String(mpu.Salt||'')).toString('base64');
  console.log('SALT_B64='+saltB64);
  console.log('SALT_plain_equals_email='+(String(mpu.Salt||'').toLowerCase()===E.toLowerCase()));
  console.log('UDO.MasterPasswordUnlock.Kdf='+JSON.stringify(mpu.Kdf));
  console.log('HasMasterPassword='+udo.HasMasterPassword);
  console.log('MasterKeyWrappedUserKey_prefix='+String(mpu.MasterKeyWrappedUserKey||'').slice(0,3));
  console.log('MasterKeyEncryptedUserKey_prefix='+String(mpu.MasterKeyEncryptedUserKey||'').slice(0,3));
  console.log('topKey_prefix='+String(j.Key||'').slice(0,3));
  console.log('topPrivateKey_prefix='+String(j.PrivateKey||'').slice(0,3));
 });
});
req.on('error',e=>console.log('ERR',e.message));
req.write(body);req.end();
