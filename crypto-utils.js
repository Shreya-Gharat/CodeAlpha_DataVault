const crypto = require('crypto');

if (!process.env.AES_KEY || process.env.AES_KEY.length !== 64) {
  throw new Error('AES_KEY must be set to 64 hex characters (32 bytes) for AES-256');
}
const KEY = Buffer.from(process.env.AES_KEY, 'hex');

// AES-256-GCM: encrypts AND authenticates, so tampered ciphertext fails to decrypt.
// Stored format (base64): 12-byte IV | 16-byte auth tag | ciphertext
function encrypt(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), enc]).toString('base64');
}

function decrypt(payload) {
  const data = Buffer.from(payload, 'base64');
  const iv = data.subarray(0, 12);
  const tag = data.subarray(12, 28);
  const enc = data.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
}

module.exports = { encrypt, decrypt };
