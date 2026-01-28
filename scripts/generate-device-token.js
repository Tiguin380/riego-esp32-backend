const crypto = require('crypto');

// Genera un token largo y aleatorio para usar como device_token (X-Device-Token).
// Recomendación: 32 bytes (64 hex chars). Backend exige >= 12 caracteres.

const bytes = Number(process.argv[2] || 32);
if (!Number.isFinite(bytes) || bytes < 16 || bytes > 256) {
  console.error('Uso: node scripts/generate-device-token.js [bytes]  (16..256)');
  process.exit(1);
}

const token = crypto.randomBytes(bytes).toString('hex');
process.stdout.write(token + '\n');
