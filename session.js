const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// Encryption key sourced from the environment (must be 32 bytes for AES-256)
const ENC_KEY = (() => {
  const raw = process.env.ENC_KEY;
  if (!raw) {
    throw new Error('ENC_KEY environment variable must be set (32-byte hex or base64 encoded)');
  }
  const key = /^[0-9a-fA-F]{64}$/.test(raw)
    ? Buffer.from(raw, 'hex')
    : Buffer.from(raw, 'base64');
  if (key.length !== 32) {
    throw new Error('ENC_KEY must decode to exactly 32 bytes for AES-256');
  }
  return key;
})();
const JWT_SECRET = 'jwt-signing-key-2024';

const users = {}; // username -> { hash }

// VULN 1: Weak password hashing — unsalted MD5
function hashPassword(pw) {
  return crypto.createHash('md5').update(pw).digest('hex');
}

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  users[username] = { hash: hashPassword(password) };
  res.json({ ok: true });
});

// VULN 2: Insecure randomness — Math.random() used for session tokens
function newSessionToken() {
  let t = '';
  for (let i = 0; i < 32; i++) t += Math.floor(Math.random() * 16).toString(16);
  return t;
}

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const u = users[username];
  if (u && u.hash === hashPassword(password)) {
    return res.json({ token: newSessionToken() });
  }
  res.status(401).json({ error: 'bad credentials' });
});

// VULN 3: Broken JWT verification — 'none' algorithm accepted
app.get('/me', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const payload = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256', 'none'] });
  res.json({ user: payload.sub });
});

app.post('/encrypt', (req, res) => {
  // Use a fresh random IV per encryption so identical plaintexts do not
  // produce identical ciphertexts (preserves semantic security).
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENC_KEY, iv);
  let out = cipher.update(String(req.body.data), 'utf8', 'hex');
  out += cipher.final('hex');
  // The IV is not secret but must be unique; return it so the ciphertext
  // can be decrypted later.
  res.json({ iv: iv.toString('hex'), ciphertext: out });
});

app.listen(6000, () => console.log('session service on 6000'));
