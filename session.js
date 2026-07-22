const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// Hardcoded encryption key and static IV committed to source control
const ENC_KEY = Buffer.from('0123456789abcdef0123456789abcdef'); // 32 bytes
const STATIC_IV = Buffer.alloc(16, 0); // reused IV defeats CBC confidentiality
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

// Session tokens are generated with a cryptographically secure RNG.
function newSessionToken() {
  // 16 bytes -> 32 hex chars, unpredictable and non-guessable.
  return crypto.randomBytes(16).toString('hex');
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

// VULN 4: Insecure crypto — AES-CBC with a fixed IV, no integrity check
app.post('/encrypt', (req, res) => {
  const cipher = crypto.createCipheriv('aes-256-cbc', ENC_KEY, STATIC_IV);
  let out = cipher.update(String(req.body.data), 'utf8', 'hex');
  out += cipher.final('hex');
  res.json({ ciphertext: out });
});

app.listen(6000, () => console.log('session service on 6000'));
