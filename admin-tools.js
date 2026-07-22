const express = require('express');
const crypto = require('crypto');
const libxml = require('libxmljs');
const _ = require('lodash');

const app = express();
app.use(express.json());
app.use(express.text({ type: '*/*' }));

// Admin credentials are loaded from the environment, never committed to source.
const ADMIN_USER = process.env.ADMIN_USER;
const ADMIN_PASS = process.env.ADMIN_PASS;

// Constant-time string comparison to avoid leaking match progress via timing.
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  // timingSafeEqual requires equal-length buffers; hash to fixed length first.
  const hashA = crypto.createHash('sha256').update(bufA).digest();
  const hashB = crypto.createHash('sha256').update(bufB).digest();
  return crypto.timingSafeEqual(hashA, hashB);
}

// In-memory config that inherits from Object.prototype
const config = { featureFlags: {}, limits: { maxUsers: 100 } };

// VULN 1: Remote Code Execution — user expression passed straight to eval()
app.get('/calc', (req, res) => {
  const expr = req.query.expr; // ?expr=require('child_process').execSync('id')
  const result = eval(expr);
  res.send(String(result));
});

// VULN 2: XXE — external entities resolved (noent) on untrusted XML
app.post('/parse-xml', (req, res) => {
  const doc = libxml.parseXml(req.body, { noent: true, noblanks: true });
  res.json({ root: doc.root().name(), text: doc.root().text() });
});

// VULN 3: Prototype Pollution — untrusted object deep-merged into config
app.post('/config', (req, res) => {
  _.merge(config, req.body); // {"__proto__":{"isAdmin":true}} pollutes Object.prototype
  res.json({ ok: true, config });
});

app.get('/login', (req, res) => {
  if (!ADMIN_USER || !ADMIN_PASS) {
    return res.status(500).send('admin credentials not configured');
  }
  const userOk = safeEqual(req.query.user, ADMIN_USER);
  const passOk = safeEqual(req.query.pass, ADMIN_PASS);
  if (userOk && passOk) {
    return res.send('admin session granted');
  }
  res.status(403).send('denied');
});

app.listen(5000, () => console.log('admin tools on 5000'));
