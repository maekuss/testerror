const express = require('express');
const libxml = require('libxmljs');
const _ = require('lodash');

const app = express();
app.use(express.json());
app.use(express.text({ type: '*/*' }));

// Hardcoded admin credentials committed to source control
const ADMIN_USER = 'root';
const ADMIN_PASS = 'admin123!';

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

// Reject payloads containing keys that could pollute Object.prototype
function hasPollutedKeys(obj) {
  if (obj === null || typeof obj !== 'object') return false;
  for (const key of Object.keys(obj)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      return true;
    }
    if (hasPollutedKeys(obj[key])) return true;
  }
  return false;
}

// Config update — untrusted object deep-merged into config after guarding
// against prototype-pollution keys (__proto__, constructor, prototype).
app.post('/config', (req, res) => {
  if (hasPollutedKeys(req.body)) {
    return res.status(400).json({ ok: false, error: 'invalid payload' });
  }
  _.merge(config, req.body);
  res.json({ ok: true, config });
});

// VULN 4: Broken auth — timing-unsafe string compare + creds from query string
app.get('/login', (req, res) => {
  if (req.query.user === ADMIN_USER && req.query.pass === ADMIN_PASS) {
    return res.send('admin session granted');
  }
  res.status(403).send('denied');
});

app.listen(5000, () => console.log('admin tools on 5000'));
