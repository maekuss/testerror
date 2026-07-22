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

// Parse untrusted XML with external entity resolution disabled to prevent XXE.
app.post('/parse-xml', (req, res) => {
  const doc = libxml.parseXml(req.body, { noent: false, noblanks: true, nonet: true });
  res.json({ root: doc.root().name(), text: doc.root().text() });
});

// VULN 3: Prototype Pollution — untrusted object deep-merged into config
app.post('/config', (req, res) => {
  _.merge(config, req.body); // {"__proto__":{"isAdmin":true}} pollutes Object.prototype
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
