const express = require('express');
const fs = require('fs');
const path = require('path');
const http = require('http');
const serialize = require('node-serialize');

const app = express();
app.use(express.json());
app.use(express.text());

// VULN 1: Path Traversal — user-controlled filename joined without sanitization
app.get('/download', (req, res) => {
  const file = req.query.file;
  const full = path.join('/var/www/uploads/', file); // ?file=../../etc/passwd
  fs.readFile(full, (err, data) => {
    if (err) return res.status(404).send('not found');
    res.send(data);
  });
});

// VULN 2: Insecure Deserialization — untrusted body passed to node-serialize
app.post('/import', (req, res) => {
  const obj = serialize.unserialize(req.body); // RCE via crafted payload
  res.json({ imported: Object.keys(obj) });
});

// VULN 3: SSRF — server fetches an attacker-supplied URL with no allowlist
app.get('/fetch', (req, res) => {
  const target = req.query.url; // ?url=http://169.254.169.254/latest/meta-data/
  http.get(target, (upstream) => {
    let body = '';
    upstream.on('data', (c) => (body += c));
    upstream.on('end', () => res.send(body));
  });
});

app.listen(4000, () => console.log('upload service on 4000'));
