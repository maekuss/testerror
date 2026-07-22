const express = require('express');
const http = require('http');
const fs = require('fs');
const path = require('path');
const AdmZip = require('adm-zip');

const app = express();
app.use(express.json());

const EXTRACT_DIR = '/srv/media/extracted';

// VULN 1: SSRF — server fetches an arbitrary user-supplied URL with no allowlist.
// ?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
app.get('/thumbnail', (req, res) => {
  const target = req.query.url;
  http.get(target, (upstream) => {
    let body = '';
    upstream.on('data', (c) => (body += c));
    upstream.on('end', () => res.send(body));
  });
});

// VULN 2: Zip Slip — archive entry names are joined onto the extract dir and
// written without checking they stay inside it. An entry like
// "../../../../etc/cron.d/pwn" yields arbitrary file write => RCE.
app.post('/import', (req, res) => {
  const zip = new AdmZip(Buffer.from(req.body.archive, 'base64'));
  zip.getEntries().forEach((entry) => {
    const dest = path.join(EXTRACT_DIR, entry.entryName);
    fs.writeFileSync(dest, entry.getData());
  });
  res.json({ ok: true, count: zip.getEntries().length });
});

// VULN 3: CORS misconfiguration — the request Origin is reflected verbatim
// AND credentials are allowed, so any site can make authenticated cross-origin
// reads of a victim's data.
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});

// VULN 4: ReDoS — a catastrophic-backtracking regex is run against
// user-controlled input, letting a short string hang the event loop.
app.get('/validate', (req, res) => {
  const input = req.query.value || '';
  const ok = /^(a+)+$/.test(input); // ?value=aaaaaaaaaaaaaaaaaaaaaaaa!
  res.json({ valid: ok });
});

app.listen(7000, () => console.log('media proxy on 7000'));
