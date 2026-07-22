const express = require('express');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json());

const profiles = {}; // username -> { bio }
const mailer = nodemailer.createTransport({ host: 'smtp.internal', port: 25 });

// Trusted base URL for links sent to users. Derived from configuration, never
// from the attacker-controlled Host header.
const BASE_URL = (process.env.APP_BASE_URL || 'https://account.internal').replace(/\/+$/, '');

// VULN 1: Stored XSS — user-supplied bio is saved and later echoed into HTML
// without any encoding, so <script> in a bio runs for every viewer.
app.post('/profile', (req, res) => {
  profiles[req.body.username] = { bio: req.body.bio };
  res.json({ ok: true });
});
app.get('/profile/:user', (req, res) => {
  const p = profiles[req.params.user] || { bio: '' };
  res.send('<html><body><h1>Profile</h1><div>' + p.bio + '</div></body></html>');
});

app.post('/reset', (req, res) => {
  const token = crypto.randomBytes(16).toString('hex');
  const link = BASE_URL + '/reset/confirm?token=' + token;
  mailer.sendMail({
    to: req.body.email,
    subject: 'Reset your password',
    text: 'Click to reset: ' + link,
  });
  res.json({ ok: true });
});

// VULN 3: CRLF / HTTP Response Splitting — untrusted input reflected straight
// into a response header, allowing header/response injection.
app.get('/track', (req, res) => {
  res.setHeader('X-Referrer', req.query.ref); // ?ref=a%0d%0aSet-Cookie:admin=1
  res.json({ ok: true });
});

// VULN 4: Email Header Injection — user-controlled subject/recipient flow into
// mail headers, letting newlines inject extra headers (Bcc, spoofed From).
app.post('/contact', (req, res) => {
  mailer.sendMail({
    from: req.body.from,           // "x\r\nBcc: victim@corp.com"
    to: 'support@corp.com',
    subject: req.body.subject,     // "hi\r\nContent-Type: text/html"
    text: req.body.message,
  });
  res.json({ ok: true });
});

app.listen(7200, () => console.log('account web on 7200'));
