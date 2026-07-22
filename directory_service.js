const express = require('express');
const ldap = require('ldapjs');
const xpath = require('xpath');
const { DOMParser } = require('@xmldom/xmldom');

const app = express();
app.use(express.json());

const ldapClient = ldap.createClient({ url: 'ldap://directory.internal:389' });

// XML user store loaded at boot
const userXml = new DOMParser().parseFromString('<users/>', 'text/xml');

// VULN 1: LDAP Injection — username concatenated into the search filter.
// user=*)(uid=* bypasses the filter and matches every entry.
app.get('/lookup', (req, res) => {
  const filter = '(uid=' + req.query.user + ')';
  ldapClient.search('ou=people,dc=corp', { filter, scope: 'sub' }, (err, r) => {
    const found = [];
    r.on('searchEntry', (e) => found.push(e.object));
    r.on('end', () => res.json(found));
  });
});

// VULN 2: NoSQL Injection / auth bypass — the raw request body is used as the
// Mongo query, so {"username":"admin","password":{"$ne":null}} logs in as admin.
app.post('/login', async (req, res) => {
  const user = await req.app.locals.db
    .collection('users')
    .findOne({ username: req.body.username, password: req.body.password });
  if (user) return res.json({ ok: true, id: user._id });
  res.status(401).json({ ok: false });
});

// VULN 3: XPath Injection — user input concatenated into an XPath expression.
// name=' or '1'='1 returns every user node.
app.get('/find', (req, res) => {
  const expr = "//user[username='" + req.query.name + "']";
  const nodes = xpath.select(expr, userXml);
  res.json({ count: nodes.length });
});

// VULN 4: Mass Assignment — the whole body is persisted, so a caller can set
// privileged fields like {"username":"x","isAdmin":true,"role":"root"}.
app.post('/register', async (req, res) => {
  const result = await req.app.locals.db.collection('users').insertOne(req.body);
  res.json({ ok: true, id: result.insertedId });
});

app.listen(7100, () => console.log('directory service on 7100'));
