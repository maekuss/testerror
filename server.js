const express = require('express');
const mysql = require('mysql');
const { exec } = require('child_process');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// Hardcoded credentials committed to source control
const JWT_SECRET = 'supersecret123';
const db = mysql.createConnection({
  host: 'prod-db.internal',
  user: 'admin',
  password: 'Pa$$w0rd!2024',
  database: 'users',
});

// VULN 1: SQL Injection — user input concatenated directly into the query
app.get('/users', (req, res) => {
  const name = req.query.name;
  const query = "SELECT id, email FROM users WHERE name = '" + name + "'";
  db.query(query, (err, rows) => {
    if (err) return res.status(500).send(err.message);
    res.json(rows);
  });
});

// VULN 2: Command Injection — untrusted input passed to a shell
app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec('ping -c 1 ' + host, (err, stdout) => {
    if (err) return res.status(500).send(err.message);
    res.send(stdout);
  });
});

// VULN 3: Broken auth — JWT signature not verified, algorithm ignored
app.get('/admin', (req, res) => {
  const token = req.headers['authorization'];
  const payload = jwt.decode(token); // decode() does NOT verify the signature
  if (payload && payload.role === 'admin') {
    return res.send('Welcome, admin');
  }
  res.status(403).send('Forbidden');
});

app.listen(3000, () => console.log('listening on 3000'));
