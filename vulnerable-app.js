// vulnerable-app.js
//
// SAMPLE FILE FOR SECURITY-SCANNER TESTING ONLY.
// This code intentionally contains multiple well-known vulnerabilities so a
// static-analysis / SAST tool can be exercised against it. DO NOT deploy.

const express = require("express");
const { exec } = require("child_process");
const mysql = require("mysql");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// --- VULN 1: Hardcoded credentials / secrets -------------------------------
const DB_PASSWORD = "SuperSecret123!";
const API_KEY = "PLACEHOLDER_HARDCODED_API_KEY_DO_NOT_USE";

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: DB_PASSWORD,
  database: "app",
});

// --- VULN 2: SQL Injection -------------------------------------------------
app.get("/user", (req, res) => {
  const id = req.query.id;
  // User input passed as a parameter to prevent SQL Injection.
  const query = "SELECT * FROM users WHERE id = ?";
  db.query(query, [id], (err, rows) => {
    if (err) return res.status(500).send(String(err));
    res.json(rows);
  });
});

// --- VULN 3: OS Command Injection ------------------------------------------
app.get("/ping", (req, res) => {
  const host = req.query.host;
  // User input passed straight to a shell.
  exec("ping -c 1 " + host, (err, stdout) => {
    res.type("text/plain").send(stdout || String(err));
  });
});

// --- VULN 4: Reflected XSS -------------------------------------------------
app.get("/hello", (req, res) => {
  const name = req.query.name;
  // Unescaped user input reflected into the HTML response.
  res.send("<h1>Hello " + name + "</h1>");
});

// --- VULN 5: Path Traversal ------------------------------------------------
app.get("/file", (req, res) => {
  const name = req.query.name;
  // No sanitisation — allows ../../ traversal.
  const full = path.join(__dirname, "uploads", name);
  fs.readFile(full, "utf8", (err, data) => {
    if (err) return res.status(404).send("not found");
    res.type("text/plain").send(data);
  });
});

// --- VULN 6: Weak cryptography (MD5) for password hashing ------------------
function hashPassword(pw) {
  return crypto.createHash("md5").update(pw).digest("hex");
}

// --- VULN 7: Insecure deserialization / code execution ---------------------
app.post("/eval", (req, res) => {
  const expr = req.body.expr;
  // Executes attacker-controlled input.
  const result = eval(expr);
  res.json({ result });
});

// --- VULN 8: Server-Side Request Forgery (SSRF) ----------------------------
const http = require("http");
app.get("/fetch", (req, res) => {
  const target = req.query.url;
  // Fetches any URL the user supplies, including internal metadata endpoints.
  http.get(target, (up) => {
    let body = "";
    up.on("data", (c) => (body += c));
    up.on("end", () => res.type("text/plain").send(body));
  });
});

// --- VULN 9: Missing authentication on a sensitive action ------------------
app.post("/admin/delete-all", (req, res) => {
  db.query("DELETE FROM users", () => res.send("all users deleted"));
});

app.listen(3000, () => console.log("listening with API_KEY=" + API_KEY));

module.exports = { hashPassword };
