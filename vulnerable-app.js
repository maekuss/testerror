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
  // User input concatenated directly into the query.
  const query = "SELECT * FROM users WHERE id = '" + id + "'";
  db.query(query, (err, rows) => {
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
function safeEval(expr) {
  if (typeof expr !== "string") {
    throw new Error("Expression must be a string");
  }

  const tokens = [];
  let i = 0;
  while (i < expr.length) {
    const char = expr[i];
    if (/\s/.test(char)) {
      i++;
      continue;
    }
    if (/[0-9.]/.test(char)) {
      let numStr = "";
      while (i < expr.length && /[0-9.]/.test(expr[i])) {
        numStr += expr[i];
        i++;
      }
      const num = parseFloat(numStr);
      if (isNaN(num)) {
        throw new Error("Invalid number");
      }
      tokens.push({ type: "NUMBER", value: num });
      continue;
    }
    if (["+", "-", "*", "/", "(", ")"].includes(char)) {
      tokens.push({ type: "OPERATOR", value: char });
      i++;
      continue;
    }
    throw new Error("Invalid character in expression: " + char);
  }

  let tokenIndex = 0;

  function peek() {
    return tokens[tokenIndex];
  }

  function consume(expectedValue) {
    const token = peek();
    if (!token) {
      throw new Error("Unexpected end of expression");
    }
    if (expectedValue !== undefined && token.value !== expectedValue) {
      throw new Error(`Expected ${expectedValue} but got ${token.value}`);
    }
    tokenIndex++;
    return token;
  }

  function parseExpression() {
    let val = parseTerm();
    while (true) {
      const next = peek();
      if (next && next.type === "OPERATOR" && (next.value === "+" || next.value === "-")) {
        const op = consume().value;
        const right = parseTerm();
        if (op === "+") val += right;
        else val -= right;
      } else {
        break;
      }
    }
    return val;
  }

  function parseTerm() {
    let val = parseFactor();
    while (true) {
      const next = peek();
      if (next && next.type === "OPERATOR" && (next.value === "*" || next.value === "/")) {
        const op = consume().value;
        const right = parseFactor();
        if (op === "*") {
          val *= right;
        } else {
          if (right === 0) {
            throw new Error("Division by zero");
          }
          val /= right;
        }
      } else {
        break;
      }
    }
    return val;
  }

  function parseFactor() {
    const token = peek();
    if (!token) {
      throw new Error("Unexpected end of expression");
    }
    if (token.type === "NUMBER") {
      consume();
      return token.value;
    }
    if (token.type === "OPERATOR" && token.value === "(") {
      consume("(");
      const val = parseExpression();
      consume(")");
      return val;
    }
    if (token.type === "OPERATOR" && token.value === "-") {
      consume("-");
      return -parseFactor();
    }
    if (token.type === "OPERATOR" && token.value === "+") {
      consume("+");
      return parseFactor();
    }
    throw new Error("Unexpected token: " + token.value);
  }

  const result = parseExpression();
  if (tokenIndex < tokens.length) {
    throw new Error("Unexpected extra tokens");
  }
  return result;
}

app.post("/eval", (req, res) => {
  const expr = req.body.expr;
  try {
    const result = safeEval(expr);
    res.json({ result });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
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
