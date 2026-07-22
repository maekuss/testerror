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

// Safe arithmetic evaluator: parses and evaluates a restricted grammar of
// numbers, + - * / % ( ), rejecting any identifiers, function calls, or other
// JavaScript constructs. This avoids eval() and the associated RCE risk.
function evalArithmetic(input) {
  if (typeof input !== 'string') {
    throw new Error('expression must be a string');
  }
  // Tokenize: numbers (int/float), operators, and parentheses only.
  const tokens = [];
  const re = /\s*(?:(\d+(?:\.\d+)?|\.\d+)|([+\-*/%()]))/g;
  let lastIndex = 0;
  let m;
  while ((m = re.exec(input)) !== null) {
    if (m.index !== lastIndex) {
      throw new Error('invalid character in expression');
    }
    tokens.push(m[1] !== undefined ? { type: 'num', value: parseFloat(m[1]) } : { type: 'op', value: m[2] });
    lastIndex = re.lastIndex;
  }
  if (lastIndex !== input.length) {
    throw new Error('invalid character in expression');
  }

  // Recursive-descent parser for expressions with standard precedence.
  let pos = 0;
  const peek = () => tokens[pos];
  const next = () => tokens[pos++];

  function parseExpression() {
    let value = parseTerm();
    while (peek() && peek().type === 'op' && (peek().value === '+' || peek().value === '-')) {
      const op = next().value;
      const rhs = parseTerm();
      value = op === '+' ? value + rhs : value - rhs;
    }
    return value;
  }

  function parseTerm() {
    let value = parseFactor();
    while (peek() && peek().type === 'op' && (peek().value === '*' || peek().value === '/' || peek().value === '%')) {
      const op = next().value;
      const rhs = parseFactor();
      if (op === '*') value *= rhs;
      else if (op === '/') value /= rhs;
      else value %= rhs;
    }
    return value;
  }

  function parseFactor() {
    const token = peek();
    if (!token) throw new Error('unexpected end of expression');
    if (token.type === 'op' && (token.value === '+' || token.value === '-')) {
      next();
      const value = parseFactor();
      return token.value === '-' ? -value : value;
    }
    if (token.type === 'op' && token.value === '(') {
      next();
      const value = parseExpression();
      const closing = next();
      if (!closing || closing.type !== 'op' || closing.value !== ')') {
        throw new Error('missing closing parenthesis');
      }
      return value;
    }
    if (token.type === 'num') {
      next();
      return token.value;
    }
    throw new Error('unexpected token in expression');
  }

  const result = parseExpression();
  if (pos !== tokens.length) {
    throw new Error('unexpected trailing tokens in expression');
  }
  return result;
}

// Evaluate a user-supplied arithmetic expression using a safe parser instead
// of eval(), which would allow arbitrary code execution.
app.get('/calc', (req, res) => {
  const expr = req.query.expr;
  try {
    const result = evalArithmetic(expr);
    res.send(String(result));
  } catch (err) {
    res.status(400).send('invalid expression');
  }
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

// VULN 4: Broken auth — timing-unsafe string compare + creds from query string
app.get('/login', (req, res) => {
  if (req.query.user === ADMIN_USER && req.query.pass === ADMIN_PASS) {
    return res.send('admin session granted');
  }
  res.status(403).send('denied');
});

app.listen(5000, () => console.log('admin tools on 5000'));
