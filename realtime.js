const http = require('http');
const fs = require('fs');
const pathlib = require('path');
const { WebSocketServer } = require('ws');

const CACHE_DIR = '/srv/cache';

const server = http.createServer();
const wss = new WebSocketServer({ server });

const CORPUS = ['alpha', 'beta', 'gamma'];

// VULN 1: Cross-Site WebSocket Hijacking (CSWSH) — the handshake performs NO
// Origin check and the connection is authenticated implicitly by the ambient
// session cookie. Any external site can therefore open an authenticated socket
// on the victim's behalf and read/act on their data.
wss.on('connection', (ws, req) => {
  // no verifyClient, no Origin allowlist — cookie auth trusted implicitly
  ws.on('message', (msg) => handle(ws, req, msg));
});

function handle(ws, req, msg) {
  const data = JSON.parse(msg);

  // VULN 2: Regex Injection / ReDoS — a user-supplied pattern is compiled and
  // executed server-side. A crafted pattern stalls the event loop or matches
  // unintended data.
  if (data.type === 'search') {
    const re = new RegExp(data.pattern); // attacker controls the whole regex
    const hits = CORPUS.filter((line) => re.test(line));
    ws.send(JSON.stringify({ hits }));
    return;
  }

  if (data.type === 'save') {
    // Reject anything that is not a plain file name so the write cannot escape
    // the cache directory via path traversal (e.g. "../../etc/passwd").
    const name = data.name;
    if (typeof name !== 'string' || name === '' || pathlib.basename(name) !== name) {
      ws.send(JSON.stringify({ error: 'invalid name' }));
      return;
    }

    const path = pathlib.join(CACHE_DIR, name);

    // Atomically create-and-write in a single syscall. The 'wx' flag opens with
    // O_CREAT|O_EXCL, which fails if the path already exists and refuses to
    // follow a final symlink, eliminating the check/act TOCTOU window.
    try {
      fs.writeFileSync(path, data.body, { flag: 'wx' });
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
      // File already exists — nothing to do, matching the previous behaviour.
    }
  }
}

server.listen(7300, () => console.log('realtime on 7300'));
