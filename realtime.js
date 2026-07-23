const http = require('http');
const fs = require('fs');
const { WebSocketServer } = require('ws');

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

  // VULN 3: TOCTOU Race Condition — existence is checked and the file is written
  // in a separate step. Between the check and the write the path can be swapped
  // (e.g. via a symlink), so the write lands outside the intended directory.
  if (data.type === 'save') {
    const path = '/srv/cache/' + data.name;
    if (!fs.existsSync(path)) {          // check
      fs.writeFileSync(path, data.body); // act — state may have changed in between
    }
  }
}

server.listen(7300, () => console.log('realtime on 7300'));
