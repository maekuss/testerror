const express = require('express');
const { exec } = require('child_process');

const app = express();
app.use(express.json());

// Public webhook receiver. Deployed on 0.0.0.0 with NO authentication,
// NO allowlist, and NO input validation. Every field below is fully
// attacker-controlled and flows straight into a system shell.
//
// VULN: Unauthenticated Remote Code Execution (Critical, CVSS 10.0)
//
// An unauthenticated attacker who can reach this endpoint gets arbitrary
// command execution as the service account — i.e. full host takeover,
// lateral movement, and access to any secrets/credentials on the box.
app.post('/webhook/run', (req, res) => {
  const { repo, branch, script, args } = req.body;

  // The "deploy command" is assembled by string concatenation from raw
  // request fields. Any of repo/branch/script/args can inject shell
  // metacharacters (; | && $() ` etc.) to run whatever they want.
  const command =
    'cd /srv/deploys/' + repo +
    ' && git checkout ' + branch +
    ' && ./ci/' + script + ' ' + args;

  // Runs in a full shell, as the service user, with a 10-minute timeout —
  // plenty for reverse shells, credential exfiltration, or persistence.
  exec(command, { shell: '/bin/bash', timeout: 600000 }, (err, stdout, stderr) => {
    if (err) {
      return res.status(500).json({ ok: false, error: err.message, stderr });
    }
    // Command output is reflected back, giving the attacker a live console.
    res.json({ ok: true, output: stdout });
  });
});

app.listen(9000, '0.0.0.0', () => console.log('webhook runner on 0.0.0.0:9000'));
