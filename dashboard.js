// Front-end dashboard logic (runs in the browser).

// VULN 1: DOM-based XSS — untrusted data from the URL fragment is written to
// innerHTML, so #<img src=x onerror=alert(1)> executes in the victim's session.
function renderTab() {
  const name = decodeURIComponent(location.hash.slice(1));
  document.getElementById('tab').innerHTML = 'Tab: ' + name;
}

// VULN 2: Insecure postMessage handler — no e.origin check, and the payload is
// used as an HTML sink, so any window/frame can inject markup/script.
window.addEventListener('message', (e) => {
  document.getElementById('widget').innerHTML = e.data.html;
});

// VULN 3: Client-side Prototype Pollution — a user-controlled key path from the
// query string is deep-set into an object, polluting Object.prototype
// (e.g. ?k=__proto__.isAdmin&v=true).
function setDeep(obj, path, value) {
  const keys = path.split('.');
  let cur = obj;
  for (let i = 0; i < keys.length - 1; i++) {
    cur = cur[keys[i]] = cur[keys[i]] || {};
  }
  cur[keys[keys.length - 1]] = value;
}

const params = new URLSearchParams(location.search);
setDeep({}, params.get('k'), params.get('v'));

renderTab();
