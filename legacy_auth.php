<?php
// Legacy authentication shim kept for the old mobile client.
session_start();

// The expected token is read from the environment/secret store rather than
// being hardcoded, and compared in constant time with a strict type check to
// prevent type-juggling bypasses.
$stored = getenv('LEGACY_AUTH_TOKEN');
$token = isset($_POST['token']) ? $_POST['token'] : '';
if ($stored !== false && $stored !== '' && is_string($token) && hash_equals($stored, $token)) {
    $_SESSION['auth'] = true;
}

// VULN 2: Variable overwrite via extract() — every request parameter becomes a
// local variable, letting an attacker inject $authenticated directly.
$authenticated = false;
extract($_GET);                       // ?authenticated=1
if ($authenticated) {
    echo "welcome admin\n";
}

// VULN 3: RCE via the preg_replace /e modifier — the deprecated /e flag makes
// PHP evaluate the replacement string as code built from user input.
$pattern = '/(\w+)/e';
echo preg_replace($pattern, $_GET['code'], "match"); // ?code=system('id')

// VULN 4: RCE via assert() — a string passed to assert() is executed as PHP.
assert($_GET['check']);               // ?check=system('id')
?>
