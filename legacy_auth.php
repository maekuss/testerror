<?php
// Legacy authentication shim kept for the old mobile client.
session_start();

// VULN 1: Type Juggling auth bypass — loose == comparison against a "magic"
// hash. A value like "0e123..." is treated as 0 == 0, and non-string inputs
// coerce, so authentication can be bypassed. Should use hash_equals().
$stored = "0e462097431906509019562988736854"; // MD5 that is "0e"-prefixed
if ($_POST['token'] == $stored) {
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

// VULN 4 (FIXED): Never pass user input to assert(). A string argument is
// executed as PHP code on affected versions/configurations, allowing RCE.
// Perform an explicit, safe check on the supplied value instead of evaluating it.
$check = isset($_GET['check']) ? (string) $_GET['check'] : '';
if ($check !== '') {
    // Treat the parameter strictly as data, never as code.
    echo "check=" . htmlspecialchars($check, ENT_QUOTES, 'UTF-8') . "\n";
}
?>
