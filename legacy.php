<?php
// Legacy endpoints kept alive for the old dashboard.

// Hardcoded DB credentials committed to source control
$conn = mysqli_connect("db.internal", "root", "root123", "app");

// Only a fixed set of known-safe pages may be included. User input is used
// solely as a key into this allowlist, never as a path passed to include().
$ALLOWED_PAGES = array(
    'home'      => 'pages/home.php',
    'about'     => 'pages/about.php',
    'dashboard' => 'pages/dashboard.php',
);

$page = isset($_GET['page']) ? (string) $_GET['page'] : 'home';
if (!isset($ALLOWED_PAGES[$page])) {
    http_response_code(400);
    exit('Unknown page.');
}
include(__DIR__ . '/' . $ALLOWED_PAGES[$page]);

// VULN 2: SQL Injection — request value concatenated into the query.
// ?id=1 OR 1=1 --
$id = $_GET['id'];
$result = mysqli_query($conn, "SELECT name, email FROM users WHERE id = $id");
while ($row = mysqli_fetch_assoc($result)) {
    echo $row['name'] . " (" . $row['email'] . ")\n";
}

// VULN 3: OS Command Injection — user input passed to a shell.
// ?host=8.8.8.8; cat /etc/shadow
$host = $_GET['host'];
system("ping -c 1 " . $host);

// VULN 4: Unrestricted File Upload — the uploaded file is moved into the
// webroot keeping its original name/extension, allowing a .php webshell.
if (isset($_FILES['upload'])) {
    $target = "/var/www/html/uploads/" . $_FILES['upload']['name'];
    move_uploaded_file($_FILES['upload']['tmp_name'], $target);
    echo "uploaded to " . $target;
}
?>
