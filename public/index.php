<?php
declare(strict_types=1);

require dirname(__DIR__) . "/src/bootstrap.php";

$path = parse_url($_SERVER["REQUEST_URI"] ?? "/", PHP_URL_PATH) ?: "/";
$method = $_SERVER["REQUEST_METHOD"] ?? "GET";

if ($path === "/health") {
    json_out(["ok" => true]);
}

// PATCH: every POST must carry the CSRF token from the form (see csrf_field() in bootstrap.php).
if ($method === "POST") {
    verify_csrf();
}

if ($path === "/" && $method === "GET") {
    render("home", ["title" => "Locker", "items" => current_user() ? vault_items_for(current_user()) : []]);
}

if ($path === "/login" && $method === "GET") {
    render("login", ["title" => "Sign in", "email" => "", "error" => null]);
}

if ($path === "/login" && $method === "POST") {
    $email = substr(strtolower(trim(field($_POST, "email"))), 0, 254);
    $password = field($_POST, "password");
    // PATCH: stop password guessing - after 5 misses the account is paused for 15 minutes.
    if (too_many_failures($email)) {
        render("login", ["title" => "Sign in", "email" => $email, "error" => "Too many attempts. Wait 15 minutes and try again."], 429);
    }
    $user = find_user_by_email($email);
    if ($user) {
        $ok = verify_password($password, $user["password_hash"]);
    } else {
        // PATCH: do the same slow hash for unknown emails so response time does not reveal who has an account.
        hash_password($password);
        $ok = false;
    }
    if (!$ok) {
        record_failure($email);
        render("login", ["title" => "Sign in", "email" => $email, "error" => "Those credentials do not match a Locker account."], 401);
    }
    clear_failures($email);
    // PATCH: old SHA-256-era hash? Replace it with a normal bcrypt hash now that we have the password.
    if (password_needs_upgrade($user["password_hash"])) {
        set_user_password($email, $password);
    }
    login_user((int)$user["id"]);
    redirect("/");
}

if ($path === "/register" && $method === "GET") {
    render("register", ["title" => "Create account", "values" => [], "error" => null]);
}

if ($path === "/register" && $method === "POST") {
    $email = strtolower(trim(field($_POST, "email")));
    $display = trim(field($_POST, "display_name"));
    $password = field($_POST, "password");
    $values = ["email" => $email, "display_name" => $display];
    // PATCH: was only str_ends_with(".edu"), so "x.edu" or "<junk>.edu" passed. Must be a real address shape too.
    if (strlen($email) > 254 || !filter_var($email, FILTER_VALIDATE_EMAIL) || !str_ends_with($email, ".edu")) {
        render("register", ["title" => "Create account", "values" => $values, "error" => "Use a .edu email so the locker stays on campus."]);
    }
    // PATCH: added upper limits. bcrypt only reads the first 72 bytes, and unbounded input is a cheap DoS.
    if (strlen($display) < 2 || strlen($display) > 80 || strlen($password) < 8 || strlen($password) > 72) {
        render("register", ["title" => "Create account", "values" => $values, "error" => "Name (2-80 characters) and an 8-72 character password are required."]);
    }
    if (find_user_by_email($email)) {
        render("register", ["title" => "Create account", "values" => $values, "error" => "That email already has an account."]);
    }
    $id = create_user($email, $display, $password, "member");
    login_user($id);
    redirect("/");
}

if ($path === "/logout" && $method === "POST") {
    logout_user();
    redirect("/");
}

if ($path === "/forgot" && $method === "GET") {
    render("forgot", ["title" => "Reset password", "notice" => null]);
}

if ($path === "/forgot" && $method === "POST") {
    $email = strtolower(trim(field($_POST, "email")));
    if (find_user_by_email($email)) {
        // PATCH: token is now random; it is delivered out-of-band (server log = mail stand-in), never shown here.
        $token = issue_reset_token($email);
        if ($token !== null) {
            deliver_reset_link($email, $token);
        }
    }
    render("forgot", [
        "title" => "Reset password",
        // PATCH: text updated - tokens now last 30 minutes and work once.
        "notice" => "If that address is in Locker, a reset link was queued for campus mail. The link works once and expires after 30 minutes.",
    ]);
}

if ($path === "/reset" && $method === "GET") {
    render("reset", [
        "title" => "Choose a new password",
        "email" => field($_GET, "email"),
        "token" => field($_GET, "token"),
        "error" => null,
    ]);
}

if ($path === "/reset" && $method === "POST") {
    $email = strtolower(trim(field($_POST, "email")));
    $token = trim(field($_POST, "token"));
    $password = field($_POST, "password");
    if (strlen($password) < 8 || strlen($password) > 72) {
        render("reset", ["title" => "Choose a new password", "email" => $email, "token" => $token, "error" => "Password needs 8 to 72 characters."]);
    }
    // PATCH: consume_reset_token() now needs a real, unexpired, unused token that was issued for this email.
    if (!consume_reset_token($email, $token)) {
        render("reset", ["title" => "Choose a new password", "email" => $email, "token" => $token, "error" => "That reset token is not valid for this address. Request a new one."]);
    }
    set_user_password($email, $password);
    // PATCH: a successful reset also lifts the login pause. Old sessions die via the pw_sig check in auth.php.
    clear_failures($email);
    render("login", ["title" => "Sign in", "email" => $email, "error" => "Password updated. Sign in."]);
}

if ($path === "/items/new" && $method === "GET") {
    require_login();
    render("new_item", ["title" => "Store a secret", "error" => null, "values" => []]);
}

if ($path === "/items" && $method === "POST") {
    require_login();
    $user = current_user();
    $label = trim(field($_POST, "label"));
    $secret = trim(field($_POST, "secret"));
    $notes = trim(field($_POST, "notes"));
    // PATCH: added upper limits so one request cannot stuff megabytes into the database.
    if (strlen($label) < 2 || strlen($secret) < 2 || strlen($label) > 120 || strlen($secret) > 2000 || strlen($notes) > 4000) {
        render("new_item", ["title" => "Store a secret", "error" => "Label and secret are required (label up to 120, secret up to 2000, notes up to 4000 characters).", "values" => compact("label", "secret", "notes")]);
    }
    add_vault_item((int)$user["id"], $label, $secret, $notes);
    redirect("/");
}

http_response_code(404);
render("error", ["title" => "Missing", "message" => "That page is not in Locker."], 404);
