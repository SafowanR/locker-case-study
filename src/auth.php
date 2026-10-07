<?php
declare(strict_types=1);

// PATCH: login throttle settings - 5 wrong passwords per account per 15 minutes.
const LOGIN_MAX_FAILURES = 5;
const LOGIN_WINDOW_SECONDS = 900;

function find_user_by_email(string $email): ?array
{
    $stmt = db()->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $row = $stmt->fetch();
    return $row ?: null;
}

function create_user(string $email, string $display, string $password, string $role): int
{
    $stmt = db()->prepare("INSERT INTO users (email, password_hash, display_name, role) VALUES (?, ?, ?, ?)");
    $stmt->execute([$email, hash_password($password), $display, $role]);
    return (int)db()->lastInsertId();
}

function set_user_password(string $email, string $password): void
{
    $stmt = db()->prepare("UPDATE users SET password_hash = ? WHERE email = ?");
    $stmt->execute([hash_password($password), $email]);
}

// PATCH: new. Short fingerprint of the current password hash, kept in the session.
function password_sig(string $passwordHash): string
{
    return substr(hash("sha256", $passwordHash), 0, 32);
}

function login_user(int $userId): void
{
    session_regenerate_id(true);
    $_SESSION["user_id"] = $userId;
    // PATCH: remember which password this session logged in with (checked in current_user()).
    $stmt = db()->prepare("SELECT password_hash FROM users WHERE id = ?");
    $stmt->execute([$userId]);
    $_SESSION["pw_sig"] = password_sig((string)$stmt->fetchColumn());
    // PATCH: fresh CSRF token for the signed-in session.
    unset($_SESSION["csrf"]);
}

function logout_user(): void
{
    $_SESSION = [];
    if (ini_get("session.use_cookies")) {
        $p = session_get_cookie_params();
        // PATCH: clear the cookie with the same flags it was set with (adds SameSite).
        setcookie(session_name(), "", [
            "expires" => time() - 42000,
            "path" => $p["path"],
            "domain" => $p["domain"],
            "secure" => $p["secure"],
            "httponly" => $p["httponly"],
            "samesite" => $p["samesite"] ?: "Lax",
        ]);
    }
    session_destroy();
}

function current_user(): ?array
{
    if (empty($_SESSION["user_id"])) {
        return null;
    }
    $stmt = db()->prepare("SELECT id, email, display_name, role, password_hash FROM users WHERE id = ?");
    $stmt->execute([(int)$_SESSION["user_id"]]);
    $row = $stmt->fetch();
    if (!$row) {
        return null;
    }
    // PATCH: if the password changed since this session logged in (e.g. a reset), the session is dead.
    // Before, a stolen/old session stayed valid forever even after the owner reset the password.
    if (!hash_equals(password_sig((string)$row["password_hash"]), (string)($_SESSION["pw_sig"] ?? ""))) {
        $_SESSION = [];
        return null;
    }
    unset($row["password_hash"]);
    return $row;
}

function require_login(): void
{
    if (!current_user()) {
        redirect("/login");
    }
}

// PATCH: new - login throttling. The old /login allowed unlimited password guesses.
function too_many_failures(string $email): bool
{
    $stmt = db()->prepare("SELECT COUNT(*) FROM login_attempts WHERE email = ? AND at > ?");
    $stmt->execute([$email, time() - LOGIN_WINDOW_SECONDS]);
    return (int)$stmt->fetchColumn() >= LOGIN_MAX_FAILURES;
}

function record_failure(string $email): void
{
    $pdo = db();
    $pdo->prepare("INSERT INTO login_attempts (email, at) VALUES (?, ?)")->execute([$email, time()]);
    // Keep the table small.
    $pdo->prepare("DELETE FROM login_attempts WHERE at <= ?")->execute([time() - LOGIN_WINDOW_SECONDS]);
}

function clear_failures(string $email): void
{
    db()->prepare("DELETE FROM login_attempts WHERE email = ?")->execute([$email]);
}
