<?php
declare(strict_types=1);

// PATCH: never print PHP errors to the browser (they leak file paths and SQL). Log them instead.
ini_set("display_errors", "0");
ini_set("log_errors", "1");
set_exception_handler(function (Throwable $e): void {
    error_log("[locker] " . get_class($e) . ": " . $e->getMessage());
    if (!headers_sent()) {
        http_response_code(500);
        header("Content-Type: text/plain; charset=utf-8");
    }
    echo "Something went wrong.";
});

// PATCH: session cookie hardening. The old cookie had no flags at all.
//  - HttpOnly: page scripts cannot read it
//  - SameSite=Lax: not sent on cross-site POSTs
//  - Secure: only sent over HTTPS when the site is on HTTPS (Render sets X-Forwarded-Proto)
//  - strict mode: PHP refuses session ids it did not create (session fixation)
$isHttps = (($_SERVER["HTTPS"] ?? "") === "on") || (($_SERVER["HTTP_X_FORWARDED_PROTO"] ?? "") === "https");
ini_set("session.use_strict_mode", "1");
ini_set("session.use_only_cookies", "1");
session_name("locker_sid");
session_set_cookie_params([
    "lifetime" => 0,
    "path" => "/",
    "secure" => $isHttps,
    "httponly" => true,
    "samesite" => "Lax",
]);
session_start();

// PATCH: security headers on every response (none were sent before).
header_remove("X-Powered-By");                       // do not advertise the PHP version
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");                     // no clickjacking of the vault
header("Referrer-Policy: no-referrer");              // the reset link has a token in the URL
header("Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'");
header("Cache-Control: no-store");                   // secrets are not kept in browser/proxy caches
if ($isHttps) {
    header("Strict-Transport-Security: max-age=31536000");
}

require __DIR__ . "/db.php";
require __DIR__ . "/crypto.php";
require __DIR__ . "/auth.php";
require __DIR__ . "/vault.php";

init_db();
seed();

function render(string $view, array $data = [], int $status = 200): void
{
    http_response_code($status);
    extract($data, EXTR_SKIP);
    $currentUser = current_user();
    require dirname(__DIR__) . "/templates/layout_start.php";
    require dirname(__DIR__) . "/templates/{$view}.php";
    require dirname(__DIR__) . "/templates/layout_end.php";
    exit;
}

function redirect(string $to): void
{
    header("Location: " . $to);
    exit;
}

function json_out(array $data): void
{
    header("Content-Type: application/json");
    echo json_encode($data);
    exit;
}

function e(mixed $value): string
{
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8");
}

// PATCH: new - CSRF protection. No form had a token, so another website could submit
// /items, /logout, /login etc. using the visitor's cookie.
function csrf_token(): string
{
    if (empty($_SESSION["csrf"])) {
        $_SESSION["csrf"] = bin2hex(random_bytes(32));
    }
    return $_SESSION["csrf"];
}

// Hidden input that every <form method="post"> in templates/ now includes.
function csrf_field(): string
{
    return '<input type="hidden" name="csrf" value="' . e(csrf_token()) . '">';
}

// Called once in index.php for every POST.
function verify_csrf(): void
{
    $sent = $_POST["csrf"] ?? "";
    if (!is_string($sent) || empty($_SESSION["csrf"]) || !hash_equals($_SESSION["csrf"], $sent)) {
        render("error", ["title" => "Form expired", "message" => "That form is out of date. Go back, reload the page, and try again."], 400);
    }
}

// PATCH: new - read a form field as a string. ?email[]=x style arrays used to reach (string) casts
// and raise warnings; now they are just treated as empty.
function field(array $source, string $name): string
{
    $v = $source[$name] ?? "";
    return is_string($v) ? $v : "";
}
