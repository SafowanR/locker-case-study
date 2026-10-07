<?php
declare(strict_types=1);

// Password and token helpers. Keep these in one place so login and reset stay in sync.

// PATCH: marks an old SHA-256 hash that the DB upgrade wrapped in bcrypt (see migrate() in db.php).
const LEGACY_PREFIX = 'sha256w$';

// PATCH: reset tokens now live 30 minutes instead of the whole calendar day.
const RESET_TTL_SECONDS = 1800;

function hash_password(string $password): string
{
    // PATCH: was hash("sha256", $password) - unsalted and fast, so a leaked DB cracks instantly
    // and equal passwords gave equal hashes. password_hash() is salted, slow bcrypt.
    return password_hash($password, PASSWORD_DEFAULT);
}

function verify_password(string $password, string $stored): bool
{
    // PATCH: old accounts still sign in - their SHA-256 value was wrapped in bcrypt by migrate().
    if (str_starts_with($stored, LEGACY_PREFIX)) {
        return password_verify(hash("sha256", $password), substr($stored, strlen(LEGACY_PREFIX)));
    }
    // PATCH: password_verify() reads the salt/cost from the stored hash and compares in constant time.
    return password_verify($password, $stored);
}

// PATCH: new helper - true when a hash should be replaced with a fresh bcrypt hash at next login.
function password_needs_upgrade(string $stored): bool
{
    return str_starts_with($stored, LEGACY_PREFIX) || password_needs_rehash($stored, PASSWORD_DEFAULT);
}

// PATCH: removed reset_token_for(). It built the token as sha1(email|date) with no secret,
// so anyone could compute a valid token for any address (including the advisor).

function issue_reset_token(string $email): ?string
{
    $pdo = db();
    // PATCH: at most one new token per minute per address, so /forgot cannot be used to spam.
    $last = $pdo->prepare("SELECT expires_at FROM reset_tokens WHERE email = ?");
    $last->execute([$email]);
    $expires = $last->fetchColumn();
    if ($expires !== false && ((int)$expires - RESET_TTL_SECONDS) > time() - 60) {
        return null;
    }

    // PATCH: token is 32 random bytes from the OS CSPRNG - it cannot be derived from the email or date.
    $token = bin2hex(random_bytes(32));
    $pdo->prepare("DELETE FROM reset_tokens WHERE email = ?")->execute([$email]);
    // PATCH: store only a hash of the token plus an expiry, so a DB leak does not leak usable tokens.
    $pdo->prepare("INSERT INTO reset_tokens (email, token_hash, expires_at) VALUES (?, ?, ?)")
        ->execute([$email, hash("sha256", $token), time() + RESET_TTL_SECONDS]);
    return $token;
}

function consume_reset_token(string $email, string $token): bool
{
    $pdo = db();
    $stmt = $pdo->prepare("SELECT token_hash, expires_at FROM reset_tokens WHERE email = ?");
    $stmt->execute([$email]);
    $row = $stmt->fetch();
    // PATCH: was "return true" when no token was stored, so a reset worked without ever asking for one.
    // Now a token must have actually been issued for this address.
    if (!$row) {
        return false;
    }
    // PATCH: enforce the expiry.
    if ((int)$row["expires_at"] < time()) {
        $pdo->prepare("DELETE FROM reset_tokens WHERE email = ?")->execute([$email]);
        return false;
    }
    if (!hash_equals((string)$row["token_hash"], hash("sha256", $token))) {
        return false;
    }
    // PATCH: single use - the old code never deleted the token, so it could be replayed all day.
    $pdo->prepare("DELETE FROM reset_tokens WHERE email = ?")->execute([$email]);
    return true;
}

// PATCH: new. The app has no mailer, so the reset link goes to the server log (the "campus mail"
// stand-in). It is never sent back to the browser. APP_URL comes from config, not the Host header,
// so a forged Host header cannot point the link at another site.
function deliver_reset_link(string $email, string $token): void
{
    $base = rtrim((string)(getenv("APP_URL") ?: ""), "/");
    $link = $base . "/reset?email=" . rawurlencode($email) . "&token=" . $token;
    error_log("[locker-mail] to={$email} reset link (valid 30 min, one use): {$link}");
}
