<?php
declare(strict_types=1);

function db(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }
    $path = getenv("DATABASE_PATH") ?: (dirname(__DIR__) . "/data/locker.db");
    if (!is_dir(dirname($path))) {
        // PATCH: was 0777 (world-writable). The data folder holds every secret, so owner-only.
        mkdir(dirname($path), 0700, true);
    }
    $pdo = new PDO("sqlite:" . $path);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $pdo->exec("PRAGMA journal_mode = WAL");
    $pdo->exec("PRAGMA busy_timeout = 5000");
    return $pdo;
}

function init_db(): void
{
    db()->exec("
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            display_name TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'member',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS vault_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            label TEXT NOT NULL,
            secret TEXT NOT NULL,
            notes TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
    ");
    // PATCH: reset_tokens moved into migrate() because its columns changed.
    migrate();
}

// PATCH: new. One-time upgrade so a database created by the unpatched app is fixed too,
// not just fresh installs. PRAGMA user_version records that it already ran.
function migrate(): void
{
    $pdo = db();
    if ((int)$pdo->query("PRAGMA user_version")->fetchColumn() >= 1) {
        return;
    }
    $pdo->beginTransaction();
    try {
        // Old predictable tokens are thrown away; new table stores a token hash + expiry.
        $pdo->exec("DROP TABLE IF EXISTS reset_tokens");
        $pdo->exec("
            CREATE TABLE reset_tokens (
                email TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            )
        ");
        // Failed sign-ins, used by the login throttle in auth.php.
        $pdo->exec("CREATE TABLE IF NOT EXISTS login_attempts (email TEXT NOT NULL, at INTEGER NOT NULL)");
        $pdo->exec("CREATE INDEX IF NOT EXISTS idx_login_attempts ON login_attempts (email, at)");

        $update = $pdo->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
        foreach ($pdo->query("SELECT id, password_hash FROM users")->fetchAll() as $u) {
            // Only touch old unsalted SHA-256 values (64 hex chars).
            if (!preg_match('/^[0-9a-f]{64}$/', $u["password_hash"])) {
                continue;
            }
            if (hash_equals(hash("sha256", "not-in-the-readme"), $u["password_hash"])) {
                // The advisor's old password was hardcoded in this file, so it is public. Replace it.
                $update->execute([hash_password(bin2hex(random_bytes(24))), $u["id"]]);
            } else {
                // No plain SHA-256 left on disk: wrap it in bcrypt. verify_password() understands the
                // prefix, and /login swaps it for a normal hash the next time the user signs in.
                $update->execute([LEGACY_PREFIX . password_hash($u["password_hash"], PASSWORD_DEFAULT), $u["id"]]);
            }
        }
        $pdo->exec("PRAGMA user_version = 1");
        $pdo->commit();
    } catch (Throwable $e) {
        $pdo->rollBack();
        throw $e;
    }
}

function seed(): void
{
    $pdo = db();
    $count = (int)$pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();
    if ($count > 0) {
        return;
    }

    $pdo->beginTransaction();
    try {
        $maya = create_user("maya@campus.edu", "Maya Chen", "campus123", "member");
        create_user("devon@campus.edu", "Devon Alvarez", "campus123", "member");
        // PATCH: was the literal "not-in-the-readme". The repo is public, so that password was public too.
        // Now it comes from the ADVISOR_PASSWORD env var, or is random (advisor then uses the reset flow).
        $advisorPassword = getenv("ADVISOR_PASSWORD") ?: bin2hex(random_bytes(24));
        $advisor = create_user("advisor@campus.edu", "Club Advisor", $advisorPassword, "advisor");

        add_vault_item($maya, "Shop door code", "4421#", "Works on the east stair after 6pm.");
        add_vault_item($maya, "Instagram login", "robotics.club / tape-measure", "2FA is Maya's phone.");
        add_vault_item(
            $advisor,
            "Advisor hold — do not share on the wall",
            "LOCKER-4410",
            "Emergency disbursement PIN for the student-org card. Rotate after spring banquet."
        );
        $pdo->commit();
    } catch (Throwable $e) {
        $pdo->rollBack();
        throw $e;
    }
}
