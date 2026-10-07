<?php
$path = parse_url($_SERVER["REQUEST_URI"] ?? "/", PHP_URL_PATH) ?: "/";
// PATCH: was "serve any file that exists under public/". Now only known static types are served
// directly, and only if the resolved path is really inside public/. Everything else goes to index.php.
$file = realpath(__DIR__ . $path);
$static = ["css", "js", "png", "jpg", "svg", "ico", "txt"];
if (
    $file !== false
    && str_starts_with($file, __DIR__ . DIRECTORY_SEPARATOR)
    && is_file($file)
    && in_array(strtolower(pathinfo($file, PATHINFO_EXTENSION)), $static, true)
) {
    return false;
}
require __DIR__ . "/index.php";
