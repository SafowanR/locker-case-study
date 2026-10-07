<section class="narrow">
  <h1>Choose a new password</h1>
  <?php if (!empty($error)): ?><p class="flash"><?= e($error) ?></p><?php endif; ?>
  <form method="post" action="/reset" class="stack">
    <?= csrf_field() ?><!-- PATCH: CSRF token, checked by verify_csrf() -->
    <label><span>Email</span><input type="email" name="email" value="<?= e($email) ?>" required></label>
    <label><span>Token</span><input type="text" name="token" value="<?= e($token) ?>" required></label>
    <label><span>New password</span><input type="password" name="password" minlength="8" maxlength="72" required></label>
    <button type="submit">Update password</button>
  </form>
</section>
