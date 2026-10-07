<section class="narrow">
  <h1>Create a Locker account</h1>
  <?php if (!empty($error)): ?><p class="flash"><?= e($error) ?></p><?php endif; ?>
  <form method="post" action="/register" class="stack">
    <?= csrf_field() ?><!-- PATCH: CSRF token, checked by verify_csrf() -->
    <label><span>Campus email</span><input type="email" name="email" value="<?= e($values["email"] ?? "") ?>" required></label>
    <label><span>Display name</span><input type="text" name="display_name" value="<?= e($values["display_name"] ?? "") ?>" required></label>
    <label><span>Password</span><input type="password" name="password" minlength="8" maxlength="72" required></label>
    <button type="submit">Create account</button>
  </form>
</section>
