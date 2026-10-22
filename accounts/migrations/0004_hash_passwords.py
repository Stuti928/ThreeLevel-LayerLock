# Data migration — hash all plaintext passwords in the UserData table.
#
# FORWARD:
#   For each row whose password / rgb_password does not already look like a
#   Django hash, replace the plaintext value with make_password(plaintext).
#   Rows that are already hashed are left untouched — the migration is
#   idempotent and safe to re-run.
#
# BACKWARD (rollback):
#   Irreversible — hashed values cannot be reversed to plaintext.
#   Rollback by restoring the database backup created before this migration.
#
# Algorithm used: Django default (PBKDF2-SHA256 with per-value random salt).

from django.db import migrations
from django.db.migrations.exceptions import IrreversibleError

# Prefixes that identify a value as already hashed by Django's hasher stack.
_HASH_PREFIXES = (
    'pbkdf2_sha256$',
    'pbkdf2_sha1$',
    'argon2$',
    'bcrypt_sha256$',
    'bcrypt$',
    'sha1$',
    'md5$',
)


def _is_hashed(value: str) -> bool:
    return any(value.startswith(p) for p in _HASH_PREFIXES)


def hash_plaintext_passwords(apps, schema_editor):
    """Hash any plaintext password / rgb_password rows."""
    # Use the historical model provided by the migration framework so this
    # migration remains correct even if the model changes later.
    UserData = apps.get_model('accounts', 'UserData')

    # Import make_password inside the function so it picks up the hasher
    # configuration that is active at the time the migration runs.
    from django.contrib.auth.hashers import make_password

    rows_updated = 0
    for user in UserData.objects.all():
        changed = False

        if not _is_hashed(user.password):
            user.password = make_password(user.password)
            changed = True

        if not _is_hashed(user.rgb_password):
            user.rgb_password = make_password(user.rgb_password)
            changed = True

        if changed:
            user.save(update_fields=['password', 'rgb_password'])
            rows_updated += 1

    # Print is suppressed during tests; visible during ./manage.py migrate
    print(f'\n  Hashed passwords for {rows_updated} user(s).')


def reverse_hash_passwords(apps, schema_editor):
    raise IrreversibleError(
        "Hashed passwords cannot be reversed to plaintext. "
        "Restore the database backup (db.sqlite3.backup_*) to roll back."
    )


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0003_widen_password_fields'),
    ]

    operations = [
        migrations.RunPython(
            hash_plaintext_passwords,
            reverse_code=reverse_hash_passwords,
        ),
    ]
