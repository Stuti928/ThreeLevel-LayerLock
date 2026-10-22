# Hand-written migration — widen password fields to accommodate PBKDF2 hashes.
# This is a schema-only migration; no data is touched here.
# The companion data migration (0004) hashes the stored plaintext values.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_alter_userdata_id'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userdata',
            name='username',
            field=models.CharField(max_length=150),
        ),
        migrations.AlterField(
            model_name='userdata',
            name='password',
            field=models.CharField(max_length=255),
        ),
        migrations.AlterField(
            model_name='userdata',
            name='rgb_password',
            field=models.CharField(max_length=255),
        ),
    ]
