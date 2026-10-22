from django.db import models


class UserData(models.Model):
    username = models.CharField(max_length=150)
    email = models.EmailField()

    # Stored as Django PBKDF2SHA256 hashes (max ~89 chars for current defaults;
    # 255 gives headroom for future algorithm changes).
    password = models.CharField(max_length=255)
    rgb_password = models.CharField(max_length=255)

    image_password = models.ImageField(upload_to='password_images/')

    def __str__(self):
        return self.username