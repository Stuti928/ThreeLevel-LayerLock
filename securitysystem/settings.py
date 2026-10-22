"""
Django settings for securitysystem project.

Configuration is split into two layers:
  - This file contains safe defaults for local development.
  - Sensitive values and production overrides are read from environment
    variables (see .env.example).  Never commit .env to version control.

For a production deployment checklist see:
  https://docs.djangoproject.com/en/5.2/howto/deployment/checklist/
"""

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------

# SECURITY WARNING: keep the secret key used in production secret!
# Generate a new key:  python -c "import secrets; print(secrets.token_urlsafe(50))"
# In production, set the SECRET_KEY environment variable; do NOT commit it.
SECRET_KEY = os.environ.get(
    'SECRET_KEY',
    'django-insecure--mp)k^*eh62*#%9n6o47a@v^40q4e0lwi%$^!%-hi=y-j4ryc3',
)

# SECURITY WARNING: never enable DEBUG in production.
DEBUG = os.environ.get('DEBUG', 'True') == 'True'

# In production, list every hostname/IP that serves the application.
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', 'localhost 127.0.0.1').split()

# ---------------------------------------------------------------------------
# Application definition
# ---------------------------------------------------------------------------

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    'django_ratelimit',
    'accounts',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'securitysystem.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'securitysystem.wsgi.application'

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# ---------------------------------------------------------------------------
# Password hashing
#
# Django's default PBKDF2-SHA256 is used for both account passwords and RGB
# passwords.  The hasher list is explicit here so it is easy to add Argon2
# or bcrypt later by prepending to this list.
# ---------------------------------------------------------------------------

PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
]

# ---------------------------------------------------------------------------
# Password validation (used by Django's own auth forms; not enforced by our
# custom UserData model, but kept here for completeness).
# ---------------------------------------------------------------------------

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# ---------------------------------------------------------------------------
# Internationalisation
# ---------------------------------------------------------------------------

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# ---------------------------------------------------------------------------
# Static & media files
# ---------------------------------------------------------------------------

STATIC_URL = 'static/'
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# ---------------------------------------------------------------------------
# File upload limits
# Reject request bodies larger than 10 MB before they reach view code.
# The per-file limit (5 MB) is also enforced in the image_auth view.
# ---------------------------------------------------------------------------

DATA_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024   # 10 MB
FILE_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024   # 10 MB

# ---------------------------------------------------------------------------
# Default primary key
# ---------------------------------------------------------------------------

DEFAULT_AUTO_FIELD = 'django.db.models.AutoField'

# ---------------------------------------------------------------------------
# Authentication redirects
# ---------------------------------------------------------------------------

LOGIN_URL = '/login/'

# ---------------------------------------------------------------------------
# Session & CSRF security
#
# Development defaults — all cookies are HTTP-only (no JS access).
# For production over HTTPS, add these to your environment / settings override:
#
#   SESSION_COOKIE_SECURE  = True   # Send session cookie only over HTTPS
#   CSRF_COOKIE_SECURE     = True   # Send CSRF cookie only over HTTPS
#   SECURE_HSTS_SECONDS    = 31536000
#   SECURE_HSTS_INCLUDE_SUBDOMAINS = True
#   SECURE_HSTS_PRELOAD    = True
#   SECURE_SSL_REDIRECT    = True   # Redirect all HTTP → HTTPS
# ---------------------------------------------------------------------------

SESSION_COOKIE_HTTPONLY = True   # Prevent JavaScript from reading the cookie
CSRF_COOKIE_HTTPONLY = True      # Same for the CSRF token cookie

# Production-only overrides — activate when HTTPS is available.
if os.environ.get('DJANGO_PRODUCTION') == '1':
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_SSL_REDIRECT = True

# ---------------------------------------------------------------------------
# Rate limiting (django-ratelimit)
#
# django-ratelimit uses the Django cache backend named by RATELIMIT_USE_CACHE.
# The default LocMemCache works correctly for local single-process development
# but is not shared across processes or server restarts, so it is unsuitable
# for production multi-process deployments.
#
# django-ratelimit's system check flags LocMemCache as unsupported.  We
# silence that check here and document the production requirement below.
#
# Production requirement: configure CACHES to use memcached or Redis and
# remove 'django_ratelimit.E003' and 'django_ratelimit.W001' from this list.
# ---------------------------------------------------------------------------

RATELIMIT_USE_CACHE = 'default'

SILENCED_SYSTEM_CHECKS = [
    'django_ratelimit.E003',  # LocMemCache is not shared — acceptable for dev
    'django_ratelimit.W001',  # LocMemCache not officially supported — dev only
]
