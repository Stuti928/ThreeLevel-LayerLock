# ThreeLevel LayerLock — Three-Level Authentication System

A secure Django web application implementing multi-factor, sequential
authentication across three independent credential layers: a conventional
password, a strictly validated colour secret (RGB triplet, hexadecimal, or
recognised colour name), and an image-key verification layer.

---

## Features

- **Level 1 — Password authentication:** Standard email + password sign-in with PBKDF2-SHA256 password hashing and generic error messaging.
- **Level 2 — RGB colour authentication:** Strict colour validation accepting RGB triplets (e.g. `255,0,128`), hexadecimal colours (e.g. `#FF0080` or `FF0080`), or recognised CSS3/X11 colour names (e.g. `purple`, `red`, `blue`). Normalised and hashed at rest.
- **Level 3 — Image authentication:** Pixel-content verification using Pillow. Uploaded files are verified via normalised 64×64 thumbnail SHA-256 digests; raw files are never permanently stored.
- **Sequential access control:** Enforced strictly via session state machine (`user_id` → `rgb_passed` → `authenticated`). Direct navigation to higher levels without passing previous gates is blocked.
- **Security & hardening:** IP-based rate limiting (10 attempts/min via `django-ratelimit`), timing-safe password verification, CSRF enforcement, and upload size/type inspection.
- **Responsive dark UI:** Professional cyber-security interface built with pure CSS and glassmorphism styling.
- **Production-ready configuration:** `.gitignore`, `.env.example`, and production deployment guidelines included.

---

## Technologies

| Layer | Technology |
|---|---|
| Backend | Python 3.10+, Django 5.2 |
| Security | Django PBKDF2-SHA256, django-ratelimit 4.1 |
| Image processing | Pillow 12.3 (PIL.ImageColor) |
| Database | SQLite (development) |
| Templating | Django templates + Vanilla CSS |
| Session storage | Django database-backed sessions |

---

## Architecture & folder structure

```
ThreeLevel-LayerLock/
├── accounts/               # Main Django application
│   ├── migrations/         # Database migrations (0001 to 0004)
│   ├── models.py           # UserData model
│   ├── validators.py       # Level 2 colour validation module
│   ├── views.py            # View logic, session guards, auth pipeline
│   ├── urls.py             # App-level URL routing
│   └── tests.py            # Comprehensive 85-test automated test suite
├── securitysystem/         # Django project package
│   ├── settings.py         # Config with env-variable overrides & rate limiting
│   ├── urls.py             # Root URL configuration
│   └── wsgi.py
├── templates/              # HTML templates (LayerLock UI)
│   ├── base.html           # Layout shell, glassmorphism design system
│   ├── home.html           # Landing page with interactive feature overview
│   ├── register.html       # Three-tier credential registration
│   ├── login.html          # Level 1 sign-in
│   ├── rgb_auth.html       # Level 2 colour authentication
│   ├── image_auth.html     # Level 3 image verification
│   └── dashboard.html      # Protected user dashboard
├── media/                  # Uploaded image credentials (gitignored)
│   └── password_images/
├── .env.example            # Environment variable template
├── .gitignore              # Git ignore rules for venv, DB, caches, secrets
├── project_report.docx     # Project documentation report
├── requirements.txt        # Pinned Python dependencies
└── manage.py
```

---

## Prerequisites

- Python 3.10 or later
- pip (bundled with Python)
- Windows, macOS, or Linux

---

## Windows setup and installation

```powershell
# 1. Clone the repository
git clone https://github.com/Stuti928/ThreeLevel-LayerLock.git
cd ThreeLevel-LayerLock

# 2. Create and activate a virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Copy the environment template
copy .env.example .env
# Edit .env and set a strong SECRET_KEY

# 5. Apply database migrations
python manage.py migrate

# 6. Start the development server
python manage.py runserver
```

Open your browser at **http://127.0.0.1:8000/**

---

## Database migrations

```powershell
# Apply all pending migrations
python manage.py migrate

# Check migration status
python manage.py showmigrations
```

No custom migrations are needed for fresh installations. All tables are
created from the existing migration files in `accounts/migrations/`.

---

## How to use each authentication stage

### Registration (`/register/`)
1. Fill in Username, Email address, and Password (Level 1 credential).
2. Enter a valid colour secret (Level 2 credential):
   - **RGB triplet:** `255,0,128` (integers 0–255, optional whitespace allowed).
   - **Hexadecimal colour:** `#FF0080` or `FF0080` (6 hex digits).
   - **Recognised colour name:** `purple`, `red`, `blue`, `green`, `black`, `white`, etc. (standard CSS3/X11 names).
   *(Arbitrary text is rejected).*
3. Upload an image file from your computer (Level 3 credential). **Keep a copy of this image** — you must upload it again to authenticate.
4. Click **Create account**. You are redirected to the sign-in page.

### Sign in — Level 1 (`/login/`)
Enter the email and password you registered. On success you are redirected to Level 2.

### RGB Authentication — Level 2 (`/rgb/`)
Enter the colour password you registered (RGB triplet, hex, or colour name). On success you are redirected to Level 3.

### Image Authentication — Level 3 (`/image-auth/`)
Upload the same image file you registered. The pixel content of the uploaded image is compared against the stored image using a normalised SHA-256 hash — the filename does not matter, but the pixel content must match exactly. On success you are redirected to the dashboard.

### Dashboard (`/dashboard/`)
Visible only after completing all three levels. Shows an authentication summary. Use **Sign out** to end the session.

### Logout (`/logout/`)
Flushes the session and redirects to the sign-in page.

---

## Testing

```powershell
# Run Django system checks
python manage.py check

# Run the full automated test suite (85 tests covering guards, validation, auth, rate limiting)
python manage.py test accounts
```

### Manual test checklist

| Test | Expected result |
|---|---|
| `GET /` | Home page with Register and Sign in buttons |
| `GET /dashboard/` without session | Redirect to `/login/` |
| `GET /rgb/` without session | Redirect to `/login/` |
| `GET /image-auth/` without Level 2 | Redirect to `/rgb/` |
| Register with all fields blank | Field-level validation errors |
| Register with arbitrary RGB text (`ABC`) | "Enter a valid RGB value, hexadecimal colour, or recognised colour name." |
| Sign in with wrong credentials | "Invalid email or password." |
| RGB auth with invalid format or wrong colour | "Invalid or incorrect RGB password. Please try again." |
| Image auth — no file submitted | "No file uploaded." |
| Image auth — file > 5 MB | "File too large." |
| Image auth — non-image file | "Invalid or unsupported image file." |
| Image auth — wrong image | "Image does not match." |
| Image auth — correct image | Redirect to `/dashboard/` |
| Logout | Session cleared, redirect to sign-in |

---

## Known limitations

- **Image pixel comparison** — the image-password hash is sensitive to exact pixel values. Re-saving a JPEG at a different quality level will change pixel values and fail authentication. Perceptual hashing would be more forgiving but is outside the scope of this demo.
- **SQLite** — suitable for local development only. A production deployment should use PostgreSQL or MySQL.
- **No HTTPS enforcement** — `SESSION_COOKIE_SECURE` and `CSRF_COOKIE_SECURE` must be set to `True` in production behind TLS.
- **No email verification** — accounts are created without confirming the email address.
- **RGB password is low-entropy by nature** — the credential is whatever text the user types (e.g. `255,0,0`). PBKDF2 protects the stored value, but a weak credential is still a weak credential.

---

## Development vs production settings

| Setting | Development | Production |
|---|---|---|
| `DEBUG` | `True` | `False` (via env var) |
| `SECRET_KEY` | Insecure default | Strong random key via `SECRET_KEY` env var |
| `ALLOWED_HOSTS` | `localhost 127.0.0.1` | Your domain(s) via `ALLOWED_HOSTS` env var |
| `SESSION_COOKIE_SECURE` | Not set (HTTP OK) | `True` (HTTPS only) |
| `CSRF_COOKIE_SECURE` | Not set | `True` |
| Database | SQLite | PostgreSQL / MySQL |
| Static files | Served by `runserver` | `collectstatic` + web server |
| Media files | Served by Django dev server | Served by web server (Nginx/Apache) |

Add the following to `settings.py` before deploying to production:

```python
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
```

---

## Preparing for public GitHub release

1. Ensure `.gitignore` excludes `db.sqlite3`, `db.sqlite3.backup_*`, `media/`, `password_images/`, `venv/`, and `.env`. ✓ Already configured.
2. **Generate a new `SECRET_KEY`** — see the section below. The default key in `settings.py` must be treated as publicly known.
3. Run `python manage.py check --deploy` (with `DEBUG=False`) and address all warnings.
4. Replace any personal images in `media/` before making the repository public.
5. Choose and add an open-source license (see below).

---

## Generating a new SECRET_KEY (Windows PowerShell)

The `SECRET_KEY` committed in this repository is insecure and must **never** be
used in production. Generate a fresh key locally and set it as an environment
variable — do not put it in any file that is committed to Git.

```powershell
# Step 1 — generate a strong random key (run this once)
.\venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(50))"

# Step 2 — set it for the current PowerShell session only (testing)
$env:SECRET_KEY = "paste-your-generated-key-here"

# Step 3 — for a persistent deployment, add the variable to your hosting
#           platform's environment configuration (e.g. Railway, Render, Azure).
#           Never put the real key in .env.example, settings.py, or any
#           file tracked by Git.
```

**Effect of rotating the key:**
Django uses `SECRET_KEY` to sign session cookies and CSRF tokens.  After
rotation, all active user sessions are invalidated — every logged-in user is
logged out automatically.  No database change is needed.

---

## Removing the old key from Git history (before first public push)

> **Only perform this step if the repository has never been pushed publicly.**
> If it has already been pushed, treat the key as permanently exposed and
> rotate to a new key instead of rewriting history.

The insecure default key was committed in the repository's initial state.
Before making the repository public, remove it from all historical commits
using `git-filter-repo`.

```powershell
# ── Prerequisites ───────────────────────────────────────────────────────────

# 1. Make a full backup of the repository before any rewrite.
#    If anything goes wrong you can restore from this copy.
Copy-Item -Path "." -Destination "..\ThreeLevel-LayerLock_backup" -Recurse

# 2. Verify the backup exists and looks correct.
Get-ChildItem "..\ThreeLevel-LayerLock_backup"

# 3. Install git-filter-repo (requires Python and pip).
.\venv\Scripts\python.exe -m pip install git-filter-repo

# ── Rewrite history ─────────────────────────────────────────────────────────

# 4. Create a replacements file.
#    Replace OLD_KEY_HERE with the exact key string from settings.py.
#    Do NOT paste it into this README — only into the local file below.
Set-Content -Path "replacements.txt" -Value "OLD_KEY_HERE==>REDACTED_SECRET_KEY"

# 5. Run the rewrite (this modifies ALL commits that contain the old key).
git filter-repo --replace-text replacements.txt

# 6. Remove the replacements file — it contains the old key.
Remove-Item "replacements.txt"

# ── Verify ──────────────────────────────────────────────────────────────────

# 7. Confirm the old key no longer appears in any commit.
git log -p | Select-String "django-insecure"
# Expected: no output (zero matches).

# 8. Run the tests to confirm nothing was broken.
.\venv\Scripts\python.exe manage.py test accounts

# ── Push ────────────────────────────────────────────────────────────────────

# 9. Force-push the rewritten history to GitHub.
#    Only do this before anyone else has cloned the repository.
git push origin main --force
```

> ⚠ `git filter-repo` rewrites commit SHAs. Any existing clones or forks
> become incompatible.  Only use this before the first public push.

---

## License

A license has **not** been added automatically. Please choose one and confirm
before committing it. The **MIT License** is a common choice for educational
projects of this type. Once you confirm, add a `LICENSE` file to the
repository root.

---

## Contributing

Pull requests and issues are welcome. Please open an issue first to discuss
significant changes.
