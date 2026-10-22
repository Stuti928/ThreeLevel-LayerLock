import hashlib

from django.contrib import messages
from django.contrib.auth.hashers import check_password, make_password
from django.shortcuts import render, redirect
from django_ratelimit.decorators import ratelimit
from PIL import Image, UnidentifiedImageError

from .models import UserData
from .validators import validate_rgb_password, RGB_VALIDATION_ERROR_MESSAGE

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum allowed upload size for Level 3 image auth (5 MB).
_MAX_IMAGE_UPLOAD_BYTES = 5 * 1024 * 1024

# Prefixes that identify a value already hashed by Django's hasher stack.
# Used to support a smooth transition from the pre-hardening database state.
_HASH_PREFIXES = (
    'pbkdf2_sha256$',
    'pbkdf2_sha1$',
    'argon2$',
    'bcrypt_sha256$',
    'bcrypt$',
    'sha1$',
    'md5$',
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _image_hash(img: Image.Image) -> str:
    """Return a stable SHA-256 hex digest for a PIL Image.

    The image is converted to RGBA and resized to a fixed 64×64 thumbnail so
    that minor re-saves (different JPEG quality, EXIF metadata) still produce
    the same hash as long as the pixel content is the same.
    """
    normalised = img.convert("RGBA").resize((64, 64), Image.LANCZOS)
    return hashlib.sha256(normalised.tobytes()).hexdigest()


def _is_hashed(value: str) -> bool:
    """Return True if value looks like a Django-hashed password."""
    return any(value.startswith(p) for p in _HASH_PREFIXES)


def _verify_password(plaintext: str, stored: str) -> bool:
    """Verify a password against its stored representation.

    Supports both hashed values (post-migration) and plaintext values
    (legacy rows that somehow escaped the migration), with automatic
    rehashing of legacy rows not handled here — call _upgrade_if_needed()
    for that.  Never leaks the stored value on failure.
    """
    if _is_hashed(stored):
        return check_password(plaintext, stored)
    # Legacy plaintext comparison — only reached for rows that were not
    # hashed by the data migration (e.g. a fresh dev DB with no migration).
    return stored == plaintext


def _upgrade_hash_if_needed(user, field: str, plaintext: str) -> None:
    """If the stored value for `field` is still plaintext, hash it now.

    This provides a self-healing path for any row that was not caught by
    the data migration (e.g. inserted before migration, direct DB edits).
    """
    stored = getattr(user, field)
    if not _is_hashed(stored):
        setattr(user, field, make_password(plaintext))
        user.save(update_fields=[field])


def _require_session(request):
    """Return a redirect response if no user_id is in the session, else None."""
    if not request.session.get('user_id'):
        return redirect('login')
    return None


# ---------------------------------------------------------------------------
# Public views
# ---------------------------------------------------------------------------

def home(request):
    """Landing page — redirects already-authenticated users to the dashboard."""
    if request.session.get('user_id'):
        return redirect('dashboard')
    return render(request, 'home.html')


def register(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '').strip()
        rgb_password = request.POST.get('rgb_password', '').strip()
        image_password = request.FILES.get('image_password')

        errors = {}
        if not username:
            errors['username'] = 'Username is required.'
        if not email:
            errors['email'] = 'Email is required.'
        elif UserData.objects.filter(email=email).exists():
            # Reject duplicate emails at the form level so the login view
            # never has to deal with MultipleObjectsReturned going forward.
            errors['email'] = 'An account with this email address already exists.'
        if not password:
            errors['password'] = 'Password is required.'
        normalised_rgb = None
        if not rgb_password:
            errors['rgb_password'] = 'RGB password is required.'
        else:
            is_valid, normalised_rgb = validate_rgb_password(rgb_password)
            if not is_valid:
                errors['rgb_password'] = RGB_VALIDATION_ERROR_MESSAGE
        if not image_password:
            errors['image_password'] = 'An image password is required.'

        if errors:
            return render(request, 'register.html', {'errors': errors,
                                                      'values': request.POST})

        UserData.objects.create(
            username=username,
            email=email,
            password=make_password(password),          # hashed at rest
            rgb_password=make_password(normalised_rgb),  # hashed at rest
            image_password=image_password,
        )
        messages.success(request, "Registration successful! You can now log in.")
        return redirect('login')

    return render(request, 'register.html')


@ratelimit(key='ip', rate='10/m', method='POST', block=True)
def login(request):
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '').strip()

        # Use a generic error message for every failure path — never leak
        # whether the email, the password, or a duplicate account is the cause.
        _generic_error = 'Invalid email or password.'

        try:
            user = UserData.objects.get(email=email)
        except UserData.DoesNotExist:
            return render(request, 'login.html', {'error': _generic_error})
        except UserData.MultipleObjectsReturned:
            # More than one account shares this email address.  We cannot
            # safely identify which account the user intends to access, so we
            # treat this as an authentication failure.  The duplicate accounts
            # must be resolved by the site operator before any of them can log
            # in via this email.
            return render(request, 'login.html', {'error': _generic_error})

        if not _verify_password(password, user.password):
            return render(request, 'login.html', {'error': _generic_error})

        # Opportunistically rehash legacy plaintext rows on successful login.
        _upgrade_hash_if_needed(user, 'password', password)

        request.session['user_id'] = user.id
        return redirect('rgb')

    return render(request, 'login.html')


def logout(request):
    request.session.flush()
    messages.success(request, "You have been logged out.")
    return redirect('login')


# ---------------------------------------------------------------------------
# Protected views — require session from Level 1 onwards
# ---------------------------------------------------------------------------

@ratelimit(key='ip', rate='10/m', method='POST', block=True)
def rgb_auth(request):
    guard = _require_session(request)
    if guard:
        return guard

    if request.method == 'POST':
        rgb_password = request.POST.get('rgb_password', '').strip()
        user_id = request.session.get('user_id')

        try:
            user = UserData.objects.get(id=user_id)
        except UserData.DoesNotExist:
            request.session.flush()
            return redirect('login')

        # Standard generic error for all Level 2 authentication failures so as
        # not to leak whether failure was due to invalid format or incorrect value,
        # nor reveal the nature of stored credentials.
        _generic_error = 'Invalid or incorrect RGB password. Please try again.'

        # Validate colour format before comparing against stored hash.
        is_valid, normalised_rgb = validate_rgb_password(rgb_password)
        if not is_valid:
            return render(request, 'rgb_auth.html', {'error': _generic_error})

        # Compare submitted secret (normalised first; raw as fallback for pre-existing accounts).
        if not (_verify_password(normalised_rgb, user.rgb_password) or
                _verify_password(rgb_password, user.rgb_password)):
            return render(request, 'rgb_auth.html', {'error': _generic_error})

        # Opportunistically rehash legacy plaintext rows on success using normalised form.
        _upgrade_hash_if_needed(user, 'rgb_password', normalised_rgb)

        # Mark Level 2 passed so Level 3 page cannot be reached directly.
        request.session['rgb_passed'] = True
        return redirect('image_auth')

    return render(request, 'rgb_auth.html')


def image_auth(request):
    guard = _require_session(request)
    if guard:
        return guard

    # Enforce sequential authentication: Level 2 must be passed first.
    if not request.session.get('rgb_passed'):
        return redirect('rgb')

    if request.method == 'POST':
        user_id = request.session.get('user_id')

        # ── File presence check ──────────────────────────────────────────────
        uploaded_file = request.FILES.get('image')
        if not uploaded_file:
            return render(request, 'image_auth.html',
                          {'error': 'No file uploaded. Please choose an image.'})

        # ── Upload-size limit ────────────────────────────────────────────────
        if uploaded_file.size > _MAX_IMAGE_UPLOAD_BYTES:
            return render(request, 'image_auth.html',
                          {'error': 'File too large. Maximum allowed size is 5 MB.'})

        # ── Pillow content validation (do not trust extension / MIME) ────────
        try:
            uploaded_img = Image.open(uploaded_file)
            uploaded_img.verify()          # raises on corrupt / non-image data
            uploaded_file.seek(0)          # verify() exhausts the stream
            uploaded_img = Image.open(uploaded_file)
            uploaded_img.load()            # fully decode pixel data
        except (UnidentifiedImageError, Exception):
            return render(request, 'image_auth.html',
                          {'error': 'Invalid or unsupported image file.'})

        # ── Retrieve stored image for this user ──────────────────────────────
        try:
            user = UserData.objects.get(id=user_id)
        except UserData.DoesNotExist:
            request.session.flush()
            return redirect('login')

        if not user.image_password:
            return render(request, 'image_auth.html',
                          {'error': 'No image password is registered for this account.'})

        # ── Load and hash the registered image ───────────────────────────────
        try:
            stored_img = Image.open(user.image_password.path)
            stored_img.load()
        except Exception:
            return render(request, 'image_auth.html',
                          {'error': 'Could not read stored image password. '
                                    'Please contact support.'})

        # ── Compare pixel hashes ─────────────────────────────────────────────
        if _image_hash(uploaded_img) == _image_hash(stored_img):
            request.session['authenticated'] = True
            return redirect('dashboard')

        return render(request, 'image_auth.html',
                      {'error': 'Image does not match. Authentication failed.'})

    return render(request, 'image_auth.html')


def dashboard(request):
    guard = _require_session(request)
    if guard:
        return guard

    # Must have completed all three levels.
    if not request.session.get('authenticated'):
        return redirect('login')

    user_id = request.session.get('user_id')
    try:
        user = UserData.objects.get(id=user_id)
    except UserData.DoesNotExist:
        request.session.flush()
        return redirect('login')

    return render(request, 'dashboard.html', {'username': user.username})
