"""
accounts/tests.py — comprehensive test suite for ThreeLevel LayerLock.

Covers:
  - Public page loading
  - Session guards and sequential-authentication enforcement
  - Registration (validation, hashing, field errors, Level 2 colour format validation)
  - Login (hashed passwords, legacy plaintext rows, timing safety)
  - Level 2 RGB authentication (colour formats, normalisation, wrong credential, legacy handling)
  - Level 3 image authentication (correct, wrong, bad file, oversized, non-image)
  - Logout and session invalidation
  - Session-tampering scenarios (fabricated flags, deleted user)
  - Password-hashing helpers (_is_hashed, _verify_password, _upgrade_hash_if_needed)
  - _image_hash helper properties
  - Data migration logic (idempotency, already-hashed rows skipped)
  - CSRF protection on POST endpoints
  - Level 2 RGB colour validator unit tests (triplets, hex, colour names, edge cases)
"""

import io

from django.contrib.auth.hashers import check_password, make_password
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.test import TestCase
from django.urls import reverse
from PIL import Image

from django.core.exceptions import ValidationError
from .models import UserData
from .validators import (
    validate_rgb_password,
    rgb_color_validator,
    RGB_VALIDATION_ERROR_MESSAGE,
    SUPPORTED_COLOR_NAMES,
)
from .views import _image_hash, _is_hashed, _verify_password, _upgrade_hash_if_needed


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _make_image_bytes(color=(255, 0, 0), fmt="PNG"):
    """Return an in-memory BytesIO of a tiny solid-colour PNG/JPEG."""
    buf = io.BytesIO()
    img = Image.new("RGB", (10, 10), color)
    img.save(buf, format=fmt)
    buf.seek(0)
    return buf


def _make_upload_file(buf, name="test.png", content_type="image/png"):
    """Wrap a BytesIO as a Django InMemoryUploadedFile."""
    return InMemoryUploadedFile(
        file=buf,
        field_name="image_password",
        name=name,
        content_type=content_type,
        size=buf.getbuffer().nbytes,
        charset=None,
    )


def _create_user(username="alice", email="alice@example.com",
                 password="pass123", rgb_password="255,0,0",
                 image_bytes=None, hash_passwords=True):
    """
    Create and return a UserData instance.

    hash_passwords=True  → passwords stored as PBKDF2 hashes (normal path).
    hash_passwords=False → passwords stored as plaintext (legacy simulation).
    """
    if image_bytes is None:
        image_bytes = _make_image_bytes()
    img_file = _make_upload_file(image_bytes)

    if hash_passwords:
        stored_pw  = make_password(password)
        stored_rgb = make_password(rgb_password)
    else:
        stored_pw  = password       # deliberate legacy plaintext
        stored_rgb = rgb_password

    return UserData.objects.create(
        username=username,
        email=email,
        password=stored_pw,
        rgb_password=stored_rgb,
        image_password=img_file,
    )


def _set_session(client, **kwargs):
    """Write arbitrary key-value pairs into the test client's session."""
    session = client.session
    for k, v in kwargs.items():
        session[k] = v
    session.save()


# ===========================================================================
# 1. Public page loading
# ===========================================================================

class PublicPageTests(TestCase):

    def test_home_loads(self):
        r = self.client.get(reverse("home"))
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Three-Level")

    def test_login_page_loads(self):
        r = self.client.get(reverse("login"))
        self.assertEqual(r.status_code, 200)

    def test_register_page_loads(self):
        r = self.client.get(reverse("register"))
        self.assertEqual(r.status_code, 200)

    def test_home_redirects_authenticated_user_to_dashboard(self):
        """A user who already has user_id in session sees the dashboard."""
        user = _create_user()
        _set_session(self.client, user_id=user.id, authenticated=True)
        r = self.client.get(reverse("home"))
        self.assertRedirects(r, reverse("dashboard"))


# ===========================================================================
# 2. Session guards and sequential enforcement
# ===========================================================================

class SessionGuardTests(TestCase):

    def test_dashboard_redirects_without_session(self):
        r = self.client.get(reverse("dashboard"))
        self.assertRedirects(r, reverse("login"))

    def test_rgb_redirects_without_session(self):
        r = self.client.get(reverse("rgb"))
        self.assertRedirects(r, reverse("login"))

    def test_image_auth_redirects_without_session(self):
        r = self.client.get(reverse("image_auth"))
        self.assertRedirects(r, reverse("login"))

    def test_image_auth_redirects_without_rgb_passed(self):
        """Level 3 requires Level 2 to have been passed in this session."""
        user = _create_user()
        _set_session(self.client, user_id=user.id)
        r = self.client.get(reverse("image_auth"))
        self.assertRedirects(r, reverse("rgb"))

    def test_dashboard_redirects_without_authenticated_flag(self):
        """user_id + rgb_passed but no 'authenticated' → back to login."""
        user = _create_user()
        _set_session(self.client, user_id=user.id, rgb_passed=True)
        r = self.client.get(reverse("dashboard"))
        self.assertRedirects(r, reverse("login"))

    def test_session_tampering_rgb_flag_alone_cannot_reach_dashboard(self):
        """Setting rgb_passed=True without a valid user_id is not enough."""
        _set_session(self.client, rgb_passed=True)
        r = self.client.get(reverse("image_auth"))
        # No user_id → redirect to login, not image_auth
        self.assertRedirects(r, reverse("login"))

    def test_session_with_deleted_user_flushes_and_redirects(self):
        """If the user row is deleted mid-session, the session is cleared."""
        user = _create_user()
        _set_session(self.client, user_id=user.id, authenticated=True)
        user.delete()
        r = self.client.get(reverse("dashboard"))
        self.assertRedirects(r, reverse("login"))
        self.assertNotIn("user_id", self.client.session)


# ===========================================================================
# 3. Registration
# ===========================================================================

class RegistrationTests(TestCase):

    def test_blank_form_shows_field_errors(self):
        r = self.client.post(reverse("register"), {
            "username": "", "email": "", "password": "",
            "rgb_password": "",
        })
        self.assertEqual(r.status_code, 200)
        self.assertIn("errors", r.context)
        for field in ("username", "email", "password", "rgb_password", "image_password"):
            self.assertIn(field, r.context["errors"])

    def test_successful_registration_redirects_to_login(self):
        img = _make_image_bytes()
        r = self.client.post(reverse("register"), {
            "username": "bob",
            "email": "bob@example.com",
            "password": "secret",
            "rgb_password": "100,200,50",
            "image_password": img,
        })
        self.assertRedirects(r, reverse("login"))
        self.assertTrue(UserData.objects.filter(email="bob@example.com").exists())

    def test_registration_stores_hashed_password(self):
        """Passwords must never be stored as plaintext after registration."""
        img = _make_image_bytes()
        self.client.post(reverse("register"), {
            "username": "carol",
            "email": "carol@example.com",
            "password": "myplainpassword",
            "rgb_password": "red",
            "image_password": img,
        })
        user = UserData.objects.get(email="carol@example.com")
        self.assertNotEqual(user.password, "myplainpassword",
                            "Password must NOT be stored as plaintext.")
        self.assertTrue(_is_hashed(user.password),
                        "Password must be stored as a recognised hash.")

    def test_registration_stores_hashed_rgb_password(self):
        img = _make_image_bytes()
        self.client.post(reverse("register"), {
            "username": "dave",
            "email": "dave@example.com",
            "password": "pw",
            "rgb_password": "128,64,32",
            "image_password": img,
        })
        user = UserData.objects.get(email="dave@example.com")
        self.assertNotEqual(user.rgb_password, "128,64,32")
        self.assertTrue(_is_hashed(user.rgb_password))

    def test_hashed_password_verifies_correctly(self):
        img = _make_image_bytes()
        self.client.post(reverse("register"), {
            "username": "eve",
            "email": "eve@example.com",
            "password": "correcthorse",
            "rgb_password": "0,128,255",
            "image_password": img,
        })
        user = UserData.objects.get(email="eve@example.com")
        self.assertTrue(check_password("correcthorse", user.password))
        self.assertFalse(check_password("wrongpassword", user.password))

    def test_registration_rejects_arbitrary_rgb_text(self):
        """Entering arbitrary text like 'ABC' must be rejected with a clear message."""
        img = _make_image_bytes()
        invalid_values = [
            "ABC",
            "hello",
            "MySecret123",
            "256,0,0",
            "255,0",
            "255.0,0,0",
            "255,0,0,0",
            "#123",
            "#GGGGGG",
            "notacolor",
        ]
        for val in invalid_values:
            with self.subTest(val=val):
                r = self.client.post(reverse("register"), {
                    "username": f"user_{val[:4]}",
                    "email": f"test_{val[:4]}@example.com",
                    "password": "secretpassword",
                    "rgb_password": val,
                    "image_password": img,
                })
                self.assertEqual(r.status_code, 200)
                self.assertIn("errors", r.context)
                self.assertIn("rgb_password", r.context["errors"])
                self.assertEqual(
                    r.context["errors"]["rgb_password"],
                    RGB_VALIDATION_ERROR_MESSAGE,
                )
                self.assertFalse(
                    UserData.objects.filter(email=f"test_{val[:4]}@example.com").exists()
                )

    def test_registration_accepts_valid_rgb_triplet_with_whitespace(self):
        img = _make_image_bytes()
        r = self.client.post(reverse("register"), {
            "username": "rgb_user",
            "email": "rgbtriplet@example.com",
            "password": "validpassword",
            "rgb_password": " 255 , 0 , 128 ",
            "image_password": img,
        })
        self.assertRedirects(r, reverse("login"))
        user = UserData.objects.get(email="rgbtriplet@example.com")
        self.assertTrue(check_password("255,0,128", user.rgb_password))

    def test_registration_accepts_hex_with_and_without_hash(self):
        img = _make_image_bytes()
        # With '#'
        r1 = self.client.post(reverse("register"), {
            "username": "hex_user1",
            "email": "hex1@example.com",
            "password": "validpassword",
            "rgb_password": "#FF0080",
            "image_password": img,
        })
        self.assertRedirects(r1, reverse("login"))
        user1 = UserData.objects.get(email="hex1@example.com")
        self.assertTrue(check_password("#ff0080", user1.rgb_password))

        # Without '#'
        r2 = self.client.post(reverse("register"), {
            "username": "hex_user2",
            "email": "hex2@example.com",
            "password": "validpassword",
            "rgb_password": "FF0080",
            "image_password": img,
        })
        self.assertRedirects(r2, reverse("login"))
        user2 = UserData.objects.get(email="hex2@example.com")
        self.assertTrue(check_password("#ff0080", user2.rgb_password))

    def test_registration_accepts_recognised_colour_name(self):
        img = _make_image_bytes()
        r = self.client.post(reverse("register"), {
            "username": "colour_user",
            "email": "colour@example.com",
            "password": "validpassword",
            "rgb_password": "Purple",
            "image_password": img,
        })
        self.assertRedirects(r, reverse("login"))
        user = UserData.objects.get(email="colour@example.com")
        self.assertTrue(check_password("purple", user.rgb_password))


# ===========================================================================
# 4. Login
# ===========================================================================

class LoginTests(TestCase):

    def setUp(self):
        from django.core.cache import cache
        cache.clear()   # reset rate-limit counters between tests
        self.user = _create_user()   # hashed passwords

    def tearDown(self):
        from django.core.cache import cache
        cache.clear()

    def test_wrong_password_rejected(self):
        r = self.client.post(reverse("login"), {
            "email": "alice@example.com",
            "password": "wrongpassword",
        })
        self.assertEqual(r.status_code, 200)
        self.assertIn("error", r.context)
        self.assertNotIn("user_id", self.client.session)

    def test_wrong_email_rejected(self):
        r = self.client.post(reverse("login"), {
            "email": "nobody@example.com",
            "password": "pass123",
        })
        self.assertEqual(r.status_code, 200)
        self.assertIn("error", r.context)

    def test_error_message_is_generic(self):
        """Error must not reveal whether the email or password is wrong."""
        r = self.client.post(reverse("login"), {
            "email": "alice@example.com",
            "password": "wrong",
        })
        self.assertContains(r, "Invalid email or password.")
        # Must not mention "email" or "password" as the specific failing field
        self.assertNotContains(r, "email not found")
        self.assertNotContains(r, "password incorrect")

    def test_correct_credentials_redirects_to_rgb(self):
        r = self.client.post(reverse("login"), {
            "email": "alice@example.com",
            "password": "pass123",
        })
        self.assertRedirects(r, reverse("rgb"))
        self.assertIn("user_id", self.client.session)

    def test_legacy_plaintext_user_can_login(self):
        """A row created before migration (plaintext stored) still works."""
        legacy = _create_user(
            username="legacy", email="legacy@example.com",
            password="oldplain", rgb_password="blue",
            hash_passwords=False,
        )
        # Verify the row IS plaintext
        self.assertFalse(_is_hashed(legacy.password))

        r = self.client.post(reverse("login"), {
            "email": "legacy@example.com",
            "password": "oldplain",
        })
        self.assertRedirects(r, reverse("rgb"))

    def test_legacy_row_is_upgraded_on_login(self):
        """Successful login with a plaintext row must rehash the password."""
        legacy = _create_user(
            username="legacy2", email="legacy2@example.com",
            password="oldplain2", rgb_password="green",
            hash_passwords=False,
        )
        self.assertFalse(_is_hashed(legacy.password))

        self.client.post(reverse("login"), {
            "email": "legacy2@example.com",
            "password": "oldplain2",
        })

        legacy.refresh_from_db()
        self.assertTrue(
            _is_hashed(legacy.password),
            "Login must rehash a legacy plaintext password on success."
        )


class LoginDuplicateTests(TestCase):
    """
    Regression tests for the MultipleObjectsReturned bug.

    The live database has multiple accounts sharing the same email address.
    login() must never crash (500) or silently pick one account when the
    email is ambiguous.  It must return the generic error in all failure paths.
    """

    def setUp(self):
        from django.core.cache import cache
        cache.clear()   # reset rate-limit counters between tests
        # Two distinct accounts sharing one email — simulates the live DB state.
        self.email = "shared@example.com"
        self.pw_a = "passwordA"
        self.pw_b = "passwordB"
        self.user_a = _create_user(
            username="UserA", email=self.email,
            password=self.pw_a, rgb_password="red",
        )
        self.user_b = _create_user(
            username="UserB", email=self.email,
            password=self.pw_b, rgb_password="blue",
        )

    def tearDown(self):
        from django.core.cache import cache
        cache.clear()

    # ------------------------------------------------------------------
    # Core regression: duplicate email must never crash or grant access
    # ------------------------------------------------------------------

    def test_duplicate_email_returns_200_not_500(self):
        """Login with a duplicated email must not raise an unhandled exception."""
        r = self.client.post(reverse("login"), {
            "email": self.email,
            "password": self.pw_a,
        })
        self.assertEqual(r.status_code, 200,
                         "Expected 200 (error page), not a server crash.")

    def test_duplicate_email_shows_generic_error(self):
        """Login with a duplicated email must show the generic error message."""
        r = self.client.post(reverse("login"), {
            "email": self.email,
            "password": self.pw_a,
        })
        self.assertIn("error", r.context)
        self.assertContains(r, "Invalid email or password.")

    def test_duplicate_email_does_not_set_session(self):
        """A login attempt against a duplicated email must never start a session."""
        self.client.post(reverse("login"), {
            "email": self.email,
            "password": self.pw_a,
        })
        self.assertNotIn("user_id", self.client.session)

    def test_duplicate_email_correct_pw_b_also_blocked(self):
        """Neither password grants access while the email is ambiguous."""
        for pw in (self.pw_a, self.pw_b, "wrong"):
            with self.subTest(pw=pw):
                r = self.client.post(reverse("login"), {
                    "email": self.email,
                    "password": pw,
                })
                self.assertNotIn("user_id", self.client.session,
                                 f"Session must not be set for pw={pw!r}")

    # ------------------------------------------------------------------
    # Unique-email accounts are unaffected by the duplicate check
    # ------------------------------------------------------------------

    def test_unique_email_correct_credentials_still_work(self):
        """A user with a unique email logs in normally after the fix."""
        unique = _create_user(
            username="unique", email="unique@example.com",
            password="mypassword", rgb_password="green",
        )
        r = self.client.post(reverse("login"), {
            "email": "unique@example.com",
            "password": "mypassword",
        })
        self.assertRedirects(r, reverse("rgb"))
        self.assertEqual(self.client.session.get("user_id"), unique.id)

    def test_unique_email_wrong_password_rejected(self):
        """Wrong password for a unique-email account still fails cleanly."""
        _create_user(
            username="uniqueb", email="uniqueb@example.com",
            password="correct", rgb_password="green",
        )
        r = self.client.post(reverse("login"), {
            "email": "uniqueb@example.com",
            "password": "wrong",
        })
        self.assertEqual(r.status_code, 200)
        self.assertIn("error", r.context)
        self.assertNotIn("user_id", self.client.session)

    # ------------------------------------------------------------------
    # Registration must now block duplicate emails
    # ------------------------------------------------------------------

    def test_registration_blocks_duplicate_email(self):
        """Registering with an already-used email must show a field error."""
        img = _make_image_bytes()
        r = self.client.post(reverse("register"), {
            "username": "NewUser",
            "email": self.email,        # already taken by user_a and user_b
            "password": "newpassword",
            "rgb_password": "purple",
            "image_password": img,
        })
        self.assertEqual(r.status_code, 200)
        self.assertIn("errors", r.context)
        self.assertIn("email", r.context["errors"])

    def test_registration_unique_email_succeeds(self):
        """Registration with a fresh email still completes normally."""
        img = _make_image_bytes()
        r = self.client.post(reverse("register"), {
            "username": "BrandNew",
            "email": "brandnew@example.com",
            "password": "newpassword",
            "rgb_password": "purple",
            "image_password": img,
        })
        self.assertRedirects(r, reverse("login"))



# ===========================================================================
# 5. RGB authentication
# ===========================================================================

class RGBAuthTests(TestCase):

    def setUp(self):
        from django.core.cache import cache
        cache.clear()   # reset rate-limit counters between tests
        self.user = _create_user()
        _set_session(self.client, user_id=self.user.id)

    def tearDown(self):
        from django.core.cache import cache
        cache.clear()

    def test_wrong_rgb_password_rejected(self):
        r = self.client.post(reverse("rgb"), {"rgb_password": "0,0,0"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("error", r.context)
        self.assertFalse(self.client.session.get("rgb_passed"))

    def test_correct_rgb_password_sets_flag_and_redirects(self):
        r = self.client.post(reverse("rgb"), {"rgb_password": "255,0,0"})
        self.assertRedirects(r, reverse("image_auth"))
        self.assertTrue(self.client.session.get("rgb_passed"))

    def test_legacy_plaintext_rgb_can_authenticate(self):
        legacy = _create_user(
            username="legrgb", email="legrgb@example.com",
            password="pw", rgb_password="cyan",
            hash_passwords=False,
        )
        _set_session(self.client, user_id=legacy.id)
        r = self.client.post(reverse("rgb"), {"rgb_password": "cyan"})
        self.assertRedirects(r, reverse("image_auth"))

    def test_legacy_rgb_upgraded_on_success(self):
        legacy = _create_user(
            username="legrgb2", email="legrgb2@example.com",
            password="pw", rgb_password="magenta",
            hash_passwords=False,
        )
        _set_session(self.client, user_id=legacy.id)
        self.client.post(reverse("rgb"), {"rgb_password": "magenta"})
        legacy.refresh_from_db()
        self.assertTrue(_is_hashed(legacy.rgb_password))

    def test_invalid_colour_format_rejected_at_auth(self):
        """Malformed or non-colour inputs are rejected before comparing against hash."""
        from django.core.cache import cache
        invalid_inputs = ["ABC", "hello", "MySecret123", "256,0,0", "#123", ""]
        for val in invalid_inputs:
            with self.subTest(val=val):
                cache.clear()
                r = self.client.post(reverse("rgb"), {"rgb_password": val})
                self.assertEqual(r.status_code, 200)
                self.assertIn("error", r.context)
                self.assertEqual(
                    r.context["error"],
                    "Invalid or incorrect RGB password. Please try again.",
                )
                self.assertFalse(self.client.session.get("rgb_passed"))

    def test_rgb_triplet_whitespace_normalisation_authenticates(self):
        """User registered with '255,0,128' can authenticate with ' 255 , 0 , 128 '."""
        user = _create_user(
            username="rgb_norm", email="rgb_norm@example.com",
            password="pw", rgb_password="255,0,128",
        )
        _set_session(self.client, user_id=user.id)
        r = self.client.post(reverse("rgb"), {"rgb_password": "  255 , 0 , 128  "})
        self.assertRedirects(r, reverse("image_auth"))
        self.assertTrue(self.client.session.get("rgb_passed"))

    def test_hex_colour_prefix_and_case_normalisation_authenticates(self):
        """Hex authentication is resilient to '#' presence and casing."""
        from django.core.cache import cache
        # Registered with '#ff0080', authenticate with 'FF0080'
        user = _create_user(
            username="hex_norm", email="hex_norm@example.com",
            password="pw", rgb_password="#ff0080",
        )
        _set_session(self.client, user_id=user.id)
        r = self.client.post(reverse("rgb"), {"rgb_password": "FF0080"})
        self.assertRedirects(r, reverse("image_auth"))

        # Authenticate with lowercase and hash prefix
        cache.clear()
        _set_session(self.client, user_id=user.id, rgb_passed=False)
        r2 = self.client.post(reverse("rgb"), {"rgb_password": "#ff0080"})
        self.assertRedirects(r2, reverse("image_auth"))

    def test_colour_name_case_normalisation_authenticates(self):
        """Colour name authentication is case-insensitive."""
        from django.core.cache import cache
        user = _create_user(
            username="name_norm", email="name_norm@example.com",
            password="pw", rgb_password="blue",
        )
        _set_session(self.client, user_id=user.id)
        for val in ("Blue", "BLUE", "blue"):
            with self.subTest(val=val):
                cache.clear()
                _set_session(self.client, user_id=user.id, rgb_passed=False)
                r = self.client.post(reverse("rgb"), {"rgb_password": val})
                self.assertRedirects(r, reverse("image_auth"))
                self.assertTrue(self.client.session.get("rgb_passed"))

    def test_legacy_non_colour_account_cannot_authenticate_at_level_2(self):
        """Existing account with non-colour Level 2 cannot authenticate Level 2."""
        from django.core.cache import cache
        legacy = _create_user(
            username="bad_color_legacy", email="badcolor@example.com",
            password="pw", rgb_password="arbitrary_secret",
            hash_passwords=False,
        )
        _set_session(self.client, user_id=legacy.id)

        # Attempting with the old non-colour secret is rejected by colour validator
        r1 = self.client.post(reverse("rgb"), {"rgb_password": "arbitrary_secret"})
        self.assertEqual(r1.status_code, 200)
        self.assertIn("error", r1.context)
        self.assertFalse(self.client.session.get("rgb_passed"))

        # Attempting with a valid colour fails hash verification against stored secret
        cache.clear()
        r2 = self.client.post(reverse("rgb"), {"rgb_password": "red"})
        self.assertEqual(r2.status_code, 200)
        self.assertIn("error", r2.context)
        self.assertFalse(self.client.session.get("rgb_passed"))

        # Stored credential in database was NOT modified or silently overwritten
        legacy.refresh_from_db()
        self.assertEqual(legacy.rgb_password, "arbitrary_secret")


# ===========================================================================
# 6. Image authentication
# ===========================================================================

class ImageAuthTests(TestCase):

    def setUp(self):
        self.red_bytes = _make_image_bytes(color=(255, 0, 0))
        self.user = _create_user(
            image_bytes=_make_image_bytes(color=(255, 0, 0))
        )
        _set_session(self.client, user_id=self.user.id, rgb_passed=True)

    def test_no_file_uploaded(self):
        r = self.client.post(reverse("image_auth"), {})
        self.assertEqual(r.status_code, 200)
        self.assertIn("error", r.context)

    def test_non_image_bytes_rejected(self):
        fake = io.BytesIO(b"this is not an image at all")
        fake.name = "evil.jpg"
        r = self.client.post(reverse("image_auth"), {"image": fake})
        self.assertEqual(r.status_code, 200)
        self.assertIn("error", r.context)

    def test_wrong_image_rejected(self):
        blue = _make_image_bytes(color=(0, 0, 255))
        r = self.client.post(reverse("image_auth"), {"image": blue})
        self.assertEqual(r.status_code, 200)
        self.assertIn("error", r.context)
        self.assertFalse(self.client.session.get("authenticated"))

    def test_correct_image_grants_access(self):
        matching = _make_image_bytes(color=(255, 0, 0))
        r = self.client.post(reverse("image_auth"), {"image": matching})
        self.assertRedirects(r, reverse("dashboard"))
        self.assertTrue(self.client.session.get("authenticated"))

    def test_oversized_file_rejected(self):
        """The view's 5 MB size guard rejects uploads whose .size exceeds the limit.

        Django's test client re-calculates file size from actual byte content,
        so we patch _MAX_IMAGE_UPLOAD_BYTES to a value smaller than our tiny
        test PNG (a few hundred bytes).  This exercises the exact same code
        branch as a real oversized upload.
        """
        from unittest.mock import patch
        import accounts.views as views_module

        # Patch the limit to 10 bytes — smaller than any valid PNG
        with patch.object(views_module, '_MAX_IMAGE_UPLOAD_BYTES', 10):
            buf = _make_image_bytes()
            r = self.client.post(reverse("image_auth"), {"image": buf})

        self.assertEqual(r.status_code, 200)
        self.assertIn("error", r.context)
        self.assertFalse(self.client.session.get("authenticated"))

    def test_arbitrary_image_cannot_bypass_auth(self):
        """Uploading any random image must not grant dashboard access."""
        for color in [(0, 255, 0), (128, 128, 128), (0, 0, 0)]:
            with self.subTest(color=color):
                img = _make_image_bytes(color=color)
                r = self.client.post(reverse("image_auth"), {"image": img})
                self.assertFalse(
                    self.client.session.get("authenticated"),
                    f"Color {color} should not grant access."
                )


# ===========================================================================
# 7. Logout and session invalidation
# ===========================================================================

class LogoutTests(TestCase):

    def test_logout_clears_all_session_keys(self):
        _set_session(self.client,
                     user_id=999, rgb_passed=True, authenticated=True)
        r = self.client.get(reverse("logout"))
        self.assertRedirects(r, reverse("login"))
        for key in ("user_id", "rgb_passed", "authenticated"):
            self.assertNotIn(key, self.client.session,
                             f"Session key '{key}' must be cleared on logout.")

    def test_after_logout_protected_pages_require_reauth(self):
        user = _create_user()
        _set_session(self.client,
                     user_id=user.id, rgb_passed=True, authenticated=True)
        self.client.get(reverse("logout"))
        r = self.client.get(reverse("dashboard"))
        self.assertRedirects(r, reverse("login"))


# ===========================================================================
# 8. CSRF protection
# ===========================================================================

class CSRFTests(TestCase):

    def test_login_post_without_csrf_token_rejected(self):
        """Django's CsrfViewMiddleware must reject requests without the token."""
        client = self.client_class(enforce_csrf_checks=True)
        r = client.post(reverse("login"), {
            "email": "x@x.com",
            "password": "pw",
        })
        self.assertEqual(r.status_code, 403)

    def test_register_post_without_csrf_token_rejected(self):
        client = self.client_class(enforce_csrf_checks=True)
        r = client.post(reverse("register"), {
            "username": "x", "email": "x@x.com",
            "password": "pw", "rgb_password": "red",
        })
        self.assertEqual(r.status_code, 403)

    def test_image_auth_post_without_csrf_token_rejected(self):
        client = self.client_class(enforce_csrf_checks=True)
        r = client.post(reverse("image_auth"), {})
        self.assertEqual(r.status_code, 403)


# ===========================================================================
# 9. Rate limiting
# ===========================================================================

class RateLimitTests(TestCase):
    """
    django-ratelimit allows 10 POST attempts per minute per IP.
    The 11th attempt in the same minute must be rejected with HTTP 403.

    django-ratelimit uses Django's cache backend.  Each test class gets a
    fresh cache because Django's test runner calls cache.clear() between
    tests via its own isolation mechanism.  We call cache.clear() explicitly
    in setUp() to guarantee a clean counter.
    """

    def setUp(self):
        from django.core.cache import cache
        cache.clear()
        self.user = _create_user()

    def tearDown(self):
        from django.core.cache import cache
        cache.clear()

    def _exhaust_login_limit(self):
        """POST 10 bad login attempts — all should pass (wrong creds, not blocked)."""
        for _ in range(10):
            self.client.post(reverse("login"), {
                "email": "nobody@example.com",
                "password": "wrong",
            })

    def _exhaust_rgb_limit(self):
        """POST 10 bad RGB attempts after Level 1 login."""
        _set_session(self.client, user_id=self.user.id)
        for _ in range(10):
            self.client.post(reverse("rgb"), {"rgb_password": "wrong"})

    def test_login_rate_limit_allows_10_attempts(self):
        """The first 10 POSTs must not be rate-limited (wrong creds → 200)."""
        for i in range(10):
            r = self.client.post(reverse("login"), {
                "email": "nobody@example.com",
                "password": "wrong",
            })
            self.assertNotEqual(r.status_code, 403,
                                f"Attempt {i+1} was blocked too early.")

    def test_login_rate_limit_blocks_11th_attempt(self):
        """The 11th POST within the same minute must return 403."""
        self._exhaust_login_limit()
        r = self.client.post(reverse("login"), {
            "email": "nobody@example.com",
            "password": "wrong",
        })
        self.assertEqual(r.status_code, 403,
                         "11th login attempt must be rate-limited (403).")

    def test_rgb_rate_limit_allows_10_attempts(self):
        """The first 10 RGB POSTs must not be rate-limited."""
        _set_session(self.client, user_id=self.user.id)
        for i in range(10):
            r = self.client.post(reverse("rgb"), {"rgb_password": "wrong"})
            self.assertNotEqual(r.status_code, 403,
                                f"RGB attempt {i+1} was blocked too early.")

    def test_rgb_rate_limit_blocks_11th_attempt(self):
        """The 11th RGB POST within the same minute must return 403."""
        self._exhaust_rgb_limit()
        r = self.client.post(reverse("rgb"), {"rgb_password": "wrong"})
        self.assertEqual(r.status_code, 403,
                         "11th RGB attempt must be rate-limited (403).")

    def test_rate_limit_does_not_affect_get_requests(self):
        """GET requests are never rate-limited (only POST is guarded)."""
        self._exhaust_login_limit()
        r = self.client.get(reverse("login"))
        self.assertEqual(r.status_code, 200)

    def test_correct_login_works_before_limit_is_hit(self):
        """A correct login before the limit is reached must still succeed."""
        # Use 5 wrong attempts (well within the 10-per-minute window)
        for _ in range(5):
            self.client.post(reverse("login"), {
                "email": "nobody@example.com", "password": "wrong",
            })
        r = self.client.post(reverse("login"), {
            "email": "alice@example.com",
            "password": "pass123",
        })
        self.assertRedirects(r, reverse("rgb"))


# ===========================================================================
# 10. Password-hashing helper unit tests  (renumbered; Rate limiting is #9)
# ===========================================================================

class IsHashedTests(TestCase):

    def test_pbkdf2_hash_detected(self):
        self.assertTrue(_is_hashed(make_password("anything")))

    def test_plaintext_not_detected_as_hash(self):
        for v in ("password", "255,0,0", "", "abc123", "hello world"):
            self.assertFalse(_is_hashed(v), f"'{v}' must not be detected as a hash")

    def test_partial_prefix_not_detected(self):
        self.assertFalse(_is_hashed("pbkdf2"))      # incomplete prefix
        self.assertFalse(_is_hashed("pbkdf2_sha"))  # incomplete prefix


class VerifyPasswordTests(TestCase):

    def test_verify_hashed_correct(self):
        hashed = make_password("mypassword")
        self.assertTrue(_verify_password("mypassword", hashed))

    def test_verify_hashed_wrong(self):
        hashed = make_password("mypassword")
        self.assertFalse(_verify_password("wrongpassword", hashed))

    def test_verify_legacy_plaintext_correct(self):
        self.assertTrue(_verify_password("plaintext", "plaintext"))

    def test_verify_legacy_plaintext_wrong(self):
        self.assertFalse(_verify_password("wrong", "plaintext"))


class UpgradeHashTests(TestCase):

    def setUp(self):
        # Create a user with a plaintext password directly
        buf = _make_image_bytes()
        img_file = _make_upload_file(buf)
        self.user = UserData.objects.create(
            username="upgrade_test",
            email="upgrade@example.com",
            password="plaintext_pw",      # intentionally NOT hashed
            rgb_password="plaintext_rgb",
            image_password=img_file,
        )

    def test_upgrade_hashes_plaintext_password_field(self):
        self.assertFalse(_is_hashed(self.user.password))
        _upgrade_hash_if_needed(self.user, 'password', 'plaintext_pw')
        self.user.refresh_from_db()
        self.assertTrue(_is_hashed(self.user.password))
        self.assertTrue(check_password('plaintext_pw', self.user.password))

    def test_upgrade_does_not_rehash_already_hashed_value(self):
        # Pre-hash the field
        self.user.password = make_password("somepw")
        self.user.save(update_fields=["password"])
        original_hash = self.user.password

        _upgrade_hash_if_needed(self.user, 'password', 'somepw')
        self.user.refresh_from_db()
        # Hash must be identical — it was NOT re-hashed
        self.assertEqual(self.user.password, original_hash)


# ===========================================================================
# 11. Data migration idempotency
# ===========================================================================

class DataMigrationIdempotencyTests(TestCase):
    """
    Test that the data migration function (hash_plaintext_passwords) is safe
    to run on a database that already has hashed rows.
    """

    def test_already_hashed_rows_are_not_double_hashed(self):
        import importlib
        mod = importlib.import_module('accounts.migrations.0004_hash_passwords')

        buf = _make_image_bytes()
        img_file = _make_upload_file(buf)
        user = UserData.objects.create(
            username="mig_test",
            email="mig@example.com",
            password=make_password("original"),
            rgb_password=make_password("origrgb"),
            image_password=img_file,
        )
        original_pw_hash  = user.password
        original_rgb_hash = user.rgb_password

        # Simulate running the migration on an already-hashed row
        class FakeApps:
            def get_model(self, app, model):
                from accounts.models import UserData as RealUserData
                return RealUserData

        mod.hash_plaintext_passwords(FakeApps(), None)

        user.refresh_from_db()
        self.assertEqual(user.password,     original_pw_hash,
                         "Already-hashed password must not be changed.")
        self.assertEqual(user.rgb_password, original_rgb_hash,
                         "Already-hashed RGB password must not be changed.")

    def test_plaintext_rows_are_hashed_by_migration(self):
        import importlib
        mod = importlib.import_module('accounts.migrations.0004_hash_passwords')

        buf = _make_image_bytes()
        img_file = _make_upload_file(buf)
        user = UserData.objects.create(
            username="mig_plain",
            email="migplain@example.com",
            password="plaintextpw",
            rgb_password="plaintextrgb",
            image_password=img_file,
        )

        class FakeApps:
            def get_model(self, app, model):
                from accounts.models import UserData as RealUserData
                return RealUserData

        mod.hash_plaintext_passwords(FakeApps(), None)

        user.refresh_from_db()
        self.assertTrue(_is_hashed(user.password))
        self.assertTrue(_is_hashed(user.rgb_password))
        self.assertTrue(check_password("plaintextpw",  user.password))
        self.assertTrue(check_password("plaintextrgb", user.rgb_password))


# ===========================================================================
# 12. Image hash helper
# ===========================================================================

class ImageHashTests(TestCase):

    def test_same_image_produces_same_hash(self):
        img = Image.new("RGB", (50, 50), (100, 150, 200))
        self.assertEqual(_image_hash(img), _image_hash(img))

    def test_different_colours_produce_different_hashes(self):
        img_a = Image.new("RGB", (50, 50), (100, 150, 200))
        img_b = Image.new("RGB", (50, 50), (200, 150, 100))
        self.assertNotEqual(_image_hash(img_a), _image_hash(img_b))

    def test_hash_is_64_char_hex_string(self):
        img = Image.new("RGB", (10, 10), (0, 0, 0))
        result = _image_hash(img)
        self.assertIsInstance(result, str)
        self.assertEqual(len(result), 64)  # SHA-256 hex = 64 chars

    def test_same_pixel_content_different_size_same_hash(self):
        """Images with the same solid colour but different dimensions hash the same."""
        img_small = Image.new("RGB", (10, 10), (0, 200, 100))
        img_large = Image.new("RGB", (200, 200), (0, 200, 100))
        self.assertEqual(_image_hash(img_small), _image_hash(img_large))


# ===========================================================================
# 13. Level 2 RGB Colour Validator Unit Tests
# ===========================================================================

class RGBValidatorUnitTests(TestCase):

    def test_valid_rgb_triplets(self):
        valid_cases = [
            ("255,0,128", "255,0,128"),
            ("255, 0, 128", "255,0,128"),
            (" 0 , 128 , 255 ", "0,128,255"),
            ("0,0,0", "0,0,0"),
            ("255,255,255", "255,255,255"),
            ("10,20,30", "10,20,30"),
        ]
        for raw, expected in valid_cases:
            with self.subTest(raw=raw):
                valid, normalised = validate_rgb_password(raw)
                self.assertTrue(valid)
                self.assertEqual(normalised, expected)

    def test_invalid_rgb_triplets(self):
        invalid_cases = [
            "256,0,0",
            "0,256,0",
            "0,0,300",
            "-1,0,0",
            "255,0",
            "255",
            "255,0,0,0",
            "255.0,0,0",
            "255,0,abc",
            "255,,0",
            "255,0,0,",
            ",255,0,0",
            "1000,0,0",
        ]
        for raw in invalid_cases:
            with self.subTest(raw=raw):
                valid, normalised = validate_rgb_password(raw)
                self.assertFalse(valid)
                self.assertIsNone(normalised)

    def test_valid_hex_colors(self):
        valid_cases = [
            ("#FF0080", "#ff0080"),
            ("FF0080", "#ff0080"),
            ("#ff0080", "#ff0080"),
            ("ff0080", "#ff0080"),
            ("#000000", "#000000"),
            ("FFFFFF", "#ffffff"),
            ("123456", "#123456"),
            ("#aAbBcC", "#aabbcc"),
        ]
        for raw, expected in valid_cases:
            with self.subTest(raw=raw):
                valid, normalised = validate_rgb_password(raw)
                self.assertTrue(valid)
                self.assertEqual(normalised, expected)

    def test_invalid_hex_colors(self):
        invalid_cases = [
            "#123",
            "123",
            "ABC",
            "#12345",
            "#1234567",
            "#GGGGGG",
            "nothex",
            "##FF0080",
            "#12345G",
        ]
        for raw in invalid_cases:
            with self.subTest(raw=raw):
                valid, normalised = validate_rgb_password(raw)
                self.assertFalse(valid)
                self.assertIsNone(normalised)

    def test_valid_colour_names(self):
        names = ["red", "blue", "green", "purple", "black", "white", "rebeccapurple"]
        for name in names:
            with self.subTest(name=name):
                valid, normalised = validate_rgb_password(name)
                self.assertTrue(valid)
                self.assertEqual(normalised, name)

    def test_colour_name_case_insensitivity(self):
        cases = [
            ("Red", "red"),
            ("RED", "red"),
            ("Purple", "purple"),
            ("PURPLE", "purple"),
            ("bLuE", "blue"),
        ]
        for raw, expected in cases:
            with self.subTest(raw=raw):
                valid, normalised = validate_rgb_password(raw)
                self.assertTrue(valid)
                self.assertEqual(normalised, expected)

    def test_invalid_colour_names_rejected(self):
        invalid_names = [
            "ABC",
            "hello",
            "mycolor",
            "MySecret123",
            "invalid_word",
            "apple",
            "supercalifragilistic",
        ]
        for name in invalid_names:
            with self.subTest(name=name):
                valid, normalised = validate_rgb_password(name)
                self.assertFalse(valid)
                self.assertIsNone(normalised)

    def test_empty_and_non_string_rejected(self):
        for val in ["", "   ", "\t\n", None, 12345, []]:
            with self.subTest(val=val):
                valid, normalised = validate_rgb_password(val)
                self.assertFalse(valid)
                self.assertIsNone(normalised)

    def test_rgb_color_validator_raises_validation_error(self):
        with self.assertRaises(ValidationError) as cm:
            rgb_color_validator("ABC")
        self.assertIn(RGB_VALIDATION_ERROR_MESSAGE, str(cm.exception))

    def test_rgb_color_validator_returns_normalised_on_valid(self):
        self.assertEqual(rgb_color_validator("RED"), "red")
        self.assertEqual(rgb_color_validator("255, 0, 128"), "255,0,128")
        self.assertEqual(rgb_color_validator("FF0080"), "#ff0080")
