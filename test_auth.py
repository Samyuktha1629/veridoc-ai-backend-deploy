import os
import unittest
from unittest.mock import patch

import backend.auth as auth
from backend.auth import (
    hash_password,
    issue_token,
    token_username,
    validate_auth_configuration,
    verify_password,
    verify_token,
)


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.auth_environment = patch.dict(os.environ, {
            "SESSION_SECRET": "test-session-secret-that-is-not-for-production",
        }, clear=True)
        self.auth_environment.start()
        self.addCleanup(self.auth_environment.stop)

    def test_password_hash_is_salted_and_verifiable(self):
        first_hash = hash_password("correct horse battery staple")
        second_hash = hash_password("correct horse battery staple")
        self.assertNotEqual(first_hash, second_hash)
        self.assertTrue(verify_password("correct horse battery staple", first_hash))
        self.assertFalse(verify_password("incorrect", first_hash))
        self.assertFalse(verify_password("password", "malformed"))
        self.assertNotIn("correct horse battery staple", first_hash)

    def test_signed_token_is_valid_and_contains_its_owner(self):
        token = issue_token("reviewer")
        self.assertTrue(verify_token(token))
        self.assertEqual(token_username(token), "reviewer")

    def test_token_rejects_tampering_and_malformed_input(self):
        token = issue_token("reviewer")
        payload, signature = token.split(".")
        self.assertFalse(verify_token(f"{payload}.tampered-{signature}"))
        self.assertFalse(verify_token("not-a-token"))

    def test_expired_token_is_rejected(self):
        with patch.object(auth.time, "time", return_value=1000):
            token = issue_token("reviewer")
        with patch.object(auth.time, "time", return_value=1000 + auth.TOKEN_LIFETIME_SECONDS):
            self.assertFalse(verify_token(token))

    def test_production_requires_a_strong_session_secret(self):
        with patch.dict(os.environ, {"APP_ENV": "production", "SESSION_SECRET": ""}):
            with self.assertRaises(RuntimeError):
                validate_auth_configuration()

    def test_production_requires_exact_https_cors_origins(self):
        with patch.dict(os.environ, {
            "APP_ENV": "production",
            "SESSION_SECRET": "test-session-secret-that-is-not-for-production",
            "CORS_ORIGINS": "http://localhost:3000",
        }):
            with self.assertRaises(RuntimeError):
                validate_auth_configuration()


if __name__ == "__main__":
    unittest.main()
