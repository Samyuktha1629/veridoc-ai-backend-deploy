import unittest
from unittest.mock import patch

from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend import app as app_module
from backend import database
from backend.auth import token_username


class AccountTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite://")
        database.Base.metadata.create_all(self.engine)
        self.session_patch = patch.object(
            database,
            "_Session",
            sessionmaker(bind=self.engine, expire_on_commit=False),
        )
        self.session_patch.start()
        self.addCleanup(self.session_patch.stop)
        self.addCleanup(self.engine.dispose)

    def test_public_registration_creates_multiple_accounts(self):
        self.assertEqual(
            app_module.auth_status(),
            {"required": True, "setup_required": True},
        )

        first = app_module.register(app_module.RegisterRequest(
            username="ReviewerOne",
            password="first-secure-password",
        ))
        second = app_module.register(app_module.RegisterRequest(
            username="ReviewerTwo",
            password="second-secure-password",
        ))

        self.assertEqual(token_username(first["access_token"]), "reviewerone")
        self.assertEqual(token_username(second["access_token"]), "reviewertwo")
        app_module.require_authenticated(f"Bearer {first['access_token']}")
        app_module.require_authenticated(f"Bearer {second['access_token']}")
        self.assertEqual(
            app_module.auth_status(),
            {"required": True, "setup_required": False},
        )
        self.assertEqual(
            app_module.login(app_module.LoginRequest(
                username="ReviewerOne",
                password="first-secure-password",
            ))["token_type"],
            "bearer",
        )
        self.assertEqual(
            app_module.login(app_module.LoginRequest(
                username="ReviewerTwo",
                password="second-secure-password",
            ))["token_type"],
            "bearer",
        )
        with self.assertRaises(HTTPException) as duplicate:
            app_module.register(app_module.RegisterRequest(
                username="reviewerone",
                password="another-secure-password",
            ))
        self.assertEqual(duplicate.exception.status_code, 409)


if __name__ == "__main__":
    unittest.main()
