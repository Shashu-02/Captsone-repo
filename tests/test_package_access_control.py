import tempfile
import unittest
from pathlib import Path

from backend import auth_manager


class PackageAccessControlTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_db = auth_manager.DB_PATH
        auth_manager.DB_PATH = Path(self.tmp.name) / "users.sqlite3"
        auth_manager.initialize()
        with auth_manager._connect() as con:
            con.executemany(
                "INSERT INTO users(username,password_salt,password_hash,role,status) VALUES(?,?,?,?,?)",
                [
                    ("alice", "00", "x", "sender", "approved"),
                    ("bob", "00", "x", "receiver", "approved"),
                    ("mallory", "00", "x", "receiver", "approved"),
                ],
            )

    def tearDown(self):
        auth_manager.DB_PATH = self.old_db
        self.tmp.cleanup()

    def test_only_listed_receiver_can_access(self):
        auth_manager.register_package_access("bafy-test", "alice", ["bob"])
        self.assertTrue(auth_manager.can_access_package("bafy-test", "bob"))
        self.assertFalse(auth_manager.can_access_package("bafy-test", "mallory"))

    def test_revoked_receiver_loses_access(self):
        auth_manager.register_package_access("bafy-test", "alice", ["bob"])
        auth_manager.review_user("bob", "revoked", "admin")
        self.assertFalse(auth_manager.can_access_package("bafy-test", "bob"))


if __name__ == "__main__":
    unittest.main()
