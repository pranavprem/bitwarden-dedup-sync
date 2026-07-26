import json
import tempfile
import unittest
from pathlib import Path

from bwsync.parsers import ParseError, detect_csv_format, load_source, parse_bitwarden_json
from tests.fixtures import bw_login, bw_note, write_apple_csv, write_chrome_csv, write_vault


class TestFormatDetection(unittest.TestCase):
    def test_detects_each_format(self):
        self.assertEqual(detect_csv_format(["name", "url", "username", "password", "note"]), "chrome")
        self.assertEqual(
            detect_csv_format(["title", "url", "username", "password", "notes", "otpauth"]), "apple"
        )
        self.assertEqual(
            detect_csv_format(["folder", "name", "login_username", "login_password"]),
            "bitwarden-csv",
        )
        self.assertEqual(
            detect_csv_format(["url", "username", "password", "httprealm", "formactionorigin"]),
            "firefox",
        )

    def test_unknown_raises(self):
        with self.assertRaises(ParseError):
            detect_csv_format(["alpha", "beta"])


class TestBitwardenJson(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_parses_logins_and_notes(self):
        path = write_vault(
            self.dir / "vault.json",
            [
                bw_login("i1", "GitHub", "me@x.com", "pw", ["https://github.com"], totp="SEED"),
                bw_note("n1", "Passport", "number 123"),
            ],
            folders=[{"id": "f1", "name": "Work"}],
        )
        logins, others, folders = parse_bitwarden_json(path)
        self.assertEqual(len(logins), 1)
        self.assertEqual(len(others), 1)
        self.assertEqual(folders, {"f1": "Work"})
        self.assertEqual(logins[0].item_id, "i1")
        self.assertEqual(logins[0].totp, "SEED")
        self.assertTrue(logins[0].from_vault)

    def test_trashed_items_ignored(self):
        # A trashed duplicate must not be counted, or we would "delete" it twice.
        path = write_vault(
            self.dir / "vault.json",
            [
                bw_login("i1", "GitHub", "me@x.com", "pw"),
                bw_login("i2", "GitHub", "me@x.com", "pw", deleted=True),
            ],
        )
        logins, _, _ = parse_bitwarden_json(path)
        self.assertEqual([c.item_id for c in logins], ["i1"])

    def test_encrypted_export_rejected_with_actionable_message(self):
        path = self.dir / "enc.json"
        path.write_text(json.dumps({"encrypted": True, "data": "…"}), encoding="utf-8")
        with self.assertRaises(ParseError) as ctx:
            parse_bitwarden_json(path)
        self.assertIn("ENCRYPTED", str(ctx.exception))

    def test_csv_rejected_as_vault(self):
        path = write_chrome_csv(self.dir / "c.csv", [("A", "https://a.com", "u", "p", "")])
        with self.assertRaises(ParseError) as ctx:
            load_source(path, "bitwarden", expect_vault=True)
        self.assertIn("must be JSON", str(ctx.exception))


class TestCsvParsing(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_chrome(self):
        path = write_chrome_csv(
            self.dir / "chrome.csv",
            [("GitHub", "https://github.com/login", "me@x.com", "pw", "a note")],
        )
        creds, _, _ = load_source(path, "chrome")
        self.assertEqual(len(creds), 1)
        self.assertEqual(creds[0].source, "chrome")
        self.assertEqual(creds[0].ref, "chrome:0")
        self.assertEqual(creds[0].notes, "a note")
        self.assertFalse(creds[0].from_vault)

    def test_apple_with_otp(self):
        path = write_apple_csv(
            self.dir / "apple.csv",
            [("GitHub", "https://github.com", "me@x.com", "pw", "", "otpauth://totp/x?secret=S")],
        )
        creds, _, _ = load_source(path, "apple")
        self.assertEqual(creds[0].totp, "otpauth://totp/x?secret=S")

    def test_passwordless_rows_dropped(self):
        # Chrome exports blank rows for federated "Sign in with Google" entries.
        path = write_chrome_csv(
            self.dir / "chrome.csv",
            [("Real", "https://a.com", "u", "p", ""), ("Federated", "https://b.com", "u", "", "")],
        )
        creds, _, _ = load_source(path, "chrome")
        self.assertEqual([c.name for c in creds], ["Real"])

    def test_label_drives_ref(self):
        path = write_chrome_csv(self.dir / "x.csv", [("A", "https://a.com", "u", "p", "")])
        creds, _, _ = load_source(path, "extra0")
        self.assertEqual(creds[0].ref, "extra0:0")

    def test_bom_tolerated(self):
        path = self.dir / "bom.csv"
        path.write_text("﻿name,url,username,password,note\nA,https://a.com,u,p,\n", "utf-8")
        creds, _, _ = load_source(path, "chrome")
        self.assertEqual(len(creds), 1)


if __name__ == "__main__":
    unittest.main()
