import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from bwsync.apply import ApplyError, BwCli, Journal, execute, load_plan, resolve_sources
from bwsync.cli import main
from bwsync.parsers import sha256_file
from tests.fixtures import bw_login, bw_note, write_apple_csv, write_chrome_csv, write_vault


class RecordingCli(BwCli):
    """Captures the operations a real run would perform, without touching a vault."""

    def __init__(self):
        super().__init__(dry_run=False, echo=lambda _: None)
        self.created: list[dict] = []
        self.edited: list[tuple[str, dict]] = []
        self.deleted: list[str] = []
        self.folders_created: list[str] = []
        self.synced = 0

    def create_item(self, payload):
        self.created.append(payload)
        return json.dumps({"id": f"new{len(self.created)}"})

    def edit_item(self, item_id, payload):
        self.edited.append((item_id, payload))
        return "{}"

    def create_folder(self, name):
        self.folders_created.append(name)
        return f"folder-{len(self.folders_created)}"

    def delete_item(self, item_id, permanent=False):
        self.deleted.append(item_id)

    def list_folders(self):
        return {}

    def sync(self):
        self.synced += 1


class PlanTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.out = self.dir / "out"

    def tearDown(self):
        self.tmp.cleanup()

    def run_plan(self, *extra_args, items=None, chrome=None, apple=None):
        vault_path = write_vault(self.dir / "vault.json", items or [])
        args = ["plan", "--vault", str(vault_path), "--out", str(self.out), *extra_args]
        if chrome is not None:
            args += ["--chrome", str(write_chrome_csv(self.dir / "chrome.csv", chrome))]
        if apple is not None:
            args += ["--apple", str(write_apple_csv(self.dir / "apple.csv", apple))]
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(args), 0)
        return load_plan(self.out / "plan.json")


class TestPlanContents(PlanTestCase):
    def test_plan_contains_no_secrets(self):
        plan = self.run_plan(
            items=[
                bw_login("i1", "GitHub", "me@x.com", "s3cr3t-vault", ["https://github.com"]),
                bw_login("i2", "GitHub", "me@x.com", "s3cr3t-vault", ["https://github.com"]),
            ],
            chrome=[("Reddit", "https://reddit.com", "me", "s3cr3t-chrome", "private note")],
            apple=[("Bank", "https://hsbc.co.uk", "me", "s3cr3t-apple", "", "otpauth://x?secret=S")],
        )
        blob = json.dumps(plan)
        for secret in (
            "s3cr3t-vault",
            "s3cr3t-chrome",
            "s3cr3t-apple",
            "private note",
            "otpauth://x?secret=S",
        ):
            self.assertNotIn(secret, blob, f"plan leaked {secret!r}")

    def test_report_contains_no_secrets(self):
        self.run_plan(
            items=[bw_login("i1", "GitHub", "me@x.com", "s3cr3t-vault", ["https://github.com"])],
            chrome=[("Reddit", "https://reddit.com", "me", "s3cr3t-chrome", "private note")],
        )
        for name in ("report.md", "new-items.csv"):
            path = self.out / name
            if path.exists():
                text = path.read_text(encoding="utf-8")
                self.assertNotIn("s3cr3t-vault", text)
                self.assertNotIn("s3cr3t-chrome", text)
                self.assertNotIn("private note", text)

    def test_outputs_are_owner_only(self):
        self.run_plan(items=[bw_login("i1", "A", "u", "p", ["https://a.com"])])
        self.assertEqual((self.out / "plan.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.out / "report.md").stat().st_mode & 0o777, 0o600)

    def test_exact_duplicates_produce_deletes(self):
        plan = self.run_plan(
            items=[
                bw_login("i1", "GitHub", "u", "pw", ["https://github.com"]),
                bw_login("i2", "GitHub", "u", "pw", ["https://www.github.com"]),
                bw_login("i3", "GitHub", "u", "pw", ["https://github.com/login"]),
            ]
        )
        deletes = [a for a in plan["actions"] if a["op"] == "delete"]
        self.assertEqual(len(deletes), 2)
        self.assertEqual(plan["stats"]["vault_deletes"], 2)

    def test_conflicts_never_delete_and_are_filed_for_review(self):
        plan = self.run_plan(
            items=[bw_login("i1", "GitHub", "u", "vaultpw", ["https://github.com"])],
            chrome=[("GitHub", "https://github.com", "u", "differentpw", "")],
        )
        self.assertEqual([a for a in plan["actions"] if a["op"] == "delete"], [])
        creates = [a for a in plan["actions"] if a["op"] == "create"]
        self.assertEqual(len(creates), 1)
        self.assertTrue(creates[0]["conflict"])
        self.assertEqual(creates[0]["folder"], "Review/Conflicts")
        self.assertEqual(len(plan["conflicts"]), 1)
        self.assertEqual(len(plan["conflicts"][0]["variants"]), 2)

    def test_import_already_in_vault_is_skipped(self):
        plan = self.run_plan(
            items=[bw_login("i1", "GitHub", "u", "samepw", ["https://github.com"])],
            chrome=[("GitHub", "https://github.com", "u", "samepw", "")],
        )
        self.assertEqual([a for a in plan["actions"] if a["op"] == "create"], [])

    def test_new_import_goes_to_import_folder(self):
        plan = self.run_plan(chrome=[("Reddit", "https://reddit.com", "u", "pw", "")], items=[])
        creates = [a for a in plan["actions"] if a["op"] == "create"]
        self.assertEqual(creates[0]["folder"], "Imported")
        self.assertIn({"op": "ensure_folder", "name": "Imported"}, plan["actions"])

    def test_no_import_flag_only_dedupes(self):
        plan = self.run_plan(
            "--no-import",
            items=[
                bw_login("i1", "GitHub", "u", "pw", ["https://github.com"]),
                bw_login("i2", "GitHub", "u", "pw", ["https://github.com"]),
            ],
            chrome=[("Reddit", "https://reddit.com", "u", "pw", "")],
        )
        self.assertEqual([a for a in plan["actions"] if a["op"] == "create"], [])
        self.assertEqual(len([a for a in plan["actions"] if a["op"] == "delete"]), 1)

    def test_duplicate_notes_are_deleted(self):
        plan = self.run_plan(
            items=[
                bw_note("n1", "Passport", "number 123", "2023-01-01T00:00:00.000Z"),
                bw_note("n2", "Passport", "number 123", "2024-01-01T00:00:00.000Z"),
                bw_note("n3", "Passport", "number 456"),
            ]
        )
        deletes = [a for a in plan["actions"] if a["op"] == "delete"]
        self.assertEqual([d["item_id"] for d in deletes], ["n2"])
        self.assertEqual(plan["stats"]["note_card_deletes"], 1)


class TestApplyExecution(PlanTestCase):
    def test_dry_run_makes_no_changes(self):
        self.run_plan(
            items=[
                bw_login("i1", "GitHub", "u", "pw", ["https://github.com"]),
                bw_login("i2", "GitHub", "u", "pw", ["https://www.github.com"]),
            ],
            chrome=[("Reddit", "https://reddit.com", "u", "pw2", "")],
        )
        cli = BwCli(dry_run=True, echo=lambda _: None)
        plan = load_plan(self.out / "plan.json")
        counts = execute(plan, cli, Journal(self.dir / "j", enabled=False), echo=lambda _: None)
        self.assertEqual(counts["deleted"], 1)
        self.assertFalse((self.dir / "j").exists())

    def test_execution_creates_updates_and_deletes(self):
        self.run_plan(
            items=[
                bw_login("i1", "GitHub", "u", "pw", ["https://github.com"], notes="keep"),
                bw_login("i2", "GitHub", "u", "pw", ["https://gist.github.com"], totp="SEED"),
            ],
            chrome=[("Reddit", "https://reddit.com", "u", "redditpw", "")],
        )
        cli = RecordingCli()
        plan = load_plan(self.out / "plan.json")
        execute(plan, cli, Journal(self.dir / "j", enabled=False), echo=lambda _: None)

        self.assertEqual(cli.deleted, ["i1"])  # i2 keeps the TOTP, so i1 is redundant
        self.assertEqual(len(cli.edited), 1)
        item_id, payload = cli.edited[0]
        self.assertEqual(item_id, "i2")
        self.assertEqual(payload["login"]["totp"], "SEED")
        self.assertEqual(payload["notes"], "keep")  # rescued off the deleted duplicate
        hosts = {u["uri"] for u in payload["login"]["uris"]}
        self.assertIn("https://github.com", hosts)
        self.assertIn("https://gist.github.com", hosts)

        self.assertEqual(len(cli.created), 1)
        self.assertEqual(cli.created[0]["login"]["password"], "redditpw")
        self.assertEqual(cli.created[0]["folderId"], "folder-1")
        self.assertEqual(cli.synced, 2)  # before and after

    def test_totp_is_rescued_onto_keeper(self):
        self.run_plan(
            items=[
                bw_login("i1", "GitHub", "u", "pw", ["https://github.com"], passkey=True),
                bw_login("i2", "GitHub", "u", "pw", ["https://github.com"], totp="RESCUEME"),
            ]
        )
        cli = RecordingCli()
        execute(
            load_plan(self.out / "plan.json"),
            cli,
            Journal(self.dir / "j", enabled=False),
            echo=lambda _: None,
        )
        self.assertEqual(cli.deleted, ["i2"])
        self.assertEqual(cli.edited[0][1]["login"]["totp"], "RESCUEME")

    def test_journal_makes_apply_resumable(self):
        self.run_plan(
            items=[
                bw_login("i1", "GitHub", "u", "pw", ["https://github.com"]),
                bw_login("i2", "GitHub", "u", "pw", ["https://github.com"]),
            ]
        )
        plan = load_plan(self.out / "plan.json")
        journal_path = self.dir / "j"
        first = RecordingCli()
        execute(plan, first, Journal(journal_path), echo=lambda _: None)
        # Fully identical items: the deterministic tiebreak keeps the first-listed.
        self.assertEqual(first.deleted, ["i2"])

        second = RecordingCli()
        counts = execute(plan, second, Journal(journal_path), echo=lambda _: None)
        self.assertEqual(second.deleted, [])
        self.assertGreater(counts["skipped"], 0)

    def test_modified_source_aborts_apply(self):
        self.run_plan(chrome=[("Reddit", "https://reddit.com", "u", "pw", "")], items=[])
        write_chrome_csv(self.dir / "chrome.csv", [("Reddit", "https://reddit.com", "u", "CHANGED", "")])
        with self.assertRaises(ApplyError) as ctx:
            resolve_sources(load_plan(self.out / "plan.json"))
        self.assertIn("changed since the plan was generated", str(ctx.exception))

    def test_missing_source_aborts_apply(self):
        self.run_plan(chrome=[("Reddit", "https://reddit.com", "u", "pw", "")], items=[])
        (self.dir / "chrome.csv").unlink()
        with self.assertRaises(ApplyError):
            resolve_sources(load_plan(self.out / "plan.json"))

    def test_unsupported_plan_version_rejected(self):
        self.run_plan(items=[bw_login("i1", "A", "u", "p", ["https://a.com"])])
        path = self.out / "plan.json"
        data = json.loads(path.read_text())
        data["version"] = 99
        path.write_text(json.dumps(data))
        with self.assertRaises(ApplyError):
            load_plan(path)


class TestEndToEndIdempotence(PlanTestCase):
    def test_second_plan_on_cleaned_vault_is_a_no_op(self):
        """After applying, a fresh export must plan zero further deletions."""
        items = [
            bw_login("i1", "GitHub", "u", "pw", ["https://github.com"]),
            bw_login("i2", "GitHub", "u", "pw", ["https://www.github.com"]),
            bw_login("i3", "Bank", "me", "bankpw", ["https://hsbc.co.uk"]),
        ]
        plan = self.run_plan(items=items)
        deleted = {a["item_id"] for a in plan["actions"] if a["op"] == "delete"}
        self.assertTrue(deleted)

        # Simulate the post-apply vault: deleted items gone, keeper URIs merged.
        remaining = [i for i in items if i["id"] not in deleted]
        for item in remaining:
            if item["id"] == "i1":
                item["login"]["uris"] = [
                    {"match": None, "uri": "https://github.com"},
                    {"match": None, "uri": "https://www.github.com"},
                ]
        second = self.run_plan(items=remaining)
        self.assertEqual([a for a in second["actions"] if a["op"] == "delete"], [])
        self.assertEqual([a for a in second["actions"] if a["op"] == "update"], [])


if __name__ == "__main__":
    unittest.main()
