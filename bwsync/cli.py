"""Command-line interface.

    bwsync plan  --vault vault.json --apple apple.csv --chrome chrome.csv
    bwsync apply --plan out/plan.json            # dry run
    bwsync apply --plan out/plan.json --confirm  # execute
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from bwsync import __version__
from bwsync.apply import ApplyError, BwCli, Journal, execute, load_plan
from bwsync.dedupe import build_groups, find_non_login_duplicates
from bwsync.model import Credential, NonLoginItem
from bwsync.parsers import ParseError, load_source, sha256_file
from bwsync.planner import IMPORT_FOLDER, build_plan, write_plan
from bwsync.report import write_reports


def _err(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


def _add_source(
    label: str,
    path: Path | None,
    credentials: list[Credential],
    non_logins: list[NonLoginItem],
    sources: dict[str, dict[str, str]],
    expect_vault: bool = False,
) -> None:
    if path is None:
        return
    creds, others, _ = load_source(path, label, expect_vault=expect_vault)
    credentials.extend(creds)
    non_logins.extend(others)
    sources[label] = {
        "path": str(path.resolve()),
        "sha256": sha256_file(path),
        "count": str(len(creds)),
    }


def cmd_plan(args: argparse.Namespace) -> int:
    credentials: list[Credential] = []
    non_logins: list[NonLoginItem] = []
    sources: dict[str, dict[str, str]] = {}

    try:
        _add_source("bitwarden", args.vault, credentials, non_logins, sources, expect_vault=True)
        _add_source("apple", args.apple, credentials, non_logins, sources)
        _add_source("chrome", args.chrome, credentials, non_logins, sources)
        for position, extra in enumerate(args.extra or []):
            _add_source(f"extra{position}", Path(extra), credentials, non_logins, sources)
    except ParseError as exc:
        _err(str(exc))
        return 2

    groups = build_groups(credentials, aggressive_username=args.aggressive_username)
    non_login_duplicates = find_non_login_duplicates(non_logins)

    plan = build_plan(
        groups,
        non_login_duplicates,
        sources,
        options={
            "aggressive_username": args.aggressive_username,
            "import_folder": None if args.no_import_folder else args.import_folder,
            "bwsync_version": __version__,
        },
        import_new=not args.no_import,
    )

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        out_dir.chmod(0o700)
    except OSError:
        pass  # A non-owned or network-mounted directory is the user's call.

    plan_path = out_dir / "plan.json"
    write_plan(plan, plan_path)
    written = write_reports(plan, out_dir)

    stats = plan.stats
    print(f"Read {len(credentials)} logins across {len(sources)} source(s).")
    print(f"  {stats['groups']} distinct site+username identities")
    print(f"  {stats['vault_deletes']} vault logins are exact duplicates -> delete")
    print(f"  {stats['note_card_deletes']} duplicate notes/cards/identities -> delete")
    print(f"  {stats['vault_updates']} vault items gain URLs / 2FA / notes from their duplicates")
    print(f"  {stats['creates'] - stats['conflict_creates']} new logins to import")
    print(f"  {stats['conflict_creates']} conflicting logins filed for review")
    print(f"  {stats['conflict_groups']} identities have conflicting passwords")
    print()
    print(f"Plan:   {plan_path}")
    print(f"Report: {written['report']}")
    print()
    print("Review the report, then:")
    print(f"  bwsync apply --plan {plan_path}            # dry run")
    print(f"  bwsync apply --plan {plan_path} --confirm  # execute")
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    plan_path = Path(args.plan)
    try:
        plan = load_plan(plan_path)
    except (OSError, ValueError, ApplyError) as exc:
        _err(str(exc))
        return 2

    dry_run = not args.confirm
    cli = BwCli(executable=args.bw, session=os.environ.get("BW_SESSION"), dry_run=dry_run)

    try:
        if not dry_run:
            cli.ensure_unlocked()
        journal = Journal(plan_path.with_suffix(".journal"), enabled=not dry_run)
        counts = execute(plan, cli, journal, permanent=args.permanent)
    except ApplyError as exc:
        _err(str(exc))
        return 1

    print()
    if dry_run:
        print("Dry run complete — nothing was changed.")
        print(
            f"Would create {counts['created']}, update {counts['updated']}, "
            f"delete {counts['deleted']}, add {counts['folders']} folder(s)."
        )
        print("Re-run with --confirm to execute.")
    else:
        print(
            f"Done. Created {counts['created']}, updated {counts['updated']}, "
            f"deleted {counts['deleted']}, added {counts['folders']} folder(s)."
            + (f" Skipped {counts['skipped']} already applied." if counts["skipped"] else "")
        )
        if not args.permanent and counts["deleted"]:
            print("Deleted items are in the Bitwarden Trash and can be restored.")
        print()
        print("Verify by re-exporting your vault and running `bwsync plan` again:")
        print("a clean vault reports 0 deletes.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bwsync",
        description=(
            "Deduplicate a Bitwarden vault and merge in Apple Passwords / Chrome "
            "exports. Runs entirely offline; never handles your master password."
        ),
    )
    parser.add_argument("--version", action="version", version=f"bwsync {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    plan_parser = sub.add_parser("plan", help="analyse exports and write a plan (changes nothing)")
    plan_parser.add_argument(
        "--vault", type=Path, required=True, help="Bitwarden unencrypted .json export"
    )
    plan_parser.add_argument("--apple", type=Path, help="Apple Passwords .csv export")
    plan_parser.add_argument("--chrome", type=Path, help="Google Chrome .csv export")
    plan_parser.add_argument(
        "--extra", action="append", help="additional CSV export (repeatable; e.g. Firefox)"
    )
    plan_parser.add_argument("--out", default="out", help="output directory (default: out)")
    plan_parser.add_argument(
        "--import-folder",
        default=IMPORT_FOLDER,
        help=f"folder for newly imported logins (default: {IMPORT_FOLDER})",
    )
    plan_parser.add_argument(
        "--no-import-folder", action="store_true", help="import new logins to no folder"
    )
    plan_parser.add_argument(
        "--no-import",
        action="store_true",
        help="only deduplicate the vault; do not import anything new",
    )
    plan_parser.add_argument(
        "--aggressive-username",
        action="store_true",
        help="treat Gmail dot/plus variants as the same username (merges more)",
    )
    plan_parser.set_defaults(func=cmd_plan)

    apply_parser = sub.add_parser("apply", help="execute a plan via the Bitwarden CLI")
    apply_parser.add_argument("--plan", required=True, help="path to plan.json")
    apply_parser.add_argument(
        "--confirm", action="store_true", help="actually make changes (default is a dry run)"
    )
    apply_parser.add_argument(
        "--permanent",
        action="store_true",
        help="hard-delete instead of moving to Trash (not recoverable)",
    )
    apply_parser.add_argument("--bw", default="bw", help="path to the Bitwarden CLI binary")
    apply_parser.set_defaults(func=cmd_apply)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        _err("interrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
