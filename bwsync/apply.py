"""Execute a plan against a live vault through the Bitwarden CLI.

Credential handling rules enforced here:

  * We never ask for, read or store the master password. The user unlocks `bw`
    themselves and exports `BW_SESSION`; we only inherit it from the environment.
  * Item payloads are base64-encoded and written to `bw` over **stdin**, never
    passed as argv, so plaintext secrets never appear in the process table.
  * `bw` output is only surfaced verbatim on failure, and item payloads are never
    echoed. Progress lines identify items by name and id.
  * Deletes go to the Trash by default, so a mistake is recoverable in-product.

Every completed action is appended to a journal file, making `apply` resumable
and idempotent: a re-run skips whatever already succeeded.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from bwsync.model import Credential
from bwsync.parsers import ParseError, load_source, sha256_file
from bwsync.planner import PLAN_VERSION


class ApplyError(Exception):
    """Raised when the vault is not in a state where the plan can be executed."""


@dataclass
class BwCli:
    """Thin wrapper over the `bw` binary."""

    executable: str = "bw"
    session: str | None = None
    dry_run: bool = True
    echo: Callable[[str], None] = print

    def _env(self) -> dict[str, str]:
        env = dict(os.environ)
        if self.session:
            env["BW_SESSION"] = self.session
        # Keep the CLI non-interactive: a hidden prompt would hang the run.
        env["BW_NOINTERACTION"] = "true"
        return env

    def run(self, args: list[str], stdin_data: str | None = None, check: bool = True) -> str:
        result = subprocess.run(
            [self.executable, *args],
            input=stdin_data,
            capture_output=True,
            text=True,
            env=self._env(),
        )
        if check and result.returncode != 0:
            # stderr from bw does not include the payload we piped in.
            raise ApplyError(
                f"`bw {' '.join(args)}` failed (exit {result.returncode}): "
                f"{result.stderr.strip() or result.stdout.strip()}"
            )
        return result.stdout.strip()

    def ensure_unlocked(self) -> None:
        if not shutil.which(self.executable):
            raise ApplyError(
                "The Bitwarden CLI (`bw`) was not found on PATH. Install it with "
                "`brew install bitwarden-cli` (or `npm i -g @bitwarden/cli`)."
            )
        raw = self.run(["status"])
        try:
            status = json.loads(raw).get("status")
        except json.JSONDecodeError as exc:
            raise ApplyError(f"Could not read `bw status` output: {raw}") from exc
        if status == "unauthenticated":
            raise ApplyError("`bw` is logged out. Run `bw login`, then `bw unlock`.")
        if status != "unlocked":
            raise ApplyError(
                "The vault is locked. Run `export BW_SESSION=$(bw unlock --raw)` in this "
                "shell, then re-run. bwsync never handles your master password."
            )

    # -- mutating operations -------------------------------------------------

    def _send_object(self, args: list[str], payload: dict[str, Any]) -> str:
        encoded = base64.b64encode(
            json.dumps(payload, ensure_ascii=False).encode("utf-8")
        ).decode("ascii")
        if self.dry_run:
            return ""
        return self.run(args, stdin_data=encoded)

    def create_item(self, payload: dict[str, Any]) -> str:
        return self._send_object(["create", "item"], payload)

    def edit_item(self, item_id: str, payload: dict[str, Any]) -> str:
        return self._send_object(["edit", "item", item_id], payload)

    def create_folder(self, name: str) -> str | None:
        output = self._send_object(["create", "folder"], {"name": name})
        if not output:
            return None
        try:
            return json.loads(output).get("id")
        except json.JSONDecodeError:
            return None

    def delete_item(self, item_id: str, permanent: bool = False) -> None:
        if self.dry_run:
            return
        args = ["delete", "item", item_id]
        if permanent:
            args.append("--permanent")
        self.run(args)

    def list_folders(self) -> dict[str, str]:
        if self.dry_run and not self.session:
            return {}
        raw = self.run(["list", "folders"])
        try:
            folders = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return {f["name"]: f["id"] for f in folders if isinstance(f, dict) and f.get("id")}

    def sync(self) -> None:
        if not self.dry_run:
            self.run(["sync"])


class Journal:
    """Append-only record of completed actions, for resumability."""

    def __init__(self, path: Path, enabled: bool = True):
        self.path = path
        self.enabled = enabled
        self.done: set[str] = set()
        if enabled and path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    self.done.add(line.strip())

    def key(self, action: dict[str, Any]) -> str:
        return f"{action['op']}:{action.get('item_id') or action.get('ref') or action.get('name')}"

    def completed(self, action: dict[str, Any]) -> bool:
        return self.key(action) in self.done

    def record(self, action: dict[str, Any]) -> None:
        if not self.enabled:
            return
        key = self.key(action)
        self.done.add(key)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(key + "\n")
        self.path.chmod(0o600)


def load_plan(path: Path) -> dict[str, Any]:
    plan = json.loads(path.read_text(encoding="utf-8"))
    if plan.get("version") != PLAN_VERSION:
        raise ApplyError(
            f"{path}: plan format version {plan.get('version')} is not supported by this "
            f"version of bwsync (expects {PLAN_VERSION}). Re-run `bwsync plan`."
        )
    return plan


def resolve_sources(plan: dict[str, Any]) -> dict[str, Credential]:
    """Re-read the export files named by the plan and index them by ref.

    Digests are verified first: a plan reviewed against one set of exports must
    not be executed against a different one.
    """
    by_ref: dict[str, Credential] = {}
    for source, info in plan["sources"].items():
        path = Path(info["path"])
        if not path.exists():
            raise ApplyError(
                f"Source file for '{source}' is missing: {path}\n"
                f"apply re-reads the exports because the plan deliberately stores no secrets."
            )
        actual = sha256_file(path)
        if actual != info["sha256"]:
            raise ApplyError(
                f"{path} changed since the plan was generated "
                f"(expected {info['sha256'][:16]}…, found {actual[:16]}…). "
                f"Re-run `bwsync plan` so you review what will actually be applied."
            )
        try:
            credentials, _, _ = load_source(path, source)
        except ParseError as exc:
            raise ApplyError(str(exc)) from exc
        for cred in credentials:
            by_ref[cred.ref] = cred
    return by_ref


def _login_payload(cred: Credential, uris: list[str], folder_id: str | None) -> dict[str, Any]:
    return {
        "organizationId": None,
        "collectionIds": None,
        "folderId": folder_id,
        "type": 1,
        "name": cred.name or (uris[0] if uris else cred.username) or "Untitled",
        "notes": cred.notes,
        "favorite": False,
        "reprompt": 0,
        "fields": list(cred.fields) or None,
        "login": {
            "uris": [{"match": None, "uri": uri} for uri in uris] or None,
            "username": cred.username or None,
            "password": cred.password or None,
            "totp": cred.totp,
        },
    }


def execute(
    plan: dict[str, Any],
    cli: BwCli,
    journal: Journal,
    permanent: bool = False,
    echo: Callable[[str], None] = print,
) -> dict[str, int]:
    by_ref = resolve_sources(plan)
    counts = {"created": 0, "updated": 0, "deleted": 0, "folders": 0, "skipped": 0}

    if not cli.dry_run:
        echo("Syncing vault before changes…")
        cli.sync()

    folder_ids = cli.list_folders()

    for action in plan["actions"]:
        if journal.completed(action):
            counts["skipped"] += 1
            continue
        op = action["op"]

        if op == "ensure_folder":
            name = action["name"]
            if name in folder_ids:
                echo(f"  folder exists: {name}")
            else:
                echo(f"{'[dry-run] ' if cli.dry_run else ''}create folder: {name}")
                new_id = cli.create_folder(name)
                if new_id:
                    folder_ids[name] = new_id
                counts["folders"] += 1

        elif op == "delete":
            echo(
                f"{'[dry-run] ' if cli.dry_run else ''}delete "
                f"{action['item_id'][:8]}  {action['name'] or '(unnamed)'}  "
                f"[{action['label']}]"
            )
            cli.delete_item(action["item_id"], permanent=permanent)
            counts["deleted"] += 1

        elif op == "update":
            keeper = by_ref.get(action["ref"])
            if keeper is None:
                raise ApplyError(f"Plan references unknown item {action['ref']}.")
            payload = _apply_update(action, keeper, by_ref)
            echo(
                f"{'[dry-run] ' if cli.dry_run else ''}update "
                f"{action['item_id'][:8]}  {action['name'] or '(unnamed)'}  "
                f"({', '.join(_gains(action))})"
            )
            cli.edit_item(action["item_id"], payload)
            counts["updated"] += 1

        elif op == "create":
            cred = by_ref.get(action["ref"])
            if cred is None:
                raise ApplyError(f"Plan references unknown item {action['ref']}.")
            folder_id = folder_ids.get(action["folder"]) if action["folder"] else None
            if action["folder"] and folder_id is None and not cli.dry_run:
                raise ApplyError(f"Folder '{action['folder']}' could not be resolved.")
            echo(
                f"{'[dry-run] ' if cli.dry_run else ''}create "
                f"{action['name'] or '(unnamed)'}  [{action['label']}]"
                f"{'  -> ' + action['folder'] if action['folder'] else ''}"
            )
            cli.create_item(_login_payload(cred, action["uris"], folder_id))
            counts["created"] += 1

        else:
            raise ApplyError(f"Unknown plan operation '{op}'.")

        if not cli.dry_run:
            journal.record(action)

    if not cli.dry_run:
        echo("Syncing vault after changes…")
        cli.sync()

    return counts


def _gains(action: dict[str, Any]) -> list[str]:
    """Summarise what an update absorbs, listing only what actually changes."""
    gains = []
    added = len(action.get("added_uris") or [])
    if added:
        gains.append(f"+{added} url")
    if action.get("take_totp_from"):
        gains.append("+2FA seed")
    if action.get("take_notes_from"):
        gains.append("+notes")
    if action.get("field_count"):
        gains.append(f"+{action['field_count']} fields")
    return gains or ["no change"]


def _apply_update(
    action: dict[str, Any], keeper: Credential, by_ref: dict[str, Credential]
) -> dict[str, Any]:
    """Rebuild the keeper's full item with absorbed metadata.

    `bw edit item` replaces the whole object, so we start from the item exactly
    as exported and change only what the plan authorises.
    """
    item = json.loads(json.dumps(keeper.raw))  # deep copy; never mutate the parse
    login = item.setdefault("login", {})

    if action.get("uris"):
        login["uris"] = action["uris"]

    totp_ref = action.get("take_totp_from")
    if totp_ref:
        donor = by_ref.get(totp_ref)
        if donor is None:
            raise ApplyError(f"Plan references unknown TOTP donor {totp_ref}.")
        login["totp"] = donor.totp

    notes_ref = action.get("take_notes_from")
    if notes_ref:
        donor = by_ref.get(notes_ref)
        if donor is None:
            raise ApplyError(f"Plan references unknown notes donor {notes_ref}.")
        item["notes"] = donor.notes

    for tagged in action.get("add_fields_from") or []:
        ref, _, position = tagged.partition("#")
        donor = by_ref.get(ref)
        if donor is None or not position.isdigit() or int(position) >= len(donor.fields):
            raise ApplyError(f"Plan references unknown custom field {tagged}.")
        item.setdefault("fields", [])
        item["fields"] = list(item.get("fields") or []) + [donor.fields[int(position)]]

    return item
