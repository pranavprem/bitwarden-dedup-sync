"""Parsers for every export format involved, producing `Credential` objects.

Supported inputs:
  * Bitwarden unencrypted JSON export  (the vault side; carries item ids)
  * Bitwarden CSV export               (accepted, but ids are absent -> import only)
  * Apple Passwords CSV                (Title,URL,Username,Password,Notes,OTPAuth)
  * Google Chrome CSV                  (name,url,username,password,note)
  * Firefox CSV                        (bonus; recognised by its distinctive columns)

Format detection is by header signature, so the user never has to declare which
file is which beyond naming the vault export.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from pathlib import Path
from typing import Any, Iterable

from bwsync.model import (
    TYPE_LOGIN,
    Credential,
    NonLoginItem,
    parse_timestamp,
)


class ParseError(Exception):
    """Raised when an input file cannot be interpreted as a known export."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_text(path: Path) -> str:
    # Chrome and Apple both emit UTF-8; Windows-origin files may carry a BOM.
    return path.read_text(encoding="utf-8-sig")


def _clean(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _uri_list(raw: Any) -> tuple[str, ...]:
    """Normalise a Bitwarden `login.uris` array into plain strings."""
    if not isinstance(raw, list):
        return ()
    out = []
    for entry in raw:
        if isinstance(entry, dict):
            uri = _clean(entry.get("uri"))
        else:
            uri = _clean(entry)
        if uri:
            out.append(uri)
    return tuple(out)


# --------------------------------------------------------------------------
# Bitwarden JSON
# --------------------------------------------------------------------------


def parse_bitwarden_json(path: Path) -> tuple[list[Credential], list[NonLoginItem], dict[str, str]]:
    """Parse an unencrypted Bitwarden JSON export.

    Returns (logins, non_login_items, folder_id_to_name).
    """
    try:
        data = json.loads(_read_text(path))
    except json.JSONDecodeError as exc:
        raise ParseError(f"{path}: not valid JSON ({exc}).") from exc

    if not isinstance(data, dict):
        raise ParseError(f"{path}: expected a JSON object at the top level.")
    if data.get("encrypted"):
        raise ParseError(
            f"{path}: this is an ENCRYPTED Bitwarden export. Re-export choosing "
            f'"Password protected" -> off, i.e. the plain ".json" format.'
        )
    items = data.get("items")
    if not isinstance(items, list):
        raise ParseError(f"{path}: no 'items' array — is this a Bitwarden JSON export?")

    folders = {
        _clean(f.get("id")): _clean(f.get("name"))
        for f in data.get("folders") or []
        if isinstance(f, dict) and _clean(f.get("id"))
    }

    logins: list[Credential] = []
    others: list[NonLoginItem] = []

    for index, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        # Items already in the trash must not be counted as duplicates.
        if item.get("deletedDate"):
            continue
        item_id = _clean(item.get("id"))
        item_type = item.get("type")
        revision = parse_timestamp(item.get("revisionDate"))

        if item_type == TYPE_LOGIN and isinstance(item.get("login"), dict):
            login = item["login"]
            folder_id = _clean(item.get("folderId")) or None
            logins.append(
                Credential(
                    source="bitwarden",
                    index=index,
                    name=_clean(item.get("name")),
                    username=_clean(login.get("username")),
                    password=login.get("password") or "",
                    uris=_uri_list(login.get("uris")),
                    totp=_clean(login.get("totp")) or None,
                    notes=_clean(item.get("notes")) or None,
                    item_id=item_id or None,
                    folder_id=folder_id,
                    folder_name=folders.get(folder_id or ""),
                    favorite=bool(item.get("favorite")),
                    reprompt=int(item.get("reprompt") or 0),
                    fields=tuple(f for f in (item.get("fields") or []) if isinstance(f, dict)),
                    passkey_ids=_passkey_ids(login),
                    revision=revision,
                    creation=parse_timestamp(item.get("creationDate")),
                    raw=item,
                )
            )
        elif isinstance(item_type, int) and item_id:
            others.append(
                NonLoginItem(
                    index=index,
                    item_id=item_id,
                    item_type=item_type,
                    name=_clean(item.get("name")),
                    content_hash=_non_login_hash(item),
                    revision=revision,
                    raw=item,
                )
            )

    return logins, others, folders


def _passkey_ids(login: dict[str, Any]) -> frozenset[str]:
    """credentialIds of the passkeys on a login item.

    A credential with no id is given a synthetic one from its position so it can
    never be mistaken for a copy of another passkey — unknown identity must read
    as "distinct", never as "same".
    """
    credentials = login.get("fido2Credentials")
    if not isinstance(credentials, list):
        return frozenset()
    ids = set()
    for position, credential in enumerate(credentials):
        if not isinstance(credential, dict):
            continue
        ids.add(_clean(credential.get("credentialId")) or f"__unidentified_{position}")
    return frozenset(ids)


def _non_login_hash(item: dict[str, Any]) -> str:
    """Content fingerprint for a note/card/identity.

    Deliberately includes every user-visible field: two non-login items are only
    ever treated as duplicates when they are byte-for-byte identical in content.
    Volatile bookkeeping keys are excluded so that re-imported copies of the same
    note still match.
    """
    volatile = {
        "id",
        "revisionDate",
        "creationDate",
        "deletedDate",
        "folderId",
        "favorite",
        "passwordHistory",
        "collectionIds",
        "organizationId",
    }
    payload = {k: v for k, v in sorted(item.items()) if k not in volatile}
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# CSV formats
# --------------------------------------------------------------------------


def _sniff_rows(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    text = _read_text(path)
    if not text.strip():
        raise ParseError(f"{path}: file is empty.")
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ParseError(f"{path}: no CSV header row found.")
    headers = [(h or "").strip().lower() for h in reader.fieldnames]
    rows: list[dict[str, str]] = []
    for row in reader:
        rows.append({(k or "").strip().lower(): (v or "") for k, v in row.items()})
    return headers, rows


def detect_csv_format(headers: Iterable[str]) -> str:
    header_set = {h for h in headers}
    if "login_username" in header_set or "login_password" in header_set:
        return "bitwarden-csv"
    if {"formactionorigin", "httprealm"} & header_set:
        return "firefox"
    if "title" in header_set and "url" in header_set:
        return "apple"
    if "name" in header_set and "url" in header_set:
        return "chrome"
    if {"url", "username", "password"} <= header_set:
        return "chrome"
    raise ParseError(
        "Unrecognised CSV header. Expected an Apple Passwords, Chrome, Firefox "
        f"or Bitwarden CSV export; got columns: {sorted(header_set)}"
    )


def _first(row: dict[str, str], *keys: str) -> str:
    for key in keys:
        value = _clean(row.get(key))
        if value:
            return value
    return ""


def parse_csv(path: Path, source: str | None = None) -> list[Credential]:
    """Parse any supported CSV export into credentials."""
    headers, rows = _sniff_rows(path)
    fmt = source or detect_csv_format(headers)

    creds: list[Credential] = []
    for index, row in enumerate(rows):
        if fmt == "bitwarden-csv":
            if _clean(row.get("type")) not in ("", "login"):
                continue  # notes/cards in a CSV have no reliable identity
            name = _first(row, "name")
            username = _first(row, "login_username")
            password = row.get("login_password") or ""
            uris = tuple(u for u in (row.get("login_uri") or "").split(",") if u.strip())
            totp = _first(row, "login_totp") or None
            notes = _first(row, "notes") or None
            folder = _first(row, "folder") or None
        elif fmt == "apple":
            name = _first(row, "title", "name")
            username = _first(row, "username")
            password = row.get("password") or ""
            uris = tuple(u for u in [_first(row, "url")] if u)
            totp = _first(row, "otpauth", "otp") or None
            notes = _first(row, "notes") or None
            folder = None
        elif fmt == "firefox":
            name = _first(row, "url")
            username = _first(row, "username")
            password = row.get("password") or ""
            uris = tuple(u for u in [_first(row, "url")] if u)
            totp = None
            notes = None
            folder = None
        else:  # chrome
            name = _first(row, "name", "title")
            username = _first(row, "username")
            password = row.get("password") or ""
            uris = tuple(u for u in [_first(row, "url")] if u)
            totp = _first(row, "otpauth") or None
            notes = _first(row, "note", "notes") or None
            folder = None

        # A row with neither a password nor a TOTP secret carries nothing worth
        # migrating (Chrome exports blank rows for federated/"Sign in with"
        # entries, which are not credentials at all).
        if not password and not totp:
            continue

        creds.append(
            Credential(
                source=_source_label(fmt),
                index=index,
                name=name or (uris[0] if uris else username),
                username=username,
                password=password,
                uris=uris,
                totp=totp,
                notes=notes,
                folder_name=folder,
            )
        )
    return creds


def _source_label(fmt: str) -> str:
    return {
        "apple": "apple",
        "chrome": "chrome",
        "firefox": "firefox",
        "bitwarden-csv": "bitwarden-csv",
    }[fmt]


def load_source(path: Path, label: str, expect_vault: bool = False) -> tuple[
    list[Credential], list[NonLoginItem], dict[str, str]
]:
    """Load any supported export, dispatching on file type.

    `label` becomes each credential's `source`, and therefore the first half of
    its `ref`. It must be the same string in `plan` and `apply` or refs will not
    resolve — both derive it from the same key, so this stays consistent.
    """
    if not path.exists():
        raise ParseError(f"{path}: file not found.")
    if path.suffix.lower() == ".json":
        return parse_bitwarden_json(path)
    if expect_vault:
        raise ParseError(
            f"{path}: the Bitwarden vault export must be JSON (.json). A CSV export "
            f"omits item IDs, TOTP round-tripping and passkeys, so it cannot be "
            f"deduplicated in place."
        )
    credentials = parse_csv(path)
    for cred in credentials:
        cred.source = label
    return credentials, [], {}
