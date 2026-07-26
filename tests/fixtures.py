"""Shared fixture builders for the test-suite."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def bw_login(
    item_id: str,
    name: str,
    username: str,
    password: str,
    uris: list[str] | None = None,
    totp: str | None = None,
    notes: str | None = None,
    folder_id: str | None = None,
    revision: str = "2024-01-01T00:00:00.000Z",
    fields: list[dict] | None = None,
    passkey: bool = False,
    deleted: bool = False,
) -> dict[str, Any]:
    return {
        "id": item_id,
        "organizationId": None,
        "folderId": folder_id,
        "type": 1,
        "reprompt": 0,
        "name": name,
        "notes": notes,
        "favorite": False,
        "fields": fields or [],
        "deletedDate": "2024-06-01T00:00:00.000Z" if deleted else None,
        "revisionDate": revision,
        "creationDate": revision,
        "login": {
            "fido2Credentials": [{"credentialId": "x"}] if passkey else [],
            "uris": [{"match": None, "uri": u} for u in (uris or [])],
            "username": username,
            "password": password,
            "totp": totp,
        },
        "collectionIds": None,
    }


def bw_note(item_id: str, name: str, notes: str, revision: str = "2024-01-01T00:00:00.000Z") -> dict:
    return {
        "id": item_id,
        "organizationId": None,
        "folderId": None,
        "type": 2,
        "reprompt": 0,
        "name": name,
        "notes": notes,
        "favorite": False,
        "fields": [],
        "secureNote": {"type": 0},
        "deletedDate": None,
        "revisionDate": revision,
        "creationDate": revision,
        "collectionIds": None,
    }


def write_vault(path: Path, items: list[dict], folders: list[dict] | None = None) -> Path:
    path.write_text(
        json.dumps({"encrypted": False, "folders": folders or [], "items": items}),
        encoding="utf-8",
    )
    return path


def write_chrome_csv(path: Path, rows: list[tuple[str, str, str, str, str]]) -> Path:
    lines = ["name,url,username,password,note"]
    lines += [",".join(f'"{value}"' for value in row) for row in rows]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def write_apple_csv(path: Path, rows: list[tuple[str, str, str, str, str, str]]) -> Path:
    lines = ["Title,URL,Username,Password,Notes,OTPAuth"]
    lines += [",".join(f'"{value}"' for value in row) for row in rows]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
