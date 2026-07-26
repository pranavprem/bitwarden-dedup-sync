"""Source-agnostic credential model.

Every parser produces `Credential` objects. Downstream code (normalisation,
grouping, planning) never sees vendor-specific shapes.

A `Credential` is identified by its `ref` ("<source>:<index>") which is stable
for a given export file. Plans reference credentials by `ref` only, so a plan
file never has to contain a password.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# Bitwarden item type codes (from the Bitwarden API/export schema).
TYPE_LOGIN = 1
TYPE_SECURE_NOTE = 2
TYPE_CARD = 3
TYPE_IDENTITY = 4

TYPE_NAMES = {
    TYPE_LOGIN: "login",
    TYPE_SECURE_NOTE: "note",
    TYPE_CARD: "card",
    TYPE_IDENTITY: "identity",
}


@dataclass
class Credential:
    """One login entry from one source."""

    source: str
    index: int
    name: str
    username: str
    password: str
    uris: tuple[str, ...] = ()
    totp: str | None = None
    notes: str | None = None
    item_id: str | None = None
    folder_id: str | None = None
    folder_name: str | None = None
    favorite: bool = False
    reprompt: int = 0
    fields: tuple[dict[str, Any], ...] = ()
    has_passkey: bool = False
    revision: datetime | None = None
    creation: datetime | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def ref(self) -> str:
        return f"{self.source}:{self.index}"

    @property
    def from_vault(self) -> bool:
        """True for items that already live in Bitwarden.

        Keyed on the item id rather than the source label: only a JSON vault
        export carries ids, and only an item with an id can be edited or deleted
        in place. A Bitwarden *CSV* therefore counts as an import, correctly.
        """
        return self.item_id is not None

    def sort_key(self) -> tuple:
        """Deterministic tiebreak so planning output is reproducible."""
        return (self.source, self.index)


@dataclass
class NonLoginItem:
    """A Bitwarden secure note / card / identity.

    These are deduplicated only on exact content equality, never merged.
    """

    index: int
    item_id: str
    item_type: int
    name: str
    content_hash: str
    revision: datetime | None
    raw: dict[str, Any]

    @property
    def ref(self) -> str:
        return f"bitwarden:{self.index}"

    @property
    def type_name(self) -> str:
        return TYPE_NAMES.get(self.item_type, f"type{self.item_type}")


def parse_timestamp(value: Any) -> datetime | None:
    """Parse a Bitwarden ISO-8601 timestamp, tolerating the trailing 'Z'.

    Returns None rather than raising: a missing or malformed date only costs us
    a tiebreak signal, and must never abort a run over the whole vault.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    # Naive timestamps are assumed UTC so all comparisons stay ordered.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed
