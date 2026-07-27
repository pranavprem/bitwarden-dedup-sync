"""Grouping and duplicate resolution.

The algorithm, in one paragraph:

  Pool every credential from every source. Group by (registrable domain,
  normalised username). Inside each group, sub-group by *exact password*. Every
  password sub-group collapses to exactly one surviving item — that is the only
  place a deletion can be produced, and it is safe by construction because all
  members share identical password bytes. A group with more than one password
  sub-group is a CONFLICT: the same login has diverging passwords across copies,
  which a machine cannot resolve, so nothing in it is deleted and the extra
  passwords are preserved for human review.

Consequence worth stating plainly: no distinct password can ever be lost.
"""

from __future__ import annotations

import hmac
import os
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256

from bwsync.model import Credential, NonLoginItem
from bwsync.normalize import domain_key, normalize_uri, username_key

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# Per-run key for password fingerprints shown in reports. Regenerated every run
# and never persisted, so a leaked report cannot be used to attack the hashes:
# the fingerprints are only comparable to each other within one report.
_FINGERPRINT_KEY = os.urandom(32)


def fingerprint(password: str) -> str:
    """Short, non-reversible label letting a human tell two passwords apart."""
    if not password:
        return "(empty)"
    return hmac.new(_FINGERPRINT_KEY, password.encode("utf-8"), sha256).hexdigest()[:8]


@dataclass
class PasswordSubgroup:
    """All copies of one credential that share the exact same password."""

    password: str
    members: list[Credential] = field(default_factory=list)

    @property
    def keeper(self) -> Credential:
        """The member that survives; every other member is redundant."""
        return max(self.members, key=_keeper_score)

    @property
    def vault_members(self) -> list[Credential]:
        return [c for c in self.members if c.from_vault]

    @property
    def redundant_vault_members(self) -> list[Credential]:
        """Vault copies safe to delete.

        A copy is only redundant if the keeper already holds every passkey it
        holds. A passkey's private key exists nowhere else and cannot be merged
        across items, so a copy carrying a credentialId the keeper lacks is a
        real credential that would be destroyed — it stays.
        """
        keeper = self.keeper
        return [
            c
            for c in self.vault_members
            if c is not keeper and c.passkey_ids <= keeper.passkey_ids
        ]

    @property
    def passkey_protected_members(self) -> list[Credential]:
        """Vault copies spared because they hold passkeys the keeper does not."""
        keeper = self.keeper
        return [
            c
            for c in self.vault_members
            if c is not keeper and not (c.passkey_ids <= keeper.passkey_ids)
        ]


@dataclass
class Group:
    """Everything sharing one (domain, username) identity."""

    domain: str
    username: str
    subgroups: list[PasswordSubgroup] = field(default_factory=list)

    @property
    def is_conflict(self) -> bool:
        return len(self.subgroups) > 1

    @property
    def label(self) -> str:
        return f"{self.domain or '(no domain)'} / {self.username or '(no username)'}"

    @property
    def members(self) -> list[Credential]:
        return [c for sub in self.subgroups for c in sub.members]


def _keeper_score(cred: Credential) -> tuple:
    """Rank candidates so the richest, most-established copy survives.

    Ordering rationale, most significant first:
      * a vault item beats an imported row (keeps the existing id and history)
      * secrets and metadata that would otherwise be lost outrank convenience
      * newest revision, then a stable source/index tiebreak for determinism
    """
    return (
        1 if cred.from_vault else 0,
        # Count, not a flag: keeping the copy with the most passkeys minimises
        # how many siblings have to be spared for holding a unique one.
        len(cred.passkey_ids),
        1 if cred.totp else 0,
        1 if cred.notes else 0,
        len(cred.fields),
        1 if cred.folder_id or cred.folder_name else 0,
        1 if cred.favorite else 0,
        len({normalize_uri(u) for u in cred.uris if normalize_uri(u)}),
        (cred.revision or _EPOCH).timestamp(),
        -cred.index,
        cred.source,
    )


def build_groups(credentials: list[Credential], aggressive_username: bool = False) -> list[Group]:
    """Pool all sources and produce (domain, username) groups."""
    buckets: dict[tuple[str, str], list[Credential]] = defaultdict(list)
    for cred in credentials:
        key = (
            domain_key(cred.uris, cred.name),
            username_key(cred.username, aggressive=aggressive_username),
        )
        buckets[key].append(cred)

    groups: list[Group] = []
    for (domain, username), members in buckets.items():
        by_password: dict[str, PasswordSubgroup] = {}
        for cred in sorted(members, key=Credential.sort_key):
            sub = by_password.get(cred.password)
            if sub is None:
                sub = by_password[cred.password] = PasswordSubgroup(password=cred.password)
            sub.members.append(cred)
        # Order subgroups by the best member so reports read deterministically.
        subgroups = sorted(
            by_password.values(),
            key=lambda s: (-_keeper_score(s.keeper)[0], s.keeper.sort_key()),
        )
        groups.append(Group(domain=domain, username=username, subgroups=subgroups))

    groups.sort(key=lambda g: (g.domain, g.username))
    return groups


def merge_uris(subgroup: PasswordSubgroup) -> list[str]:
    """URIs the keeper should end up with: its own plus every sibling's.

    Deduplicated on normalised host, but the *original* string is kept so that
    Bitwarden's URI matching rules and any deep-link paths survive.
    """
    keeper = subgroup.keeper
    seen: set[str] = set()
    ordered: list[str] = []
    for cred in [keeper] + [c for c in subgroup.members if c is not keeper]:
        for uri in cred.uris:
            key = normalize_uri(uri)
            if not key or key in seen:
                continue
            seen.add(key)
            ordered.append(uri.strip())
    return ordered


def merged_field_additions(subgroup: PasswordSubgroup) -> list[dict]:
    """Custom fields present on siblings but missing from the keeper."""
    keeper = subgroup.keeper
    have = {(f.get("name"), f.get("value")) for f in keeper.fields}
    additions: list[dict] = []
    for cred in subgroup.members:
        if cred is keeper:
            continue
        for candidate in cred.fields:
            key = (candidate.get("name"), candidate.get("value"))
            if key not in have:
                have.add(key)
                additions.append(candidate)
    return additions


def donor_for(subgroup: PasswordSubgroup, attribute: str) -> Credential | None:
    """Find a sibling that can supply an attribute the keeper lacks.

    Used for TOTP and notes: a duplicate created by an older export often holds
    the only copy of a 2FA seed, and collapsing the duplicate must not drop it.
    """
    keeper = subgroup.keeper
    if getattr(keeper, attribute):
        return None
    for cred in sorted(subgroup.members, key=lambda c: -_keeper_score(c)[-2]):
        if cred is keeper:
            continue
        if getattr(cred, attribute):
            return cred
    return None


@dataclass
class NonLoginDuplicate:
    keeper: NonLoginItem
    redundant: list[NonLoginItem]


def find_non_login_duplicates(items: list[NonLoginItem]) -> list[NonLoginDuplicate]:
    """Byte-identical notes/cards/identities produced by repeated imports."""
    buckets: dict[tuple[int, str], list[NonLoginItem]] = defaultdict(list)
    for item in items:
        buckets[(item.item_type, item.content_hash)].append(item)

    duplicates: list[NonLoginDuplicate] = []
    for members in buckets.values():
        if len(members) < 2:
            continue
        # Keep the oldest copy: it is the one other references were built on.
        ordered = sorted(members, key=lambda i: ((i.revision or _EPOCH).timestamp(), i.index))
        duplicates.append(NonLoginDuplicate(keeper=ordered[0], redundant=ordered[1:]))
    duplicates.sort(key=lambda d: (d.keeper.type_name, d.keeper.name.lower()))
    return duplicates
