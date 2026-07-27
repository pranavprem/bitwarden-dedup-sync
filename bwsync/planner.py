"""Turn resolved groups into an executable, secret-free plan.

A plan never contains a password, TOTP seed or note body. It references source
credentials by `ref` ("chrome:41") and records the SHA-256 of every input file.
`bwsync apply` re-reads the exports, verifies those digests, and only then
resolves refs back into secrets. That keeps the reviewable artefact safe to open,
diff and keep around, and makes a plan useless on its own.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from bwsync.dedupe import (
    Group,
    NonLoginDuplicate,
    donor_for,
    fingerprint,
    merge_uris,
    merged_field_additions,
)
from bwsync.model import Credential
from bwsync.normalize import normalize_uri

PLAN_VERSION = 1
CONFLICT_FOLDER = "Review/Conflicts"
IMPORT_FOLDER = "Imported"


@dataclass
class Plan:
    sources: dict[str, dict[str, str]]
    actions: list[dict[str, Any]] = field(default_factory=list)
    conflicts: list[dict[str, Any]] = field(default_factory=list)
    passkey_holds: list[dict[str, Any]] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)
    options: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(
            {
                "version": PLAN_VERSION,
                "options": self.options,
                "sources": self.sources,
                "stats": self.stats,
                "actions": self.actions,
                "conflicts": self.conflicts,
                "passkey_holds": self.passkey_holds,
            },
            indent=2,
            ensure_ascii=False,
        )


def _uri_objects(uris: list[str], existing: Credential) -> list[dict[str, Any]]:
    """Preserve each existing URI's match rule; new URIs inherit the default."""
    match_by_uri = {
        normalize_uri(entry.get("uri", "")): entry.get("match")
        for entry in (existing.raw.get("login", {}).get("uris") or [])
        if isinstance(entry, dict)
    }
    return [{"match": match_by_uri.get(normalize_uri(u)), "uri": u} for u in uris]


def build_plan(
    groups: list[Group],
    non_login_duplicates: list[NonLoginDuplicate],
    sources: dict[str, dict[str, str]],
    options: dict[str, Any],
    import_new: bool = True,
) -> Plan:
    plan = Plan(sources=sources, options=options)
    folders_needed: set[str] = set()

    counts = {
        "groups": len(groups),
        "conflict_groups": 0,
        "vault_deletes": 0,
        "vault_updates": 0,
        "creates": 0,
        "conflict_creates": 0,
        "note_card_deletes": 0,
        "already_in_vault": 0,
        "passkey_holds": 0,
    }

    for group in groups:
        if group.is_conflict:
            counts["conflict_groups"] += 1
            plan.conflicts.append(_describe_conflict(group))

        for subgroup in group.subgroups:
            keeper = subgroup.keeper

            # 0. Record copies spared for holding a passkey the keeper lacks.
            for spared in subgroup.passkey_protected_members:
                plan.passkey_holds.append(
                    {
                        "label": group.label,
                        "name": spared.name,
                        "item_id": spared.item_id,
                        "kept_item_id": keeper.item_id,
                        "unique_passkeys": len(spared.passkey_ids - keeper.passkey_ids),
                        "reason": (
                            "identical password, but holds a passkey the kept item does "
                            "not — a passkey cannot be copied between items, so deleting "
                            "this would destroy that credential"
                        ),
                    }
                )
                counts["passkey_holds"] += 1

            # 1. Collapse redundant vault copies. Safe: identical passwords.
            for redundant in subgroup.redundant_vault_members:
                plan.actions.append(
                    {
                        "op": "delete",
                        "item_id": redundant.item_id,
                        "ref": redundant.ref,
                        "label": group.label,
                        "name": redundant.name,
                        "kept_item_id": keeper.item_id,
                        "reason": "identical password to the kept item",
                    }
                )
                counts["vault_deletes"] += 1

            if keeper.from_vault:
                update = _build_update(group, subgroup, keeper)
                if update:
                    plan.actions.append(update)
                    counts["vault_updates"] += 1
                elif len(subgroup.members) > 1:
                    counts["already_in_vault"] += 1
                continue

            # 2. Nothing in this subgroup is in the vault yet -> create it.
            if not import_new:
                continue
            folder = CONFLICT_FOLDER if group.is_conflict else (options.get("import_folder") or None)
            if folder:
                folders_needed.add(folder)
            plan.actions.append(
                {
                    "op": "create",
                    "ref": keeper.ref,
                    "label": group.label,
                    "name": keeper.name,
                    "folder": folder,
                    "uris": merge_uris(subgroup),
                    "merge_refs": [c.ref for c in subgroup.members if c is not keeper],
                    "conflict": group.is_conflict,
                    "reason": (
                        "same site+username as an existing vault item but a different "
                        "password — filed for review, nothing overwritten"
                        if group.is_conflict
                        else "not present in the vault"
                    ),
                }
            )
            counts["creates"] += 1
            if group.is_conflict:
                counts["conflict_creates"] += 1

    for duplicate in non_login_duplicates:
        for redundant in duplicate.redundant:
            plan.actions.append(
                {
                    "op": "delete",
                    "item_id": redundant.item_id,
                    "ref": redundant.ref,
                    "label": f"{duplicate.keeper.type_name}: {duplicate.keeper.name}",
                    "name": redundant.name,
                    "kept_item_id": duplicate.keeper.item_id,
                    "reason": "byte-identical to the kept item",
                }
            )
            counts["note_card_deletes"] += 1

    # Folder creation must precede the creates that reference it.
    folder_actions = [{"op": "ensure_folder", "name": name} for name in sorted(folders_needed)]
    plan.actions = folder_actions + plan.actions
    plan.stats = counts
    return plan


def _build_update(group: Group, subgroup, keeper: Credential) -> dict[str, Any] | None:
    """Describe the metadata the keeper should absorb from its siblings."""
    if len(subgroup.members) == 1:
        return None

    current = {normalize_uri(u) for u in keeper.uris if normalize_uri(u)}
    merged = merge_uris(subgroup)
    added_uris = [u for u in merged if normalize_uri(u) not in current]

    totp_donor = donor_for(subgroup, "totp")
    notes_donor = donor_for(subgroup, "notes")
    field_additions = merged_field_additions(subgroup)

    if not (added_uris or totp_donor or notes_donor or field_additions):
        return None

    return {
        "op": "update",
        "item_id": keeper.item_id,
        "ref": keeper.ref,
        "label": group.label,
        "name": keeper.name,
        "uris": _uri_objects(merged, keeper) if added_uris else None,
        "added_uris": added_uris,
        "take_totp_from": totp_donor.ref if totp_donor else None,
        "take_notes_from": notes_donor.ref if notes_donor else None,
        "add_fields_from": [c["__ref"] for c in _tag_fields(field_additions, subgroup)]
        if field_additions
        else [],
        "field_count": len(field_additions),
        "reason": "absorb metadata from duplicates being deleted",
    }


def _tag_fields(additions: list[dict], subgroup) -> list[dict]:
    """Map each field addition back to the sibling ref that owns it.

    Fields can hold secrets, so the plan stores only the donor ref plus the
    field's position; `apply` re-reads the value from the source file.
    """
    tagged = []
    for cred in subgroup.members:
        for position, candidate in enumerate(cred.fields):
            if candidate in additions:
                tagged.append({"__ref": f"{cred.ref}#{position}"})
    return tagged


def _describe_conflict(group: Group) -> dict[str, Any]:
    """Human-readable conflict record. Contains no passwords — only fingerprints."""
    return {
        "domain": group.domain,
        "username": group.username,
        "label": group.label,
        "variants": [
            {
                "password_fingerprint": fingerprint(sub.password),
                "sources": sorted({c.source for c in sub.members}),
                "copies": len(sub.members),
                "in_vault": bool(sub.vault_members),
                "vault_item_ids": [c.item_id for c in sub.vault_members if c.item_id],
                "names": sorted({c.name for c in sub.members if c.name}),
                "newest": max(
                    (c.revision.isoformat() for c in sub.members if c.revision),
                    default=None,
                ),
                "has_totp": any(c.totp for c in sub.members),
            }
            for sub in group.subgroups
        ],
    }


def write_plan(plan: Plan, path: Path) -> None:
    """Write the plan with owner-only permissions."""
    path.write_text(plan.to_json(), encoding="utf-8")
    path.chmod(0o600)
