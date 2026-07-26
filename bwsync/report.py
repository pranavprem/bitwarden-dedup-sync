"""Human-readable reports.

Hard rule: reports contain no passwords, TOTP seeds, notes or custom field
values. Conflicts are described with per-run HMAC fingerprints, which let you
see *that* two copies differ (and which copies agree) without exposing either.
"""

from __future__ import annotations

import csv
from pathlib import Path

from bwsync.planner import CONFLICT_FOLDER, Plan


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    return f"{count} {singular if count == 1 else (plural or singular + 's')}"


def render_markdown(plan: Plan) -> str:
    stats = plan.stats
    lines: list[str] = []
    add = lines.append

    add("# Bitwarden consolidation plan")
    add("")
    add("Nothing has been changed yet. This describes what `bwsync apply` would do.")
    add("")

    add("## Inputs")
    add("")
    add("| Source | File | Entries | SHA-256 |")
    add("|---|---|---|---|")
    for source, info in plan.sources.items():
        add(
            f"| {source} | `{info['path']}` | {info.get('count', '?')} | "
            f"`{info['sha256'][:16]}…` |"
        )
    add("")

    add("## What will happen")
    add("")
    add("| Action | Count |")
    add("|---|---|")
    add(f"| Vault logins deleted as exact duplicates | {stats['vault_deletes']} |")
    add(f"| Duplicate notes/cards/identities deleted | {stats['note_card_deletes']} |")
    add(f"| Vault items updated (absorb URLs / 2FA / notes) | {stats['vault_updates']} |")
    add(f"| New logins imported | {stats['creates'] - stats['conflict_creates']} |")
    add(f"| Conflicting logins filed under `{CONFLICT_FOLDER}` | {stats['conflict_creates']} |")
    add(f"| Imports already present in the vault (skipped) | {stats['already_in_vault']} |")
    add("")
    add(
        f"Grouped **{_plural(stats['groups'], 'distinct site+username identity', 'distinct site+username identities')}**, "
        f"of which **{_plural(stats['conflict_groups'], 'has', 'have')} conflicting passwords**."
    )
    add("")

    add("## Safety properties of this plan")
    add("")
    add("- A delete is only ever emitted for an item whose password is **byte-identical**")
    add("  to the item being kept. No distinct password is deleted anywhere in this plan.")
    add("- Deletes go to the Bitwarden **Trash**, which is recoverable, unless you pass")
    add("  `--permanent`.")
    add("- Before a duplicate is deleted, any TOTP seed, note, custom field or URL it")
    add("  uniquely holds is copied onto the item being kept.")
    add("- Conflicts are never auto-resolved. Every distinct password survives, either in")
    add(f"  place or as a new item under `{CONFLICT_FOLDER}`.")
    add("")

    if plan.conflicts:
        add("## Conflicts needing your decision")
        add("")
        add(
            "Same site, same username, different passwords. Fingerprints are per-run "
            "HMACs — equal fingerprints mean equal passwords; they reveal nothing else."
        )
        add("")
        for conflict in sorted(plan.conflicts, key=lambda c: c["label"]):
            add(f"### {conflict['label']}")
            add("")
            add("| Fingerprint | Sources | Copies | In vault | 2FA | Newest |")
            add("|---|---|---|---|---|---|")
            for variant in conflict["variants"]:
                add(
                    f"| `{variant['password_fingerprint']}` "
                    f"| {', '.join(variant['sources'])} "
                    f"| {variant['copies']} "
                    f"| {'yes' if variant['in_vault'] else 'no'} "
                    f"| {'yes' if variant['has_totp'] else '—'} "
                    f"| {(variant['newest'] or '—')[:10]} |"
                )
            add("")

    deletes = [a for a in plan.actions if a["op"] == "delete"]
    if deletes:
        add("## Deletions (first 50)")
        add("")
        add("| Item | Identity | Kept item |")
        add("|---|---|---|")
        for action in deletes[:50]:
            add(f"| {action['name'] or '—'} | {action['label']} | `{(action['kept_item_id'] or '—')[:8]}` |")
        if len(deletes) > 50:
            add("")
            add(f"…and {len(deletes) - 50} more. See `deletions.csv` for the full list.")
        add("")

    add("## Next step")
    add("")
    add("```")
    add("bwsync apply --plan plan.json          # dry run, prints every command")
    add("bwsync apply --plan plan.json --confirm  # actually execute")
    add("```")
    add("")
    return "\n".join(lines)


def write_reports(plan: Plan, out_dir: Path) -> dict[str, Path]:
    """Write report.md plus CSVs for the actions worth eyeballing in a spreadsheet."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}

    report_path = out_dir / "report.md"
    report_path.write_text(render_markdown(plan), encoding="utf-8")
    written["report"] = report_path

    deletes = [a for a in plan.actions if a["op"] == "delete"]
    if deletes:
        path = out_dir / "deletions.csv"
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["item_id", "name", "identity", "kept_item_id", "reason"])
            for action in deletes:
                writer.writerow(
                    [
                        action["item_id"],
                        action["name"],
                        action["label"],
                        action["kept_item_id"],
                        action["reason"],
                    ]
                )
        written["deletions"] = path

    if plan.conflicts:
        path = out_dir / "conflicts.csv"
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                ["domain", "username", "password_fingerprint", "sources", "copies", "in_vault", "has_totp"]
            )
            for conflict in plan.conflicts:
                for variant in conflict["variants"]:
                    writer.writerow(
                        [
                            conflict["domain"],
                            conflict["username"],
                            variant["password_fingerprint"],
                            "|".join(variant["sources"]),
                            variant["copies"],
                            "yes" if variant["in_vault"] else "no",
                            "yes" if variant["has_totp"] else "no",
                        ]
                    )
        written["conflicts"] = path

    creates = [a for a in plan.actions if a["op"] == "create"]
    if creates:
        path = out_dir / "new-items.csv"
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["name", "identity", "source_ref", "folder", "is_conflict"])
            for action in creates:
                writer.writerow(
                    [
                        action["name"],
                        action["label"],
                        action["ref"],
                        action["folder"] or "(no folder)",
                        "yes" if action["conflict"] else "no",
                    ]
                )
        written["new_items"] = path

    for path in written.values():
        path.chmod(0o600)
    return written
