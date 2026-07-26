import unittest

from bwsync.dedupe import build_groups, donor_for, find_non_login_duplicates, merge_uris
from bwsync.model import Credential, NonLoginItem, parse_timestamp


def cred(source, index, name, username, password, uris=(), **kwargs):
    return Credential(
        source=source,
        index=index,
        name=name,
        username=username,
        password=password,
        uris=tuple(uris),
        **kwargs,
    )


def vault(index, name, username, password, uris=(), **kwargs):
    kwargs.setdefault("item_id", f"id{index}")
    kwargs.setdefault("revision", parse_timestamp("2024-01-01T00:00:00Z"))
    return cred("bitwarden", index, name, username, password, uris, **kwargs)


class TestGrouping(unittest.TestCase):
    def test_same_site_same_password_groups_into_one_subgroup(self):
        groups = build_groups(
            [
                vault(0, "GitHub", "me@x.com", "pw", ["https://github.com"]),
                vault(1, "github.com", "ME@X.COM", "pw", ["https://www.github.com/login"]),
            ]
        )
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0].subgroups), 1)
        self.assertFalse(groups[0].is_conflict)
        self.assertEqual(len(groups[0].subgroups[0].redundant_vault_members), 1)

    def test_different_passwords_are_a_conflict_and_delete_nothing(self):
        groups = build_groups(
            [
                vault(0, "GitHub", "me@x.com", "old", ["https://github.com"]),
                vault(1, "GitHub", "me@x.com", "new", ["https://github.com"]),
            ]
        )
        self.assertTrue(groups[0].is_conflict)
        for subgroup in groups[0].subgroups:
            self.assertEqual(subgroup.redundant_vault_members, [])

    def test_conflict_group_still_collapses_identical_copies(self):
        # Three copies, two passwords: the pair sharing a password still merges.
        groups = build_groups(
            [
                vault(0, "GitHub", "me@x.com", "old", ["https://github.com"]),
                vault(1, "GitHub", "me@x.com", "old", ["https://github.com"]),
                vault(2, "GitHub", "me@x.com", "new", ["https://github.com"]),
            ]
        )
        deletions = sum(len(s.redundant_vault_members) for s in groups[0].subgroups)
        self.assertTrue(groups[0].is_conflict)
        self.assertEqual(deletions, 1)

    def test_different_sites_never_group(self):
        groups = build_groups(
            [
                vault(0, "A", "u", "pw", ["https://acme.atlassian.net"]),
                vault(1, "B", "u", "pw", ["https://globex.atlassian.net"]),
            ]
        )
        self.assertEqual(len(groups), 2)

    def test_subdomains_of_one_site_do_group(self):
        groups = build_groups(
            [
                vault(0, "A", "u", "pw", ["https://mail.google.com"]),
                vault(1, "B", "u", "pw", ["https://accounts.google.com"]),
            ]
        )
        self.assertEqual(len(groups), 1)


class TestKeeperSelection(unittest.TestCase):
    def test_vault_item_beats_import(self):
        groups = build_groups(
            [
                cred("chrome", 0, "GitHub", "u", "pw", ["https://github.com"]),
                vault(1, "GitHub", "u", "pw", ["https://github.com"]),
            ]
        )
        self.assertTrue(groups[0].subgroups[0].keeper.from_vault)

    def test_richer_item_wins_among_vault_items(self):
        groups = build_groups(
            [
                vault(0, "GitHub", "u", "pw", ["https://github.com"]),
                vault(1, "GitHub", "u", "pw", ["https://github.com"], totp="SEED"),
            ]
        )
        self.assertEqual(groups[0].subgroups[0].keeper.item_id, "id1")

    def test_passkey_outranks_totp(self):
        groups = build_groups(
            [
                vault(0, "GitHub", "u", "pw", ["https://github.com"], totp="SEED"),
                vault(1, "GitHub", "u", "pw", ["https://github.com"], has_passkey=True),
            ]
        )
        self.assertEqual(groups[0].subgroups[0].keeper.item_id, "id1")

    def test_selection_is_deterministic(self):
        entries = [
            vault(0, "GitHub", "u", "pw", ["https://github.com"]),
            vault(1, "GitHub", "u", "pw", ["https://github.com"]),
        ]
        first = build_groups(entries)[0].subgroups[0].keeper.item_id
        for _ in range(5):
            self.assertEqual(build_groups(list(entries))[0].subgroups[0].keeper.item_id, first)


class TestMetadataRescue(unittest.TestCase):
    def test_totp_rescued_from_duplicate_before_deletion(self):
        groups = build_groups(
            [
                vault(0, "GitHub", "u", "pw", ["https://github.com"], notes="keep me"),
                vault(1, "GitHub", "u", "pw", ["https://github.com"], totp="SEED"),
            ]
        )
        subgroup = groups[0].subgroups[0]
        keeper = subgroup.keeper
        self.assertEqual(keeper.item_id, "id1")  # has TOTP, outranks notes
        donor = donor_for(subgroup, "notes")
        self.assertIsNotNone(donor)
        self.assertEqual(donor.notes, "keep me")

    def test_uris_are_unioned_without_duplicates(self):
        groups = build_groups(
            [
                vault(0, "GitHub", "u", "pw", ["https://github.com"]),
                vault(1, "GitHub", "u", "pw", ["https://www.github.com", "https://gist.github.com"]),
            ]
        )
        merged = merge_uris(groups[0].subgroups[0])
        hosts = {u.split("//")[1] for u in merged}
        self.assertIn("gist.github.com", hosts)
        self.assertEqual(len(merged), 2)  # github.com and www.github.com collapse


class TestNoPasswordIsEverLost(unittest.TestCase):
    """The core safety invariant, stated as an executable check."""

    def _assert_invariant(self, entries):
        from bwsync.normalize import domain_key, username_key

        before = {
            (domain_key(c.uris, c.name), username_key(c.username), c.password) for c in entries
        }
        after = {
            (g.domain, g.username, s.password) for g in build_groups(entries) for s in g.subgroups
        }
        self.assertEqual(before, after)

    def test_mixed_realistic_vault(self):
        self._assert_invariant(
            [
                vault(0, "GitHub", "me@x.com", "pw1", ["https://github.com"]),
                vault(1, "GitHub", "me@x.com", "pw1", ["https://github.com"]),
                vault(2, "GitHub", "me@x.com", "pw2", ["https://github.com"]),
                vault(3, "Bank", "me", "bankpw", ["https://hsbc.co.uk"]),
                cred("apple", 0, "GitHub", "me@x.com", "pw3", ["https://github.com"]),
                cred("chrome", 0, "Bank", "me", "bankpw", ["https://hsbc.co.uk"]),
                cred("chrome", 1, "Spotify", "me@x.com", "sp", ["android://h==@com.spotify.music/"]),
                cred("apple", 1, "Spotify", "me@x.com", "sp", ["https://spotify.com"]),
            ]
        )

    def test_empty_passwords_and_missing_usernames(self):
        self._assert_invariant(
            [
                vault(0, "Router", "", "", []),
                vault(1, "Router", "", "adminpw", []),
                cred("apple", 0, "Router", "", "adminpw", []),
            ]
        )


class TestNonLoginDuplicates(unittest.TestCase):
    def _note(self, index, item_id, content_hash, revision="2024-01-01T00:00:00Z"):
        return NonLoginItem(
            index=index,
            item_id=item_id,
            item_type=2,
            name="Passport",
            content_hash=content_hash,
            revision=parse_timestamp(revision),
            raw={},
        )

    def test_identical_notes_collapse_keeping_oldest(self):
        duplicates = find_non_login_duplicates(
            [
                self._note(0, "a", "hash1", "2024-05-01T00:00:00Z"),
                self._note(1, "b", "hash1", "2023-01-01T00:00:00Z"),
            ]
        )
        self.assertEqual(len(duplicates), 1)
        self.assertEqual(duplicates[0].keeper.item_id, "b")
        self.assertEqual([r.item_id for r in duplicates[0].redundant], ["a"])

    def test_differing_notes_are_left_alone(self):
        duplicates = find_non_login_duplicates(
            [self._note(0, "a", "hash1"), self._note(1, "b", "hash2")]
        )
        self.assertEqual(duplicates, [])


if __name__ == "__main__":
    unittest.main()
