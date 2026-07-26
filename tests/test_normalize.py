import unittest

from bwsync.normalize import (
    domain_key,
    extract_host,
    normalize_uri,
    package_to_domain,
    registrable_domain,
    username_key,
)


class TestExtractHost(unittest.TestCase):
    def test_plain_urls(self):
        self.assertEqual(extract_host("https://accounts.google.com/signin"), "accounts.google.com")
        self.assertEqual(extract_host("http://Example.COM:8443/login"), "example.com")
        self.assertEqual(extract_host("example.com/login"), "example.com")
        self.assertEqual(extract_host("  https://x.com  "), "x.com")

    def test_userinfo_and_trailing_dot_stripped(self):
        self.assertEqual(extract_host("https://user:pw@vault.example.com/"), "vault.example.com")
        self.assertEqual(extract_host("https://example.com./"), "example.com")

    def test_apple_style_trailing_label(self):
        self.assertEqual(extract_host("https://bank.co.uk (Personal)"), "bank.co.uk")

    def test_android_uri(self):
        self.assertEqual(
            extract_host("android://Rk9PQkFS==@com.spotify.music/"), "spotify.com"
        )
        self.assertEqual(
            extract_host("android://abc@com.google.android.gm/"), "google.com"
        )

    def test_ios_scheme(self):
        self.assertEqual(extract_host("ios://com.apple.store"), "apple.com")

    def test_empty(self):
        self.assertEqual(extract_host(""), "")
        self.assertEqual(extract_host("   "), "")


class TestPackageToDomain(unittest.TestCase):
    def test_standard(self):
        self.assertEqual(package_to_domain("com.spotify.music"), "spotify.com")
        self.assertEqual(package_to_domain("org.mozilla.firefox"), "mozilla.org")

    def test_generic_second_label_skipped(self):
        self.assertEqual(package_to_domain("com.google.android.gm"), "google.com")
        self.assertEqual(package_to_domain("com.app.acme"), "acme.com")

    def test_degenerate(self):
        self.assertEqual(package_to_domain("single"), "single")


class TestRegistrableDomain(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(registrable_domain("accounts.google.com"), "google.com")
        self.assertEqual(registrable_domain("google.com"), "google.com")

    def test_multi_label_suffix(self):
        self.assertEqual(registrable_domain("www.hsbc.co.uk"), "hsbc.co.uk")
        self.assertEqual(registrable_domain("secure.icicibank.co.in"), "icicibank.co.in")

    def test_shared_hosting_keeps_subdomain(self):
        # Two different companies on Atlassian are two different accounts.
        self.assertNotEqual(
            registrable_domain("acme.atlassian.net"),
            registrable_domain("globex.atlassian.net"),
        )
        self.assertEqual(registrable_domain("acme.atlassian.net"), "acme.atlassian.net")
        self.assertEqual(registrable_domain("myblog.github.io"), "myblog.github.io")

    def test_ip_and_localhost(self):
        self.assertEqual(registrable_domain("192.168.1.1"), "192.168.1.1")
        self.assertEqual(registrable_domain("localhost"), "localhost")


class TestDomainKey(unittest.TestCase):
    def test_first_usable_url_wins(self):
        self.assertEqual(domain_key(("", "https://mail.google.com/"), "Gmail"), "google.com")

    def test_falls_back_to_name(self):
        # URL-less entries must still group with their own duplicates rather
        # than collapsing into one giant blank bucket.
        self.assertEqual(domain_key((), "Wi-Fi  Router"), "name:wi-fi router")
        self.assertNotEqual(domain_key((), "Wi-Fi Router"), domain_key((), "Bank PIN"))

    def test_no_url_no_name(self):
        self.assertEqual(domain_key((), ""), "")


class TestUsernameKey(unittest.TestCase):
    def test_case_and_whitespace(self):
        self.assertEqual(username_key("  Pranav@Example.com "), "pranav@example.com")

    def test_default_preserves_gmail_dots(self):
        self.assertNotEqual(
            username_key("first.last@gmail.com"), username_key("firstlast@gmail.com")
        )

    def test_aggressive_folds_gmail(self):
        self.assertEqual(
            username_key("first.last+shop@gmail.com", aggressive=True),
            username_key("firstlast@googlemail.com", aggressive=True),
        )

    def test_aggressive_leaves_other_domains_dotted(self):
        self.assertEqual(
            username_key("first.last@work.com", aggressive=True), "first.last@work.com"
        )


class TestNormalizeUri(unittest.TestCase):
    def test_www_stripped(self):
        self.assertEqual(normalize_uri("https://www.example.com/a"), "example.com")
        self.assertEqual(normalize_uri("https://example.com"), "example.com")


if __name__ == "__main__":
    unittest.main()
