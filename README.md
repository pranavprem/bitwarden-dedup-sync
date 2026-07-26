# bwsync — consolidate Apple Passwords + Chrome into a deduplicated Bitwarden vault

Makes Bitwarden your single source of truth:

1. **Deduplicates your Bitwarden vault in place** — the mess left behind by
   repeated exports/imports.
2. **Merges in Apple Passwords and Chrome**, importing only what is genuinely
   missing.
3. **Never silently loses a password.**

Runs entirely offline. No network calls, no third-party services, no
dependencies beyond the Python standard library. It never sees, asks for, or
stores your master password.

---

## The rule that makes this safe

> **Two entries are merged only when their passwords are byte-identical.**

Everything follows from that:

- A **delete** is only ever emitted for an item whose password exactly matches
  the item being kept. Collapsing them cannot lose information.
- Same site + same username but **different passwords** is a *conflict*. A
  machine cannot know which one is current, so nothing is deleted. Every
  distinct password survives — in place if it is already in the vault, or as a
  new item under `Review/Conflicts` if it only exists in Apple/Chrome.
- Before a duplicate is deleted, anything it uniquely holds — a **TOTP seed**, a
  note, a custom field, an extra URL — is copied onto the item being kept. Old
  duplicates are frequently the only place a 2FA seed still lives.
- Deletes go to the Bitwarden **Trash**, which is recoverable in-product for 30
  days. `--permanent` opts out; don't use it on the first run.

There is a test that asserts this invariant directly
(`TestNoPasswordIsEverLost`): the set of distinct
`(site, username, password)` triples going in always equals the set coming out.

## How your secrets are handled

- **`plan.json` and every report contain no passwords**, TOTP seeds, notes or
  custom-field values. They reference source entries by id (`chrome:41`) and
  record each input file's SHA-256. `apply` re-reads the exports and verifies
  those digests before resolving anything. A plan is safe to read, diff, and
  keep; it is useless on its own.
- Conflicting passwords are shown as **per-run HMAC fingerprints**. Equal
  fingerprints mean equal passwords. The key is random per run and never
  written to disk, so the fingerprints reveal nothing outside their own report.
- Item payloads reach the `bw` CLI over **stdin**, never as command arguments,
  so plaintext never appears in the process table or your shell history.
- All generated files are written `0600`, in a `0700` directory.

The one genuinely dangerous thing in this process is the **plaintext export
files you create in step 2**. Everything else is designed around them.
Step 7 deletes them.

---

## The runbook

### 1. Install prerequisites

```bash
brew install bitwarden-cli     # or: npm install -g @bitwarden/cli
git clone <this repo> && cd bitwarden-dedup-sync
```

No `pip install` is needed; run it as `python3 -m bwsync`. (`pip install -e .`
gives you a `bwsync` command if you prefer.)

### 2. Create a scratch directory that isn't in a synced folder

Do **not** use Desktop, Documents, or anything in iCloud Drive / Dropbox /
OneDrive. A plaintext password file in a synced folder gets copied to servers
you did not intend.

```bash
mkdir -p ~/pwork && chmod 700 ~/pwork && cd ~/pwork
```

### 3. Export from each manager

**Bitwarden** (must be JSON — a CSV has no item IDs, so the vault cannot be
deduplicated in place):

- Web vault → Tools → Export vault → File format **.json** →
  *File password* left **empty** → Export vault.
- Save as `~/pwork/vault.json`. **Keep this file until you are finished** — it
  is your rollback.

**Apple Passwords** (macOS Sonoma+):

- Passwords app → File → Export All Passwords… (older macOS: System Settings →
  Passwords → ⋯ → Export All Passwords)
- Save as `~/pwork/apple.csv`.

**Chrome:**

- `chrome://password-manager/settings` → Download file.
- Save as `~/pwork/chrome.csv`.

Optionally add Firefox or any other CSV with `--extra path.csv`.

### 4. Plan (changes nothing)

```bash
cd ~/git/bitwarden-dedup-sync
python3 -m bwsync plan \
  --vault  ~/pwork/vault.json \
  --apple  ~/pwork/apple.csv \
  --chrome ~/pwork/chrome.csv \
  --out    ~/pwork/out
```

Read `~/pwork/out/report.md`. It tells you exactly what will happen and lists
every conflict. Also written: `deletions.csv`, `conflicts.csv`, `new-items.csv`.

**Resolve the conflicts before applying.** For each row in `conflicts.csv`, log
into the site and confirm which password is current. Usually the vault-only,
newest-dated one is the password you rotated and the others are stale copies —
but confirming is the whole point, so confirm.

### 5. Apply

```bash
export BW_SESSION=$(bw unlock --raw)     # you type your master password, not bwsync

python3 -m bwsync apply --plan ~/pwork/out/plan.json            # dry run: prints every change
python3 -m bwsync apply --plan ~/pwork/out/plan.json --confirm  # execute
```

`apply` is resumable and idempotent — it journals each completed action, so if
it is interrupted, re-running picks up exactly where it stopped.

### 6. Verify before deleting anything anywhere else

```bash
# Re-export the vault from the web vault to ~/pwork/vault2.json, then:
python3 -m bwsync plan --vault ~/pwork/vault2.json --out ~/pwork/check
```

A clean vault reports **0 deletions and 0 updates**. Then spot-check by hand:

- Open 5–10 important logins in Bitwarden and confirm the password and 2FA.
- Confirm `Review/Conflicts` is empty (or that you have consciously resolved it).
- **Actually log in** to your 3 most critical accounts — bank, email, and the
  account that recovers everything else.

### 7. Only now, decommission the others

Do these one at a time, with a few days between, so you notice anything missing
while the exports still exist:

- **Chrome:** `chrome://password-manager/settings` → delete all passwords, and
  turn **off** "Offer to save passwords" so it does not refill.
- **Apple Passwords:** delete entries, and turn off AutoFill (System Settings →
  General → AutoFill & Passwords) so iCloud Keychain stops capturing new ones.
- Install the Bitwarden browser extension and set it as the autofill provider on
  macOS and iOS so new credentials land in the right place from now on.

### 8. Shred the plaintext exports

```bash
rm -P ~/pwork/*.csv ~/pwork/*.json      # -P overwrites before unlinking
rm -rf ~/pwork
```

Also empty your Downloads folder and Trash — browser exports often leave a copy
there. If you are on a Time Machine or backup schedule, note that these files
may have been backed up between step 3 and now.

---

## Options

| Flag | Effect |
|---|---|
| `--no-import` | Only deduplicate the vault; import nothing. Good for a cautious first pass. |
| `--import-folder NAME` | Folder for new imports (default `Imported`). |
| `--no-import-folder` | Import to no folder. |
| `--aggressive-username` | Treat `first.last+tag@gmail.com` and `firstlast@gmail.com` as the same user. Merges more; opt-in because some people keep those deliberately separate. |
| `--extra FILE.csv` | Additional CSV source; repeatable. |
| `--permanent` | Hard-delete instead of using the Trash. Not recommended on a first run. |

## Rolling back

Deleted items sit in the Bitwarden **Trash** (web vault → Trash → Restore).
If something has gone badly wrong, `~/pwork/vault.json` from step 3 is a
complete snapshot of the vault before any change.

## How matching works

Entries group by **registrable domain + normalised username**:

- `mail.google.com` and `accounts.google.com` → both `google.com` (same account).
- `acme.atlassian.net` and `globex.atlassian.net` stay **separate** — shared
  hosting domains are recognised, so two tenants are never conflated.
- `android://…@com.spotify.music/` (how Chrome stores Android credentials) maps
  to `spotify.com`, so your app and web logins deduplicate against each other.
- Multi-part suffixes like `hsbc.co.uk` and `icicibank.co.in` are handled.
- Entries with no URL at all (`Wi-Fi Router`, `Bank PIN`) group by title, so
  they still deduplicate against their own copies instead of collapsing into
  one bucket.
- Usernames are compared case-insensitively and whitespace-trimmed.

Domain rules use a curated suffix list rather than the full Public Suffix List
(which would need network refresh). Unlisted suffixes fall back to "last two
labels", which is correct for essentially all gTLDs. A wrong guess can only ever
cause a *missed* merge, never an incorrect one — the byte-identical-password
rule blocks any unsafe collapse regardless.

## Known limits

- **Attachments and passkeys cannot be moved.** They are not in the export
  format. Items *holding* them are always preferred as the survivor, so they are
  never the item deleted — but if you have attachments on a duplicate, move them
  by hand first.
- **Bitwarden Sends** are out of scope.
- Chrome exports drop federated "Sign in with Google" entries (they contain no
  password); those rows are skipped rather than imported as empty items.
- Only unencrypted Bitwarden JSON exports are supported as the vault input.

## Development

```bash
python3 -m unittest discover -s tests -t .
```

64 tests, no dependencies. The suite covers domain/username normalisation, all
four export formats, keeper selection, TOTP rescue, conflict handling,
resumability, digest verification, the secret-free-output guarantee, and the
no-password-is-ever-lost invariant.
