#!/usr/bin/env bash
#
# Interactive front end for bwsync. Driven by the Makefile:
#
#   make setup    prerequisites, work directory, guided exports
#   make dedup    plan -> review -> dry run -> apply
#   make verify   fresh export, confirm the vault is clean
#   make shred    securely delete the plaintext exports
#
# Kept bash 3.2-compatible: /bin/bash on macOS is still 3.2, and Make 3.81 has
# no .ONESHELL, which is why this logic lives here rather than in the Makefile.
#
# Never uses `set -x`: the trace would print the BW_SESSION key and item payloads.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONF="$REPO_DIR/.bwsync.conf"
DEFAULT_WORKDIR="$HOME/bwsync-work"

# --------------------------------------------------------------------------
# Presentation
# --------------------------------------------------------------------------

if [ -t 1 ] && command -v tput >/dev/null 2>&1 && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
    BOLD="$(tput bold)"; DIM="$(tput dim)"; RED="$(tput setaf 1)"
    GREEN="$(tput setaf 2)"; YELLOW="$(tput setaf 3)"; BLUE="$(tput setaf 4)"
    RESET="$(tput sgr0)"
else
    BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; BLUE=""; RESET=""
fi

heading() { printf '\n%s%s%s\n%s\n' "$BOLD$BLUE" "$1" "$RESET" "${DIM}$(printf '%.0s-' $(seq 1 ${#1}))$RESET"; }
say()     { printf '%s\n' "$1"; }
note()    { printf '%s\n' "${DIM}$1${RESET}"; }
good()    { printf '%s\n' "${GREEN}✓${RESET} $1"; }
warn()    { printf '%s\n' "${YELLOW}!${RESET} $1"; }
die()     { printf '\n%s %s\n' "${RED}error:${RESET}" "$1" >&2; exit 1; }
have()    { command -v "$1" >/dev/null 2>&1; }

# ask VAR "Prompt" ["default"] — reads into the named variable.
ask() {
    local __var="$1" __prompt="$2" __default="${3:-}" __reply=""
    if [ -n "$__default" ]; then
        printf '%s %s[%s]%s ' "$__prompt" "$DIM" "$__default" "$RESET"
    else
        printf '%s ' "$__prompt"
    fi
    read -r __reply </dev/tty || true
    [ -z "$__reply" ] && __reply="$__default"
    eval "$__var=\$__reply"
}

# confirm "Question" [default_yes] — returns 0 for yes.
confirm() {
    local prompt="$1" default="${2:-no}" reply="" hint="y/N"
    [ "$default" = "yes" ] && hint="Y/n"
    while true; do
        printf '%s %s(%s)%s ' "$prompt" "$DIM" "$hint" "$RESET"
        read -r reply </dev/tty || reply=""
        [ -z "$reply" ] && reply="$default"
        case "$(printf '%s' "$reply" | tr '[:upper:]' '[:lower:]')" in
            y|yes) return 0 ;;
            n|no)  return 1 ;;
            *)     say "Please answer y or n." ;;
        esac
    done
}

# Require the user to type an exact word. Used before anything irreversible.
require_phrase() {
    local phrase="$1" reply=""
    printf 'Type %s%s%s to continue: ' "$BOLD" "$phrase" "$RESET"
    read -r reply </dev/tty || reply=""
    [ "$reply" = "$phrase" ]
}

pause() { printf '\n%sPress Enter when done…%s' "$DIM" "$RESET"; read -r _ </dev/tty || true; printf '\n'; }

# --------------------------------------------------------------------------
# Config (records the work directory so later targets stop asking)
# --------------------------------------------------------------------------

load_conf() { [ -f "$CONF" ] && . "$CONF" || true; }

save_conf() {
    # %q so a path containing spaces survives being sourced back in.
    printf '# Written by `make setup`. Paths only — never secrets.\nWORKDIR=%q\n' "$1" > "$CONF"
    chmod 600 "$CONF"
}

require_workdir() {
    load_conf
    if [ -z "${WORKDIR:-}" ] || [ ! -d "${WORKDIR:-}" ]; then
        ask WORKDIR "Path to your work directory:" "$DEFAULT_WORKDIR"
        WORKDIR="${WORKDIR/#\~/$HOME}"
        [ -d "$WORKDIR" ] || die "$WORKDIR does not exist. Run 'make setup' first."
    fi
}

py() { (cd "$REPO_DIR" && python3 -m bwsync "$@"); }

# --------------------------------------------------------------------------
# setup
# --------------------------------------------------------------------------

check_python() {
    have python3 || die "python3 not found. Install Python 3.10 or newer."
    if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
        die "Python 3.10+ required (found $(python3 -V 2>&1))."
    fi
    good "python3 $(python3 -V 2>&1 | cut -d' ' -f2)"
}

check_bw() {
    if have bw; then
        good "Bitwarden CLI $(bw --version 2>/dev/null || echo '(version unknown)')"
        return 0
    fi
    warn "The Bitwarden CLI (bw) is not installed."
    say "It is needed to apply changes to your vault. Planning works without it."

    # One offer, using whichever package manager is present — no nagging.
    local installer="" cmd=""
    if have brew; then
        installer="Homebrew"; cmd="brew install bitwarden-cli"
    elif have npm; then
        installer="npm"; cmd="npm install -g @bitwarden/cli"
    fi

    if [ -n "$installer" ] && confirm "Install it now with $installer?" yes; then
        $cmd || warn "Install failed. You can run it yourself: $cmd"
    else
        warn "Skipping. Install it before 'make dedup':"
        note "    brew install bitwarden-cli    # or: npm install -g @bitwarden/cli"
        return 0
    fi
    have bw && good "Bitwarden CLI installed." || true
}

# Plaintext password exports must not land somewhere that syncs them to a server.
warn_if_synced() {
    local path resolved
    path="$1"
    resolved="$(cd "$(dirname "$path")" 2>/dev/null && pwd || printf '%s' "$path")/$(basename "$path")"
    case "$resolved" in
        *Library/Mobile\ Documents*|*Dropbox*|*OneDrive*|*Google\ Drive*|*/Desktop/*|*/Documents/*|*iCloud*)
            warn "$resolved looks like it is inside a cloud-synced folder."
            say  "Your exports contain plaintext passwords. Putting them there uploads"
            say  "them to a server, and deleting them later may not remove every copy."
            confirm "Use it anyway?" no || return 1
            ;;
    esac
    return 0
}

# guided_export LABEL FILENAME REQUIRED INSTRUCTIONS...
# A required export cannot be skipped: the loop only exits once the file exists.
guided_export() {
    local label="$1" filename="$2" required="$3"; shift 3
    local target="$WORKDIR/$filename"

    heading "Export from $label"
    local line
    for line in "$@"; do say "  $line"; done
    say ""
    say "  Save it as: ${BOLD}$target${RESET}"

    if [ -f "$target" ]; then
        note ""
        note "  A file is already there ($(wc -c < "$target" | tr -d ' ') bytes)."
        confirm "  Re-export and replace it?" no || { good "Keeping the existing $filename."; return 0; }
    fi

    while true; do
        pause
        if [ -f "$target" ]; then
            chmod 600 "$target" 2>/dev/null || true
            good "Found $filename ($(wc -c < "$target" | tr -d ' ') bytes)."
            return 0
        fi
        warn "Nothing at $target yet."
        # Browsers usually drop the file in ~/Downloads under a vendor name.
        local found
        found="$(find "$HOME/Downloads" -maxdepth 1 -type f \( -name '*.csv' -o -name '*bitwarden*.json' \) -mtime -1 2>/dev/null | head -5 || true)"
        if [ -n "$found" ]; then
            say "Recently downloaded files that might be it:"
            printf '%s\n' "$found" | sed 's/^/    /'
            local pick
            ask pick "Path to move into place (blank to retry):" ""
            if [ -n "$pick" ] && [ -f "${pick/#\~/$HOME}" ]; then
                mv "${pick/#\~/$HOME}" "$target"
                chmod 600 "$target"
                good "Moved into place as $filename."
                return 0
            fi
        fi
        if [ "$required" = "yes" ]; then
            warn "The Bitwarden vault export is required — it is what gets deduplicated,"
            warn "and it is your rollback snapshot. Let's try again."
        elif confirm "Skip $label for now?" no; then
            warn "Skipping $label. You can add it later by re-running 'make setup'."
            return 1
        fi
    done
}

cmd_setup() {
    heading "Prerequisites"
    check_python
    check_bw

    heading "Work directory"
    say "This holds your plaintext exports until step 'make shred' destroys them."
    say "Do not use Desktop, Documents, iCloud Drive, Dropbox or OneDrive."
    load_conf
    # Held separately so a rejected answer never becomes the next default —
    # otherwise pressing Enter would re-submit the invalid value forever.
    local suggested="${WORKDIR:-$DEFAULT_WORKDIR}"
    while true; do
        ask WORKDIR "Where should it go?" "$suggested"
        WORKDIR="${WORKDIR/#\~/$HOME}"
        # An absolute path is required: a typo like "n" would otherwise silently
        # create a junk directory wherever make happened to be invoked from.
        case "$WORKDIR" in
            /*) ;;
            *)  warn "Please give an absolute path starting with / or ~ (got '$WORKDIR')."
                continue ;;
        esac
        if [ -e "$WORKDIR" ] && [ ! -d "$WORKDIR" ]; then
            warn "$WORKDIR exists and is not a directory."
            continue
        fi
        warn_if_synced "$WORKDIR" && break
    done
    mkdir -p "$WORKDIR"
    chmod 700 "$WORKDIR"
    save_conf "$WORKDIR"
    good "Using $WORKDIR (owner-only, mode 700)."

    heading "Exports"
    say "You will now export from each password manager. Take them one at a time."
    say "${DIM}These files contain your passwords in plaintext. They stay on this"
    say "machine and are destroyed at the end by 'make shred'.${RESET}"

    guided_export "Bitwarden" "vault.json" yes \
        "1. Open the web vault: https://vault.bitwarden.com" \
        "2. Tools → Export vault" \
        "3. File format: ${BOLD}.json${RESET}   (NOT .csv — a CSV has no item IDs," \
        "   so your vault could not be deduplicated in place)" \
        "4. Leave the file password ${BOLD}empty${RESET} — an encrypted export cannot be read" \
        "5. Export vault" \
        "" \
        "   Keep this file until you are completely finished: it is your rollback."

    guided_export "Apple Passwords" "apple.csv" no \
        "1. Open the Passwords app" \
        "2. File → Export All Passwords…" \
        "   (older macOS: System Settings → Passwords → ⋯ → Export All Passwords)" \
        "3. Confirm with Touch ID or your login password" || true

    guided_export "Google Chrome" "chrome.csv" no \
        "1. Open chrome://password-manager/settings" \
        "2. Under 'Export passwords', click Download file" \
        "3. Confirm with Touch ID or your login password" || true

    heading "Ready"
    say "Files in $WORKDIR:"
    ls -lh "$WORKDIR" 2>/dev/null | tail -n +2 | sed 's/^/    /' || true
    say ""
    say "Next: ${BOLD}make dedup${RESET}"
}

# --------------------------------------------------------------------------
# dedup
# --------------------------------------------------------------------------

# resolve_source VAR "label" filename required
resolve_source() {
    local __var="$1" label="$2" filename="$3" required="$4"
    local candidate="$WORKDIR/$filename" answer=""
    if [ -f "$candidate" ]; then
        eval "$__var=\$candidate"
        good "$label: $candidate"
        return 0
    fi
    if [ "$required" = "yes" ]; then
        ask answer "Path to your $label export:" ""
    else
        ask answer "Path to your $label export (blank to skip):" ""
    fi
    answer="${answer/#\~/$HOME}"
    if [ -z "$answer" ]; then
        [ "$required" = "yes" ] && die "The Bitwarden vault export is required."
        note "Skipping $label."
        eval "$__var=''"
        return 0
    fi
    [ -f "$answer" ] || die "$answer not found."
    eval "$__var=\$answer"
    good "$label: $answer"
}

unlock_vault() {
    have bw || die "The Bitwarden CLI (bw) is not installed. Run 'make setup'."

    local status
    status="$(bw status 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status",""))' 2>/dev/null || echo "")"

    if [ "$status" = "unauthenticated" ] || [ -z "$status" ]; then
        heading "Log in to Bitwarden"
        say "The CLI will prompt you directly. bwsync never sees your master password."
        bw login </dev/tty
        status="locked"
    fi

    if [ "$status" = "unlocked" ] && [ -n "${BW_SESSION:-}" ]; then
        good "Vault already unlocked."
        return 0
    fi

    heading "Unlock Bitwarden"
    say "The CLI will prompt for your master password. bwsync never sees or stores it;"
    say "it only inherits the session key the CLI hands back."
    # Assigned, never echoed, never written to disk.
    BW_SESSION="$(bw unlock --raw </dev/tty)"
    export BW_SESSION
    [ -n "$BW_SESSION" ] || die "Unlock failed."
    good "Unlocked."
}

cmd_dedup() {
    require_workdir
    heading "Sources"
    resolve_source VAULT  "Bitwarden vault" "vault.json" yes
    resolve_source APPLE  "Apple Passwords" "apple.csv"  no
    resolve_source CHROME "Chrome"          "chrome.csv" no

    # An array, not a string: a work directory containing spaces would otherwise
    # word-split into bogus arguments.
    local -a args
    args=(--vault "$VAULT" --out "$WORKDIR/out")
    [ -n "$APPLE" ]  && args+=(--apple "$APPLE")
    [ -n "$CHROME" ] && args+=(--chrome "$CHROME")

    heading "Options"
    if confirm "Merge Gmail dot/plus variants (first.last@ = firstlast@) as one user?" no; then
        args+=(--aggressive-username)
    fi
    if confirm "Deduplicate only, importing nothing new? (cautious first pass)" no; then
        args+=(--no-import)
    fi

    heading "Planning"
    note "Nothing is changed by this step."
    py plan "${args[@]}"

    local plan="$WORKDIR/out/plan.json"
    local report="$WORKDIR/out/report.md"
    [ -f "$plan" ] || die "No plan was produced."

    local conflicts
    conflicts="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["conflicts"]))' "$plan")"

    heading "Review"
    say "Full report: ${BOLD}$report${RESET}"
    if confirm "Open the report now?" yes; then
        if have open; then open "$report"; else "${PAGER:-less}" "$report" </dev/tty; fi
    fi

    if [ "$conflicts" -gt 0 ]; then
        heading "$conflicts conflict(s) need your decision"
        say "These are logins where the same site and username have ${BOLD}different${RESET}"
        say "passwords across your managers. Nothing will be deleted for them, and every"
        say "distinct password is preserved — but you should work out which is current."
        say ""
        sed -n '/## Conflicts needing/,/^## /p' "$report" | sed '$d' | sed 's/^/  /'
        say ""
        say "Details: ${BOLD}$WORKDIR/out/conflicts.csv${RESET}"
        confirm "Continue anyway? (conflicts are preserved, not resolved)" yes \
            || { note "Stopped. Resolve the conflicts, re-export, and run 'make dedup' again."; exit 0; }
    fi

    heading "Dry run"
    note "Still nothing changed — this prints every command that would run."
    local log="$WORKDIR/out/dryrun.log"
    # Written first, then paged. Piping straight into `head` would SIGPIPE the
    # producer, and with `pipefail` that would abort the whole script.
    py apply --plan "$plan" > "$log"
    chmod 600 "$log" 2>/dev/null || true
    head -40 "$log"
    local total
    total="$(grep -c '^\[dry-run\]' "$log" || true)"
    [ "${total:-0}" -gt 40 ] && note "… $((total - 40)) more; full output in $log"

    heading "Apply"
    say "This modifies your live Bitwarden vault."
    say "Deleted items go to the ${BOLD}Trash${RESET} and can be restored for 30 days."
    say "Your rollback snapshot is ${BOLD}$VAULT${RESET}."
    say ""
    if ! require_phrase "apply"; then
        note "Nothing was changed. Re-run 'make dedup' when you are ready."
        exit 0
    fi

    unlock_vault
    py apply --plan "$plan" --confirm

    heading "Done"
    say "Next: ${BOLD}make verify${RESET} — re-exports your vault and confirms it is clean."
    say "Do not delete passwords from Apple or Chrome until that passes."
}

# --------------------------------------------------------------------------
# verify
# --------------------------------------------------------------------------

cmd_verify() {
    require_workdir
    unlock_vault

    heading "Re-exporting the vault"
    local fresh="$WORKDIR/vault-after.json"
    rm -f "$fresh"
    # bw may ask for the master password again to authorise an export; that
    # prompt goes straight to the terminal.
    bw export --format json --output "$fresh" </dev/tty >/dev/null
    chmod 600 "$fresh"
    good "Exported to $fresh"

    heading "Checking"
    py plan --vault "$fresh" --out "$WORKDIR/check" --no-import

    local remaining
    remaining="$(python3 -c '
import json, sys
plan = json.load(open(sys.argv[1]))
print(sum(1 for a in plan["actions"] if a["op"] in ("delete", "update")))' "$WORKDIR/check/plan.json")"

    say ""
    if [ "$remaining" -eq 0 ]; then
        good "${BOLD}Vault is clean — no duplicates remain.${RESET}"
        say ""
        say "Before decommissioning Apple and Chrome, verify by hand:"
        say "  • Open 5-10 important logins in Bitwarden; check password and 2FA codes."
        say "  • Confirm the ${BOLD}Review/Conflicts${RESET} folder is empty or resolved."
        say "  • Actually log in to your bank, your email, and whatever account"
        say "    recovers everything else."
        say ""
        say "Then: ${BOLD}make shred${RESET}"
    else
        warn "$remaining item(s) still look duplicated."
        say "Report: $WORKDIR/check/report.md"
        say "This is expected if you stopped the apply partway."
        say ""
        warn "To go again, re-export from the ${BOLD}web vault${RESET}, not this CLI export."
        say "Some bw CLI versions write an empty fido2Credentials array"
        say "(bitwarden/clients#6925), which would hide your passkeys from planning."
        say "Replace $WORKDIR/vault.json with a fresh web-vault export, then 'make dedup'."
        exit 1
    fi
}

# --------------------------------------------------------------------------
# shred
# --------------------------------------------------------------------------

cmd_shred() {
    require_workdir
    heading "Destroy plaintext exports"
    say "About to permanently delete:"
    find "$WORKDIR" -type f \( -name '*.csv' -o -name '*.json' -o -name '*.log' \) 2>/dev/null | sed 's/^/    /'
    say ""
    warn "Your vault export is your rollback snapshot. Only do this once you have"
    warn "verified the vault AND successfully logged in to your critical accounts."
    say ""
    if ! require_phrase "destroy"; then
        note "Nothing deleted."
        exit 0
    fi

    # rm -P overwrites the file before unlinking on macOS; plain rm elsewhere.
    # Probed against a throwaway temp file — never against a real path.
    local RM="rm -f" probe
    probe="$(mktemp)"
    if rm -P "$probe" 2>/dev/null; then RM="rm -P"; else rm -f "$probe"; fi
    find "$WORKDIR" -type f -exec $RM {} \; 2>/dev/null || true
    rm -rf "$WORKDIR"
    rm -f "$CONF"
    good "Deleted $WORKDIR."
    say ""
    say "Also worth checking for stray copies:"
    say "  • ~/Downloads (browser exports often leave one there)"
    say "  • your Trash — empty it"
    say "  • any Time Machine or cloud backup taken while the exports existed"
}

# --------------------------------------------------------------------------

case "${1:-}" in
    setup)  cmd_setup ;;
    dedup)  cmd_dedup ;;
    verify) cmd_verify ;;
    shred)  cmd_shred ;;
    *)      die "Unknown command '${1:-}'. Use: setup | dedup | verify | shred" ;;
esac
