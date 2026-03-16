#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RESOLVERS_URL="https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
WORDLIST_URL="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt"

RESOLVERS_FILE="$SCRIPT_DIR/resolvers.txt"
WORDLIST_FILE="$SCRIPT_DIR/subdomains-top1million-110000.txt"

update_file() {
    local url="$1" dest="$2" name="$3" tmp
    tmp=$(mktemp)

    printf "Updating %s ... " "$name"
    if wget -q -O "$tmp" "$url" && [ -s "$tmp" ]; then
        old=$(wc -l < "$dest" 2>/dev/null || echo 0)
        cp "$tmp" "$dest"
        new=$(wc -l < "$dest")
        printf "done (%s -> %s lines)\n" "$old" "$new"
    else
        printf "FAILED (keeping existing file)\n" >&2
    fi
    rm -f "$tmp"
}

update_file "$RESOLVERS_URL" "$RESOLVERS_FILE" "resolvers.txt"
update_file "$WORDLIST_URL"  "$WORDLIST_FILE"  "subdomains-top1million-110000.txt"
