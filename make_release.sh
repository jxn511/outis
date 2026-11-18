#!/usr/bin/env bash
# make_release.sh -- build outis-$VERSION.tar.gz from pkg/, reproducibly.
#
#   REFERENCE_SCANNER=/path/to/reference/pii_scan.py ./make_release.sh
#   REFERENCE_SCANNER=none ./make_release.sh      # deliberately skip that gate
#   BARE_TOKENS=/path/to/tokens.txt ...           # optional extra scan
#
# REFUSES (exit 2, no archive written) unless ALL of these pass, each judged by
# its own exit status and never through a pipe:
#   1. the suite                 python3 pkg/tests/run_tests.py
#   2. the package's own gate    python3 pkg/pii_scan.py pkg --gate
#   3. the reference gate        python3 "$REFERENCE_SCANNER" pkg --gate
#                                (REFERENCE_SCANNER must be set; the value
#                                `none` skips it and says so in the output)
#   4. a bare-token scan         only when BARE_TOKENS names a file of
#                                extended regexes, one per line (kept OUTSIDE
#                                the package: a token list is itself a leak)
#
# REPRODUCIBLE: members sorted by name, every mtime fixed at the release date,
# owner/group 0, modes normalised, gzip without name or timestamp. The archive
# is built twice and the two digests compared before it is published here.
# Prints the archive's sha256 and writes it beside the archive.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE" || exit 2
VERSION=0.1.1
NAME=outis-$VERSION
ARCHIVE=$NAME.tar.gz
RELEASE_DATE="2026-11-17 00:00:00 UTC"
export PYTHONDONTWRITEBYTECODE=1

refuse() { echo "REFUSED: $*" >&2; exit 2; }

[ -d pkg ] || refuse "no pkg/ beside this script"
[ -f pkg/pii_scan.py ] || refuse "pkg/pii_scan.py missing"
find pkg -name __pycache__ -type d -prune -exec rm -rf {} +

LOG=$(mktemp)
trap 'rm -f "$LOG"' EXIT

echo "  [1/4] suite"
if ! python3 pkg/tests/run_tests.py >"$LOG" 2>&1; then
    tail -20 "$LOG" >&2
    refuse "the suite failed"
fi
grep -E '^(OK|FAILED)' "$LOG" | sed 's/^/        /'
grep '^Ran ' "$LOG" | sed 's/^/        /'

echo "  [2/4] the package's own gate"
if ! python3 pkg/pii_scan.py pkg --gate >"$LOG" 2>&1; then
    cat "$LOG" >&2
    refuse "the package's own gate failed"
fi
grep 'findings            :' "$LOG" | sed 's/^/        /'

echo "  [3/4] the reference gate"
if [ -z "${REFERENCE_SCANNER:-}" ]; then
    refuse "REFERENCE_SCANNER is not set (a path to the reference pii_scan.py, or 'none')"
elif [ "$REFERENCE_SCANNER" = "none" ]; then
    echo "        SKIPPED by REFERENCE_SCANNER=none"
else
    [ -f "$REFERENCE_SCANNER" ] || refuse "REFERENCE_SCANNER does not exist"
    if ! python3 "$REFERENCE_SCANNER" pkg --gate >"$LOG" 2>&1; then
        sed 's/^/        /' "$LOG" >&2
        refuse "the reference gate failed"
    fi
    grep 'findings            :' "$LOG" | sed 's/^/        /'
fi

echo "  [4/4] bare-token scan"
if [ -n "${BARE_TOKENS:-}" ]; then
    [ -f "$BARE_TOKENS" ] || refuse "BARE_TOKENS does not exist"
    if grep -rqiIE -f "$BARE_TOKENS" pkg; then
        # locations only, never the matched token
        grep -rniIE -f "$BARE_TOKENS" pkg | cut -d: -f1,2 >&2
        refuse "the bare-token scan found matches"
    fi
    if grep -rqIE '/home/[a-z]{2,}/' pkg; then
        grep -rnIE '/home/[a-z]{2,}/' pkg | cut -d: -f1,2 >&2
        refuse "a home path is present"
    fi
    echo "        0 matches ($(grep -c . "$BARE_TOKENS") patterns + the generic home-path form)"
else
    echo "        not requested (BARE_TOKENS unset)"
fi

build() {   # $1 = output path
    tar --sort=name --format=gnu \
        --mtime="$RELEASE_DATE" --owner=0 --group=0 --numeric-owner \
        --mode='u=rwX,go=rX' \
        --exclude='__pycache__' --exclude='*.pyc' \
        --transform="s,^pkg,$NAME," \
        -cf - pkg | gzip -n -9 > "$1"
}

TMPA=$(mktemp); TMPB=$(mktemp)
trap 'rm -f "$LOG" "$TMPA" "$TMPB"' EXIT
build "$TMPA" || refuse "tar failed"
build "$TMPB" || refuse "tar failed"
SHA_A=$(sha256sum "$TMPA" | cut -d' ' -f1)
SHA_B=$(sha256sum "$TMPB" | cut -d' ' -f1)
[ "$SHA_A" = "$SHA_B" ] || refuse "two builds differ ($SHA_A vs $SHA_B): not reproducible"

mv "$TMPA" "$ARCHIVE.new" && mv "$ARCHIVE.new" "$ARCHIVE" || refuse "could not write $ARCHIVE"
chmod 0644 "$ARCHIVE"
SHA=$(sha256sum "$ARCHIVE" | cut -d' ' -f1)
[ "$SHA" = "$SHA_A" ] || refuse "archive digest changed on the way to disk"
echo "$SHA  $ARCHIVE" > "$ARCHIVE.sha256"
echo "  members: $(tar -tzf "$ARCHIVE" | grep -vc '/$') files"
echo "  $ARCHIVE"
echo "  sha256 $SHA"
