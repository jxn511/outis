#!/usr/bin/env python3
"""builder_guard.py -- a builder refuses markdown that carries a blocking finding.

DERIVED TEXT IS NEW MATERIAL. A converter's output -- a renderer over a PDF,
OCR over a scan, any tool that PRODUCES text -- is material the ingress scan
has never seen, however clean its input was. On the reference instance a
conversion fleet delivered 488 converted documents straight to the build; 108
author-block addresses reached the envelopes of 38 documents and were caught
only by the egress sieve, with a disagreement of 0 because ingress had never
run on those files and so had cleared nothing. The remedy there was to make the
wrong state UNREACHABLE at the build rather than detected at egress: the
builder refuses markdown with a blocking finding and names the kinds in a
`pii_blocked` ledger row.

THE ONE CALL a builder makes, before it builds an envelope from a markdown
file:

    import builder_guard
    v = builder_guard.guard_markdown(md_path, ledger_path)
    if v.refused:
        continue        # not built; the ledger row says why

`guard_markdown` scans with pii_scan (the single definition), decides
"blocking" with pii_gate.is_blocking (the same partition the egress gate uses:
RECORDED kinds such as ORCID never block), and appends ONE row to the ledger in
ledger.for_each's row form:

    passed    status "ok",      detail "built",                 files [1, 1]
    refused   status "dropped", detail "pii_blocked: <kinds>",  files [1, 0]

The row names KINDS, never values: a report of personal data must not contain
the personal data. Because a refusal is a reasoned drop, the ledger conserves
records: files in = passed + refused, which ledger.for_each checks for the CLI.

An unreadable file is refused too (kind `unreadable`): it has not been cleared.

CLI:  python3 builder_guard.py FILE... --ledger L [--rulings R]
Exit: 0 every file passed; 1 any file refused; 2 could not run (bad arguments,
      malformed RULINGS, or the ledger did not balance).
"""

import argparse
import collections
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ledger
import pii_gate
import pii_scan

TOOL_VERSION = "builder_guard.py 0.1.1"

Verdict = collections.namedtuple("Verdict", "key kinds blocking refused row")


def _is_path(path_or_text):
    # A string is a PATH only when it names an existing file and is a single
    # line; anything else is markdown text. Bytes are never a path.
    return (isinstance(path_or_text, str) and "\n" not in path_or_text
            and os.path.isfile(path_or_text))


def assess(path_or_text, key=None, is_path=None):
    """(key, kinds, blocking_kinds) for one markdown file or text. No ledger.

    `is_path` True: the argument IS a path, and a path that cannot be read is
    refused as `unreadable` (the CLI always says so). None: a single-line
    string naming an existing file is a path, anything else is text.
    """
    if is_path is None:
        is_path = _is_path(path_or_text)
    if is_path:
        k = key or path_or_text
        if not os.path.isfile(path_or_text):
            return k, ["unreadable"], ["unreadable"]
        try:
            hits = pii_scan.scan_file(path_or_text)
        except OSError:
            return k, ["unreadable"], ["unreadable"]
    else:
        text = path_or_text
        if isinstance(text, bytes):
            import text_decode
            text = text_decode.decode_document(text)
        # The key for raw text is a digest, never the text: the ledger row
        # must not be able to carry what it reports.
        k = key or "text:" + hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest()[:16]
        hits = pii_scan.scan_text(text, k)
    kinds = sorted({h[0] for h in hits})
    blocking = [x for x in kinds if pii_gate.is_blocking(x)]
    return k, kinds, blocking


def row_for(blocking):
    """The ledger Row for a verdict: a reasoned drop naming kinds, or ok."""
    if blocking:
        return ledger.dropped("pii_blocked: " + ",".join(blocking), files=(1, 0))
    return ledger.ok("built", files=(1, 1))


def guard_markdown(path_or_text, ledger_path, rulings=None, key=None, is_path=None):
    """Guard ONE markdown file (a path) or markdown text before it is built.

    Returns Verdict(key, kinds, blocking, refused, row). `refused` is True
    when any blocking kind is present; the caller must not build. Exactly one
    row is appended to `ledger_path` in ledger.for_each's row form.
    `rulings`: a RULINGS path to activate first (raises pii_scan.RulingsError
    on a malformed file); None keeps whatever rulings are active.
    """
    if rulings is not None:
        pii_scan.configure_rulings(rulings)
    k, kinds, blocking = assess(path_or_text, key, is_path)
    row = row_for(blocking)
    refused = bool(blocking)
    ledger.append_row(ledger_path, k, row)
    return Verdict(k, kinds, blocking, refused, row)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+", help="markdown files about to be built")
    ap.add_argument("--ledger", required=True, help="ledger path (rewritten atomically)")
    ap.add_argument("--rulings", default=None,
                    help="local RULINGS file (else $%s)" % pii_scan.RULINGS_ENV)
    ap.add_argument("--version", action="version", version=TOOL_VERSION)
    args = ap.parse_args(argv)

    refused_cli = pii_scan._rulings_cli(args.rulings)
    if refused_cli:
        return refused_cli

    refused = []

    def handle(path):
        _k, _kinds, blocking = assess(path, is_path=True)
        if blocking:
            refused.append((path, blocking))
        return row_for(blocking)

    try:
        _rows, balance = ledger.for_each(args.files, handle, args.ledger,
                                         key_of=lambda p: p, stream=None)
    except ledger.LedgerError as e:
        sys.stderr.write("REFUSED: %s\n" % e)
        return 2
    n = len(args.files)
    print("  %d in, %d passed, %d refused, %d unaccounted"
          % (n, n - len(refused), len(refused), n - len(_rows)))
    for path, blocking in refused:
        # kinds only -- never the values
        print("    REFUSED %s  pii_blocked: %s" % (path, ",".join(blocking)))
    print("  ledger -> %s" % args.ledger)
    if ledger.unbalanced(balance) or len(_rows) != n:
        sys.stderr.write("ERROR: the ledger does not balance: %s\n" % balance)
        return 2
    return 1 if refused else 0


if __name__ == "__main__":
    sys.exit(main())
