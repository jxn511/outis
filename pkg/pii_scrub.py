#!/usr/bin/env python3
"""pii_scrub.py -- remove personal data from a corpus, preserving the evidence.

The companion to `pii_scan.py`. Scanning finds; this removes. The procedure
(PROCEDURE.md, steps 2 and 5) requires both to run as the first pass over
anything new.

WHAT IT DOES, AND THE ONE DISTINCTION THAT MATTERS.

    the Email and Contact fields     value removed  -- a contact address is
                                                     never useful to a reader
                                                     and always personal
    the Referee and PC Reader fields line removed   -- confidential internal
                                                     review
    the Responsible field            KEPT           -- "who owns this file?"
                                                     is a legitimate question
    bare addresses                   replaced       -- with [address removed]
    ORCID, home paths, credentials,  replaced       -- with a placeholder
    shell-prompt and host accounts

Author names on published work are NOT touched. The line is published versus
confidential, not names versus not-names.

THE EVIDENCE IS PRESERVED, ALWAYS.

Every file changed is copied to quarantine BEFORE it is written, alongside a
record of exactly what was removed. A scrub destroys the very thing a later
reviewer needs in order to check the scrub was correct, so the original is
withdrawn from the corpus rather than destroyed: failure direction favours
retention.

Dry run by default. `--apply` writes. Every file visited leaves one row in
<quarantine>/<label>_scrub_ledger.jsonl (ledger.for_each), so a file cannot
leave the run unaccounted for.
"""

import argparse
import collections
import hashlib
import json
import os
import re
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ledger
import pii_scan
from pii_scan import secret_is_wrapped_plain_word

TOOL_VERSION = "pii_scrub.py 0.1.1"

ADDRESS = "[address removed]"

# Whole lines whose VALUE names an individual performing confidential review.
DROP_LINE = re.compile(
    r"^[ \t]*(?:#|//|%)?[ \t]*(?:Referees?|PC[ ]?Reader|Reviewer)[ \t]*:[ \t]*\S.*$",
    re.M | re.I)
# Credential assignments: keep the key, drop the VALUE. pii_scan detects these
# but this module once had no rule to remove one -- a gap found on the
# reference instance when a thesis was discovered documenting a root-shell
# procedure with a literal host password. Scanning without a matching scrub
# means the gate can only ever report that finding, never clear it.
SECRET_VALUE = re.compile(
    r"(?i)(\b(?:api[_-]?key|secret|passwd|password|token)\b\s*[:=]\s*)"
    r"(['\"]?)([A-Za-z0-9._\-/+]{8,})")
CREDENTIAL = "[credential removed]"
# The local part of a shell prompt. Generic by construction, so the redacted
# prompt still reads as a prompt and cannot itself be flagged.
PROMPT_USER = "user"


def _benign_covers(text, m):
    """Does an exemption COVER the start of finding `m`?

    pii_scan uses exactly this test; this module once used a naive
    `BENIGN.search(window)` -- "benign appears anywhere nearby" -- and the two
    disagreed the moment the rules grew. Concretely: scrubbing a line of the
    form `PassWord : <value> [root@<host> root]` found `root@` inside the +/-8
    window, ruled the whole line benign by the RFC 2142 role-mailbox rule, and
    silently declined to remove a real credential. The scanner still flagged
    it, so scan and scrub disagreed and the gate could never be cleared.

    One definition, shared: coverage of the match START, never proximity. The
    shared definition LIVES in pii_scan.benign_covers (which also reads the
    local RULINGS) and this is a delegating shim.
    """
    return pii_scan.benign_covers(text, m.start(), m.end())

# Contact fields: keep the key, drop the value, so the record shape survives.
BLANK_VALUE = re.compile(
    r"^([ \t]*(?:#|//|%)?[ \t]*(?:Email|E-mail|Contact)[ \t]*:[ \t]*)\S.*$",
    re.M | re.I)


def _redact_home_path(removed):
    """Build the pii_scan.HOMEDIR replacement callback.

    Two things this must get right, both found the hard way on the reference
    instance:

    1. The removal record is a LENGTH, never the value -- matching "address"
       and "credential" below. Before this it stored `m.group(0)` verbatim,
       and `--apply` writes `removed` straight into <file>.removed.json, so
       the scrub's own report of what it removed was reproducing the
       personal data it removed -- the "a report must not contain the value"
       rule, violated by this one line for as long as the two-component
       GPFS_HOMEDIR class went undetected.

    2. A two-component match (`/home/<group>/<user>`) must be replaced
       with TWO placeholders, not one. Collapsing to a single "/home/REDACTED"
       leaves whatever trailing path segment follows (`/lumi/runs` becomes
       "/home/REDACTED/lumi") sitting in EXACTLY the shape GPFS_HOMEDIR's own
       residual-recovery rule exists to catch -- comp1 reading REDACTED,
       comp2 not -- so a re-scan (or a second scrub pass) misreads an
       ordinary directory name as a second leaked username. Caught by
       test_pii_scrub_home_path_detail_never_carries_the_username's own
       scan-the-output assertion, which is the same "scrub output must pass
       the gate that motivated it" requirement every other kind here is
       held to.
    """
    def redact(m):
        val = m.group(0)
        removed.append(("home_path", "<%d chars>" % len(val)))
        # A two-component match always has 3 slashes ("/home/<g>/<u>"); the
        # plain single-component fallback always has 2 ("/home/<u>"). This
        # counts slashes rather than re-deriving which alternative of
        # HOMEDIR matched, so it stays correct if the pattern's internal
        # grouping ever changes.
        if val.count("/") >= 3:
            return "/home/REDACTED/REDACTED"
        return "/home/REDACTED"
    return redact


def scrub_text(text, keep_orcid=False):
    """(new_text, [(kind, removed_snippet)]). Whole lines or whole values only.

    `keep_orcid` leaves ORCID identifiers in place. It exists because the two
    findings sit on OPPOSITE sides of section 0's actual line, which is
    published versus confidential and not names versus not-names:

      contact address   always removed. The name already carries whatever
                        retrieval value exists, and nobody should be able to
                        extract a colleague's address from a chatbot.
      ORCID             an identifier PUBLISHED on the paper alongside the
                        author list, which the procedure calls not a leak.

    It is a flag and not a default because the call belongs to the instance's
    privacy owner, not to this tool, and a caller that cannot interpret a
    finding must stop rather than proceed. Default stays fail-closed: scrub
    both.
    """
    removed = []

    def drop(m):
        removed.append(("confidential_role_line", m.group(0).strip()[:90]))
        return ""

    def blank(m):
        removed.append(("contact_value", m.group(0).strip()[:90]))
        return m.group(1) + ADDRESS

    out = DROP_LINE.sub(drop, text)
    out = BLANK_VALUE.sub(blank, out)

    def addr(m):
        if _benign_covers(out, m):
            return m.group(0)
        removed.append(("address", "<%d chars>" % len(m.group(0))))
        return ADDRESS

    def cred(m):
        # The exemptions still govern: an instance that has ruled a call-valued
        # assignment safe (a `literal:` row in its RULINGS) must not see it
        # rewritten into a placeholder.
        if _benign_covers(out, m):
            return m.group(0)
        # SYMMETRY WITH THE SCAN, and it is imported rather than restated: a
        # wrapped plain word is not a credential (see
        # pii_scan.secret_is_wrapped_plain_word). If this predicate and
        # pii_scan's ever diverged, the scan
        # would report a finding this function refuses to remove and the gate
        # could never be cleared.
        if secret_is_wrapped_plain_word(m.group(0)):
            return m.group(0)
        removed.append(("credential", "<%d chars>" % len(m.group(3))))
        return m.group(1) + CREDENTIAL

    out = SECRET_VALUE.sub(cred, out)
    out = pii_scan.EMAIL.sub(addr, out)
    if not keep_orcid:
        out = pii_scan.ORCID.sub(
            lambda m: (removed.append(("orcid", "<redacted>"))
                       or "0000-0000-0000-0000"), out)
    # Substituted on pii_scan's OWN compiled pattern, imported rather than
    # restated, for the reason the SECRET_VALUE comment records: a finding the
    # scan reports and the scrub will not remove is a gate that can never clear.
    # The HOST survives -- it is infrastructure, and the prompt's shape is what
    # makes a transcript readable. Only the local part is an identity.
    def prompt(m):
        removed.append(("shell_prompt", "<%d chars>" % len(m.group(0))))
        if m.group(1):                       # [user@host ...]$
            return "[%s@%s%s]%s" % (PROMPT_USER, m.group(2), m.group(3), m.group(0)[-1])
        return "%s@%s%s%s" % (PROMPT_USER, m.group(5), m.group(6), m.group(0)[-1])

    # An account on a numeric host. Substituted on pii_scan's OWN pattern, imported
    # rather than restated -- see the SHELL_PROMPT note directly above. The HOST is
    # infrastructure and survives, so `ssh user@<IPv4 address>` still reads as
    # an instruction; only the local part is an identity.
    def hostacct(m):
        removed.append(("host_account", "<%d chars>" % len(m.group(1))))
        return "%s@%s" % (PROMPT_USER, m.group(2))

    out = pii_scan.HOST_ACCOUNT.sub(hostacct, out)
    out = pii_scan.SHELL_PROMPT.sub(prompt, out)
    out = pii_scan.HOMEDIR.sub(_redact_home_path(removed), out)
    # collapse the blank lines a dropped line leaves behind
    out = re.sub(r"\n{3,}", "\n\n", out)
    return out, removed


def scrub_file_text(path, text, keep_orcid=False):
    """scrub_text for a FILE: .html/.htm working copies are entity-decoded
    first (pii_scan.HTML_EXT -- the entity-encoded "@" class), so the scrubber
    removes exactly what the scanner finds; other files are scrubbed as-is.
    Decoding is applied only when something is removed, so a clean HTML file
    is left byte-identical."""
    import html as _html
    ext = os.path.splitext(path)[1].lower()
    if ext in pii_scan.HTML_EXT:
        decoded = _html.unescape(text)
        new, removed = scrub_text(decoded, keep_orcid=keep_orcid)
        return (new, removed) if removed else (text, [])
    if ext in (".json", ".jsonl"):
        new, removed = _scrub_json_text(text, keep_orcid=keep_orcid)
        if new is not None:
            return new, removed
        # not valid JSON despite the extension: fall through and scrub as text,
        # which is what it evidently is
    return scrub_text(text, keep_orcid=keep_orcid)


def _scrub_json_text(text, keep_orcid=False):
    """Scrub a JSON document by its DECODED string values, then re-serialize.

    THE DEFECT THIS CLOSES, found on a raw wiki tree on the reference instance:
    18 of 2,812 files were corrupted by scrubbing the SERIALIZED BYTES. In those
    bytes an address sat immediately after a `\\n` escape, so the address
    pattern -- whose local part is [A-Za-z0-9._%+-]+ -- consumed the `n` as its
    first character, and the replacement left a dangling backslash followed by
    `[address removed]`. Invalid JSON, and NOTHING CAUGHT IT: the PII gate went
    green, because a file that has been scrubbed and broken has no findings
    either. It was found only by a metamorphic check that the tree still
    parsed.

    This is the two-sieve representational failure in a third costume: the
    scrub must read the same representation the CONTENT lives in, not a
    serialization of it. Working on the decoded values means an escape cannot
    be split, because escapes do not exist at that level.

    Returns (new_text, removed) or (None, []) when the text is not JSON.
    """
    try:
        doc = json.loads(text)
    except (ValueError, TypeError):
        return None, []
    removed = []

    def walk(node):
        if isinstance(node, str):
            new, rem = scrub_text(node, keep_orcid=keep_orcid)
            if rem:
                removed.extend(rem)
            return new
        if isinstance(node, list):
            return [walk(v) for v in node]
        if isinstance(node, dict):
            # Keys are scrubbed too: a dict keyed by address is as much a
            # disclosure as one valued by it.
            return dict((walk(k) if isinstance(k, str) else k, walk(v))
                        for k, v in node.items())
        return node

    scrubbed = walk(doc)
    if not removed:
        return text, []
    return json.dumps(scrubbed, sort_keys=True, ensure_ascii=True), removed


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root")
    ap.add_argument("--quarantine", required=True)
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--label", default=None, help="strand name for the ledger")
    ap.add_argument("--keep-orcid", action="store_true",
                    help="leave ORCID identifiers in place. An ORCID is "
                         "PUBLISHED alongside the author list, which the "
                         "procedure calls not a leak; a contact address never "
                         "is. The instance's privacy owner decides.")
    ap.add_argument("--rulings", default=None,
                    help="local RULINGS file (else $%s); the same exemptions "
                         "the scanner applies" % pii_scan.RULINGS_ENV)
    ap.add_argument("--version", action="version", version=TOOL_VERSION)
    args = ap.parse_args(argv)

    refused = pii_scan._rulings_cli(args.rulings)
    if refused:
        return refused
    if not os.path.exists(args.root):
        sys.stderr.write("REFUSED: no such file or directory: %s\n" % args.root)
        return 2

    targets = []
    # A single FILE is a valid target. os.walk over one yields nothing, so the
    # CLI used to scrub zero files and exit 0 -- a tool reporting success for
    # work it did not do. Found redacting home paths out of a report before it
    # was handed over.
    if os.path.isfile(args.root):
        targets = [args.root]
        args.root = os.path.dirname(os.path.abspath(args.root))
    for r, ds, fs in (os.walk(args.root) if not targets else []):
        ds[:] = [d for d in ds if d not in (".git", "__pycache__")]
        for f in fs:
            ext = os.path.splitext(f)[1].lower()
            # The first pass used pii_scan.TEXT_EXT and missed 34 files in one
            # code tree alone -- .conf, .inc, .bak and extensionless scripts carry
            # addresses. Scrubbing must cover everything the SCANNER flags, or
            # the two disagree and the gate stays red forever. So: attempt any
            # file that is not obviously binary, and let the decode decide.
            if ext in pii_scan.EXTRACTABLE:
                continue                      # PDFs: content is not editable here
            targets.append(os.path.join(r, f))
    targets.sort()
    label = args.label or os.path.basename(args.root.rstrip("/"))
    stats = collections.Counter()

    def handle(path):
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
        except OSError as e:
            return ledger.failed("unreadable: %s" % e, files=(1, 0))
        if b"\0" in raw[:4096]:
            return ledger.skipped("binary", files=(1, 1))
        # surrogateescape, NOT "replace". This function READS AND WRITES the file,
        # so a lossy decode here does not merely mis-read a byte -- it destroys it
        # on the way back out. Measured on the reference instance: a thread-archive
        # re-harvest was about to store byte-exact source, and this line would have converted every
        # non-UTF-8 byte to U+FFFD immediately afterwards, undoing the whole harvest
        # while reporting success. surrogateescape parks unknown bytes in
        # U+DC80..U+DCFF and the matching encode below puts them back unchanged, so
        # the only bytes this function alters are the ones it deliberately removes.
        text = raw.decode("utf-8", "surrogateescape")
        new, removed = scrub_file_text(path, text, keep_orcid=args.keep_orcid)
        if not removed:
            return ledger.skipped("clean", files=(1, 1))
        for k, _v in removed:
            stats[k] += 1
        stats["files_changed"] += 1
        if not args.apply:
            return ledger.ok("dry run: would remove %d item(s)" % len(removed),
                             files=(1, 1))
        rel = os.path.relpath(path, args.root)
        q = os.path.join(args.quarantine, label, rel)
        os.makedirs(os.path.dirname(q), exist_ok=True)
        shutil.copyfile(path, q + ".original")
        with open(q + ".removed.json", "w", encoding="ascii", errors="replace") as f:
            json.dump({"file": rel,
                       "removed": [{"kind": k, "detail": v} for k, v in removed]},
                      f, ensure_ascii=True, sort_keys=True, indent=1)
        tmp = path + ".new"
        with open(tmp, "w", encoding="utf-8", errors="surrogateescape") as f:
            f.write(new)
        os.replace(tmp, path)
        return ledger.ok("removed %d item(s)" % len(removed), files=(1, 1))

    led = os.path.join(args.quarantine, "%s_scrub_ledger.jsonl" % label)
    os.makedirs(args.quarantine, exist_ok=True)
    _, balance = ledger.for_each(targets, handle, led,
                                 key_of=lambda p: os.path.relpath(p, args.root),
                                 stream=None)
    print("  strand          : %s" % label)
    print("  text files       : %d" % len(targets))
    print("  files changed    : %d" % stats["files_changed"])
    # EVERY class this run removed, derived from what was actually removed
    # rather than from a list written by hand. The hand-written list was
    # ("address", "contact_value", "confidential_role_line", "orcid",
    # "home_path") and it omitted "credential": an ingress scrub on the
    # reference instance removed a host password from a tutorial page,
    # recorded it correctly in that file's .removed.json, and did not mention
    # it in the summary a human reads. The per-file record and the summary
    # disagreed, and the summary is the one anybody looks at.
    #
    # "A named list is the wrong shape" inside a PII tool, where the cost of an
    # omission is a finding class nobody knows was found. Deriving the list
    # makes the omission unreachable rather than merely detectable.
    for k in sorted(k for k in stats if k != "files_changed"):
        print("    %-24s %d" % (k, stats[k]))
    if not args.apply:
        print("\n  DRY RUN. Nothing written. Re-run with --apply.")
    else:
        print("  originals quarantined at: %s" % os.path.join(args.quarantine, label))
    unb = ledger.unbalanced(balance)
    if unb:
        sys.stderr.write("ERROR unbalanced: %s\n" % unb)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
