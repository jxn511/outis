#!/usr/bin/env python3
"""pii_scan.py -- the single definition of personal data, and the gate that stops it.

STANDING RULE (PROCEDURE.md, step 2):

    STRIP ALL PII AS THE FIRST PASS OVER ANYTHING NEW, BEFORE ANY OTHER
    PROCESSING. NO EXCEPTIONS.

This module is that rule made executable. Nothing enters the corpus until it has
passed through here, because every alternative ordering has already failed on
the reference instance this package was extracted from:

  * an indexed paper carried three named internal referees into the embedding
    index. Found only because someone happened to read a template.
  * 1,821 of 1,845 event-generator decay files carried a maintainer name, and
    193 distinct working email addresses sat across the code corpora. Found
    only while admiring the file format.
  * an internal-note publication template rendered `\\proponents`,
    `\\referees` and `\\pcreader` -- people's names -- onto the title page of
    every internal note.

In each case the PII was found by accident while looking for something else.
That is not a detection strategy. Scanning must be the FIRST thing that happens
to new material, not a thing that happens to occur to someone.

WHY THIS FAILS CLOSED.

`gate` exits non-zero on any finding. A caller that cannot interpret a finding
must stop, not proceed. The asymmetry is the whole point: a false positive costs
a human thirty seconds; a false negative publishes a colleague's address to a
thousand-user chatbot and cannot be recalled once embedded.

WHAT IS AND IS NOT PERSONAL DATA HERE.

Published authorship is not a leak: author names on a paper are already public,
are in the metadata, and are load-bearing for retrieval ("who measured phi3?").
Confidential review is: who refereed a paper internally is not public and is
useless to a reader. The line is **published versus confidential**, not
**names versus not-names**. Contact addresses are always stripped -- nobody
should extract a colleague's email from a chatbot, and the name already carries
whatever retrieval value exists.

EXEMPTIONS, IN THREE TIERS (one excusal test, `benign_covers`, reads all three).

  NON_REFERRING  strings that cannot name a person BY CONSTRUCTION: the IETF
                 reserved namespaces (RFC 2606 / RFC 6761), the placeholders
                 this package's own scrubber writes (so a scrubbed corpus passes
                 its own gate), and the SSH URL host form. Not a ruling.
  BENIGN         the RFC 2142 role mailboxes and the POSIX system accounts.
                 The ONLY exemption list the package ships.
  local rulings  read at run time from the instance's RULINGS file (--rulings
                 or the PII_RULINGS environment variable; see RULINGS.template).
                 Never shipped, never required: absent means no local exemption.
"""

import argparse
import collections
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import text_decode

TOOL_VERSION = "pii_scan.py 0.1.0"

# --- always personal, always stripped -------------------------------------
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
ORCID = re.compile(r"\b\d{4}-\d{4}-\d{4}-\d{3}[\dX]\b")
PHONE = re.compile(r"(?<![\d.])(?:\+\d{1,3}[ -]?)?(?:\(\d{2,4}\)[ -]?)?\d{3,4}[ -]\d{3,5}(?![\d.])")

# SOME SITES NEST A HOME DIRECTORY AS /gpfs/home/<accounting group>/<username>/
# -- TWO path components, not one. The plain rule below models a home root as
# exactly one component, so on this shape it redacts the GROUP and leaves the
# USER exposed; the (?!REDACTED) lookahead then hides that residue from every
# later scan, which is the marked-done-still-exposed state exactly. Measured
# twice on the reference instance before the detector was ruled BLOCKING: a
# colleague's surname survived in two internal notes, embedded and reachable,
# until a finding-level fix. The mount+home SHAPE of a computing centre is
# public; the username component is the personal data this rule exists to
# catch.
#
# NARROWEST MEASURED SHAPE ONLY. The literal mount prefix `/gpfs/home/` is what
# every occurrence on the reference instance actually had. `/nfs/home/<group>/<user>` was
# proposed as a plausible sibling but never observed -- adding it would be
# inventing a shape, not measuring one. A first `/nfs/home/` finding is a fresh
# decision for the instance that meets it.
#
# The mount prefix is consumed through a fixed-width LOOKBEHIND, not matched
# into the finding, so a scrub redacts only the two personal components and
# leaves the (public) mount+home shape intact -- and, just as important, the
# lookbehind must be ANCHORED the same way a domain exemption's tail is:
# exactly the five characters "/gpfs" immediately before "/home/", never a
# substring or suffix match. Without the anchor, any path component merely
# ENDING in "gpfs" (`/notgpfs/home/<user>`, `s3://mygpfs/home/<user>`) would silently
# gain a rule it was never measured to need -- the unanchored-tail defect in a
# third costume.
#
# comp1 (the accounting group) is allowed to already read literally REDACTED:
# that is precisely the residual state a PRIOR single-component scrub pass
# leaves behind, and the detector must still catch comp2 there or a corpus
# scrubbed under the old one-component rule stays silently exposed forever.
# comp2 must NOT already read REDACTED, or a fully-scrubbed path re-triggers
# the gate it just passed -- the same fixed-point requirement every other
# detector here is held to (test_redaction_placeholders_are_not_re_flagged).
GPFS_HOMEDIR = r"(?<=/gpfs)/home/(?:REDACTED|(?!REDACTED)[A-Za-z0-9._-]+)/(?!REDACTED)[A-Za-z0-9._-]+"
# THE SAME IDENTIFIER, SPELLED WITH DASHES. Some tools name a working directory
# after a path with the separators replaced by dashes, so /home/<user>/project
# becomes -home-<user>-project. HOMEDIR matches on SLASHES, so on the reference
# instance the gate once ran GREEN over six dash-form occurrences of a username
# in a report -- immediately after a scrub had redacted nine slash-form paths in
# the SAME FILE. The scrub was right and the gate was right; they were reading
# different spellings of one thing, which is the "two representations" problem
# inside a single sieve.
#
# THE TRAILING DASH IS WHAT MAKES THIS SAFE. A flattened path always has a
# component after the user ("-home-<user>-project"), so requiring one rejects
# "go-home-now" and "the -home- directory" without needing a lookbehind -- and a
# lookbehind would break "-mnt-c-Users-<user>-", where the leading dash is
# preceded by an ordinary letter.
#
# FLAT_HOMEDIR_BENIGN SHIPS EMPTY. The reference instance excused one
# enumerated non-person token here by ruling; that is an instance decision, and
# an instance that needs one writes a `literal:` row in its RULINGS file.
FLAT_HOMEDIR_BENIGN = ()
FLAT_HOMEDIR = (r"-(?:home|Users)-(?!REDACTED-)"
                + (r"(?!(?:%s)-)" % "|".join(re.escape(t) for t in FLAT_HOMEDIR_BENIGN)
                   if FLAT_HOMEDIR_BENIGN else "")
                + r"[A-Za-z0-9._]+-")
HOMEDIR = re.compile(GPFS_HOMEDIR
                     + r"|/(?:home|Users)/(?!REDACTED)[A-Za-z0-9._-]+"
                     + r"|" + FLAT_HOMEDIR)
# A SHELL PROMPT carrying an account name.
#
# On the reference instance a users' guide had `ssh <user>@<login host>`
# correctly removed as an address while `[<user>@login ~]$` on the NEXT LINE
# survived -- the host there is bare `login`, with no dot, so EMAIL cannot match
# it even in principle. One identifier, two syntactic forms, a detector that
# knew one. Measured over one emitted wiki strand before the fix: 597
# occurrences, 45 distinct (user, host) pairs across 100 pages, 40 with a
# non-generic local part -- all embedded and reachable, and all passing the
# egress gate because they are not addresses.
#
# GENERIC LOCAL PARTS ARE ENUMERATED, not shape-matched: `[root@localhost ~]#`
# is every tutorial ever written, and a widening that flagged it could never
# reach green.
#
# AN ACCOUNT ON A NUMERIC HOST. EMAIL ends in `\.[A-Za-z]{2,}` -- it requires a
# dotted alphabetic TLD -- so `<account>@<IPv4 address>` can never match it.
# Measured over retrievable nodes on the reference instance before this was
# added: 62 occurrences in 16 envelopes carrying 7 distinct non-generic
# account names.
#
# A SEPARATE KIND rather than a widening of EMAIL: an account on a numeric host
# is reachable infrastructure, not correspondence, and keeping them apart means
# the gate report says which one it found.
#
# The octet bound is the addressing standard and it does real work here: it
# rejects the version-shaped strings (`build@1.2.3.999`) that would otherwise be
# the main false positive. Generic local parts are enumerated, as everywhere
# else in this module.
HOST_ACCOUNT_GENERIC = ("root", "user", "username", "guest", "localhost", "host",
                        "your", "name", "youruser", "someone")
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
HOST_ACCOUNT = re.compile(
    r"(?i)(?<![\w@.-])(?!(?:%s)@)([A-Za-z0-9._%%+-]+)@((?:%s\.){3}%s)(?![\d.])"
    % ("|".join(HOST_ACCOUNT_GENERIC), _OCTET, _OCTET))

SHELL_PROMPT_GENERIC = ("root", "user", "username", "guest", "localhost",
                        "your", "name", "login", "hostname", "youruser")
_SP_NOT_GENERIC = r"(?!(?:%s)@)" % "|".join(SHELL_PROMPT_GENERIC)
# `(?<!\\)` keeps a JSON ESCAPE out of the local part. Found on a stored wiki
# page: the file holds `\nuser@<host>:~$`, and a scanner reading it as TEXT
# absorbs the escape's `n` to get the local part "nuser" -- which is not in the
# generic list -- while the scrubber, which works on JSON-DECODED values, sees
# "user" and correctly skips it. Scan and scrub then disagree and the gate can
# never clear.
SHELL_PROMPT = re.compile(
    # [user@host ...]$   and   user@host:~$   -- the two forms enumerated.
    r"(?i)(?:\[" + _SP_NOT_GENERIC + r"(?<!\\)([A-Za-z0-9._-]+)@([A-Za-z0-9.-]+)([^\]\n]*)\]\s*[$#]"
    r"|(?<![\w@.])" + _SP_NOT_GENERIC + r"(?<!\\)([A-Za-z0-9._-]+)@([A-Za-z0-9.-]+)(:~?)\s*[$#])")

SECRET = (re.compile)(r"(?i)\b(?:api[_-]?key|secret|passwd|password|token)\b\s*[:=]\s*['\"]?[A-Za-z0-9._\-/+]{8,}")
# A SECRET assignment that WRAPS to the next line and lands on a plain
# alphabetic word is not a credential. Ruled on the reference instance on a
# census required before any change was made.
#
# The census, over a quarantined thread archive: of 21 cross-newline findings,
# 10 swallow an ordinary word, 3 a single token with no digits, 1 punctuation,
# and SEVEN swallow a mixed-alphanumeric token -- in OPERATIONS forums, where a
# password on one line and its value on the next is a plausible REAL layout
# rather than a scanner artifact.
#
# So a blanket narrowing of `\s*` to `[ \t]*` was REFUTED by measurement: it
# would have stopped catching all 21, the seven included. The rule that
# survives is narrower and fails safe -- anything that looks like a value is
# still a finding, and only a plain word is excused.
#
# This function is the SINGLE DEFINITION. pii_scrub imports it rather than
# carrying a second regex, because a scan that reports what the scrub will not
# remove is a gate that can never be cleared (see pii_scrub.SECRET_VALUE).
_SECRET_PARTS = re.compile(
    r"(?is)^(\b(?:api[_-]?key|secret|passwd|password|token)\b\s*[:=]\s*)"
    r"(['\"]?)([A-Za-z0-9._\-/+]{8,})$")
_PLAIN_WORD = re.compile(r"[A-Za-z]+$")


def secret_is_wrapped_plain_word(span):
    """True when a SECRET match crosses a newline AND its value is a plain word.

    `span` is the whole matched text. Same-line matches always return False:
    the ruling narrows the WRAPPED case only.
    """
    m = _SECRET_PARTS.match(span)
    if not m:
        return False
    if "\n" not in m.group(1):
        return False
    return bool(_PLAIN_WORD.match(m.group(3)))


PRIVKEY = re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY")
GLPAT = re.compile(r"\bglpat-[A-Za-z0-9_-]{16,}\b")

# --- confidential role fields: the NAME is the leak ------------------------
ROLE_FIELD = re.compile(
    r"^[ \t]*(?P<label>Referees?|PC[ ]?Reader|Proponents?|Responsible|Reviewer|Email|Contact)"
    r"[ \t]*:[ \t]*(?P<value>\S.*?)[ \t]*$", re.M | re.I)
# Roles whose value is confidential. `Proponents`/`Authors` are published
# authorship and are NOT in this set -- see the module docstring.
CONFIDENTIAL_ROLES = {"referee", "referees", "pc reader", "pcreader", "reviewer",
                      "email", "contact"}

DETECTORS = [
    ("email", EMAIL, "contact address"),
    ("orcid", ORCID, "personal identifier"),
    ("private_key", PRIVKEY, "private key material"),
    ("gitlab_token", GLPAT, "credential"),
    ("secret_assignment", SECRET, "credential"),
    ("home_path", HOMEDIR, "personal filesystem path"),
    ("shell_prompt", SHELL_PROMPT, "account name in a shell prompt"),
    ("host_account", HOST_ACCOUNT, "account name on a numeric host"),
]

# Formats whose bytes are binary but whose CONTENT is text, and how to extract
# it. Without this a PDF full of addresses passes the gate silently: the file is
# binary, so only key material was inspected, and everything else was skipped.
# Found on the reference instance by scanning a journal article whose first
# page carries a corresponding-author address -- the gate returned zero
# findings. That is a FALSE NEGATIVE, the one failure mode this module exists
# to prevent. pdftotext (poppler) is the one non-Python dependency, and only
# for PDFs; without it a PDF is reported `unscannable`, never passed.
EXTRACTABLE = {".pdf": ["pdftotext", "-q", "-enc", "UTF-8", "{src}", "-"]}

# Extensions worth reading as text. Binary is scanned only for key material.
TEXT_EXT = {".txt", ".md", ".rst", ".tex", ".bib", ".py", ".cc", ".h", ".c", ".hh",
            ".hpp", ".cxx", ".f", ".sh", ".csh", ".json", ".jsonl", ".xml", ".yaml",
            ".yml", ".cfg", ".ini", ".dec", ".html", ".htm", ".ipynb", ".csv", ".tsv",
            ".in", ".cmake", ".org", ""}

# --- exemption tier 1: non-referring by construction -----------------------
# Redaction placeholders are themselves email-shaped; never re-flag them, or a
# scrubbed corpus fails its own gate forever. Matched against the SURROUNDING
# text, not the match alone: `git@<host>:` is an SSH URL host only by virtue of
# the colon that follows it, and a check confined to the match cannot see that
# character.
NON_REFERRING = re.compile(
    # RFC 2606 / RFC 6761 reserved namespaces: the IETF reserved these so they
    # can never identify a real person. Covers the scrubber's own
    # REDACTED@example.invalid. An excusing alternate must COVER THE START of
    # the finding it excuses -- benign_covers checks that the match spans the
    # finding position, so a pattern beginning mid-finding (at the "@", at the
    # "=") never fires. Every alternate here therefore repeats the finding's
    # own head.
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]*"
    r"(?:example\.(?:com|net|org)|\.example|\.invalid|\.test|\.localhost)\b"
    r"|git@[A-Za-z0-9.-]+:"
    r"|0000-0000-0000-0000"
    # /home/REDACTED is the placeholder pii_scrub leaves behind, and must not
    # re-fail the gate it was written to pass. ANCHORED for the identical
    # reason GPFS_HOMEDIR's own lookbehind is anchored: unqualified, this
    # alternate's literal text is a PREFIX of the residual leak state
    # GPFS_HOMEDIR exists to catch (comp1 already reads REDACTED, comp2 does
    # not), so it would COVER that finding's start and excuse it right back out
    # of the gate. The lookahead requires what follows to be either nothing (a
    # single, fully-redacted component) or another literal REDACTED (the
    # fully-fixed two-component state); anything else is a surviving username.
    r"|/home/REDACTED(?!/(?!REDACTED)[A-Za-z0-9._-])"
    # A contact/email FIELD whose value is the scrubber's own placeholder
    # refers to nobody: where it appears, the data is already gone.
    r"|(?i:contact|email|e-mail)\s*[:=]?\s*\[address removed\]")

# --- exemption tier 2: the shipped exemption list ---------------------------
# RFC 2142 role mailboxes and POSIX system accounts: a reserved role address
# identifies a function or a machine, never a person. External oracle, same
# structure as the RFC 2606 namespace rule. THIS IS THE WHOLE SHIPPED LIST.
# Every other exemption is an instance ruling and lives in that instance's
# RULINGS file, never in this code.
BENIGN = re.compile(
    r"(?<![A-Za-z0-9._%+-])"
    r"(?i:root|daemon|nobody|postmaster|hostmaster|webmaster|abuse|noc|security"
    r"|mailer-daemon|noreply|no-reply|donotreply|usenet|news|uucp|ftp)@")


# --- exemption tier 3: local rulings ----------------------------------------
# One row per line, five fields separated by `|` (RULINGS.template):
#
#     <class>:<value> | EXEMPT or BLOCK | <reason> | <ruler role> | <YYYY-MM-DD>
#
#   address:<exact address>   that address only, case-insensitively, NEVER its
#                             domain: a sibling mailbox at the same domain is a
#                             different person and still blocks.
#   domain:<domain>           every address whose domain IS <domain> or ENDS in
#                             "." + <domain>. The tail is ANCHORED by two
#                             lookaheads (below); without them `.gov` would
#                             excuse `x@agency.gov.attacker.example`.
#   literal:<exact text>      a finding whose START lies inside an occurrence
#                             of this exact text (minimum 8 characters).
#
# BLOCK rows are accepted and recorded but create no exemption: everything
# blocks by default, so a BLOCK row documents a decision rather than changing
# behaviour. A malformed row REFUSES (RulingsError, CLI exit 2) and names its
# line: a rulings file that half-loads is an exemption list nobody can audit.
RULINGS_ENV = "PII_RULINGS"
RULING_CLASSES = ("address", "domain", "literal")
RULING_VERDICTS = ("EXEMPT", "BLOCK")
LITERAL_MIN = 8
_ADDRESS_FORM = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\Z")
_DOMAIN_FORM = re.compile(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\Z")
_DATE_FORM = re.compile(r"\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\Z")
# The anchored tail, shared by every address-shaped ruling. Written once.
#   (?![A-Za-z0-9-])  no further label characters,
#   (?!\.[A-Za-z])    and no further dotted label -- while still allowing a
#                     sentence-final period after the address.
_TAIL = r"(?![A-Za-z0-9-])(?!\.[A-Za-z])"

Ruling = collections.namedtuple("Ruling", "lineno cls value verdict reason ruler date")


class RulingsError(ValueError):
    """A malformed RULINGS row. Carries the 1-based line number."""

    def __init__(self, lineno, msg):
        ValueError.__init__(self, "RULINGS line %d: %s" % (lineno, msg))
        self.lineno = lineno


def parse_rulings(text):
    """[Ruling] from RULINGS text. Blank lines and `#` comments are skipped.

    Raises RulingsError naming the first malformed line. Never partially
    loads: the caller gets every row or an error, nothing in between.
    """
    rows = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = [f.strip() for f in line.split("|")]
        if len(fields) != 5:
            raise RulingsError(n, "expected 5 '|'-separated fields, found %d"
                               % len(fields))
        target, verdict, reason, ruler, date = fields
        if ":" not in target:
            raise RulingsError(n, "first field must be <class>:<value>, "
                               "class one of %s" % ", ".join(RULING_CLASSES))
        cls, value = target.split(":", 1)
        cls, value = cls.strip().lower(), value.strip()
        if cls not in RULING_CLASSES:
            raise RulingsError(n, "unknown class %r; expected one of %s"
                               % (cls, ", ".join(RULING_CLASSES)))
        if verdict not in RULING_VERDICTS:
            raise RulingsError(n, "verdict must be EXEMPT or BLOCK, found %r" % verdict)
        if not reason:
            raise RulingsError(n, "a ruling needs a reason")
        if not ruler:
            raise RulingsError(n, "a ruling needs the ruler's role")
        if not _DATE_FORM.match(date):
            raise RulingsError(n, "date must be YYYY-MM-DD, found %r" % date)
        if cls == "address" and not _ADDRESS_FORM.match(value):
            raise RulingsError(n, "address: needs one exact address, found %r" % value)
        if cls == "domain":
            value = value.lstrip(".")
            if not _DOMAIN_FORM.match(value):
                raise RulingsError(n, "domain: needs a bare domain such as "
                                   "'agency.example', found %r" % value)
        if cls == "literal" and len(value) < LITERAL_MIN:
            raise RulingsError(n, "literal: needs at least %d characters, found %d"
                               % (LITERAL_MIN, len(value)))
        rows.append(Ruling(n, cls, value, verdict, reason, ruler, date))
    return rows


def ruling_pattern(rows):
    """Compiled excusal pattern for the EXEMPT rows, or None when there are none."""
    alts = []
    for r in rows:
        if r.verdict != "EXEMPT":
            continue
        if r.cls == "address":
            # The exact address, never its domain: the local part is spelled
            # out, and a leading lookbehind forbids a longer local part
            # ending in this one.
            alts.append(r"(?<![A-Za-z0-9._%+-])(?i:" + re.escape(r.value) + r")" + _TAIL)
        elif r.cls == "domain":
            alts.append(r"(?<![A-Za-z0-9._%+-])(?i:[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)*"
                        + re.escape(r.value) + r")" + _TAIL)
        elif r.cls == "literal":
            alts.append(re.escape(r.value))
    if not alts:
        return None
    return re.compile("|".join(alts))


_LOCAL = None          # compiled pattern of the active local rulings, or None
_LOCAL_ROWS = []


def set_rulings(rows):
    """Activate `rows` (from parse_rulings) for every caller in this process."""
    global _LOCAL, _LOCAL_ROWS
    _LOCAL_ROWS = list(rows)
    _LOCAL = ruling_pattern(_LOCAL_ROWS)


def active_rulings():
    return list(_LOCAL_ROWS)


def configure_rulings(path=None, environ=None):
    """Resolve, load and activate the local RULINGS file. Returns the rows.

    `path` (the --rulings argument) wins over the PII_RULINGS environment
    variable. Neither set: no local exemptions, which is the shipped state.
    A path that is SET but does not exist is an error, not an empty file: a
    mistyped path silently dropping every ruling is an unauditable state.
    Raises RulingsError (lineno 0 for a missing or unreadable file).
    """
    environ = os.environ if environ is None else environ
    path = path or environ.get(RULINGS_ENV) or None
    if not path:
        set_rulings([])
        return []
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as e:
        raise RulingsError(0, "cannot read %s (%s)" % (path, type(e).__name__))
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as e:
        line = raw[:e.start].count(b"\n") + 1
        raise RulingsError(line, "non-ASCII byte; RULINGS is a 7-bit ASCII file")
    rows = parse_rulings(text)
    set_rulings(rows)
    return rows


def _rulings_cli(path):
    """configure_rulings for a CLI main(): None on success, 2 on refusal."""
    try:
        configure_rulings(path)
    except RulingsError as e:
        sys.stderr.write("REFUSED: %s\n" % e)
        return 2
    return None


def benign_covers(text, start, end=None, window=None):
    """Does an exemption COVER position `start`? The ONE definition of the
    excusal test: coverage of the position that matters, never proximity. A
    role-field path that searched for an exemption anywhere in a window let an
    SSH URL on the previous line excuse a `Referees:` line -- a false NEGATIVE
    in the fail-closed module. pii_scrub delegates here.

    `window` gives the excusal an EXPLICIT span to look in, instead of the
    default 24-character lookback. That default is a distance, and a distance
    is the wrong shape for a rule about structure.

    It cost an ingest on the reference instance. A thread-archive signature
    block aligned its value with 22 spaces:

        Email:                      [address removed]

    The scrub had removed the address; the alternate that excuses its own
    placeholder needs to see the LABEL, and at 22 spaces the label sits outside
    a 24-character lookback taken from the value. So the gate reported a
    finding that was not there, could not be cleared by scrubbing again, and
    stopped the strand. A caller that knows the finding's own extent -- as
    ROLE_FIELD does -- passes it here and the excusal works at any
    label-to-value separation.
    """
    if window is not None:
        lo, hi = window
        lo = max(0, lo)
    else:
        lo = max(0, start - 24)
        hi = (end if end is not None else start) + 8
    ctx = text[lo:hi]
    off = start - lo
    pats = [NON_REFERRING, BENIGN]
    if _LOCAL is not None:
        pats.append(_LOCAL)
    return any(b.start() <= off < b.end() for p in pats for b in p.finditer(ctx))


def scan_text(text, path="<text>"):
    """[(kind, line, snippet, why)] -- every finding in one blob."""
    out = []
    for kind, pat, why in DETECTORS:
        for m in pat.finditer(text):
            if benign_covers(text, m.start(), m.end()):
                continue
            if kind == "secret_assignment" and secret_is_wrapped_plain_word(m.group(0)):
                continue
            out.append((kind, text[:m.start()].count("\n") + 1, m.group(0)[:80], why))
    for m in ROLE_FIELD.finditer(text):
        label = " ".join(m.group("label").lower().split())
        # Coverage is tested at the VALUE start, not the label: the scrub's
        # "[address removed]" placeholder sits at the value, and THAT is the
        # position an exemption must cover to excuse the line. Testing the
        # label position would re-flag every scrubbed line; testing mere
        # proximity excused real referee names. Bounded by the FIELD, not by a
        # character count: the label and its value belong to one match,
        # however much whitespace aligns them.
        if benign_covers(text, m.start("value"), m.end(), window=m.span()):
            continue
        if label in CONFIDENTIAL_ROLES:
            out.append(("role_field:" + label, text[:m.start()].count("\n") + 1,
                        "%s: %s" % (m.group("label"), m.group("value")[:60]),
                        "confidential role, named individual"))
    return out


def scan_extractable(path, ext):
    """Scan a binary container whose content is text (PDF, and anything added).

    A failure to extract is reported as a finding, not as a clean result: an
    unreadable file has not been cleared, and silently passing it is exactly the
    false negative this module refuses to make.
    """
    import subprocess
    cmd = [a.replace("{src}", path) for a in EXTRACTABLE[ext]]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=180)
    except (OSError, subprocess.SubprocessError) as e:
        return [("unscannable", 0, os.path.basename(path),
                 "could not extract text (%s); NOT cleared" % type(e).__name__)]
    if r.returncode != 0 and not r.stdout:
        return [("unscannable", 0, os.path.basename(path),
                 "extractor exited %d; NOT cleared" % r.returncode)]
    return scan_text(r.stdout.decode("utf-8", "replace"), path)


# HTML is scanned AS A READER SEES IT. On the reference instance a page carried
# an address with an entity-encoded "@" (&#64;), invisible to a byte-level
# regex, and the ingress scan passed it; a converter decoded it into the
# markdown and the egress sieve caught it -- the representational failure mode,
# two sieves reading different forms of one thing. Decoding entities before the
# scan makes the two forms one form. Only .html/.htm are decoded: a literal
# "&#64;" in a .txt or .py file is not an address a reader would decode.
HTML_EXT = {".html", ".htm"}


def scan_file(path, max_bytes=4 << 20):
    """[findings] for one file, by its kind (extractable / binary / text / html)."""
    ext = os.path.splitext(path)[1].lower()
    if ext in EXTRACTABLE:
        return scan_extractable(path, ext)
    if ext not in TEXT_EXT and os.path.getsize(path) > max_bytes:
        return []
    with open(path, "rb") as f:
        raw = f.read(max_bytes)
    if b"\0" in raw[:4096] and ext not in TEXT_EXT:
        # binary: only key material is meaningful, and it is ASCII
        hits = scan_text(raw.decode("latin-1", "replace"), path)
        return [h for h in hits if h[0] in ("private_key", "gitlab_token")]
    # NOT errors="replace". The scanner only READS, so a lossy decode cannot
    # destroy a finding -- but it can MISS one, and a missed finding is the
    # failure direction the procedure calls unrecoverable. Every byte the old
    # decode could not interpret became U+FFFD, which breaks any pattern that
    # spans it: an address or a home path with one high byte in it simply
    # stopped matching.
    text = text_decode.decode_document(raw)
    if ext in HTML_EXT:
        import html as _html
        text = _html.unescape(text)
    elif ext in (".json", ".jsonl"):
        # NEUTRALISE JSON ESCAPES BEFORE SCANNING, length-for-length.
        #
        # A JSON file stores a newline as the two characters `\` and `n`, and a
        # scanner reading it as TEXT glues that `n` onto whatever follows:
        # `\nuser@<host>:~$` scans with local part "nuser" instead of the
        # generic "user". pii_scrub does not have this problem because it
        # scrubs JSON by its DECODED values, so the two disagreed and the gate
        # could not clear.
        #
        # Replaced with the SAME NUMBER OF CHARACTERS so that every offset this
        # function reports still points where it did. Decoding the JSON properly
        # would renumber every line and every column in the report.
        text = re.sub(r"\\[nrt]", "  ", text)
    return scan_text(text, path)


def scan_path(root, max_bytes=4 << 20):
    """{relpath: [findings]} over a file or a tree."""
    found = {}
    targets = []
    if os.path.isfile(root):
        targets = [root]
        base = os.path.dirname(root) or "."
    else:
        base = root
        for r, ds, fs in os.walk(root):
            ds[:] = [d for d in ds if d not in (".git", "__pycache__")]
            targets += [os.path.join(r, f) for f in fs]
    for p in targets:
        try:
            hits = scan_file(p, max_bytes)
        except OSError:
            continue
        if hits:
            found[os.path.relpath(p, base)] = hits
    return found


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="file or directory")
    ap.add_argument("--gate", action="store_true",
                    help="exit 1 on ANY finding (use before ingestion)")
    ap.add_argument("--report", default=None, help="write findings as JSON")
    ap.add_argument("--rulings", default=None,
                    help="local RULINGS file (else $%s; absent = no local "
                         "exemptions)" % RULINGS_ENV)
    ap.add_argument("--max-examples", type=int, default=4)
    ap.add_argument("--version", action="version", version=TOOL_VERSION)
    args = ap.parse_args(argv)

    refused = _rulings_cli(args.rulings)
    if refused:
        return refused
    if not os.path.exists(args.target):
        sys.stderr.write("REFUSED: no such file or directory: %s\n" % args.target)
        return 2

    found = scan_path(args.target)
    kinds = collections.Counter(k for hits in found.values() for k, _l, _s, _w in hits)
    total = sum(len(v) for v in found.values())
    print("  scanned : %s" % args.target)
    print("  local rulings       : %d" % len(active_rulings()))
    print("  files with findings : %d" % len(found))
    print("  findings            : %d" % total)
    for k, n in kinds.most_common():
        print("    %-24s %d" % (k, n))
    shown = 0
    for rel, hits in sorted(found.items()):
        for k, ln, snip, _why in hits:
            if shown >= args.max_examples:
                break
            # never print the value itself -- the report is not the leak
            print("    %s:%d  %s  <%d chars redacted>" % (rel, ln, k, len(snip)))
            shown += 1
    if args.report:
        with open(args.report, "w", encoding="ascii", errors="replace") as f:
            json.dump({rel: [{"kind": k, "line": l, "why": w} for k, l, _s, w in v]
                       for rel, v in found.items()}, f,
                      ensure_ascii=True, sort_keys=True, indent=1)
        print("  report -> %s (values omitted by design)" % args.report)
    if args.gate and total:
        sys.stderr.write(
            "\nGATE FAILED: %d personal-data findings in %d files.\n"
            "This material must be scrubbed BEFORE any further processing.\n"
            "Standing rule (PROCEDURE.md): strip all PII as the first pass over\n"
            "anything new. A false positive costs thirty seconds; a false\n"
            "negative cannot be recalled once embedded.\n" % (total, len(found)))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
