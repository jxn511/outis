#!/usr/bin/env python3
"""redact_names.py -- redact LISTED personal names, line-preserving, never in code.

Carried into Outis from redact_pass5.py 1.0 (a name-redaction pass built for
one corpus snapshot and its record trees) at its final form; only its names
changed. `outis.py clean` drives it with --root over a staged copy. The
snapshot/agents vocabulary below, the manifest columns (sha256_pass4 /
sha256_pass5) and the --agents / --check-records / --manifest-diff modes are
the tool as it was built; a tree given as --root is any tree.

Replaces each occurrence of a LISTED name token by the literal token <name>
(the convention of the earlier passes), one <name> per listed token, and only
where the occurrence is in COMMENT context (by the file type's own comment
syntax) or on a NAME-ONLY / ATTRIBUTION-IDIOM line of a prose-type file.
An occurrence in code is never replaced; it is counted in the ledger as a
"code occurrence, left" with file and line.

Everything the run depends on arrives at run time:

    --names FILE          one name per line, '#' comments; each whitespace-
                          separated word of a line is one listed token
                          (whole-word, case-insensitive)
    --root DIR            a snapshot tree
    --agents DIR          record .jsonl and DOC .md files
    --ledger FILE         one JSON row per changed line and per code
                          occurrence left, and a totals row; never a token
    --manifest-out FILE   the ONE pass-5 manifest (SNAPSHOT_MANIFEST_pass5.csv):
                          path,sha256_pass4,sha256_pass5,change
    --readme-out FILE     a README paragraph for the operator to append
    --apply               write; the default is a dry run that leaves every
                          tree byte-identical and writes only the ledger

Two helper modes (P9, P11), each alone on the command line:

    --check-records SNAPSHOT RECORDS
                          count fix items' old strings and quoted source
                          lines in RECORDS (.jsonl/.json, file or tree) NOT
                          found verbatim in SNAPSHOT; exit 0 only at 0
    --manifest-diff OLD NEW [--ledger FILE]
                          member diff of two manifests and, with --ledger,
                          the equality verdict against its changed files

Guarantees, each checked before anything is written (a failure refuses the
whole run, exit 2, nothing written):

  * line-preserving and in place: every changed line differs from its old
    form only at the replaced spans; the line count of every file is equal;
    the bytes are re-encoded with the codec they were decoded with (UTF-8
    when the file is valid UTF-8, else latin-1, both exact round trips);
  * parser neutrality: for every changed .dec/.DEC/.pdl/.table file the
    '#'-comment-stripped, whitespace-collapsed content is equal before and
    after; the refusal names the file;
  * JSON records: a .jsonl line is touched only if it is EXACTLY the
    ensure_ascii, sort_keys serialisation of itself (either default or
    compact separators); replacement happens only inside string VALUES and
    the result must re-serialise to itself; any other record is refused
    (left unchanged, counted, and its eligible tokens count as residue).

After --apply the trees are re-scanned with the same names and rules; the
residue (eligible occurrences still present) is reported and the exit status
is 0 only when the residue is 0.

Exit status (the repo convention): 0 success; 1 ran with degradation (a
refused record, residue, a listed token in a file path); 2 could not run.

Python 3 standard library only.
"""

import argparse
import csv
import datetime
import difflib
import hashlib
import json
import os
import re
import stat
import sys

TOOL_VERSION = "redact_names.py 0.2.0 (redact_pass5.py 1.0)"
PLACEHOLDER = "<name>"
MIN_TOKEN_LEN = 2

# The pass-5 manifest: ONE file in the latest (pass-4) form, ruled
# 2026-11-17 from the real inputs: snapshot-relative path, the checksum
# before this pass (sha256_pass4), after it (sha256_pass5), and the change.
MANIFEST_COLUMNS = ("path", "sha256_pass4", "sha256_pass5", "change")


# ---------------------------------------------------------------------------
# File-type families. ENUMERATED, never shape-matched.
#
#   hash     '#' to end of line. EvtGen .dec/.DEC and .pdl have NO quoted
#            strings: the EvtGen decay-file and particle-list parsers read
#            whitespace-separated tokens and drop everything after '#'. So a
#            '#' anywhere starts a comment and no quote state is tracked.
#            .table (pdt.table) is a data table with the same '#' rule.
#   tcl      '#' starts a comment only at the start of a command (first
#            non-blank of the line, or after ';'), outside a double-quoted
#            word -- Tcl's own rule, narrowed to one line.
#   c        '//' to end of line (with backslash continuation) and /* */
#            across lines; string, character and raw-string literals are
#            code, so a '//' inside "http://..." is NOT a comment.
#   texthash .txt free text: '#' outside a double-quoted run on the line.
#   jsonl    records; see analyse_jsonl.
#   shellish (beyond the contract's list) code-bearing types whose comment is
#            '#' at a word start outside single/double quotes: shell, perl,
#            python, make, cmake. Without this family they would fall into
#            'text', where an attribution-idiom line is replaced WHOLE --
#            and `author = "X"` in a script is code. "Never code" outranks.
#   fortran  (beyond the contract's list) fixed-form column-1 C/c/*/! and an
#            inline '!' outside quotes. EvtGen ships Fortran.
#   text     everything else (README, .md, .csv, no extension): no comment
#            syntax; only whole name-only / attribution-idiom lines.
#
# In every CODE-BEARING family (hash, tcl, c, shellish, fortran) only comment
# spans are eligible. The "(b) name-only / attribution line" rule applies to
# the PROSE families (texthash, text) and inside JSON string values, because
# in a code-bearing type the part of a line outside its comment is code by
# that type's syntax, and the contract's first rule is never code.
# ---------------------------------------------------------------------------
FAM_HASH = "hash"
FAM_TCL = "tcl"
FAM_C = "c"
FAM_TEXTHASH = "texthash"
FAM_JSONL = "jsonl"
FAM_SHELLISH = "shellish"
FAM_FORTRAN = "fortran"
FAM_TEXT = "text"
FAM_PROSE = "prose"

EXT_FAMILY = {
    ".dec": FAM_HASH, ".pdl": FAM_HASH, ".table": FAM_HASH,
    ".tcl": FAM_TCL,
    ".cc": FAM_C, ".hh": FAM_C, ".h": FAM_C, ".icc": FAM_C,
    # P13 (ruled 2026-11-17): prose types have no code to protect; EVERY
    # listed-token occurrence in them is replaced.
    ".txt": FAM_PROSE, ".md": FAM_PROSE, ".history": FAM_PROSE, ".log": FAM_PROSE,
    ".csv": FAM_PROSE, ".lst": FAM_PROSE, ".listing": FAM_PROSE,
    ".jsonl": FAM_JSONL,
    # beyond the contract's enumeration (see above)
    ".c": FAM_C, ".cpp": FAM_C, ".cxx": FAM_C, ".hpp": FAM_C, ".hxx": FAM_C,
    ".sh": FAM_SHELLISH, ".csh": FAM_SHELLISH, ".tcsh": FAM_SHELLISH,
    ".bash": FAM_SHELLISH, ".ksh": FAM_SHELLISH, ".zsh": FAM_SHELLISH,
    ".pl": FAM_SHELLISH, ".pm": FAM_SHELLISH, ".py": FAM_SHELLISH,
    ".mk": FAM_SHELLISH, ".cmake": FAM_SHELLISH,
    ".f": FAM_FORTRAN, ".for": FAM_FORTRAN, ".f77": FAM_FORTRAN,
    ".f90": FAM_FORTRAN,
}
# Case-sensitive exceptions: .C is C++, .F is Fortran with cpp.
EXT_FAMILY_EXACT = {".C": FAM_C, ".F": FAM_FORTRAN}
BASENAME_FAMILY = {"GNUmakefile": FAM_SHELLISH, "Makefile": FAM_SHELLISH,
                   "makefile": FAM_SHELLISH}
CODE_FAMILIES = {FAM_HASH, FAM_TCL, FAM_C, FAM_SHELLISH, FAM_FORTRAN}
NEUTRALITY_EXTS = {".dec", ".pdl", ".table"}   # compared lower-cased


class Refuse(Exception):
    """The run cannot proceed; nothing is (or has been) written to a tree."""


# ---------------------------------------------------------------------------
# The names
# ---------------------------------------------------------------------------
_WORDRUN = re.compile(r"\w+")


def _fold(s):
    """casefold, plus the dotted/dotless i pair, which re.IGNORECASE treats
    as equal and str.casefold does not -- so the pre-filter can never reject
    a text the regex would match."""
    return s.casefold().replace("\u0131", "i").replace("i\u0307", "i")


# Enumerated name particles (P19/P24): ambiguous by construction.
NAME_PARTICLES = frozenset(
    "de da di do du del della der den des dos das van von ter ten la le lo al el "
    "bin ibn ben mac mc st".split())


class NameList(object):
    """The listed tokens and one compiled whole-word, case-insensitive matcher."""

    def __init__(self, entries, stats):
        self.stats = stats
        self.line_of = {}            # casefolded variant -> names-file line
        self.tokens = [tok for _ln, tok in entries]
        self.token_of_key = {}       # casefolded variant -> casefolded token
        self.member_of_token = {}    # casefolded token -> unambiguous / ambiguous / identifier
        variants = []
        for lineno, tok in entries:
            forms = [tok]
            # A UTF-8 file decoded as latin-1 (because it was not valid UTF-8
            # as a whole) shows a non-ASCII name as its UTF-8 bytes; match
            # that form too. Identical to tok for an ASCII token.
            moj = tok.encode("utf-8").decode("latin-1")
            if moj != tok:
                forms.append(moj)
            for f in forms:
                key = f.casefold()
                if key not in self.line_of:
                    self.line_of[key] = lineno
                    self.token_of_key[key] = tok.casefold()
                    variants.append(f)
        variants.sort(key=lambda v: (-len(v), v))
        # A cheap pre-filter (measured: the alternation regex over ~1,100
        # tokens runs at ~1.7 MB/s; a word-set probe is an order faster).
        # A token can only match where its first word-run occurs as a whole
        # word-run of the text, so a text containing none of those runs has
        # no match. The regex below stays the single definition of a match.
        self.keys = set()
        for v in variants:
            run = re.match(r"\w+", v)
            self.keys.add(_fold(run.group(0)) if run else "")
        self.keyless = "" in self.keys
        # Whole word: no word character (Unicode \w: letters, digits, '_')
        # on either side. "Abc" never matches inside "Abcson" nor inside
        # "Abc_count"; it does match in "Abc's" and "Abc-Xyz".
        self.rx = re.compile(r"(?<!\w)(?:%s)(?!\w)"
                             % "|".join(re.escape(v) for v in variants),
                             re.IGNORECASE)
        self.variants = variants
        self.rx_main, self.rx_amb = self.rx, None
        self._compile_mask()

    def _compile_mask(self):
        """P33: the OUTPUT form of the matcher -- what the sample, the ledger
        and the report mask, and what the post-write guard refuses on. The
        hyphen exemption governs replacement in the corpus only: in the
        outputs an UNAMBIGUOUS or IDENTIFIER token is found as a SUBSTRING
        (no word boundary: "Ali-<tok>", "<tok>/<tok>", "<tok>99",
        "<tok>_count"), and an AMBIGUOUS token wherever no LETTER adjoins it
        ("re-derivations", "max(" -- but not "there")."""
        # a token of three characters or fewer takes the letter-boundary form
        # whatever its class (an unambiguous token is longer by definition;
        # a two-letter token as a substring would mask "dec" in every path)
        amb = [v for v in self.variants
               if self.member_of_token.get(self.token_of_key[v.casefold()]) == "ambiguous"
               or len(v) <= 3]
        rest = [v for v in self.variants if v not in set(amb)]
        alt = lambda vs: "|".join(re.escape(v) for v in vs)
        self.rx_mask_sub = re.compile("(?:%s)" % alt(rest), re.IGNORECASE) if rest else None
        self.rx_mask_amb = (re.compile(r"(?<![^\W\d_])(?:%s)(?![^\W\d_])" % alt(amb),
                                       re.IGNORECASE) if amb else None)

    def find_mask(self, text):
        """P33: [(start, end)] of listed tokens in the OUTPUT form, skipping
        any inside an existing <name> placeholder; non-overlapping."""
        ph, k = [], text.find(PLACEHOLDER)
        while k >= 0:
            ph.append((k, k + len(PLACEHOLDER)))
            k = text.find(PLACEHOLDER, k + 1)
        spans = []
        for rx in (self.rx_mask_sub, self.rx_mask_amb):
            if rx is not None:
                spans.extend(m.span() for m in rx.finditer(text))
        spans.sort(key=lambda se: (se[0], -se[1]))
        out, last = [], -1
        for s, e in spans:
            if s < last or any(s < pe and ps < e for ps, pe in ph):
                continue
            out.append((s, e))
            last = e
        return out

    def find_mask_unambiguous(self, text):
        return [(s, e) for s, e in self.find_mask(text)
                if self.member(text[s:e]) == "unambiguous"]

    def _compile_find(self):
        """P19/P24: two matchers. UNAMBIGUOUS tokens keep the whole-word rule
        above. AMBIGUOUS and IDENTIFIER tokens (dictionary words, three
        letters or fewer, particles; name-like tokens with a code
        occurrence) also treat '-' as part of a word on either side, so they
        never match inside a hyphenated compound ("re-derivations",
        "re-pin", "RE-CHECK")."""
        amb = [v for v in self.variants
               if self.member_of_token.get(self.token_of_key[v.casefold()])
               in ("ambiguous", "identifier")]
        main = [v for v in self.variants if v not in set(amb)]
        alt = lambda vs: "|".join(re.escape(v) for v in vs)
        self.rx_main = (re.compile(r"(?<!\w)(?:%s)(?!\w)" % alt(main), re.IGNORECASE)
                        if main else None)
        self.rx_amb = (re.compile(r"(?<![\w-])(?:%s)(?![\w-])" % alt(amb), re.IGNORECASE)
                       if amb else None)
        self._compile_mask()

    @classmethod
    def load(cls, path, allow_empty=False):
        if not path or not os.path.isfile(path):
            raise Refuse("names file missing (--names); refusing before any read of a tree")
        with open(path, "rb") as f:
            raw = f.read()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise Refuse("names file is not UTF-8; refusing before any read of a tree")
        entries, seen = [], set()
        stats = {"names_lines": 0, "tokens_listed": 0, "tokens_dropped_short": 0,
                 "tokens_duplicate": 0}
        for i, line in enumerate(text.split("\n"), 1):
            body = line.split("#", 1)[0].strip()
            if not body:
                continue
            stats["names_lines"] += 1
            for word in body.split():
                tok = word.strip(".,;:()[]\"")
                if len(tok) < MIN_TOKEN_LEN:
                    # An initial ("J.") as a whole-word token would replace
                    # every lone letter in every comment. Counted, never used.
                    stats["tokens_dropped_short"] += 1
                    continue
                key = tok.casefold()
                if key in seen:
                    stats["tokens_duplicate"] += 1
                    continue
                seen.add(key)
                entries.append((i, tok))
        stats["tokens_listed"] = len(entries)
        if not entries and allow_empty:
            return entries
        if not entries:
            raise Refuse("names file has no usable token (empty after comments); "
                         "refusing before any read of a tree")
        return cls(entries, stats)

    def set_membership(self, unamb_path, amb_path, ident_path, root=None, dictionary=None):
        """P19: three run-time lists partition --names: UNAMBIGUOUS (not a
        dictionary word, longer than three letters, not a particle; the
        merge gate's list -- P15's 'gate' class), AMBIGUOUS (dictionary
        words, three letters or fewer, particles) and IDENTIFIER (also a
        code identifier). Given at all, all three are required and must
        partition --names exactly; every mismatch refuses, by count. With
        none, every token is unambiguous (the pre-P19 behaviour, stated in
        the report)."""
        paths = (("unambiguous", unamb_path), ("ambiguous", amb_path),
                 ("identifier", ident_path))
        given = [cls for cls, p in paths if p]
        if not given:
            self._auto_partition(root, dictionary)
        else:
            if len(given) != 3:
                raise Refuse("P19: --unambiguous-names, --ambiguous-names and --identifier-names "
                             "are given together (%d of 3 given)" % len(given))
            listed = set(k.casefold() for k in self.tokens)
            sets = {}
            for cls, path in paths:
                sub = NameList.load(path, allow_empty=True)
                toks = [t for _l, t in sub] if isinstance(sub, list) else sub.tokens
                extra = [t for t in toks if t.casefold() not in listed]
                if extra:
                    raise Refuse("%d token(s) of the %s membership file are not in --names"
                                 % (len(extra), cls))
                sets[cls] = set(t.casefold() for t in toks)
            for a, b in (("unambiguous", "ambiguous"), ("unambiguous", "identifier"),
                         ("ambiguous", "identifier")):
                if sets[a] & sets[b]:
                    raise Refuse("%d token(s) are in both the %s and the %s membership files"
                                 % (len(sets[a] & sets[b]), a, b))
            missing = len(listed - sets["unambiguous"] - sets["ambiguous"] - sets["identifier"])
            if missing:
                raise Refuse("%d token(s) of --names are in no membership file" % missing)
            for tok in self.tokens:
                k = tok.casefold()
                self.member_of_token[k] = next(c for c in sets if k in sets[c])
            self.stats["membership_source"] = "files"
        for cls in ("unambiguous", "ambiguous", "identifier"):
            self.stats["membership_%s_tokens" % cls] = sum(
                1 for v in self.member_of_token.values() if v == cls)
        self._compile_find()

    def _auto_partition(self, root, dictionary):
        """P24: the tool's own partition when no membership files are given,
        with the supplied lists' precedence: AMBIGUOUS first (three letters
        or fewer, an enumerated name particle, a --dictionary word), then
        IDENTIFIER (an occurrence in CODE context in a --root source file),
        then UNAMBIGUOUS."""
        words = set()
        if dictionary:
            if not os.path.isfile(dictionary):
                raise Refuse("--dictionary file missing")
            with open(dictionary, "rb") as f:
                words = set(w.strip().casefold() for w in
                            f.read().decode("utf-8", "replace").split() if w.strip())
        code = scan_code_tokens(root, self) if root else set()
        lines = {"ambiguous": [], "identifier": [], "unambiguous": []}
        for tok in self.tokens:
            k = tok.casefold()
            if len(tok) <= 3 or k in NAME_PARTICLES or k in words:
                cls = "ambiguous"
            elif k in code:
                cls = "identifier"
            else:
                cls = "unambiguous"
            self.member_of_token[k] = cls
            lines[cls].append(self.line_of[k])
        self.stats["membership_source"] = (
            "auto: ambiguous = three letters or fewer, a particle%s; identifier = a code "
            "occurrence in --root source; the rest unambiguous"
            % (", a --dictionary word" if dictionary else ""))
        # names-file line numbers per class (never the tokens), for the reader
        self.stats["auto_partition_names_lines"] = {c: sorted(v) for c, v in lines.items()}

    def member(self, matched):
        """'unambiguous', 'ambiguous' or 'identifier' for a matched occurrence
        (never the token)."""
        k = self.token_of_key.get(matched.casefold())
        if k is None:
            for key, tk in self.token_of_key.items():
                if re.fullmatch(re.escape(key), matched, re.IGNORECASE):
                    k = tk
                    break
        return self.member_of_token.get(k, "unambiguous")

    def find(self, text):
        """[(start, end, names_line)] of listed tokens, skipping any inside an
        existing <name> placeholder (so a listed token 'name' cannot recur)."""
        if not self.keyless and self.keys.isdisjoint(_WORDRUN.findall(_fold(text))):
            return []
        ph, k = [], text.find(PLACEHOLDER)
        while k >= 0:
            ph.append((k, k + len(PLACEHOLDER)))
            k = text.find(PLACEHOLDER, k + 1)
        spans = []
        for rx in (self.rx_main, self.rx_amb):
            if rx is not None:
                spans.extend(m.span() for m in rx.finditer(text))
        spans.sort(key=lambda se: (se[0], -se[1]))
        out, last = [], -1
        for s, e in spans:
            if s < last or any(s < pe and ps < e for ps, pe in ph):
                continue
            out.append((s, e, self.names_line(text[s:e])))
            last = e
        return out

    def names_line(self, matched):
        ln = self.line_of.get(matched.casefold())
        if ln is not None:
            return ln
        for key, ln in self.line_of.items():
            if re.fullmatch(re.escape(key), matched, re.IGNORECASE):
                return ln
        return 0

    def find_unambiguous(self, text):
        return [m for m in self.find(text)
                if self.member(text[m[0]:m[1]]) == "unambiguous"]

    def guard_text(self, text, what, corpus=False, field="text"):
        """P23: refuse to emit `what` if `text` carries an UNAMBIGUOUS token,
        or -- only when `corpus` (a value that can carry corpus text, such as
        a sample line body) -- an ambiguous or identifier token. The tool's
        own labels, kinds, reasons, headers and names-file line numbers are
        written with corpus=False: an ordinary word on the ambiguous list
        must not trip them. The refusal names the field and the token class,
        never the token."""
        for s, e in self.find_mask(text):     # P33: the output form
            cls = self.member(text[s:e])
            if cls == "unambiguous" or corpus:
                raise Refuse("%s would carry a listed token (class %s) in field %s; "
                             "nothing written" % (what, cls, field))

    def guard_rows(self, rows, what):
        """P23 over JSON rows: every string key and value is checked for an
        UNAMBIGUOUS token (the ledger carries no corpus text: its paths are
        masked for unambiguous tokens by display_path, and the rest are the
        tool's own labels). The field named is the row's top-level key."""
        def walk(v, field):
            if isinstance(v, dict):
                for k, x in v.items():
                    self.guard_text(str(k), what, False, field)
                    walk(x, field)
            elif isinstance(v, list):
                for x in v:
                    walk(x, field)
            elif isinstance(v, str):
                self.guard_text(v, what, False, field)
        for row in rows:
            for k, v in row.items():
                self.guard_text(str(k), what, False, k)
                walk(v, k)


# ---------------------------------------------------------------------------
# Comment spans by family. Each returns [(start, end)] within the line.
# ---------------------------------------------------------------------------
def hash_comment_spans(line):
    """.dec/.DEC/.pdl/.table: '#' to end of line. No quoted strings exist in
    these formats, so no quote state is tracked."""
    i = line.find("#")
    return [(i, len(line))] if i >= 0 else []


def texthash_comment_spans(line):
    """.txt: '#' outside a double-quoted run on the same line."""
    inq = False
    for i, ch in enumerate(line):
        if ch == '"':
            inq = not inq
        elif ch == "#" and not inq:
            return [(i, len(line))]
    return []


def tcl_comment_spans(line):
    """Tcl: '#' is a comment only at the start of a command."""
    n, i, inq, at_start = len(line), 0, False, True
    while i < n:
        ch = line[i]
        if inq:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                inq = False
            i += 1
            continue
        if ch in " \t\r\f\v":
            i += 1
            continue
        if at_start and ch == "#":
            return [(i, n)]
        at_start = False
        if ch == "\\":
            i += 2
            continue
        if ch == '"':
            inq = True
        elif ch == ";":
            at_start = True
        i += 1
    return []


def shellish_comment_spans(line):
    """shell/perl/python/make: '#' at a word start, outside quotes."""
    q = None
    n = len(line)
    i = 0
    while i < n:
        ch = line[i]
        if q:
            if ch == "\\" and q == '"':
                i += 2
                continue
            if ch == q:
                q = None
            i += 1
            continue
        if ch == "\\":
            i += 2
            continue
        if ch in "\"'":
            q = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t;"):
            return [(i, n)]
        i += 1
    return []


def fortran_comment_spans(line):
    """Fortran: a column-1 C/c/*/! line is a comment; '!' outside quotes
    starts an inline comment."""
    if line[:1] in ("C", "c", "*", "!"):
        return [(0, len(line))]
    q = None
    for i, ch in enumerate(line):
        if q:
            if ch == q:
                q = None
        elif ch in "\"'":
            q = ch
        elif ch == "!":
            return [(i, len(line))]
    return []


_RAW_OPEN = re.compile(r'"([^()\\\s"]{0,16})\(')


def c_comment_spans(lines):
    """C/C++ across lines: [[(start, end)] per line]."""
    result = []
    mode, quote, raw_end = "code", None, None
    for line in lines:
        n = len(line)
        core = line[:-1] if line.endswith("\r") else line
        cont = core.endswith("\\")
        spans = []
        i = 0
        while True:
            if mode == "block":
                j = line.find("*/", i)
                if j < 0:
                    spans.append((i, n))
                    break
                spans.append((i, j + 2))
                i, mode = j + 2, "code"
                continue
            if mode == "linecomment":           # a '//' comment continued by '\'
                spans.append((i, n))
                mode = "linecomment" if cont else "code"
                break
            if mode == "string":
                j, closed = i, False
                while j < n:
                    c = line[j]
                    if c == "\\":
                        j += 2
                        continue
                    if c == quote:
                        closed = True
                        j += 1
                        break
                    j += 1
                if closed:
                    i, mode = j, "code"
                    continue
                mode = "string" if cont else "code"
                break
            if mode == "raw":
                j = line.find(raw_end, i)
                if j < 0:
                    break
                i, mode = j + len(raw_end), "code"
                continue
            # code
            if i >= n:
                break
            c = line[i]
            if c == "/" and line.startswith("//", i):
                spans.append((i, n))
                mode = "linecomment" if cont else "code"
                break
            if c == "/" and line.startswith("/*", i):
                j = line.find("*/", i + 2)
                if j < 0:
                    spans.append((i, n))
                    mode = "block"
                    break
                spans.append((i, j + 2))
                i = j + 2
                continue
            if c == '"':
                if i >= 1 and line[i - 1] == "R":
                    m = _RAW_OPEN.match(line, i)
                    if m:
                        raw_end = ")" + m.group(1) + '"'
                        i, mode = m.end(), "raw"
                        continue
                i, mode, quote = i + 1, "string", '"'
                continue
            if c == "'":
                # C++14 digit separator (1'000): not a character literal
                if i >= 1 and line[i - 1].isalnum() and line[i + 1:i + 2].isalnum():
                    i += 1
                    continue
                i, mode, quote = i + 1, "string", "'"
                continue
            i += 1
        result.append([(s, e) for s, e in spans if e > s])
    return result


def generic_comment_start(eline):
    """Inside a JSON string value: where a QUOTED comment begins, or None."""
    st = eline.lstrip()
    if st.startswith("*"):
        return len(eline) - len(st)
    best = None
    for lead in ("#", "//", "/*"):
        k = eline.find(lead)
        if k >= 0 and (best is None or k < best):
            best = k
    return best


# ---------------------------------------------------------------------------
# The attribution / name-only rule (context class b)
# ---------------------------------------------------------------------------
_MON = r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?"
DATE = re.compile(
    r"(?<!\d)(?:"
    r"(?:19|20)\d\d[-/.](?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\d|3[01])"        # 2004-05-12
    r"|(?:0?[1-9]|[12]\d|3[01])[-/.](?:0?[1-9]|1[0-2])[-/.](?:19|20)?\d\d"      # 12/05/2004
    r"|(?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\d|3[01])[-/.](?:19|20)?\d\d"      # 4/28/00 (P25)
    r"|\d\d[-/.](?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\d|3[01])"                 # 00-02-10 (P25)
    r"|\d{1,2}/\d{1,2}/\d{2,4}"                                                   # 4/38/00 (P29)
    r"|(?:0?[1-9]|[12]\d|3[01])[-/. ]" + _MON + r"[-/. ,]*(?:19|20)?\d\d"     # 6 sep 00 (P30)
    r"|" + _MON + r"\s*(?:(?:0?[1-9]|[12]\d|3[01]),?\s*)?(?:19|20)\d\d"        # Nov 14, 2004; Aug19,2002
    r")(?!\d)", re.IGNORECASE)
OLD_PLACEHOLDERS = re.compile(r"<[a-z ]+>|\[[a-z ]*redacted\]", re.IGNORECASE)
NAME_CONNECTORS = {"and", "et", "al", "jr", "sr", "von", "van", "de", "der", "den",
                   "la", "le", "di", "da", "du", "del"}
_SENT = "\x00"


GROUP_LABEL = re.compile(r"\(\s*[A-Z0-9][A-Z0-9 /&.+-]*\)")


def is_name_only(line, matches):
    """Every word is a listed token, an initial, a connector, an earlier
    placeholder or a date -- plus at most as many unlisted Capitalised words
    as listed ones (a given name not on the list) -- and six words at most."""
    chars = list(line)
    for s, e, _ in reversed(matches):
        chars[s:e] = [_SENT]
    masked = "".join(chars)
    masked = OLD_PLACEHOLDERS.sub(" ", masked)
    masked = DATE.sub(" ", masked)
    # P30(a): a parenthesised group label ("(IHB AWG)") is part of a name line
    masked = GROUP_LABEL.sub(" ", masked)
    masked = re.sub(r"^[\s#/*!;%>-]*", "", masked)
    n_tok = n_cap = 0
    for w in re.split(r"[\s,;&()\[\]/-]+", masked):
        w = w.strip(".:'\"`")
        if not w:
            continue
        if w.startswith(_SENT):
            if w.strip(_SENT + "'s") == "":
                n_tok += w.count(_SENT)
                continue
            return False
        if re.fullmatch(r"(?:[A-Z]\.?){1,3}", w):
            continue
        if w.lower() in NAME_CONNECTORS:
            continue
        if (re.fullmatch(r"[^\W\d_][^\W\d_'.]*", w) and w[0].isupper()
                and not (len(w) > 1 and w.isupper())):
            # an unlisted ALL-CAPS word is a heading or a rule name
            # ("DE MINIMIS"), not a given name
            n_cap += 1
            continue
        return False
    return n_tok >= 1 and n_cap <= n_tok and n_tok + n_cap <= 6


ATTR_MAX_WORDS = 12          # P24: an attribution line is SHORT
_LEAD = re.compile(r"^[\s#/*!;%>-]*")
ATTR_START = re.compile(
    r"(?:\$(?:Id|Header|Author|Log|Revision|Date|Source|RCSfile|Locker|State)\b"
    r"|\(c\)"
    r"|(?:co-?)?authors?\b|authored\b|revisers?\b|revised\b|created\b|creator\b"
    r"|modified\b|modifications?\b|contacts?\b|maintainers?\b|maintained\b|written\b"
    r"|rewritten\b|contributors?\b|contributed\b|copyright\b"
    r"|(?:\S+\s+){0,2}by\b)", re.IGNORECASE)


BY_TOKEN = re.compile(
    r"(?<!\w)by[\s:]+(?:(?:[A-Za-z]\.-?\s*)|(?:(?:dr|prof|mr|ms|mrs)\.?\s+)|(?:<name>\s*))*$",
    re.IGNORECASE)


CITATIONS = False             # P27: --citations-published
# P30(d): "Phy" as well as "Phys", dots and spaces optional ("Phy Rev D",
# "Phys Rev", "Phys. Rev.", "Phys Lett", "Nucl Phys", "Z Phys")
_JOURNAL = (r"(?:Phys?\.?\s*Rev\.?\s*(?:Lett\.?|[A-E](?![a-z]))|Phys?\.?\s*Lett\.?\s*[AB]?"
            r"|Nucl\.?\s*Phys?\.?\s*[AB]?|Eur\.?\s*Phys?\.?\s*J\.?\s*[AC]?|Z\.?\s*Phys?\.?\s*[AC]?"
            r"|JHEP|J\.?\s*Phys\.?\s*G|Prog\.?\s*Theor\.?\s*(?:Exp\.?\s*)?Phys\.?|PTEP"
            r"|Comput\.?\s*Phys\.?\s*Commun\.?|Rev\.?\s*Mod\.?\s*Phys\.?|Chin\.?\s*Phys\.?\s*C"
            r"|Nucl\.?\s*Instrum\.?\s*Meth\.?\s*[AB]?|PRL|PRD|PLB|NPB|EPJC)")
# P27: a line carrying a citation -- a journal name with a volume, "et al",
# an arXiv or old-style archive identifier. Enumerated journals, never a
# shape: "Physics was fun in 2004" is no citation.
CITATION = re.compile(
    r"(?<!\w)" + _JOURNAL + r"\s*,?\s*\d+"
    r"|(?<!\w)et\s+al\b"
    r"|(?i:arxiv)\s*:\s*\d{4}\.\d{4,5}"
    r"|(?<![\w-])(?:hep-(?:ph|ex|th|lat)|nucl-(?:ex|th)|astro-ph|physics)/\d{7}")
# P26: a soft token right after "by " / "from ", or in possessive form, in
# comment or prose context is attribution context
# P31(a): "thanks to" and "courtesy of" anchor like "by" and "from"
_FORM_BEFORE = re.compile(r"(?<!\w)(by|from|thanks\s+to|courtesy\s+of)\s+$", re.IGNORECASE)
FORM_CTX = {"possessive": "o", "by": "y", "from": "m", "thanks to": "t", "courtesy of": "c"}
CTX_FORM = {v: k for k, v in FORM_CTX.items()}


def soft_form(line, s, e):
    """'possessive', 'by', 'from' or None for the occurrence line[s:e]."""
    if re.match(r"'s(?!\w)", line[e:e + 3], re.IGNORECASE):
        return "possessive"
    m = _FORM_BEFORE.search(line[:s])
    return " ".join(m.group(1).lower().split()) if m else None


# P28(a): listed tokens joined by these form one RUN of names
RUN_SEP = re.compile(r"\s*(?:,\s*(?:(?:and|&)\s+)?|&|/|and)\s*", re.IGNORECASE)


def anchored_forms(line, matches):
    """P28(a): {(s, e): form} -- an anchor ("by ", "from " before the run's
    first token, or a possessive on any of its tokens) carries the
    attribution context over the whole RUN of listed tokens joined by
    commas, "and", "&" or "/" ("from <A>,<B>,<C> and <D>", "<A> & <B>'s")."""
    runs, cur = [], []
    for m in sorted(matches):
        if cur and RUN_SEP.fullmatch(line[cur[-1][1]:m[0]]):
            cur.append(m)
        else:
            if cur:
                runs.append(cur)
            cur = [m]
    if cur:
        runs.append(cur)
    out = {}
    for run in runs:
        forms = [soft_form(line, s, e) for s, e, _ in run]
        if "possessive" in forms:
            form = "possessive"
        else:
            m = _FORM_BEFORE.search(line[:run[0][0]])
            form = " ".join(m.group(1).lower().split()) if m else None
        if form:
            for s, e, _ in run:
                out[(s, e)] = form
    return out


# P28(b): what may stand between the names of a citation group and between
# the group and its citation pattern: separators, "and", initials
CIT_GAP = re.compile(r"[\s,;&/]*(?:(?:and|[A-Z]\.(?:-?[A-Z]\.)*)[\s,;&/]*)*")
CITATION_WINDOW = 120


def citation_group(line, matches):
    """P28(b): the listed tokens of the CITATION GROUP(s) on a line -- the
    name run immediately before each citation pattern ("et al", a journal
    with a volume, an arXiv or archive identifier), within CITATION_WINDOW
    characters of it. Tokens elsewhere on the line are not in it."""
    out = set()
    ms = sorted(matches)
    for c in CITATION.finditer(line):
        edge = c.start()
        for s, e, _ln in reversed([m for m in ms if m[1] <= c.start()]):
            if c.start() - s > CITATION_WINDOW or not CIT_GAP.fullmatch(line[e:edge]):
                break
            out.add((s, e))
            edge = s
    return out


def _gap_words(gap):
    """Words (pieces with a letter or digit) in a gap of text."""
    return sum(1 for w in gap.split() if re.search(r"\w", w))


_LEAD_SEP = re.compile(r"\s+-\s+\S|\s*:\s*\S|\s*,\s*\S")


_INITIAL_BEFORE = re.compile(r"(?<![\w.])[A-Za-z]\.\s?$")
_URL_BEFORE = re.compile(r"(?:https?://)?[\w.-]+\.[A-Za-z]{2,}(?::\d+)?/(?:[^\s/]*/)*~$")
_CHANGELOG_TAG = re.compile(r"[Vv]?\d+(?:[-.]\d+)+\s+")
YEARLESS_DATE = re.compile(r"(?<![\d/])\d{1,2}/\d{1,2}(?![\d/])")


def soft_rule(seg, s, e, matches, is_comment):
    """P29: further attribution context for an AMBIGUOUS or IDENTIFIER token
    at seg[s:e] -> 'lead', 'date', 'subject' or None.
      lead    -- a run of listed tokens at the start of the comment/line (or
                 of a ';' clause) followed by " - ", ":" or "," and a remark
                 ("# <tok> - change eta ...", "STV; <tok>: model ...");
      date    -- on a SHORT line or inside a parenthesis, the token within
                 two words of a date, in either order
                 ("- <tok> July 19, 2002", "2004 <tok>", "(<tok>, July 26, 2000)");
      subject -- in a comment, the run opening the comment and followed by a
                 word: the sentence subject ("# <tok> intersperses ...").
    The caller replaces an IDENTIFIER subject and leaves (and counts) an
    AMBIGUOUS one."""
    # P31(c): a personal URL path ("host/~<tok>/") is attribution
    if _URL_BEFORE.search(seg[:s]) and (e == len(seg) or seg[e] in "/\"' \t)>"):
        return "url"
    # P31(b): an initial-dot-surname form ("g.<tok>", "J. <tok>")
    if _INITIAL_BEFORE.search(seg[:s]):
        return "initial"
    body = _LEAD.sub("", seg)
    off = len(seg) - len(body)
    ms = sorted((a, b) for a, b, _ in matches)
    # P31(d): the line's TEXT may begin after a changelog tag ("V00-04-72 ")
    tag = _CHANGELOG_TAG.match(seg, off)
    text_starts = [off] + ([tag.end()] if tag else [])
    # P30(c): a clause start is the comment body's start, a ";" clause, or a
    # second comment marker -- skipping any marker that follows
    starts = text_starts + [m.end() for m in
                            re.finditer(r"(?:;\s*|(?<!\S)#+\s*|//\s*)[#/*!%>\s-]*", seg)]
    for cst in starts:
        run, pos = [], cst
        for a, b in ms:
            if a < pos:
                continue
            if a == pos or (run and RUN_SEP.fullmatch(seg[pos:a])) or (run and seg[pos:a].isspace()):
                run.append((a, b))
                pos = b
            else:
                break
        if (s, e) in run:
            if _LEAD_SEP.match(seg, pos):
                return "lead"
            if is_comment and cst in text_starts and re.match(r"\s+\w", seg[pos:]):
                subject = True
                break
    else:
        subject = False
    short = len(body.split()) <= ATTR_MAX_WORDS
    in_paren = seg[:s].count("(") > seg[:s].count(")")
    if short or in_paren:
        # P31(b): a date without a year ("17/2") counts here too
        for d in list(DATE.finditer(seg)) + list(YEARLESS_DATE.finditer(seg)):
            if d.start() >= e:
                gap = seg[e:d.start()]
            elif d.end() <= s:
                gap = seg[d.end():s]
            else:
                continue
            if _gap_words(gap) <= 1:
                return "date"
    return "subject" if subject else None


def near_placeholder(line, s, e, spans):
    """P29: the token within two words of a redaction placeholder (an earlier
    pass's "[email redacted]", "[redacted]", "<name>", or a span this pass
    replaces on the same line)."""
    for ps, pe in spans:
        if ps >= e:
            gap = line[e:ps]
        elif pe <= s:
            gap = line[pe:s]
        else:
            continue
        if _gap_words(gap) <= 1:
            return True
    return False


RULE_CTX = {"lead": "l", "date": "d", "subject": "s", "placeholder": "r", "initial": "i",
            "url": "u"}
CTX_RULE = {v: k for k, v in RULE_CTX.items()}
NEAR_WHERE = ("comment", "prose", "json_string", "text", "subject")


OPENING_WORDS = 4             # P25
ATTR_KEYWORD = re.compile(
    r"(?<!\w)(?:(?:co-?)?authors?|authored|revisers?|revised|created|creator|modified"
    r"|modifications?|contacts?|maintainers?|maintained|written|rewritten|contributors?"
    r"|contributed|copyright)(?!\w)", re.IGNORECASE)


KEYWORD_START = re.compile(
    r"(?:(?:co-?)?authors?|authored|revisers?|revised|created|creator|modified"
    r"|maintainers?|maintained|contacts?|written|rewritten|contributors?|contributed)"
    r"(?!\w)\s*(?::|by\b)?", re.IGNORECASE)


def attribution_extent(line, matches):
    """-> None (not an attribution line), or the offset in `line` up to which
    soft-class tokens (ambiguous, identifier) take the attribution rule.

    P25 -- the OPENING form, whatever the line's length: within the first
    four words after the comment marker, a listed token followed by a date
    (2004-05-12, 4/28/00, 00-02-10, Nov 14, 2004, Aug19,2002, ...) or by an
    attribution keyword. The extent is the end of that date or keyword:
    tokens in the opening are replaced; the remark after it is prose (or
    comment) under the ordinary rules.

    P24(b), SHORT lines only (at most ATTR_MAX_WORDS whitespace tokens): the
    idiom at the start (a keyword, an RCS/CVS tag, a date, a by-line in the
    first three words), "by <Token>" anywhere, or a name-only line -- the
    whole line."""
    body = _LEAD.sub("", line)
    off = len(line) - len(body)
    # P30(a): a boxed header line is judged as its content -- the trailing
    # border run ("#", "*", "|", "/", with padding) is not part of it
    body = re.sub(r"[\s#*|/]+$", "", body)
    if not body:
        return None
    ms = sorted((s - off, e - off, ln) for s, e, ln in matches
                if s >= off and e - off <= len(body))
    if not ms:
        return None
    words = [m.span() for m in re.finditer(r"\S+", body)][:OPENING_WORDS]
    limit = words[-1][1]
    for s, e, _ln in ms:
        if s >= limit:
            break
        ends = [m.end() for rx in (DATE, ATTR_KEYWORD) for m in [rx.search(body, e)]
                if m and m.start() < limit]
        if ends:
            return off + min(ends)
    if len(body.split()) > ATTR_MAX_WORDS:
        # P26(d): a LONG line that opens with an attribution keyword
        # ("Author: <token> and a long remark") is the P2(b) idiom too; its
        # extent is the name run after the keyword -- listed tokens,
        # initials, connectors and earlier placeholders -- up to the last
        # listed token of that run. (Before P26 the keyword-at-start idiom
        # sat behind the 12-word bound, which is why such lines were left.)
        km = KEYWORD_START.match(body)
        if km:
            last = None
            for w in re.finditer(r"\S+", body[km.end():]):
                ws, we = km.end() + w.start(), km.end() + w.end()
                hit = [e for s, e, _ln in ms if ws <= s and e <= we]
                if hit:
                    last = max(hit)
                    continue
                bare = w.group(0).strip(",;.:()[]")
                if (not bare or bare == PLACEHOLDER or bare.lower() in NAME_CONNECTORS
                        or re.fullmatch(r"(?:[A-Z]\.?){1,3}", bare)):
                    continue
                break
            if last is not None:
                return off + last
        return None
    if ATTR_START.match(body) or DATE.match(body):
        return len(line)
    for s, _e, _ln in ms:
        if BY_TOKEN.search(body[:s]):
            return len(line)
    if is_name_only(body, ms):
        return len(line)
    return None


def is_attribution(line, matches):
    """True when the line (or its opening, P25) is an attribution line."""
    return attribution_extent(line, matches) is not None


def _inside(s, e, spans):
    return any(cs <= s and e <= ce for cs, ce in spans)


# ---------------------------------------------------------------------------
# Per-file analysis
# ---------------------------------------------------------------------------
def family_of(name, text=""):
    """Enumerated: basename, then exact extension, then README* / *LISTING*
    as prose, then extension; an extensionless text file is prose unless it
    opens with a shebang (a script: code). Anything else stays 'text'
    (whole-line rule (b) only) and is counted by extension in the totals."""
    if name in BASENAME_FAMILY:
        return BASENAME_FAMILY[name]
    ext = os.path.splitext(name)[1]
    if ext in EXT_FAMILY_EXACT:
        return EXT_FAMILY_EXACT[ext]
    if ext.lower() not in EXT_FAMILY and (name.upper().startswith("README")
                                          or "LISTING" in name.upper()):
        return FAM_PROSE
    if ext in ("", "."):
        return FAM_SHELLISH if text.startswith("#!") else FAM_PROSE
    return EXT_FAMILY.get(ext.lower(), FAM_TEXT)


def ftype_of(name):
    ext = os.path.splitext(name)[1]
    return ext[1:] if ext else "none"


def decode(data):
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return data.decode("latin-1"), "latin-1"


def splice(line, spans):
    out, prev = [], 0
    for s, e in sorted(spans):
        out.append(line[prev:s])
        out.append(PLACEHOLDER)
        prev = e
    out.append(line[prev:])
    return "".join(out)


class LineChange(object):
    def __init__(self, lineno, spans, context, hits, ctxs):
        self.lineno, self.spans, self.context, self.hits = lineno, spans, context, hits
        self.ctxs = ctxs                # one context letter per span


QUOTE_MIN = 12
AMBIGUOUS = "ambiguous"


class QuoteIndex(object):
    """P9: every snapshot line that carries a listed token, with the spans
    the pass replaces in it. A quoted copy of such a line under --agents
    (a fix item's old string, a quoted source line, DOC text) receives the
    IDENTICAL substitution -- the same tokens replaced, the same code tokens
    left -- so the quote still matches the redacted snapshot verbatim.

    A copy is recognised in either direction, on stripped text of at least
    QUOTE_MIN characters: the snapshot line (stripped) occurs inside the
    agents line, or the agents line (stripped; a partial line, as a fix
    item's old string often is) occurs inside the snapshot line."""

    def __init__(self):
        self.by_tok = {}
        self.seen = set()

    def add(self, line, matches, elig):
        L = line[:-1] if line.endswith("\r") else line
        if L in self.seen:
            return
        self.seen.add(L)
        entry = (L, frozenset((t[0], t[1]) for t in elig),
                 frozenset((s, e) for s, e, _ in matches))
        for s, e, _ in matches:
            self.by_tok.setdefault(L[s:e].casefold(), []).append(entry)

    def decide(self, E, matches):
        """{(s, e): replace?} for the matches of E inside a quoted copy, or
        AMBIGUOUS when two copies disagree about one occurrence."""
        cands, ids = [], set()
        for s, e, _ in matches:
            for ent in self.by_tok.get(E[s:e].casefold(), ()):
                if id(ent) not in ids:
                    ids.add(id(ent))
                    cands.append(ent)
        decisions = {}
        Es = E.strip()
        lead_e = len(E) - len(E.lstrip())
        for L, rep, allm in cands:
            Ls = L.strip()
            lead_l = len(L) - len(L.lstrip())
            aligns = []                     # (E start, E end, d) with Lpos = Epos + d
            if len(Ls) >= QUOTE_MIN:
                k = E.find(Ls)
                while k >= 0:
                    aligns.append((k, k + len(Ls), lead_l - k))
                    k = E.find(Ls, k + 1)
            if len(Es) >= QUOTE_MIN and Es != Ls:
                k = L.find(Es)
                while k >= 0:
                    aligns.append((lead_e, lead_e + len(Es), k - lead_e))
                    k = L.find(Es, k + 1)
            for a, b, d in aligns:
                for s, e, _ in matches:
                    if a <= s and e <= b and (s + d, e + d) in allm:
                        rp = (s + d, e + d) in rep
                        if decisions.get((s, e), rp) != rp:
                            return AMBIGUOUS
                        decisions[(s, e)] = rp
        return decisions


CODE_KEYS = {"old", "new"}     # P15 default; --code-keys overrides


FORCE_MAP, SPARE_MAP = {}, {}   # P32: {(label or None, rel): {line numbers}}
FORCE_WHERE = ("comment", "prose", "json_string", "text", "subject", "in_date", "citation")


def decide_line(line, matches, family, spans, qi, names, field=None, override=None):
    """The context decision for one line, then P29's placeholder rule: a
    soft token LEFT in comment or prose context within two words of a
    redaction placeholder -- an earlier pass's, or a span this pass replaces
    on the line -- is attribution (repeated until nothing changes, so a
    second run finds nothing more: the pass stays a fixpoint)."""
    got = _decide_line(line, matches, family, spans, qi, names, field)
    if got == AMBIGUOUS:
        return got
    elig, left = got
    if override == "spare":
        # P32: an operator-spared line -- every listed token on it is LEFT and
        # counted as spared, whatever the rules decided
        left = left + [(a, "spared", names.member(line[a:b])) for a, b, _l, _c in elig]
        return [], left
    if not left:
        return got
    end_of = {a: b for a, b, _l in matches}
    ln_of = {a: l for a, _b, l in matches}
    ph = [m.span() for m in OLD_PLACEHOLDERS.finditer(line)] + [(a, b) for a, b, _l, _c in elig]
    changed = True
    while changed:
        changed = False
        for item in list(left):
            a, where, m = item
            if m in ("ambiguous", "identifier") and where in NEAR_WHERE and a in end_of \
                    and near_placeholder(line, a, end_of[a], ph):
                left.remove(item)
                elig.append((a, end_of[a], ln_of[a], "r"))
                ph.append((a, end_of[a]))
                changed = True
    if override == "force":
        # P32: an operator-forced line -- every listed token LEFT in comment or
        # prose context is replaced whatever the rules decided; never code
        # (nor a JSON key, nor the code part of a quoted line)
        for item in list(left):
            a, where, m = item
            if where in FORCE_WHERE and a in end_of:
                left.remove(item)
                elig.append((a, end_of[a], ln_of[a], "f"))
    return elig, left


def _decide_line(line, matches, family, spans, qi, names, field=None):
    """The context decision for one line (or one embedded line of a JSON
    string value: family None, field 'code' under --code-keys else 'prose')
    -> (elig [(s, e, ln, ctx)], left [(s, where, membership)]) or AMBIGUOUS.
    ctx: a = comment syntax, b = attribution / name-only line, p = prose,
    q = quoted copy of a snapshot line (identical substitution), g = an
    UNAMBIGUOUS token outside source code (P15: never left there).
    P19/P24: an AMBIGUOUS or IDENTIFIER token outside code is replaced ONLY
    on an attribution-idiom or name-only line (in a source file: inside a
    comment that is such a line), and never elsewhere; left, it is counted
    by context. In code it is left like any token."""
    elig, left = [], []
    mem = {(s, e): names.member(line[s:e]) for s, e, _ in matches}
    soft = lambda s, e: mem[(s, e)] in ("ambiguous", "identifier")

    if CITATIONS:
        # P27/P28(b): published authorship -- the listed tokens of the
        # CITATION GROUP are LEFT (code stays code), counted, excused by the
        # post-scan; every other token on the line keeps its rules
        cit = citation_group(line, matches)
        if cit:
            for s, e, ln in matches:
                if (s, e) not in cit:
                    continue
                if family in CODE_FAMILIES and not _inside(s, e, spans):
                    left.append((s, "code", mem[(s, e)]))
                else:
                    left.append((s, "citation", mem[(s, e)]))
            matches = [m for m in matches if (m[0], m[1]) not in cit]
            if not matches:
                return elig, left
    # P30: a soft token INSIDE a date ("13/<Jun>/04") is part of the date --
    # left, not residual, and out of reach of every attribution rule
    dspans = [d.span() for d in DATE.finditer(line)]
    in_date = [m for m in matches if soft(m[0], m[1])
               and any(a <= m[0] and m[1] <= b for a, b in dspans)]
    if in_date:
        for s, e, ln in in_date:
            left.append((s, "in_date", mem[(s, e)]))
        matches = [m for m in matches if m not in in_date]
        if not matches:
            return elig, left
    forms = anchored_forms(line, matches)

    if family in CODE_FAMILIES:
        span_attr = {}
        for s, e, ln in matches:
            if not _inside(s, e, spans):
                left.append((s, "code", mem[(s, e)]))
            elif not soft(s, e):
                elig.append((s, e, ln, "a"))
            else:
                sp = next(((cs, ce) for cs, ce in spans if cs <= s and e <= ce), (0, len(line)))
                if sp not in span_attr:
                    seg = line[sp[0]:sp[1]]
                    ext = attribution_extent(
                        seg, [(a - sp[0], b - sp[0], l) for a, b, l in matches
                              if sp[0] <= a and b <= sp[1]])
                    span_attr[sp] = None if ext is None else sp[0] + ext
                if span_attr[sp] is not None and e <= span_attr[sp]:
                    elig.append((s, e, ln, "b"))
                elif forms.get((s, e)):
                    elig.append((s, e, ln, FORM_CTX[forms[(s, e)]]))
                else:
                    seg = line[sp[0]:sp[1]]
                    rule = soft_rule(seg, s - sp[0], e - sp[0],
                                     [(a - sp[0], b - sp[0], l) for a, b, l in matches
                                      if sp[0] <= a and b <= sp[1]], True)
                    if rule == "subject" and mem[(s, e)] == "ambiguous":
                        left.append((s, "subject", mem[(s, e)]))
                    elif rule:
                        elig.append((s, e, ln, RULE_CTX[rule]))
                    else:
                        left.append((s, "comment", mem[(s, e)]))
        return elig, left
    rest = matches
    if qi is not None:
        dec = qi.decide(line, matches)
        if dec == AMBIGUOUS:
            return AMBIGUOUS
        rest = []
        for s, e, ln in matches:
            if (s, e) not in dec:
                rest.append((s, e, ln))
            elif dec[(s, e)]:
                elig.append((s, e, ln, "q"))
            elif mem[(s, e)] == "unambiguous":
                elig.append((s, e, ln, "g"))
            else:
                left.append((s, "quoted_code", mem[(s, e)]))
    if not rest:
        return elig, left
    if family == FAM_PROSE:
        ctx_where = "prose"
    elif family is None:
        ctx_where = "json_code_field" if field == "code" else "json_string"
    else:
        ctx_where = "text"
    soft_rest = [m for m in rest if soft(m[0], m[1])]
    rest = [m for m in rest if not soft(m[0], m[1])]
    if soft_rest and family is None and field == "code":
        # a --code-keys field keeps comment-only semantics for the soft
        # classes too: only inside its comment, and only when that comment
        # is an attribution line (a quoted decay line keeps its model name)
        cs = generic_comment_start(line)
        cext = None if cs is None else attribution_extent(
            line[cs:], [(a - cs, b - cs, l) for a, b, l in matches if a >= cs])
        for s, e, ln in soft_rest:
            if cext is not None and s >= cs and e <= cs + cext:
                elig.append((s, e, ln, "b"))
            elif cs is not None and s >= cs and forms.get((s, e)):
                elig.append((s, e, ln, FORM_CTX[forms[(s, e)]]))
            else:
                rule = None
                if cs is not None and s >= cs:
                    rule = soft_rule(line[cs:], s - cs, e - cs,
                                     [(a - cs, b - cs, l) for a, b, l in matches if a >= cs],
                                     True)
                if rule == "subject" and mem[(s, e)] == "ambiguous":
                    left.append((s, "subject", mem[(s, e)]))
                elif rule:
                    elig.append((s, e, ln, RULE_CTX[rule]))
                else:
                    left.append((s, ctx_where, mem[(s, e)]))
    elif soft_rest:
        ext = attribution_extent(line, matches)
        prose_ctx = family == FAM_PROSE or family is None
        for s, e, ln in soft_rest:
            if ext is not None and e <= ext:
                elig.append((s, e, ln, "b"))
            elif prose_ctx and forms.get((s, e)):
                elig.append((s, e, ln, FORM_CTX[forms[(s, e)]]))
            else:
                # a quoted comment line inside prose or a record counts as a
                # comment for the subject rule; a markdown heading does not
                # the subject rule: a quoted comment line, or the TEXT of a
                # prose or text line (P31(d)); not a record value's prose
                quoted_comment = bool(re.match(r"\s*(?:#|//)", line))
                is_comment = family in (FAM_PROSE, FAM_TEXT) or quoted_comment
                rule = soft_rule(line, s, e, matches, is_comment)
                if rule == "subject" and mem[(s, e)] == "ambiguous":
                    # the subject rule is ruled for identifiers; an ambiguous
                    # subject is the residual class only in a comment
                    left.append((s, "subject" if quoted_comment else ctx_where, mem[(s, e)]))
                elif rule:
                    elig.append((s, e, ln, RULE_CTX[rule]))
                else:
                    left.append((s, ctx_where, mem[(s, e)]))
    if not rest:
        return elig, left
    # only UNAMBIGUOUS tokens remain: never left outside source code
    if family == FAM_PROSE:
        elig.extend((s, e, ln, "p") for s, e, ln in rest)
        return elig, left
    if family is None:
        cs = generic_comment_start(line)
        spans = [(cs, len(line))] if cs is not None else []
    battr = is_attribution(line, rest)
    for s, e, ln in rest:
        if battr:
            elig.append((s, e, ln, "b"))
        elif _inside(s, e, spans or []):
            elig.append((s, e, ln, "a"))
        else:
            elig.append((s, e, ln, "g"))
    return elig, left


def scan_code_tokens(root, names):
    """P24: casefolded tokens with an occurrence in CODE context (outside
    every comment span) in a source file under `root` -- the identifier
    test of the tool's own partition. Binaries are skipped."""
    found = set()
    for d, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        for fn in sorted(files):
            fam = family_of(fn)
            if fam not in CODE_FAMILIES:
                continue
            p = os.path.join(d, fn)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            with open(p, "rb") as f:
                data = f.read()
            if is_binary(data):
                continue
            lines = decode(data)[0].split("\n")
            cspans = c_comment_spans(lines) if fam == FAM_C else None
            fn_ = {FAM_HASH: hash_comment_spans, FAM_TCL: tcl_comment_spans,
                   FAM_SHELLISH: shellish_comment_spans,
                   FAM_FORTRAN: fortran_comment_spans}.get(fam)
            for i, line in enumerate(lines):
                ms = names.find(line)
                if not ms:
                    continue
                spans = cspans[i] if cspans is not None else fn_(line)
                for s, e, _ln in ms:
                    if not _inside(s, e, spans):
                        found.add(names.token_of_key.get(line[s:e].casefold(),
                                                         line[s:e].casefold()))
    return found


def analyse_lines(lines, family, names, qi=None, index=None, over=None):
    """-> (changes {idx: LineChange}, left [(idx, col, where)], refused).
    `index`, when given, collects every token-bearing line (P9)."""
    changes, left, refused = {}, [], []
    cspans = c_comment_spans(lines) if family == FAM_C else None
    span_fn = {FAM_HASH: hash_comment_spans, FAM_TCL: tcl_comment_spans,
               FAM_TEXTHASH: texthash_comment_spans,
               FAM_SHELLISH: shellish_comment_spans,
               FAM_FORTRAN: fortran_comment_spans}.get(family)
    analyse_lines.last_match_count = 0
    for idx, line in enumerate(lines):
        matches = names.find(line)
        if not matches:
            continue
        analyse_lines.last_match_count += len(matches)
        if cspans is not None:
            spans = cspans[idx]
        else:
            spans = span_fn(line) if span_fn else []
        got = decide_line(line, matches, family, spans, qi, names,
                          override=(over or {}).get(idx))
        if got == AMBIGUOUS:
            refused.append((idx, "quote_ambiguous", len(matches)))
            continue
        elig, lft = got
        if index is not None and (over or {}).get(idx) != "spare":
            # a spared line (P32) is a per-line operator exemption: it does not
            # decide its quoted copies, which follow the other copies and rules
            index.add(line, matches, elig)
        left.extend((idx, s, where, m) for s, where, m in lft)
        if elig:
            elig.sort()
            changes[idx] = LineChange(idx + 1, [(s, e) for s, e, _l, _c in elig],
                                      "".join(sorted(set(c for _s, _e, _l, c in elig))),
                                      [ln for _s, _e, ln, _c in elig],
                                      [c for _s, _e, _l, c in elig])
    return changes, left, refused


def embedded_spans(dec, names, qi=None, field="prose", override=None):
    """Inside one decoded JSON string value: -> (eligible [(a, b, ln, ctx)],
    left [(offset, where, membership)]) or AMBIGUOUS."""
    elig, left, base = [], [], 0
    for eline in dec.split("\n"):
        matches = names.find(eline)
        if matches:
            got = decide_line(eline, matches, None, None, qi, names, field, override)
            if got == AMBIGUOUS:
                return AMBIGUOUS
            elig.extend((base + s, base + e, ln, c) for s, e, ln, c in got[0])
            left.extend((base + s, w, m) for s, w, m in got[1])
        base += len(eline) + 1
    return elig, left


def json_string_tokens(s):
    """[(start, end, is_key, enclosing_key)] of the string literals of one
    JSON text, by the quote/escape grammar and the container structure: a
    value's enclosing key is the member name it sits under (an array's
    elements inherit the array's member name)."""
    out, stack, i, n = [], [], 0, len(s)
    while i < n:
        c = s[i]
        if c == '"':
            j = i + 1
            while s[j] != '"':
                j += 2 if s[j] == "\\" else 1
            top = stack[-1] if stack else None
            if top is not None and top[0] == "obj" and top[2]:
                top[1] = json.loads(s[i:j + 1])
                top[2] = False
                out.append((i, j + 1, True, None))
            else:
                out.append((i, j + 1, False, top[1] if top else None))
            i = j + 1
            continue
        if c == "{":
            stack.append(["obj", None, True])
        elif c == "[":
            stack.append(["arr", stack[-1][1] if stack else None, False])
        elif c in "}]":
            if stack:
                stack.pop()
        elif c == "," and stack and stack[-1][0] == "obj":
            stack[-1][2] = True
        i += 1
    return out


SEPARATORS = ((", ", ": "), (",", ":"))


def canonical_separators(obj, core):
    for seps in SEPARATORS:
        if json.dumps(obj, ensure_ascii=True, sort_keys=True, separators=seps) == core:
            return seps
    return None


def _enc_len(t):
    return len(json.dumps(t, ensure_ascii=True)) - 2


def _literal_offsets(lit):
    """For one raw JSON string literal (quotes included): the raw offset of
    each decoded character, plus the closing quote's offset. An escape is one
    decoded character over 2 raw characters (6 for \\uXXXX, 12 for a
    surrogate pair, which json.loads joins into one character)."""
    offs, i, n = [], 1, len(lit) - 1
    while i < n:
        offs.append(i)
        if lit[i] == "\\":
            if lit[i + 1] == "u":
                cp = int(lit[i + 2:i + 6], 16)
                if 0xD800 <= cp < 0xDC00 and lit[i + 6:i + 8] == "\\u" and \
                        0xDC00 <= int(lit[i + 8:i + 12], 16) < 0xE000:
                    i += 12
                    continue
                i += 6
            else:
                i += 2
        else:
            i += 1
    offs.append(n)
    return offs


def _string_values(obj, out):
    """String VALUES in document order (keys excluded)."""
    if isinstance(obj, dict):
        for v in obj.values():
            _string_values(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _string_values(v, out)
    elif isinstance(obj, str):
        out.append(obj)
    return out


def _mask_strings(obj):
    if isinstance(obj, dict):
        return {k: _mask_strings(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_mask_strings(v) for v in obj]
    return None if isinstance(obj, str) else obj


def analyse_jsonl(lines, names, qi=None, over=None):
    """P12: records are edited ON THEIR RAW BYTES, never re-serialised. The
    string literals of a line are found by the JSON quote/escape grammar;
    keys are excluded; inside a value the decoded text gets the context
    rules and each eligible decoded span is mapped back to its raw span,
    which alone is replaced. Every byte outside the spans is kept, so a
    record in any key order, spacing or escape style survives as written.
    Proof per line: json.loads(after) equals json.loads(before) with every
    non-string unchanged and every string value equal to its expected
    splice. Only a line that is not valid JSON is refused outright; a line
    whose edit cannot be proved (a duplicate key hiding a value, a span
    that does not map) is refused too, left byte-identical, as residue.
    -> (changes, left, refused [(idx, reason, n_eligible)])"""
    changes, left, refused = {}, [], []
    for idx, line in enumerate(lines):
        if not names.find(line) and "\\u" not in line:
            continue
        core = line[:-1] if line.endswith("\r") else line
        if not core.strip():
            continue
        try:
            obj = json.loads(core)
        except ValueError:
            n = len(names.find(core))
            if n:
                refused.append((idx, "not_json", n))
            continue
        toks = json_string_tokens(core)
        values = _string_values(obj, [])
        n_values = sum(1 for _s, _e, k, _ek in toks if not k)
        raw_spans, hits, ctx_list, local_left, n_elig, bad = [], [], [], [], 0, None
        expected, vi = list(values), 0
        for s, e, is_key, ekey in toks:
            lit = core[s:e]
            dec = json.loads(lit)
            offs = _literal_offsets(lit)
            if len(offs) != len(dec) + 1:
                bad = bad or "span_map"
                n_elig += len(names.find(dec))
                vi += 0 if is_key else 1
                continue
            if is_key:
                for ms, me, _ln in names.find(dec):
                    local_left.append((idx, s + offs[ms], "json_key", names.member(dec[ms:me])))
                continue
            got = embedded_spans(dec, names, qi,
                                 "code" if ekey in CODE_KEYS else "prose", (over or {}).get(idx))
            if got == AMBIGUOUS:
                bad = bad or "quote_ambiguous"
                n_elig += len(names.find(dec))
                vi += 1
                continue
            elig, lft = got
            for a, where, m in lft:
                local_left.append((idx, s + offs[a], where, m))
            n_elig += len(elig)
            dspans = []
            for a, b, ln, ctx in elig:
                rs, re_ = s + offs[a], s + offs[b]
                if json.loads('"%s"' % core[rs:re_]) != dec[a:b]:
                    bad = bad or "span_map"
                raw_spans.append((rs, re_))
                dspans.append((a, b))
                hits.append(ln)
                ctx_list.append(ctx)
            if vi < len(expected) and dspans:
                expected[vi] = splice(dec, dspans)
            vi += 1
        if n_values != len(values):
            bad = bad or "duplicate_key"
        if raw_spans and not bad:
            new_core = splice(core, raw_spans)
            try:
                after = json.loads(new_core)
                ok = (_mask_strings(after) == _mask_strings(obj)
                      and _string_values(after, []) == expected)
            except ValueError:
                ok = False
            if not ok:
                bad = "edit_not_proved"
        if bad and n_elig:
            refused.append((idx, bad, n_elig))
            continue
        left.extend(local_left)
        if raw_spans:
            changes[idx] = LineChange(idx + 1, raw_spans,
                                      "".join(sorted(set(ctx_list))), hits, ctx_list)
    return changes, left, refused


def neutral_form(text):
    """'#' comments stripped, whitespace collapsed: the parser's view."""
    kept = [line.split("#", 1)[0] for line in text.split("\n")]
    return " ".join(" ".join(kept).split())


class FileResult(object):
    pass


_CTRL = bytes(c for c in range(32) if c not in (8, 9, 10, 12, 13, 27))   # NUL included


MAX_TEXT_NULS = 2     # P18: below 3 NULs a file may still be text


def is_binary(data):
    """P18: binary when it carries MAX_TEXT_NULS+1 or more NUL bytes, or when
    more than 10% of the first 8 KB are control bytes (other than tab, LF,
    CR, FF, BS, ESC; a NUL counts as a control byte). A file with one or two
    stray NULs and otherwise text-like bytes is TEXT: the real snapshot held
    an ASCII decay file of 5,058 lines with ONE NUL at line 3,656 that a
    'any NUL is binary' rule skipped unredacted. The raw splice keeps the NUL
    bytes, which lie outside every replaced span. Binaries are skipped,
    counted, and named in the ledger."""
    if data.count(b"\0") > MAX_TEXT_NULS:
        return True
    head = data[:8192]
    return bool(head) and len(head) - len(head.translate(None, _CTRL)) > len(head) // 10


def tree_kind(label):
    """P17: the tree KIND (root / agents) beside its label (root, agents,
    agents1..N); every counter, paragraph and summary line keys on it."""
    return "root" if label == "root" else "agents"


def line_count(b):
    """wc -l semantics: the number of newline bytes."""
    return b.count(b"\n")


def analyse_file(label, rel, path, names, qi=None, index=None):
    """-> FileResult, or a skip reason string."""
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode):
        return "not_regular"
    with open(path, "rb") as f:
        data = f.read()
    if is_binary(data):
        return "binary"
    text, codec = decode(data)
    lines = text.split("\n")
    base = os.path.basename(rel)
    fam = family_of(base, text)
    over = {}
    for mp, mode in ((FORCE_MAP, "force"), (SPARE_MAP, "spare")):
        for ln in mp.get((label, rel), set()) | mp.get((None, rel), set()):
            over[ln - 1] = mode
    if fam == FAM_JSONL:
        changes, left, refused = analyse_jsonl(lines, names, qi, over)
    else:
        changes, left, refused = analyse_lines(lines, fam, names, qi, index, over)
    r = FileResult()
    r.label, r.rel, r.path, r.family, r.ftype = label, rel, path, fam, ftype_of(base)
    r.codec, r.old_bytes, r.changes, r.left, r.refused = codec, data, changes, left, refused
    r.new_bytes = None
    r.c_hunks = r.c_hunks_outside = 0
    # P11's any-context count. For line-oriented files it is the analysis's
    # own per-line match count (every match is classified, eligible or
    # left); for .jsonl it is a raw-text count, which can differ from the
    # decoded one (an escaped name), so the post-check reports it beside.
    r.raw_hits = (sum(len(names.find(ln)) for ln in lines) if fam == FAM_JSONL
                  else analyse_lines.last_match_count)
    r.json_doc = os.path.splitext(base)[1].lower() == ".json"
    r.nul_count = data.count(b"\0")
    r.kind = tree_kind(label)
    if changes:
        new_lines = list(lines)
        for idx, ch in changes.items():
            new_lines[idx] = splice(lines[idx], ch.spans)
        r.new_bytes = "\n".join(new_lines).encode(codec)
        if os.path.splitext(base)[1].lower() == ".json" and not _json_kept(text, new_lines):
            # a whole-document .json that parsed before and would not after:
            # refused, left byte-identical, its tokens counted as residue
            r.refused = refused + [(idx, "json_invalidated", len(ch.spans))
                                   for idx, ch in sorted(changes.items())]
            r.changes, r.new_bytes = {}, None
            return r
        verify_file(r, lines, names)
    return r


def _json_kept(old_text, new_lines):
    try:
        json.loads(old_text)
    except ValueError:
        return True
    try:
        json.loads("\n".join(new_lines))
        return True
    except ValueError:
        return False


def code_part(line, spans):
    out, prev = [], 0
    for s, e in sorted(spans):
        out.append(line[prev:s])
        prev = e
    out.append(line[prev:])
    return "".join(out)


def c_hunks_outside_comments(old_lines, new_lines):
    """P10: (hunks, hunks whose change lies OUTSIDE comment context). Each
    file is lexed on its own (old by its old text, new by its new text);
    a changed line is inside comment context only if its code part --
    the line with its comment spans removed -- is equal before and after.
    An inserted or deleted line is always outside."""
    old_sp = c_comment_spans(old_lines)
    new_sp = c_comment_spans(new_lines)
    sm = difflib.SequenceMatcher(None, old_lines, new_lines, autojunk=False)
    hunks = outside = 0
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        hunks += 1
        if tag != "replace" or (i2 - i1) != (j2 - j1):
            outside += 1
            continue
        for k in range(i2 - i1):
            if code_part(old_lines[i1 + k], old_sp[i1 + k]) != \
                    code_part(new_lines[j1 + k], new_sp[j1 + k]):
                outside += 1
                break
    return hunks, outside


def verify_file(r, old_lines, names):
    """The pre-write checks (P3, P6, P10). Raises Refuse naming the file."""
    who = display_path(r.label, r.rel, names)[0]
    new_text = r.new_bytes.decode(r.codec)
    new_lines = new_text.split("\n")
    if len(new_lines) != len(old_lines) or \
            line_count(r.new_bytes) != line_count(r.old_bytes):
        raise Refuse("line count would change in %s" % who)
    for idx, (o, n) in enumerate(zip(old_lines, new_lines)):
        ch = r.changes.get(idx)
        if ch is None:
            if o != n:
                raise Refuse("an unlisted line would change in %s:%d" % (who, idx + 1))
            continue
        for s, e in ch.spans:
            span = o[s:e]
            if r.family == FAM_JSONL:
                span = json.loads('"%s"' % span)
            if not names.rx.fullmatch(span):
                raise Refuse("a replaced span is not a listed token in %s:%d" % (who, idx + 1))
        if n != splice(o, ch.spans):
            raise Refuse("bytes outside the replaced spans would change in %s:%d"
                         % (who, idx + 1))
    if os.path.splitext(r.rel)[1].lower() in NEUTRALITY_EXTS:
        before = neutral_form(r.old_bytes.decode(r.codec))
        after = neutral_form(new_text)
        if before != after:
            raise Refuse("parser neutrality fails for %s: the comment-stripped "
                         "content would change; the whole run is refused" % who)
    if r.family == FAM_C:
        r.c_hunks, r.c_hunks_outside = c_hunks_outside_comments(old_lines, new_lines)
        if r.c_hunks_outside:
            raise Refuse("P10: %d diff hunk(s) outside comment context in %s; "
                         "the whole run is refused" % (r.c_hunks_outside, who))


def path_hits(label, rel, names):
    """P35: the listed tokens of a file path in the OUTPUT form, as
    [{names_line, class, inside_word}] -- never the token. inside_word: the
    hit is joined to a letter (a camel-case name such as EvtBtoXsgamma<tok>)."""
    shown = "%s:./%s" % (label, rel)
    out = []
    for s, e in names.find_mask(shown):
        inside = ((s > 0 and shown[s - 1].isalpha()) or (e < len(shown) and shown[e].isalpha()))
        out.append({"names_line": names.names_line(shown[s:e]),
                    "class": names.member(shown[s:e]), "inside_word": bool(inside)})
    return out


def display_path(label, rel, names):
    """(text for ledger/report, sha256 of the path if it carried a token).
    P23: only an UNAMBIGUOUS token is masked; a path carrying only ambiguous
    or identifier tokens (a dictionary word, a model name) is written as is."""
    shown = "%s:./%s" % (label, rel)
    hits = names.find_mask_unambiguous(shown)      # P33: the output form
    if not hits:
        return shown, None
    return (splice(shown, hits),
            hashlib.sha256(rel.encode("utf-8", "surrogateescape")).hexdigest())


def walk(trees, names):
    """-> (results, counts). Every file seen is either a result or a skip.
    The snapshot (root) is walked first; its token-bearing lines form the
    quote index the agents files are analysed against (P9)."""
    results, skipped = [], []
    counts = {"files_seen": 0, "files_skipped_binary": 0, "files_skipped_not_regular": 0}
    has_root = any(lab == "root" for lab, _t in trees)
    index = (QuoteIndex() if has_root and any(lab.startswith("agents") for lab, _t in trees)
             else None)
    for label, top in sorted(trees, key=lambda x: x[0] != "root"):
        qi = index if label.startswith("agents") else None
        ix = index if label == "root" else None
        for d, dirs, files in os.walk(top, followlinks=False):
            dirs.sort()
            # a symlinked directory is listed in dirs but never descended into
            for sub in dirs:
                if os.path.islink(os.path.join(d, sub)):
                    counts["files_seen"] += 1
                    counts["files_skipped_not_regular"] += 1
                    skipped.append((label, os.path.relpath(os.path.join(d, sub), top)
                                    .replace(os.sep, "/"), "not_regular"))
            for fn in sorted(files):
                p = os.path.join(d, fn)
                rel = os.path.relpath(p, top).replace(os.sep, "/")
                counts["files_seen"] += 1
                r = analyse_file(label, rel, p, names, qi, ix)
                if isinstance(r, str):
                    counts["files_skipped_" + r] += 1
                    skipped.append((label, rel, r))
                else:
                    results.append(r)
    counts["files_scanned"] = len(results)
    if counts["files_seen"] != (counts["files_scanned"] + counts["files_skipped_binary"]
                                + counts["files_skipped_not_regular"]):
        raise Refuse("file accounting does not close")
    walk.index_built = index is not None
    return results, counts, skipped


# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
WHITELIST_BASENAMES = ("testEvtGen.cc", "EvtDecayTable.cc")


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def write_atomic(path, text):
    tmp = path + ".new"
    with open(tmp, "w", encoding="ascii", errors="backslashreplace", newline="\n") as f:
        f.write(text)
    os.replace(tmp, path)


def write_in_place(path, data):
    st = os.stat(path)
    d, b = os.path.split(path)
    tmp = os.path.join(d, ".%s.pass5.tmp" % b)
    with open(tmp, "wb") as f:
        f.write(data)
    os.chmod(tmp, stat.S_IMODE(st.st_mode))
    os.replace(tmp, path)


def ledger_rows(results, names, applied):
    rows = []
    kind = "changed_line" if applied else "would_change_line"
    for r in results:
        shown, psha = display_path(r.label, r.rel, names)
        extra = {"path_sha256": psha} if psha else {}
        for idx in sorted(r.changes):
            ch = r.changes[idx]
            row = {"kind": kind, "file": shown, "line": ch.lineno, "count": len(ch.spans),
                   "context": ch.context, "ftype": r.ftype, "fclass": r.family}
            row.update(extra)
            rows.append(row)
        for idx, col, where, m in r.left:
            row = {"kind": "code_left", "file": shown, "line": idx + 1, "col": col + 1,
                   "where": where, "membership": m, "ftype": r.ftype, "fclass": r.family}
            row.update(extra)
            rows.append(row)
        for idx, reason, n in r.refused:
            row = {"kind": "record_refused", "file": shown, "line": idx + 1,
                   "reason": reason, "count": n, "ftype": r.ftype}
            row.update(extra)
            rows.append(row)
    return rows


def totals(results, counts, names, applied):
    hits = {}
    for r in results:
        for ch in r.changes.values():
            for ln in ch.hits:
                hits[str(ln)] = hits.get(str(ln), 0) + 1
    wl = {}
    for r in results:
        if os.path.basename(r.rel) in WHITELIST_BASENAMES:
            after = r.new_bytes if r.new_bytes is not None else r.old_bytes
            wl[display_path(r.label, r.rel, names)[0]] = {
                "before": line_count(r.old_bytes), "after": line_count(after)}
    t = {"kind": "totals", "mode": "apply" if applied else "dry_run", "tool": TOOL_VERSION,
         "files_changed": sum(1 for r in results if r.changes),
         "files_changed_root": sum(1 for r in results if r.changes and r.kind == "root"),
         "files_changed_agents": sum(1 for r in results if r.changes and r.kind == "agents"),
         "files_text_with_nul": sum(1 for r in results if r.nul_count),
         "lines_changed": sum(len(r.changes) for r in results),
         "tokens_replaced": sum(len(ch.spans) for r in results for ch in r.changes.values()),
         "tokens_replaced_quoted_copies": sum(ch.ctxs.count("q") for r in results
                                              for ch in r.changes.values()),
         "code_occurrences_left": sum(len(r.left) for r in results),
         "records_refused": sum(len(r.refused) for r in results),
         "records_refused_reasons": [reason for r in results for _i, reason, _n in r.refused],
         "refused_eligible_tokens": sum(n for r in results for _i, _r, n in r.refused),
         "paths_with_listed_token": sum(1 for r in results
                                        if display_path(r.label, r.rel, names)[1]),
         # P35: a path whose listed tokens are only identifier or ambiguous
         # ones (a model named after its authors: EvtBtoXsgamma<tok>.cc) is
         # written as is, counted, and is no exit condition
         "identifier_named_files": sum(1 for r in results
                                       if not display_path(r.label, r.rel, names)[1]
                                       and path_hits(r.label, r.rel, names)),
         "c_files_changed": sum(1 for r in results if r.changes and r.family == FAM_C),
         "c_hunks": sum(r.c_hunks for r in results),
         "c_hunks_outside_comment": sum(r.c_hunks_outside for r in results),
         "whitelist_line_counts": wl,
         "attribution_forms_by_tree": forms_by_tree(results),
         "attribution_rules_by_tree": rules_by_tree(results),
         "subject_left_ambiguous_by_tree": subject_left_by_tree(results),
         "citation_left_by_tree": citation_by_tree(results),
         "left_in_unlisted_types_by_ext": _left_by_ext(results),
         "hits_by_names_line": hits}
    t.update(counts)
    t.update(names.stats)
    return t


def forms_by_tree(results):
    """P26(b): per tree, the soft-token occurrences replaced by the P26 form
    rule -- each one an occurrence the rules before P26 left."""
    out = {}
    for r in results:
        for ch in r.changes.values():
            for c in ch.ctxs:
                if c in CTX_FORM:
                    d = out.setdefault(r.label, {})
                    d[CTX_FORM[c]] = d.get(CTX_FORM[c], 0) + 1
    return out


def rules_by_tree(results):
    """P29: per tree, soft-token occurrences replaced by the lead, date,
    subject and placeholder rules."""
    out = {}
    for r in results:
        for ch in r.changes.values():
            for c in ch.ctxs:
                if c in CTX_RULE:
                    d = out.setdefault(r.label, {})
                    d[CTX_RULE[c]] = d.get(CTX_RULE[c], 0) + 1
    return out


def subject_left_by_tree(results):
    """P29: ambiguous tokens left as a comment's sentence subject -- this
    pass's residual class, by count."""
    out = {}
    for r in results:
        n = sum(1 for _i, _c, w, m in r.left if w == "subject" and m == "ambiguous")
        if n:
            out[r.label] = out.get(r.label, 0) + n
    return out


def citation_by_tree(results):
    out = {}
    for r in results:
        n = sum(1 for _i, _c, w, _m in r.left if w == "citation")
        if n:
            out[r.label] = out.get(r.label, 0) + n
    return out


def left_by_tree(results):
    """{tree: {where: {membership: n}}} of every occurrence left."""
    out = {}
    for r in results:
        for _i, _c, where, m in r.left:
            d = out.setdefault(r.label, {}).setdefault(where, {})
            d[m] = d.get(m, 0) + 1
    return out


def _left_by_ext(results):
    out = {}
    for r in results:
        if r.family == FAM_TEXT and r.left:
            out[r.ftype] = out.get(r.ftype, 0) + len(r.left)
    return out


def post_check(post, label):
    """P7/P11: a gate_names-style count over one tree after the pass:
    listed tokens in ANY context, split into comment/attribution (must be
    0) and code context (excused, left); consistent iff the split sums."""
    rs = [r for r in post if r.label == label]
    residue = (sum(len(ch.spans) for r in rs for ch in r.changes.values())
               + sum(n for r in rs for _i, _r, n in r.refused))
    code = sum(len(r.left) for r in rs)
    raw = sum(r.raw_hits for r in rs if r.family != FAM_JSONL)
    raw_json = sum(r.raw_hits for r in rs if r.family == FAM_JSONL)
    classified = (sum(len(ch.spans) for r in rs if r.family != FAM_JSONL
                      for ch in r.changes.values())
                  + sum(n for r in rs if r.family != FAM_JSONL for _i, _r, n in r.refused)
                  + sum(len(r.left) for r in rs if r.family != FAM_JSONL))
    frozen = len(set((r.rel, idx) for r in rs for idx, _c, _w, _m in r.left))
    gate_out = sum(1 for r in rs for _i, _c, w, m in r.left
                   if m == "unambiguous" and w not in ("code", "citation", "spared"))
    spared = sum(1 for r in rs for _i, _c, w, _m in r.left if w == "spared")
    cit = sum(1 for r in rs for _i, _c, w, _m in r.left if w == "citation")
    amb_attr = sum(1 for r in rs for _i, _c, w, m in r.left
                   if m == "ambiguous" and w == "attribution_left")
    return {"kind": "post_check", "tree": label,
            "tokens_any_context": raw + raw_json,
            "comment_attribution": residue, "code_context": code,
            "frozen_hit_lines_excused": frozen,
            "unambiguous_left_outside_source": gate_out,
            "citation_left_excused": cit,
            "spared_left": spared,
            "ambiguous_left_on_attribution_lines": amb_attr,
            "consistent": raw == classified}


def _norm_rel(p):
    return p[2:] if p.startswith("./") else p


def snapshot_class(rel):
    """The per-class COUNT key: the path's top directory; src/<pkg> under
    src/; "root" for a file outside any class directory."""
    parts = rel.split("/")
    if len(parts) == 1:
        return "root"
    if parts[0] == "src" and len(parts) > 2:
        return "src/" + parts[1]
    return parts[0]


def by_class(results):
    out = {}
    for r in results:
        if r.kind != "root":
            continue
        c = out.setdefault(snapshot_class(r.rel), {
            "files_scanned": 0, "files_changed": 0, "lines_changed": 0,
            "tokens_replaced": 0, "code_occurrences_left": 0})
        c["files_scanned"] += 1
        c["files_changed"] += 1 if r.changes else 0
        c["lines_changed"] += len(r.changes)
        c["tokens_replaced"] += sum(len(ch.spans) for ch in r.changes.values())
        c["code_occurrences_left"] += len(r.left)
    return out


SAMPLE_WINDOW = 160          # characters of context on either side of the spans


def sample_path(ledger):
    return os.path.splitext(ledger)[0] + ".sample.txt"


def _mask(line, repl, left, repl_text, left_text="[-left-]"):
    """The line with each replaced span shown as repl_text and each listed
    token LEFT on it masked too, so the sample never carries a token."""
    marks = sorted([(s, e, repl_text) for s, e in repl] + [(s, e, left_text) for s, e in left])
    out, prev = [], 0
    for s, e, t in marks:
        out.append(line[prev:s])
        out.append(t)
        prev = e
    out.append(line[prev:])
    return "".join(out)


SAMPLE_MIN = 10


def names_line_classes(names):
    """{names-file line: membership class} (a line's tokens share a line)."""
    out = {}
    for key, ln in names.line_of.items():
        cls = names.member_of_token.get(names.token_of_key[key], "unambiguous")
        prev = out.get(ln)
        out[ln] = cls if prev in (None, cls) else "mixed:" + "+".join(sorted({prev, cls}))
    return out


def hit_table(results, names, top, bound):
    """P21: the top names-file lines by replaced-occurrence count, with the
    number of distinct files each reached; FLAGGED when the count exceeds
    `bound` or the line's token class is ambiguous. Never the token."""
    hits, spread = {}, {}
    for r in results:
        for ch in r.changes.values():
            for ln in ch.hits:
                hits[ln] = hits.get(ln, 0) + 1
                spread.setdefault(ln, set()).add((r.label, r.rel))
    classes = names_line_classes(names)
    rows = []
    for ln, c in sorted(hits.items(), key=lambda kv: (-kv[1], kv[0]))[:top]:
        cls = classes.get(ln, "unambiguous")
        flags = []
        if c > bound:
            flags.append("count above %d" % bound)
        if "ambiguous" in cls.replace("unambiguous", ""):
            flags.append("ambiguous class")
        rows.append((ln, c, len(spread[ln]), cls, flags))
    return rows


def write_sample(results, names, path, n, mode, bound=100):
    """P20: per (tree kind, context class, token class) cell, the first n
    changed lines (by tree, file, line) carrying a span of that cell, AFTER
    the change (spans already <name>) and BEFORE it (spans masked [--]);
    every listed token left on a sampled line is masked [-left-] in both, so
    a reader judges false positives without seeing a name."""
    cells = {}
    for r in sorted(results, key=lambda x: (x.label, x.rel)):
        if not r.changes:
            continue
        lines = r.old_bytes.decode(r.codec).split("\n")
        for idx in sorted(r.changes):
            ch = r.changes[idx]
            line = lines[idx]
            core = line[:-1] if line.endswith("\r") else line
            keyset = set()
            for (s, e), ctx in zip(ch.spans, ch.ctxs):
                span = core[s:e]
                if r.family == FAM_JSONL:
                    span = json.loads('"%s"' % span)
                keyset.add((r.kind, names.member(span), ctx))
            for key in keyset:
                cells.setdefault(key, []).append((r, idx, core, ch))
    n = max(n, SAMPLE_MIN)
    left_cells = {}
    for r in sorted(results, key=lambda x: (x.label, x.rel)):
        per = {}
        for i, _c, w, m in r.left:
            if m in ("ambiguous", "identifier") and w in ("comment", "prose", "json_string",
                                                           "subject"):
                per.setdefault(m, set()).add(i)
        if not per:
            continue
        lines = r.old_bytes.decode(r.codec).split("\n")
        for m, idxs in per.items():
            for idx in sorted(idxs):
                left_cells.setdefault((r.kind, m), []).append((r, idx, lines[idx]))
    out = ["redact_names sample (%s): up to %d changed line(s) per (tree kind, token class, "
           "context) cell, smaller cells whole; AFTER = as written, BEFORE = replaced spans "
           "masked [--]; listed tokens left on a line are masked [-left-] in both; never a token"
           % (mode, n),
           "context: a comment, b attribution/name-only, p prose, q quoted copy, "
           "g unambiguous outside source code, o possessive, y after 'by', m after 'from', "
           "l lead, d near a date, s comment subject, r near a placeholder", "",
           "== top 20 names-file lines by replaced occurrences (line number, count, files "
           "reached, token class; FLAG when the count exceeds %d or the class is ambiguous)"
           % bound]
    forced_cells, spared_cells = {}, {}
    for r in sorted(results, key=lambda x: (x.label, x.rel)):
        sp_idx = sorted(set(i for i, _c, w, _m in r.left if w == "spared"))
        f_idx = sorted(i for i, ch in r.changes.items() if "f" in ch.ctxs)
        if not (sp_idx or f_idx):
            continue
        lines = r.old_bytes.decode(r.codec).split("\n")
        for idx in f_idx:
            forced_cells.setdefault(r.kind, []).append((r, idx, lines[idx]))
        for idx in sp_idx:
            spared_cells.setdefault(r.kind, []).append((r, idx, lines[idx]))
    out.append("== cell index (changed cells, then LEFT, FORCED and SPARED cells)")
    for key in sorted(cells):
        out.append("  cell kind=%s class=%s context=%s: %d line(s)"
                   % (key[0], key[1], key[2], len(cells[key])))
    for key in sorted(left_cells):
        out.append("  cell LEFT kind=%s class=%s context=comment/prose: %d line(s)"
                   % (key[0], key[1], len(left_cells[key])))
    for tag, cl in (("FORCED", forced_cells), ("SPARED", spared_cells)):
        for kind in sorted(cl):
            out.append("  cell %s kind=%s: %d line(s)" % (tag, kind, len(cl[kind])))
    out.append("")
    for ln, c, files, cls, flags in hit_table(results, names, 20, bound):
        out.append("  names line %d: %d occurrence(s) in %d file(s), class %s%s"
                   % (ln, c, files, cls, ("  FLAG: " + "; ".join(flags)) if flags else ""))
    out.append("")
    for key in sorted(cells):
        rows = cells[key]
        out.append("== cell: kind=%s class=%s context=%s (sampled %d of %d lines)"
                   % (key[0], key[1], key[2], min(n, len(rows)), len(rows)))
        for r, idx, core, ch in rows[:n]:
            repl = sorted(ch.spans)
            left = [(s, e) for s, e in names.find_mask(core)
                    if not any(s < b and a < e for a, b in repl)]
            lo = max(0, repl[0][0] - SAMPLE_WINDOW)
            hi = min(len(core), repl[-1][1] + SAMPLE_WINDOW)
            for a_, b_ in left:              # never cut through a token
                if a_ < lo < b_:
                    lo = a_
                if a_ < hi < b_:
                    hi = b_
            win = core[lo:hi]
            repl_w = [(a_ - lo, b_ - lo) for a_, b_ in repl]
            left_w = [(a_ - lo, b_ - lo) for a_, b_ in left if lo <= a_ and b_ <= hi]
            where = "%s:%d" % (display_path(r.label, r.rel, names)[0], idx + 1)
            for tag, repl_text in (("AFTER ", PLACEHOLDER), ("BEFORE", "[--]")):
                body = _mask(win, repl_w, left_w, repl_text)
                # the line body is corpus text: every class refuses there
                names.guard_text(body, "the sample", corpus=True, field="line text")
                out.append("%s %s: %s%s%s" % (tag, where, "..." if lo > 0 else "", body,
                                               "..." if hi < len(core) else ""))
        out.append("")
    # P26(c)/P28(c): false negatives live in the LEFT lines -- per (tree
    # kind, token class) for the AMBIGUOUS and IDENTIFIER classes, the first
    # n lines carrying such a token left in a comment, prose or a record
    # prose field, as they stand after the pass (replaced spans <name>),
    # every listed token on them masked [-left-]; the header carries LEFT
    # and shares the "== cell:" prefix, so the cells are in the cell list
    for key in sorted(left_cells):
        rows = left_cells[key]
        out.append("== cell: LEFT kind=%s class=%s context=comment/prose "
                   "(sampled %d of %d lines; as they stand after the pass)"
                   % (key[0], key[1], min(n, len(rows)), len(rows)))
        for r, idx, line in rows[:n]:
            core = line[:-1] if line.endswith("\r") else line
            ch = r.changes.get(idx)
            repl = sorted(ch.spans) if ch else []
            left = [(a_, b_) for a_, b_ in names.find_mask(core)
                    if not any(a_ < y and x < b_ for x, y in repl)]
            marks = sorted(repl + left)
            lo = max(0, marks[0][0] - SAMPLE_WINDOW)
            hi = min(len(core), marks[-1][1] + SAMPLE_WINDOW)
            for a_, b_ in marks:
                if a_ < lo < b_:
                    lo = a_
                if a_ < hi < b_:
                    hi = b_
            win = core[lo:hi]
            body = _mask(win, [(a_ - lo, b_ - lo) for a_, b_ in repl if lo <= a_ and b_ <= hi],
                         [(a_ - lo, b_ - lo) for a_, b_ in left if lo <= a_ and b_ <= hi],
                         PLACEHOLDER)
            names.guard_text(body, "the sample", corpus=True, field="line text")
            out.append("LEFT   %s:%d: %s%s%s" % (display_path(r.label, r.rel, names)[0], idx + 1,
                                                 "..." if lo > 0 else "", body,
                                                 "..." if hi < len(core) else ""))
        out.append("")
    # P32: the operator's closure, as its own cells -- FORCED lines as they
    # read after the pass and before it (spans [--]); SPARED lines as they
    # stand (every listed token on them masked [-left-])
    def window(core, marks):
        lo = max(0, marks[0][0] - SAMPLE_WINDOW)
        hi = min(len(core), marks[-1][1] + SAMPLE_WINDOW)
        for a_, b_ in marks:
            if a_ < lo < b_:
                lo = a_
            if a_ < hi < b_:
                hi = b_
        return lo, hi

    for tag, cl in (("FORCED", forced_cells), ("SPARED", spared_cells)):
        for kind in sorted(cl):
            rows = cl[kind]
            out.append("== cell: %s kind=%s (sampled %d of %d lines; the operator's %s list)"
                       % (tag, kind, min(n, len(rows)), len(rows),
                          "--force-lines" if tag == "FORCED" else "--spare-lines"))
            for r, idx, line in rows[:n]:
                core = line[:-1] if line.endswith("\r") else line
                ch = r.changes.get(idx)
                repl = sorted(ch.spans) if ch else []
                left = [(a_, b_) for a_, b_ in names.find_mask(core)
                        if not any(a_ < y and x < b_ for x, y in repl)]
                marks = sorted(repl + left)
                if not marks:
                    continue
                lo, hi = window(core, marks)
                win = core[lo:hi]
                repl_w = [(a_ - lo, b_ - lo) for a_, b_ in repl if lo <= a_ and b_ <= hi]
                left_w = [(a_ - lo, b_ - lo) for a_, b_ in left if lo <= a_ and b_ <= hi]
                where = "%s:%d" % (display_path(r.label, r.rel, names)[0], idx + 1)
                shapes = ((("AFTER ", PLACEHOLDER), ("BEFORE", "[--]")) if tag == "FORCED"
                          else (("SPARED", PLACEHOLDER),))
                for lab_, repl_text in shapes:
                    body = _mask(win, repl_w, left_w, repl_text)
                    names.guard_text(body, "the sample", corpus=True, field="line text")
                    out.append("%s %s: %s%s%s" % (lab_, where, "..." if lo > 0 else "", body,
                                                   "..." if hi < len(core) else ""))
            out.append("")
    text = "\n".join(out) + "\n"
    # headers, labels and the file:line prefixes: unambiguous tokens only
    names.guard_text(text, "the sample", corpus=False, field="header or path")
    write_atomic(path, text)
    return sum(min(n, len(v)) for v in cells.values())


def write_manifest(results, path):
    """ONE manifest: the changed SNAPSHOT files (agents files are not
    snapshot members; the ledger records them)."""
    out = [",".join(MANIFEST_COLUMNS)]
    for r in sorted((r for r in results if r.changes and r.kind == "root"),
                    key=lambda x: x.rel):
        change = "n_redacted_lines=%d;n_tokens=%d" % (
            len(r.changes), sum(len(ch.spans) for ch in r.changes.values()))
        out.append(",".join(_csv(v) for v in (r.rel, sha256(r.old_bytes),
                                               sha256(r.new_bytes), change)))
    write_atomic(path, "\n".join(out) + "\n")
    return len(out) - 1


def _csv(v):
    return '"%s"' % v.replace('"', '""') if any(c in v for c in ',"\n') else v


def readme_paragraph(results, t, names):
    when = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%MZ")
    lines = [
        "PASS 5 (%s, %s UTC): listed name tokens (a closed names file, by count: %d lines, %d tokens)"
        % (TOOL_VERSION, when, names.stats["names_lines"], names.stats["tokens_listed"]),
        "replaced by the token <name>, one per listed token, ONLY in comment context (by each file type's comment",
        "syntax) and on name-only / attribution-idiom lines of prose files; line-preserving, in place; code",
        "occurrences left (%d, listed in the pass-5 ledger by file and line, never the token). Decay-table and"
        % t["code_occurrences_left"],
        "particle-table content unchanged (comment-stripped content equal before and after for every changed",
        ".dec/.DEC/.pdl/.table file); C/C++ diff hunks outside comment context: %d."
        % t["c_hunks_outside_comment"],
        "SNAPSHOT_MANIFEST_pass5.csv carries this pass's rows (path, sha256_pass4 = the checksum before",
        "this pass, sha256_pass5 = after it, change). %d files (%d snapshot, %d agents), %d lines, %d tokens."
        % (t["files_changed"], t["files_changed_root"], t["files_changed_agents"],
           t["lines_changed"], t["tokens_replaced"]),
    ]
    for shown, lc in sorted(t["whitelist_line_counts"].items()):
        lines.append("line count %s: %d before, %d after" % (shown.split(":", 1)[1],
                                                              lc["before"], lc["after"]))
    for kind, title in (("root", "files changed by the fifth pass"),
                        ("agents", "agents files changed by the fifth pass")):
        rs = sorted((r for r in results if r.changes and r.kind == kind),
                    key=lambda x: (x.label, x.rel))
        if kind == "agents" and not rs:
            continue
        lines.append("%s (%d):" % (title, len(rs)))
        for r in rs:
            shown, _ = display_path(r.label, r.rel, names)
            # snapshot files as ./rel (the earlier passes' listing form);
            # agents files keep their tree label (agents, agents1..N)
            lines.append("  " + ("./" + shown.split(":./", 1)[1] if kind == "root" else shown))
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Helper mode P9: --check-records SNAPSHOT RECORDS
# ---------------------------------------------------------------------------
# The record schema is not visible to this tool's author; the keys are an
# enumerated default, overridable at run time (--old-keys, --source-keys).
# A fix item is any JSON object carrying one of OLD_KEYS with a string
# value (wherever its array sits); a quoted source line is the string value
# (or each string of a list value) under one of SOURCE_KEYS.
OLD_KEYS = ("old",)        # the real fix items: line, old, new, justification, source_records
SOURCE_KEYS = ("source_line", "source_lines", "src_line", "quoted_line", "quoted_lines",
               "source_text")


def _quoted_items(obj, old_keys, source_keys, path="$"):
    if isinstance(obj, dict):
        for k in sorted(obj):
            v = obj[k]
            sub = "%s.%s" % (path, k)
            if k in old_keys and isinstance(v, str):
                yield sub, v
            elif k in source_keys:
                if isinstance(v, str):
                    yield sub, v
                elif isinstance(v, list):
                    for i, x in enumerate(v):
                        if isinstance(x, str):
                            yield "%s[%d]" % (sub, i), x
                        else:
                            for it in _quoted_items(x, old_keys, source_keys,
                                                    "%s[%d]" % (sub, i)):
                                yield it
                    continue
            if isinstance(v, (dict, list)):
                for it in _quoted_items(v, old_keys, source_keys, sub):
                    yield it
    elif isinstance(obj, list):
        for i, x in enumerate(obj):
            for it in _quoted_items(x, old_keys, source_keys, "%s[%d]" % (path, i)):
                yield it


def _tree_files(top, exts=None):
    if os.path.isfile(top):
        yield os.path.basename(top), top
        return
    for d, dirs, files in os.walk(top, followlinks=False):
        dirs.sort()
        for fn in sorted(files):
            p = os.path.join(d, fn)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            if exts and os.path.splitext(fn)[1].lower() not in exts:
                continue
            yield os.path.relpath(p, top).replace(os.sep, "/"), p


def snapshot_text(snapshot):
    """The snapshot as one text. Files are read with the redaction pass's
    own sniff (is_binary): binaries are SKIPPED, a text file with one or two
    stray NULs is read like any other. Boundaries are marked by a line of
    three NULs, which no included file can contain (each has at most two)."""
    parts = []
    for _rel, p in _tree_files(snapshot):
        with open(p, "rb") as f:
            data = f.read()
        if is_binary(data):
            continue
        parts.append(decode(data)[0])
    return "\n\0\0\0\n".join(parts)


def check_records_scan(big, records, old_keys, source_keys):
    """-> (checked, unmatched, unparsed, report lines); one substring search
    over the snapshot text per quoted item; never prints an item."""
    checked = unmatched = unparsed = 0
    report = []
    for rel, p in _tree_files(records, (".jsonl", ".json")):
        with open(p, "rb") as f:
            text = decode(f.read())[0]
        units = (list(enumerate(text.split("\n"), 1)) if p.endswith(".jsonl")
                 else [(1, text)])
        for ln, unit in units:
            if not unit.strip():
                continue
            try:
                obj = json.loads(unit)
            except ValueError:
                unparsed += 1
                continue
            for where, s in _quoted_items(obj, old_keys, source_keys):
                if not s:
                    continue
                checked += 1
                if s not in big:
                    unmatched += 1
                    report.append("  unmatched: records:./%s:%d %s" % (rel, ln, where))
    return checked, unmatched, unparsed, report


def check_records(snapshot, records, old_keys, source_keys, out):
    """Count quoted items NOT found verbatim in the snapshot."""
    if not os.path.isdir(snapshot) or not os.path.exists(records):
        raise Refuse("--check-records needs a snapshot directory and a records file or tree")
    checked, unmatched, unparsed, report = check_records_scan(
        snapshot_text(snapshot), records, old_keys, source_keys)
    out.write("check-records: %d quoted items checked, %d UNMATCHED in the snapshot, "
              "%d unparsable record units\n" % (checked, unmatched, unparsed))
    if report:
        out.write("\n".join(report) + "\n")
    if checked == 0:
        out.write("check-records: nothing was checked (no fix item or quoted source line); "
                  "a check that cannot fail is not a pass\n")
        return 1
    return 0 if unmatched == 0 else 1


# ---------------------------------------------------------------------------
# Helper mode P11: --manifest-diff OLD NEW [--ledger FILE]
# ---------------------------------------------------------------------------
def read_manifest(path):
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        return {}, None
    cols = rows[0].keys()
    pcol = next((c for c in ("file", "path") if c in cols), None)
    if pcol is None:
        raise Refuse("manifest %s has no file/path column" % os.path.basename(path))
    sumcol = next((c for c in ("sha256_pass5", "sha256_pass4", "sha256_snapshot", "sha256")
                   if c in cols), None)
    return ({"./" + _norm_rel(r[pcol]): (r.get(sumcol) if sumcol else None) for r in rows},
            sumcol)


def manifest_diff(old, new, ledger, out):
    a, ca = read_manifest(old)
    b, cb = read_manifest(new)
    added = sorted(set(b) - set(a))
    removed = sorted(set(a) - set(b))
    changed = sorted(p for p in set(a) & set(b) if a[p] != b[p])
    members = set(added) | set(removed) | set(changed)
    out.write("manifest-diff: %d members old, %d new; %d added, %d removed, %d checksum "
              "changed (columns %s / %s); member diff %d\n"
              % (len(a), len(b), len(added), len(removed), len(changed), ca, cb, len(members)))
    for tag, ps in (("+", added), ("-", removed), ("~", changed)):
        for p in ps:
            out.write("  %s %s\n" % (tag, p))
    if not ledger:
        return 0
    tot, files = None, set()
    with open(ledger) as f:
        for line in f:
            row = json.loads(line)
            if row.get("kind") == "totals":
                tot = row
            elif row.get("kind") in ("changed_line", "would_change_line") and \
                    row["file"].startswith("root:"):
                files.add(row["file"][len("root:"):])
    if tot is None:
        raise Refuse("the ledger has no totals row")
    n = tot.get("files_changed_root", tot.get("files_changed"))
    same_count = (n == len(members))
    same_set = (files == members)
    verdict = "EQUAL" if same_count and same_set else "NOT EQUAL"
    out.write("verdict: %s (ledger changed snapshot files %d, member diff %d; sets %s)\n"
              % (verdict, n, len(members), "equal" if same_set else "differ"))
    return 0 if verdict == "EQUAL" else 1


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def parse(argv):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--names")
    ap.add_argument("--root")
    ap.add_argument("--agents", action="append", default=[],
                    help="repeatable: every agents tree of the run of record, in ONE "
                         "invocation with --root (the quote index needs both)")
    ap.add_argument("--unambiguous-names", "--gate-names", dest="unambiguous_names",
                    help="P19: the unambiguous subset of --names (P15's gate list)")
    ap.add_argument("--ambiguous-names",
                    help="P19: dictionary words, tokens of three letters or fewer, particles")
    ap.add_argument("--identifier-names", help="P15: the identifier subset of --names")
    ap.add_argument("--dictionary", help="P24: a word list for the tool's own partition "
                    "(used only when no membership files are given)")
    ap.add_argument("--force-lines", help="P32: <tree-relative path>:<line> entries whose listed "
                    "tokens in comment or prose are replaced regardless of rules (never code)")
    ap.add_argument("--spare-lines", help="P32: entries whose listed tokens are left, counted "
                    "as spared")
    ap.add_argument("--citations-published", action="store_true",
                    help="P27: leave (and count) listed tokens on citation lines")
    ap.add_argument("--outlier-bound", type=int, default=100,
                    help="P21: flag a names-file line whose count exceeds this")
    ap.add_argument("--sample", type=int, default=0, metavar="N",
                    help="P20: write N changed lines per (tree kind, context, token class) "
                         "cell beside the ledger, AFTER and BEFORE (spans masked)")
    ap.add_argument("--code-keys", default="old,new",
                    help="record keys whose string values keep comment-only semantics")
    ap.add_argument("--manifest-out")
    ap.add_argument("--ledger")
    ap.add_argument("--readme-out")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--check-records", nargs=2, metavar=("SNAPSHOT", "RECORDS"))
    ap.add_argument("--old-keys", default=",".join(OLD_KEYS))
    ap.add_argument("--source-keys", default=",".join(SOURCE_KEYS))
    ap.add_argument("--manifest-diff", nargs=2, metavar=("OLD", "NEW"))
    ap.add_argument("--version", action="version", version=TOOL_VERSION)
    return ap.parse_args(argv)


_LABELLED = re.compile(r"^(root|agents\d*):(.+)$")


def load_line_list(path, flag):
    """P32: '<tree-relative path>:<line>' entries, optionally prefixed by a
    tree label ('agents2:notes.md:4'); '#' comments and blank lines skipped.
    -> [(entry, label or None, rel, line)]."""
    if not os.path.isfile(path):
        raise Refuse("%s file missing" % flag)
    out, bad = [], 0
    with open(path, "rb") as f:
        text = f.read().decode("utf-8", "replace")
    for raw in text.split("\n"):
        entry = raw.split("#", 1)[0].strip() if raw.lstrip().startswith("#") else raw.strip()
        if not entry:
            continue
        pth, _sep, num = entry.rpartition(":")
        if not pth or not num.isdigit() or int(num) < 1:
            bad += 1
            continue
        m = _LABELLED.match(pth)
        label, rel = (m.group(1), m.group(2)) if m else (None, pth)
        rel = rel[2:] if rel.startswith("./") else rel
        out.append((entry, label, rel, int(num)))
    if bad:
        raise Refuse("%d malformed %s entr(y/ies) (want <tree-relative path>:<line>)" % (bad, flag))
    return out


def overrides_report(entries, results, skipped, names, kind):
    """-> (applied, stale rows): an entry is STALE when no file of a tree
    has that path (or only a binary does), the line does not exist, or the
    line carries no listed token."""
    applied, rows = 0, []
    for entry, lab, rel, ln in entries:
        rs = [r for r in results if r.rel == rel and (lab is None or r.label == lab)]
        reason = None
        if not rs:
            reason = ("binary" if any(sr == rel and (lab is None or sl == lab) and why == "binary"
                                      for sl, sr, why in skipped) else "no_such_file")
        else:
            text = rs[0].old_bytes.decode(rs[0].codec)
            lines = text.split("\n")
            n = len(lines) - (1 if text.endswith("\n") else 0)
            if not 1 <= ln <= n:
                reason = "no_such_line"
            elif not names.find(lines[ln - 1]) and "\\u" not in lines[ln - 1]:
                reason = "no_listed_token"
        if reason:
            hits = names.find_mask_unambiguous(entry)
            shown = splice(entry, hits) if hits else entry
            rows.append({"kind": kind + "_stale", "entry": shown, "reason": reason})
        else:
            applied += 1
    return applied, rows


def exit_line(rc, t, extra=()):
    """P34: the LAST stdout line of every run -- its exit status and, for a
    non-zero one, every reason with the figure behind it."""
    reasons = []
    if t["records_refused"]:
        by = {}
        for reason in t["records_refused_reasons"]:
            by[reason] = by.get(reason, 0) + 1
        reasons.append("records refused %d (%s)" % (
            t["records_refused"], ", ".join("%s %d" % kv for kv in sorted(by.items()))))
    if t["paths_with_listed_token"]:
        reasons.append("file paths carrying an unambiguous token %d (masked)"
                       % t["paths_with_listed_token"])
        if t["identifier_named_files"]:
            reasons.append("identifier-named files %d (written as is)" % t["identifier_named_files"])
    if t["c_hunks_outside_comment"]:
        reasons.append("C/C++ hunks outside comment context %d" % t["c_hunks_outside_comment"])
    reasons.extend(extra)
    if rc == 0:
        excused = []
        if t["spare_lines"]["tokens"]:
            excused.append("operator-spared tokens %d" % t["spare_lines"]["tokens"])
        cit = sum(t["citation_left_by_tree"].values())
        if cit:
            excused.append("citation group tokens %d" % cit)
        return "exit 0: no refusal, no residue%s%s" % (
            " (%s, excused)" % ", ".join(excused) if excused else "",
            "; identifier-named files %d (written as is)" % t["identifier_named_files"]
            if t["identifier_named_files"] else "")
    return "exit %d: %s" % (rc, "; ".join(reasons) or "unexplained (a defect: report it)")


def _within(path, top):
    a, b = os.path.realpath(path), os.path.realpath(top)
    return a == b or a.startswith(b.rstrip(os.sep) + os.sep)


def _jsonl(rows):
    return "".join(json.dumps(r, ensure_ascii=True, sort_keys=True) + "\n" for r in rows)


def run(args, out):
    if args.check_records:
        return check_records(args.check_records[0], args.check_records[1],
                             tuple(k for k in args.old_keys.split(",") if k),
                             tuple(k for k in args.source_keys.split(",") if k), out)
    if args.manifest_diff:
        return manifest_diff(args.manifest_diff[0], args.manifest_diff[1], args.ledger, out)

    names = NameList.load(args.names)          # P1: before any read of a tree
    names.set_membership(args.unambiguous_names, args.ambiguous_names, args.identifier_names,
                         root=args.root, dictionary=args.dictionary)
    global CODE_KEYS, CITATIONS
    CODE_KEYS = set(k for k in args.code_keys.split(",") if k)
    CITATIONS = bool(args.citations_published)
    trees = [("root", args.root)] if args.root else []
    if len(args.agents) == 1:
        trees.append(("agents", args.agents[0]))
    else:
        trees.extend(("agents%d" % (i + 1), d) for i, d in enumerate(args.agents))
    if not trees:
        raise Refuse("one of --root / --agents is required")
    force = load_line_list(args.force_lines, "--force-lines") if args.force_lines else []
    spare = load_line_list(args.spare_lines, "--spare-lines") if args.spare_lines else []
    both = set((l, r, n) for _e, l, r, n in force) & set((l, r, n) for _e, l, r, n in spare)
    if both:
        raise Refuse("%d line(s) in both --force-lines and --spare-lines" % len(both))
    FORCE_MAP.clear()
    SPARE_MAP.clear()
    for entries, mp in ((force, FORCE_MAP), (spare, SPARE_MAP)):
        for _e, l, r, n in entries:
            mp.setdefault((l, r), set()).add(n)
    if args.apply and args.agents and not args.root:
        raise Refuse("--apply with --agents needs --root in the same invocation (P16): "
                     "the quote index is built from the snapshot; nothing written")
    for lab, d in trees:
        if not os.path.isdir(d):
            raise Refuse("--%s is not a directory" % lab)
    if not args.ledger:
        raise Refuse("--ledger is required")
    if args.apply and not (args.manifest_out and args.readme_out):
        raise Refuse("--apply requires --manifest-out and --readme-out")
    for o in (args.ledger, args.manifest_out, args.readme_out):
        if o and any(_within(o, d) for _l, d in trees):
            raise Refuse("an output path lies inside a scanned tree")

    results, counts, skipped = walk(trees, names)   # every check runs here, before any write
    index_built = walk.index_built
    t = totals(results, counts, names, args.apply)
    f_applied, f_rows = overrides_report(force, results, skipped, names, "force")
    s_applied, s_rows = overrides_report(spare, results, skipped, names, "spare")
    t["force_lines"] = {"entries": len(force), "applied": f_applied, "stale": len(f_rows),
                        "tokens": sum(ch.ctxs.count("f") for r in results
                                      for ch in r.changes.values())}
    t["spare_lines"] = {"entries": len(spare), "applied": s_applied, "stale": len(s_rows),
                        "tokens": sum(1 for r in results for _i, _c, w, _m in r.left
                                      if w == "spared")}
    t["by_class"] = by_class(results)
    t["left_by_tree"] = left_by_tree(results)
    t["quote_index_built"] = index_built
    t["agents_trees"] = {lab: os.path.basename(os.path.normpath(d))
                         for lab, d in trees if lab.startswith("agents")}
    rows = ledger_rows(results, names, args.apply)
    for lab, rel, reason in skipped:
        rows.append({"kind": "skipped", "file": display_path(lab, rel, names)[0],
                     "reason": reason})
    rows.extend(f_rows + s_rows)
    for r in results:
        hits = path_hits(r.label, r.rel, names)
        if hits:
            shown, psha = display_path(r.label, r.rel, names)
            row = {"kind": "path_tokens", "file": shown, "hits": hits}
            if psha:
                row["path_sha256"] = psha
            rows.append(row)
    for r in results:
        if r.nul_count:
            rows.append({"kind": "text_with_nul", "file": display_path(r.label, r.rel, names)[0],
                         "nul_bytes": r.nul_count, "lines_changed": len(r.changes),
                         "left": len(r.left)})
    report = [
        "redact_names: %s" % ("APPLY" if args.apply else "DRY RUN (nothing written to the trees)"),
        "names: %d lines, %d tokens listed, %d dropped (shorter than %d), %d duplicates"
        % (t["names_lines"], t["tokens_listed"], t["tokens_dropped_short"], MIN_TOKEN_LEN,
           t["tokens_duplicate"]),
        "files: %d seen = %d scanned + %d binary + %d not regular"
        % (t["files_seen"], t["files_scanned"], t["files_skipped_binary"],
           t["files_skipped_not_regular"]),
        "%s: %d files (%d snapshot, %d agents), %d lines, %d tokens -> %s (%d in quoted copies)"
        % ("changed" if args.apply else "would change", t["files_changed"],
           t["files_changed_root"], t["files_changed_agents"],
           t["lines_changed"], t["tokens_replaced"], PLACEHOLDER,
           t["tokens_replaced_quoted_copies"]),
        "code occurrences left: %d (ledger kind=code_left, file:line)" % t["code_occurrences_left"],
        "records refused: %d (eligible tokens in them: %d)"
        % (t["records_refused"], t["refused_eligible_tokens"]),
        "file paths carrying a listed token: %d" % t["paths_with_listed_token"],
        "identifier-named files: %d (written as is; not an exit condition)"
        % t["identifier_named_files"],
        "quote index: %s; in quoted copies: %d tokens"
        % ("built (--root and --agents in one invocation)" if index_built else
           "NOT built (needs --root and --agents together); quoted copies not mapped",
           t["tokens_replaced_quoted_copies"]),
        "binary files skipped: %d, not regular: %d (each named in the ledger, kind=skipped)"
        % (t["files_skipped_binary"], t["files_skipped_not_regular"]),
        "P10: C/C++ files changed %d, diff hunks %d, hunks outside comment context %d"
        % (t["c_files_changed"], t["c_hunks"], t["c_hunks_outside_comment"]),
    ]
    for lab, _d in trees:
        rs = [r for r in results if r.label == lab]
        lw = t["left_by_tree"].get(lab, {})
        # citation groups (P27/P28) and operator-spared lines (P32) are
        # printed under their own labels, so "left unambiguous" stays the
        # residue figure it was before the flag
        lwc = {w: v for w, v in lw.items() if w not in ("citation", "spared")}
        report.append("tree %s (%s): %d files scanned, %d changed, %d lines, %d tokens; "
                      "left unambiguous %d, ambiguous %d, identifier %d; citation %d; spared %d" % (
                          lab, tree_kind(lab), len(rs), sum(1 for r in rs if r.changes),
                          sum(len(r.changes) for r in rs),
                          sum(len(ch.spans) for r in rs for ch in r.changes.values()),
                          sum(v.get("unambiguous", 0) for v in lwc.values()),
                          sum(v.get("ambiguous", 0) for v in lwc.values()),
                          sum(v.get("identifier", 0) for v in lwc.values()),
                          sum(lw.get("citation", {}).values()),
                          sum(lw.get("spared", {}).values())))
    for lab, d in sorted(t["attribution_forms_by_tree"].items()):
        report.append("attribution forms replaced (P26) %s: %s" % (
            lab, ", ".join("%s %d" % (f, d[f]) for f in ("possessive", "from", "by", "thanks to",
                                                         "courtesy of") if f in d)))
    if args.force_lines:
        fl = t["force_lines"]
        report.append("force-lines: %d entries, %d applied, %d stale, %d tokens forced"
                      % (fl["entries"], fl["applied"], fl["stale"], fl["tokens"]))
    if args.spare_lines:
        sl = t["spare_lines"]
        report.append("spare-lines: %d entries, %d applied, %d stale, %d tokens spared"
                      % (sl["entries"], sl["applied"], sl["stale"], sl["tokens"]))
    for lab, d in sorted(t["attribution_rules_by_tree"].items()):
        report.append("attribution rules replaced (P29) %s: %s" % (
            lab, ", ".join("%s %d" % (k, d[k]) for k in ("lead", "date", "subject", "placeholder",
                                                          "initial", "url") if k in d)))
    report.append("ambiguous sentence-subject left (residual class): %s" % (
        ", ".join("%s %d" % kv for kv in sorted(t["subject_left_ambiguous_by_tree"].items()))
        or "none"))
    if CITATIONS:
        report.append("citation (published authorship) left: %s" % (
            ", ".join("%s %d" % kv for kv in sorted(t["citation_left_by_tree"].items()))
            or "none"))
    for r in results:
        if r.nul_count:
            report.append("text with embedded NUL %s: %d NUL byte(s), %d lines changed, %d left"
                          % (display_path(r.label, r.rel, names)[0], r.nul_count,
                             len(r.changes), len(r.left)))
    for lab, _d in trees:
        lw = t["left_by_tree"].get(lab, {})
        apart = ("code", "citation", "spared")
        g_out = sum(v.get("unambiguous", 0) for w, v in lw.items() if w not in apart)
        a_out = sum(v.get("ambiguous", 0) for w, v in lw.items() if w not in apart)
        i_out = sum(v.get("identifier", 0) for w, v in lw.items() if w not in apart)
        report.append("left outside source code: %s unambiguous %d, ambiguous %d (left by rule), "
                      "identifier %d (excused); in source code: unambiguous %d, ambiguous %d, "
                      "identifier %d" % (
                          lab, g_out, a_out, i_out, lw.get("code", {}).get("unambiguous", 0),
                          lw.get("code", {}).get("ambiguous", 0),
                          lw.get("code", {}).get("identifier", 0)))
    for cls, c in sorted(t["by_class"].items()):
        report.append("class %s: %d files changed, %d lines, %d tokens, %d code occurrences "
                      "left (of %d files scanned)"
                      % (cls, c["files_changed"], c["lines_changed"], c["tokens_replaced"],
                         c["code_occurrences_left"], c["files_scanned"]))
    for shown, lc in sorted(t["whitelist_line_counts"].items()):
        report.append("whitelist-like file %s: %d lines before, %d after"
                      % (shown, lc["before"], lc["after"]))
    degraded = bool(t["records_refused"] or t["paths_with_listed_token"]
                    or t["c_hunks_outside_comment"])

    if args.sample > 0:
        n_sampled = write_sample(results, names, sample_path(args.ledger), args.sample,
                                 "apply" if args.apply else "dry run", args.outlier_bound)
        report.append("sample written beside the ledger: %d line(s), %s"
                      % (n_sampled, os.path.basename(sample_path(args.ledger))))
    if not args.apply:
        text = _jsonl(rows + [t])
        names.guard_rows(rows + [t], "the ledger")
        names.guard_text("\n".join(report), "the report", field="summary line")
        write_atomic(args.ledger, text)
        report.append("ledger written: %d rows" % (len(rows) + 1))
        rc = 1 if degraded else 0
        report.append(exit_line(rc, t))
        out.write("\n".join(report) + "\n")
        return rc

    # --apply. Re-confirm every file is as analysed, then write.
    for r in results:
        if r.changes:
            with open(r.path, "rb") as f:
                if f.read() != r.old_bytes:
                    raise Refuse("a file changed during the run: %s"
                                 % display_path(r.label, r.rel, names)[0])
    readme = readme_paragraph(results, t, names)
    names.guard_text(readme, "the README paragraph", field="paragraph")
    for r in results:
        if r.changes:
            write_in_place(r.path, r.new_bytes)
    n_rows = write_manifest(results, args.manifest_out)
    write_atomic(args.readme_out, readme)

    # P7 / P11: the post-scan, from disk, with the same names and rules.
    post, _pc, post_skipped = walk(trees, names)
    post_rows = []
    for r in post:
        shown, _ = display_path(r.label, r.rel, names)
        for idx in sorted(r.changes):
            post_rows.append({"kind": "residue", "file": shown, "line": idx + 1,
                              "count": len(r.changes[idx].spans)})
        for idx, _reason, n in r.refused:
            post_rows.append({"kind": "residue", "file": shown, "line": idx + 1, "count": n})
    checks = [post_check(post, lab) for lab, _d in trees]
    for c in checks:
        c["binary_files_skipped"] = sum(1 for lab, _r, why in post_skipped
                                        if lab == c["tree"] and why == "binary")
        c["binary_coverage"] = (
            "binary files are not scanned or changed by this tool (named in the ledger, "
            "kind=skipped); check-records skips NUL-bearing files too; a binary is covered "
            "only by a separate binary scan")
    post_rows.extend(checks)
    residue = sum(c["comment_attribution"] + c["unambiguous_left_outside_source"]
                  + c["ambiguous_left_on_attribution_lines"] for c in checks)
    consistent = all(c["consistent"] for c in checks)
    unmatched_all = 0
    if args.root and args.agents:
        big = snapshot_text(args.root)
        okeys = tuple(k for k in args.old_keys.split(",") if k)
        skeys = tuple(k for k in args.source_keys.split(",") if k)
        for lab, d in trees:
            if not lab.startswith("agents"):
                continue
            chk, unm, unp, _rep = check_records_scan(big, d, okeys, skeys)
            unmatched_all += unm
            post_rows.append({"kind": "check_records", "tree": lab, "checked": chk,
                              "unmatched": unm, "unparsed": unp})
            report.append("check-records (same invocation) %s: %d quoted items checked, "
                          "%d UNMATCHED" % (lab, chk, unm))
    text = _jsonl(rows + [t] + post_rows)
    names.guard_rows(rows + [t] + post_rows, "the ledger")
    write_atomic(args.ledger, text)
    report.append("manifest written: %d rows; README paragraph written" % n_rows)
    for c in checks:
        report.append("post-scan %s: listed tokens in any context %d = comment/attribution %d "
                      "(residue) + left %d (code context or excused identifiers, on %d frozen "
                      "hit lines); split %s"
                      % (c["tree"], c["tokens_any_context"], c["comment_attribution"],
                         c["code_context"], c["frozen_hit_lines_excused"],
                         "consistent" if c["consistent"] else "INCONSISTENT"))
    for c in checks:
        report.append("post-scan %s: unambiguous tokens left outside source code %d + ambiguous "
                      "tokens left on attribution lines %d (residue); binary files skipped %d "
                      "(not covered here; check-records skips NUL-bearing files)"
                      % (c["tree"], c["unambiguous_left_outside_source"],
                         c["ambiguous_left_on_attribution_lines"], c["binary_files_skipped"]))
    report.append("residue %d" % residue)
    rc = 0 if (residue == 0 and consistent and not degraded and unmatched_all == 0) else 1
    extra = []
    if residue:
        extra.append("residue %d" % residue)
    for c in checks:
        if not c["consistent"]:
            extra.append("post-check split inconsistent in %s" % c["tree"])
    if unmatched_all:
        extra.append("check-records unmatched %d" % unmatched_all)
    report.append(exit_line(rc, t, extra))
    names.guard_text("\n".join(report), "the report", field="summary line")
    out.write("\n".join(report) + "\n")
    return rc


def main(argv=None, out=None):
    out = out or sys.stdout
    try:
        return run(parse(argv), out)
    except Refuse as e:
        sys.stderr.write("REFUSED: %s\n" % e)
        return 2


if __name__ == "__main__":
    sys.exit(main())
