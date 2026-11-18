#!/usr/bin/env python3
"""ledger.py -- iterate records in a way that cannot silently drop one.

The defect this makes unrepresentable. Six times in one day on the reference
instance a loop over records contained a bare `continue` that removed a record
from the corpus while only incrementing a counter, and the counters were
summarised into a line that read the same whether or not anything had been
lost. Detecting that afterwards
means remembering to check. Removing it means arranging that the loop body
cannot decline to account for a record.

    for r in records:
        if not r.eprints:
            continue                    # <- a record leaves, nothing records it

    for_each(records, handle, ledger)   # <- handle MUST return a Row

`continue` is not available inside a handler: the handler is a function, and
its RETURN VALUE is the ledger row. A handler that falls off the end returns
None, which raises. There is no path from "record entered" to "record left"
that does not pass through a written row.

Multiple conserved quantities. Records are not the only thing that leaks. The
representation merge conserved leaves perfectly while losing 73% of page
information; the citation join conserved works while reducing 13,614 edges to
3,868 integers. Conserving one measure says nothing about the others, so a Row
carries a `measures` dict of {name: (n_in, n_out)} and for_each reports the
balance per measure:

    n_in  =  n_out + dropped + source

A stage that legitimately creates -- the merge emitting supplement chunks,
tier 3 minting a PDF -- declares its source term. A stage claiming source=0
that runs positive is fabricating; one claiming source>=0 that runs negative
is losing. Both are reported; neither is inferred.

The dropped term is computed, not declared: a row with status "dropped"
carries its in-out gap into the identity, because a drop that passed through
a written, reasoned row is accounted movement, not loss. The same gap inside
an ok/skipped/failed row still flags -- that is the silent loss the identity
exists to catch.

`sources={m: None}` declares the source term UNKNOWABLE for that measure --
a chunker cannot know its leaf count before parsing. The measure is reported
with "source=unchecked" and excluded from unbalanced(); it is never an error
and never silently treated as zero. Unchecked is per measure: it does not
excuse any other measure in the same run.
"""

import collections
import json
import os
import sys
import time

Row = collections.namedtuple("Row", "status detail measures")
Row.__new__.__defaults__ = (None, None)


def ok(detail=None, **measures):
    return Row("ok", detail, measures or None)


def skipped(detail=None, **measures):
    return Row("skipped", detail, measures or None)


def dropped(detail, **measures):
    """A record deliberately removed. `detail` is REQUIRED: a drop without a
    stated reason is the defect this module exists to prevent."""
    return Row("dropped", detail, measures or None)


def failed(detail, **measures):
    return Row("failed", detail, measures or None)


class LedgerError(Exception):
    pass


def for_each(records, handler, ledger_path=None, key_of=None,
             sources=None, stream=sys.stdout, allow_duplicates=False):
    """Apply handler to every record, writing exactly one ledger row for each.

    handler(record) -> Row. Returning None raises: there is no way to process
    a record without saying what happened to it.

    sources: {measure: expected_source_term}. Omit a measure to assert it is
    conserved (source 0). Present with a value to declare deliberate creation.
    Present with None to declare the source term unknowable in advance: the
    measure is reported as unchecked and excluded from unbalanced().

    allow_duplicates: by default a repeated key raises, because the ledger
    would stop being one row per record and the accounting identity would
    silently stop meaning what it says. Some real streams legitimately carry
    repeats -- a manifest listing one key superseded on two grounds, one
    identifier cited by two parents. Refusing outright would make
    for_each inapplicable there, and the author would write a hand-rolled loop
    instead: the very thing this module exists to remove. So the strictness is
    a default with a deliberate, COUNTED override, not a wall. Every repeat is
    marked `duplicate_key` in its row and totalled as `_duplicate_key`.

    Returns (rows, balance). Balance is per measure:
        {name: {"in": .., "out": .., "source": .., "residual": ..}}
    residual != declared source means the stage is not doing what it claims.
    """
    key_of = key_of or (lambda r: r.get("id") if isinstance(r, dict) else str(r))
    sources = sources or {}
    rows = []
    counts = collections.Counter()
    totals = collections.defaultdict(lambda: [0, 0, 0])  # measure -> [in, out, dropped]
    seen_keys = set()

    fh = None
    if ledger_path:
        os.makedirs(os.path.dirname(os.path.abspath(ledger_path)), exist_ok=True)
        fh = open(ledger_path + ".new", "w", encoding="ascii", errors="replace")

    try:
        for rec in records:
            key = key_of(rec)
            row = handler(rec)
            if row is None:
                raise LedgerError(
                    "handler returned None for %r. Every record must yield a "
                    "Row: use ledger.ok/skipped/dropped/failed. A handler that "
                    "falls off the end is the silent-drop defect." % (key,))
            if not isinstance(row, Row):
                raise LedgerError("handler returned %r, not a Row" % type(row))
            if row.status == "dropped" and not row.detail:
                raise LedgerError(
                    "record %r dropped with no stated reason" % (key,))
            dup = key in seen_keys
            if dup and not allow_duplicates:
                raise LedgerError(
                    "duplicate key %r: the ledger would not be one row per "
                    "record. If this stream legitimately carries repeats, pass "
                    "allow_duplicates=True -- deliberately, and it is counted."
                    % (key,))
            seen_keys.add(key)
            counts[row.status] += 1
            if dup:
                counts["_duplicate_key"] += 1
            for m, pair in (row.measures or {}).items():
                a, b = pair if isinstance(pair, (tuple, list)) else (pair, pair)
                totals[m][0] += a
                totals[m][1] += b
                if row.status == "dropped":
                    # A reasoned drop's gap is accounted movement. The
                    # same gap in any other status stays in the residual.
                    totals[m][2] += a - b
            out = {"key": key, "status": row.status, "detail": row.detail,
                   "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
            if dup:
                out["duplicate_key"] = True
            if row.measures:
                out["measures"] = {k: list(v) if isinstance(v, (tuple, list))
                                   else [v, v] for k, v in row.measures.items()}
            rows.append(out)
            if fh:
                fh.write(json.dumps(out, ensure_ascii=True, sort_keys=True) + "\n")
                # Flush per row, AT THE .new PATH. Rows are readable mid-run
                # only at ledger_path + ".new"; the documented path appears at
                # the final rename (an earlier comment here claimed the
                # documented path was live mid-run, which is how a watcher
                # ends up reading a file that does not exist yet).
                # Without the flush a long job is indistinguishable from a
                # hung one, which cost two misdiagnoses on the reference
                # instance.
                fh.flush()
    finally:
        if fh:
            fh.close()
    if ledger_path:
        os.replace(ledger_path + ".new", ledger_path)

    balance = {}
    for m, (a, b, d) in sorted(totals.items()):
        declared = sources.get(m, 0)
        # residual honours the documented identity n_in = n_out + dropped +
        # source: it is the creation the stage exhibited AFTER crediting its
        # reasoned drops. Balanced when it equals the declared source term.
        balance[m] = {"in": a, "out": b, "dropped": d,
                      "declared_source": declared,
                      "residual": b + d - a}

    if stream:
        stream.write("  records: %d\n" % len(rows))
        for s, n in sorted(counts.items()):
            if s == "_duplicate_key":
                stream.write("    %-10s %d  (repeats, allowed explicitly)\n"
                             % ("duplicate", n))
            else:
                stream.write("    %-10s %d\n" % (s, n))
        for m, bal in balance.items():
            if bal["declared_source"] is None:
                src, flag = "unchecked", ""
            else:
                src = "%+d" % bal["declared_source"]
                flag = ("" if bal["residual"] == bal["declared_source"]
                        else "  <-- UNBALANCED")
            drop = " dropped=%d" % bal["dropped"] if bal["dropped"] else ""
            stream.write("    measure %-10s in=%d out=%d%s source=%s residual=%+d%s\n"
                         % (m, bal["in"], bal["out"], drop, src,
                            bal["residual"], flag))
        if ledger_path:
            stream.write("    ledger -> %s\n" % ledger_path)
    return rows, balance


def unbalanced(balance):
    """Measures whose residual does not match the declared source term.
    A measure declared unknowable (source None) is unchecked, never
    unbalanced -- and never excuses any other measure."""
    return [m for m, b in balance.items()
            if b["declared_source"] is not None
            and b["residual"] != b["declared_source"]]
