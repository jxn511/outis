#!/usr/bin/env python3
"""pii_gate.py -- the SECOND sieve. Gate what a reader can reach, not just what
came in.

The ingress scan (pii_scan.py) inspects material on the way in. That is
necessary and it is provably not sufficient, because the corpus is a
derivation chain:

    source -> markdown -> envelope.summary -> vector -> index
      S0        S1            S2               S3       S4

The property that matters is `for all k: PII(S_k) = {}`. An ingress scan
establishes `PII(S0) = {}` AT TIME t and says nothing about any S_k derived at
t' < t. Scrubbing is not a fixpoint over the pipeline unless it is applied to
the transitive closure of what was derived from the thing scrubbed.

WHAT THAT COSTS, MEASURED. On the reference instance one paper had its markdown
scrubbed and the original quarantined. The scrub was correct and it was
recorded as done. Its ENVELOPE still carried three named internal referees,
because the envelope was built before the scrub and never rebuilt -- so the
names stayed in the retrieval index, which is the only place they reach a
reader. Found, fixed, recorded as fixed, and still exposed.

That is the human-factors core of it. The dangerous state is not "unknown", it
is "marked done", because a done marker is exactly what stops anyone looking
again.

TWO SIEVES, AND THEY MUST READ DIFFERENT THINGS.

    ingress   source files, before any processing        (pii_scan.py)
    egress    `summary` and `title` of every node THAT HAS AN EMBEDDING

Two sieves over the same representation are one sieve run twice. Egress is
authoritative because "no personal data is retrievable" is a property of the
index, not of the source.

DISAGREEMENT IS THE PRODUCT, NOT A NUISANCE.

When egress finds what ingress has cleared, that is not merely a catch -- it is
evidence that a propagation path is broken, and it is the only symptom such a
break produces. Fixing it quietly destroys the signal. So the disagreement is
counted and reported separately from the findings themselves.

BLOCKING VERSUS RECORDED.

The line is PUBLISHED versus CONFIDENTIAL, not names versus not-names. An ORCID
is published beside the author list and is public by construction; a contact
address never is. If every finding blocked, the 27,795 ORCIDs of the reference
corpus would have held the gate red permanently -- and a gate that cannot reach
green trains the habitual bypass that destroys it. So the partition is
structural, and RECORDED is a short explicit allowlist while everything else
blocks by default. Fail closed: a new detector is blocking until someone rules
otherwise.

A REPORT OF PERSONAL DATA MUST NOT CONTAIN THE PERSONAL DATA. This tool prints
kinds, counts and locations. Never values.

WHAT THE INSTANCE SUPPLIES (nothing is built in):

    --corpus label:structure_glob[:markdown_root]    repeatable, or
    --registry FILE     one corpus per line: label | structure_glob | markdown_root or -
                        (relative paths resolve against the registry file's directory)
    --inventory-root DIR   every *.json under DIR must be covered by a registered
                        glob; an uncovered envelope is a BLOCKING finding
    --status FILE       the verdict sentinel (written only when given)

The node schema the gate reads is documented in README.md ("The node schema").
"""

import argparse
import collections
import datetime
import glob as globmod
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pii_scan

TOOL_VERSION = "pii_gate.py 0.1.0"

# Published identity: counted and printed, never blocking. Deliberately short.
# Anything absent from this set blocks, so a detector added later is blocking
# until a human rules on it -- the fail-closed direction.
RECORDED = frozenset(["orcid"])

# The node fields a reader can see. `summary` is what gets embedded; `title` is
# displayed with the hit, so an address there is equally reachable.
TEXT_FIELDS = ("summary", "title")
# A node is reachable -- in the index -- when either vector is non-empty.
VECTOR_FIELDS = ("embedding", "sparse_embedding")


class RegistryError(ValueError):
    """A malformed corpus registry row; carries the 1-based line number."""


# The verdict sentinel. An exit code does not survive a pipeline -- `gate |
# tail; echo $?` prints 0 under a FAILED banner because $? binds to the last
# command, and that trap fired on the reference instance's first invocation and
# again during a review, so a warning in the documentation demonstrably does
# not stop a careful reader. The verdict therefore also lands in a FILE,
# written from the SAME blocking count that sets the exit code, so the two
# cannot disagree. Consumers read the file:  grep -qx 'status=GREEN' <path>
def write_status(path, verdict, blocking):
    """Atomically record the gate verdict. `blocking` None means unknown --
    the run did not complete, which is its own verdict (ERROR, fail closed)."""
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    tmp = path + ".new"
    with open(tmp, "w", encoding="ascii") as fh:
        fh.write("status=%s\n" % verdict)
        fh.write("blocking=%s\n" % ("unknown" if blocking is None else blocking))
        fh.write("checked_at=%s\n" % now.isoformat().replace("+00:00", "Z"))
        fh.write("tool=%s\n" % TOOL_VERSION)
    os.replace(tmp, path)


def is_blocking(kind):
    return kind not in RECORDED


def is_ledger_artifact(path):
    """Is this file a run ledger rather than an envelope?

    THE ONE DEFINITION, imported by every caller that walks a strand (this
    module twice, scrub_envelopes), because copies of `"ledger" not in f` were
    the same predicate written several times, and the loosest one wins by
    default.

    It matches the BASENAME. The substring form read the whole path, so any
    parent directory carrying the word emptied the scan: park the corpus under
    a directory named `ledgers/`, or run a test whose temporary directory is
    named after it, and every envelope beneath silently leaves the sieve while
    the gate still reports GREEN -- a membership filter that does not report
    itself. Pinned by test_a_parked_corpus_directory_does_not_hide_a_strand.
    """
    return "ledger" in os.path.basename(path)


def retrievable_nodes(pattern):
    """(envelope_path, node_id, text) for every node a reader can actually reach.

    "Reachable" means it carries a vector. A node with `embedding` None is not
    in the index -- that is how scrub_envelopes takes something out of
    circulation -- so scanning it would report exposure that does not exist and
    dilute the findings that do.
    """
    for path in sorted(f for f in globmod.glob(pattern)
                       if not is_ledger_artifact(f)):
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
            nodes = doc.get("nodes", {})
            items = list(nodes.items())
        except (OSError, ValueError, AttributeError):
            # Unreadable is a FINDING, never a pass: the gate fails closed.
            yield path, None, None
            continue
        for nid, node in items:
            if not isinstance(node, dict):
                yield path, None, None
                break
            if not any(node.get(v) for v in VECTOR_FIELDS):
                continue
            parts = [node.get(f) for f in TEXT_FIELDS]
            text = "\n".join(p for p in parts if isinstance(p, str) and p)
            if text:
                yield path, nid, text


def source_is_clean(markdown_root, envelope_path, kind):
    """Does the CURRENT source for this envelope still carry `kind`?

    The source of envelope <name>.json is <markdown_root>/<name>/paper.md (the
    layout README.md documents). Used only to classify a disagreement. True
    here means ingress already cleared it and the egress finding is a stale
    derived copy -- a broken propagation path, which is a different defect from
    "never scanned".
    """
    if not markdown_root:
        return None
    doc = os.path.basename(envelope_path)[:-len(".json")]
    md = os.path.join(markdown_root, doc, "paper.md")
    if not os.path.isfile(md):
        return None
    try:
        with open(md, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return None
    return not any(k == kind for k, _l, _s, _w in pii_scan.scan_text(text, md))


def unregistered_envelopes(corpora, root):
    """Envelope files under `root` that no registered corpus glob covers.

    The two-sieve invariant is only as strong as the registry's enumeration: a
    structure tree missing from the list is invisible to the egress sieve and
    NOTHING FAILS. Materialized on the reference instance: two trees, 703
    envelopes carrying 64,023 reachable nodes, never gated. So the omission
    itself is made a blocking state: every *.json under the inventory root must
    fall inside the union of registered globs, and anything outside holds the
    gate red until a human registers it. Coverage is judged on FILES, not on
    directory names -- a name-shape check is a textual shadow of the property.
    """
    disk = set()
    for p in globmod.glob(os.path.join(root, "**", "*.json"), recursive=True):
        if not is_ledger_artifact(p):
            disk.add(os.path.normpath(os.path.abspath(p)))
    covered = set()
    for _label, pattern, _md in corpora:
        covered.update(os.path.normpath(os.path.abspath(f))
                       for f in globmod.glob(pattern)
                       if not is_ledger_artifact(f))
    return sorted(disk - covered)


def egress(corpora):
    kinds = collections.Counter()
    blocking, recorded = 0, 0
    stale = collections.Counter()      # ingress clean, egress dirty
    locations = []
    per_corpus = {}

    for label, pattern, md_root in corpora:
        c_block, c_rec, c_nodes = 0, 0, 0
        for path, nid, text in retrievable_nodes(pattern):
            if nid is None:
                kinds["unreadable_envelope"] += 1
                c_block += 1
                blocking += 1
                locations.append((label, os.path.basename(path), "-",
                                  "unreadable_envelope"))
                continue
            c_nodes += 1
            for kind, _line, _snip, _why in pii_scan.scan_text(text, path):
                kinds[kind] += 1
                if is_blocking(kind):
                    c_block += 1
                    blocking += 1
                    locations.append((label, os.path.basename(path), nid, kind))
                    if source_is_clean(md_root, path, kind):
                        stale[kind] += 1
                else:
                    c_rec += 1
                    recorded += 1
        per_corpus[label] = (c_nodes, c_block, c_rec)
    return {"kinds": kinds, "blocking": blocking, "recorded": recorded,
            "stale": stale, "locations": locations, "per_corpus": per_corpus}


def parse_corpus_spec(spec):
    """label:structure_glob[:markdown_root] -> (label, glob, root or None)."""
    bits = spec.split(":")
    if len(bits) < 2 or not bits[0] or not bits[1]:
        raise RegistryError("--corpus %r: expected label:structure_glob"
                            "[:markdown_root]" % spec)
    return (bits[0], bits[1], bits[2] if len(bits) > 2 and bits[2] else None)


def parse_registry(text, base="."):
    """[(label, glob, markdown_root or None)] from registry text.

    One corpus per line: `label | structure_glob | markdown_root or -`. Blank
    lines and `#` comments are skipped. Relative paths resolve against `base`
    (the registry file's own directory), so a registry means the same thing
    whatever directory the gate is run from. A malformed line refuses and is
    named: a registry that half-loads gates part of the corpus and reports
    green.
    """
    out, labels = [], set()
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        f = [x.strip() for x in line.split("|")]
        if len(f) != 3 or not f[0] or not f[1] or not f[2]:
            raise RegistryError("registry line %d: expected 'label | "
                                "structure_glob | markdown_root or -'" % n)
        if f[0] in labels:
            raise RegistryError("registry line %d: duplicate label %r" % (n, f[0]))
        labels.add(f[0])
        pat = f[1] if os.path.isabs(f[1]) else os.path.join(base, f[1])
        md = None
        if f[2] != "-":
            md = f[2] if os.path.isabs(f[2]) else os.path.join(base, f[2])
        out.append((f[0], pat, md))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--egress", action="store_true",
                    help="scan every RETRIEVABLE node (the authoritative sieve)")
    ap.add_argument("--corpus", action="append", default=[],
                    help="label:structure_glob[:markdown_root]; repeatable")
    ap.add_argument("--registry", default=None,
                    help="corpus registry file (label | glob | markdown_root or -)")
    ap.add_argument("--inventory-root", default=None,
                    help="every *.json under this directory must be covered by "
                         "a registered glob, or the gate fails")
    ap.add_argument("--gate", action="store_true",
                    help="exit 1 on any BLOCKING finding (recorded kinds never block)")
    ap.add_argument("--report", default=None, help="JSON report path (values omitted)")
    ap.add_argument("--status", default=None,
                    help="verdict sentinel path; written only when given")
    ap.add_argument("--rulings", default=None,
                    help="local RULINGS file (else $%s); the same exemptions "
                         "the scanner applies" % pii_scan.RULINGS_ENV)
    ap.add_argument("--version", action="version", version=TOOL_VERSION)
    args = ap.parse_args(argv)

    status_path = args.status

    def refuse(msg):
        # Every refusal stamps ERROR first when a sentinel was asked for, so a
        # previous run's GREEN never survives a run that could not judge.
        if args.gate and status_path:
            write_status(status_path, "ERROR", None)
        print("  REFUSED: %s" % msg, file=sys.stderr)
        return 2

    if not args.egress:
        return refuse("nothing to do: pass --egress")

    try:
        corpora = [parse_corpus_spec(s) for s in args.corpus]
        if args.registry:
            with open(args.registry, encoding="ascii") as fh:
                corpora += parse_registry(
                    fh.read(), os.path.dirname(os.path.abspath(args.registry)))
    except (RegistryError, OSError, UnicodeDecodeError) as e:
        return refuse(str(e))
    if not corpora:
        # There is no built-in corpus list: a gate with nothing registered
        # would scan nothing and report GREEN.
        return refuse("no corpus registered: pass --corpus or --registry")
    try:
        pii_scan.configure_rulings(args.rulings)
    except pii_scan.RulingsError as e:
        return refuse(str(e))

    if args.gate and status_path:
        # ERROR is stamped BEFORE the scan and overwritten only by a completed
        # one, so a crash mid-scan leaves ERROR on disk -- never the previous
        # run's GREEN claiming a verdict this run never reached. Fail closed.
        write_status(status_path, "ERROR", None)

    r = egress(corpora)

    # Register-or-fail: only a run given an inventory root judges the
    # inventory. Each unregistered envelope is a blocking finding folded into
    # the SAME count that sets sentinel and exit code, so the three cannot
    # disagree.
    if args.inventory_root:
        un = unregistered_envelopes(corpora, args.inventory_root)
        if un:
            r["blocking"] += len(un)
            r["kinds"]["unregistered_envelope"] += len(un)
            by_dir = collections.Counter(os.path.dirname(p) for p in un)
            print("  UNREGISTERED STRUCTURE TREES -- envelopes no corpus glob covers:")
            for d, n in sorted(by_dir.items()):
                print("    %-40s %6d envelope(s)" % (os.path.relpath(d, args.inventory_root), n))
            print("  These nodes have NEVER passed the egress sieve. Remedy:")
            print("  register the tree (--registry / --corpus), or move a")
            print("  non-corpus artifact out of the inventory root.")
            for p in un:
                r["locations"].append(("UNREGISTERED", os.path.basename(p),
                                       "-", "unregistered_envelope"))

    print("  EGRESS SIEVE -- personal data reachable by retrieval")
    print("  local rulings: %d" % len(pii_scan.active_rulings()))
    print("  %-12s %10s %10s %10s" % ("corpus", "nodes", "blocking", "recorded"))
    for label, _p, _m in corpora:
        n, b, rec = r["per_corpus"].get(label, (0, 0, 0))
        print("  %-12s %10d %10d %10d" % (label, n, b, rec))
    print()
    if r["kinds"]:
        print("  findings by kind (values omitted by design):")
        for k, n in r["kinds"].most_common():
            print("    %-24s %6d   %s" % (k, n,
                                          "RECORDED" if not is_blocking(k) else "BLOCKING"))
    else:
        print("  no findings")

    # The disagreement. Reported on its own line even at zero, because "we
    # checked and it was zero" and "we did not check" must not look alike.
    total_stale = sum(r["stale"].values())
    print()
    print("  INGRESS/EGRESS DISAGREEMENT : %d" % total_stale)
    if total_stale:
        for k, n in r["stale"].most_common():
            print("    %-24s %6d  <- source is CLEAN, index is not" % (k, n))
        print("  A stale derived artifact. The source was scrubbed and the")
        print("  envelope was not rebuilt, so the scrub never reached the index.")
        print("  Remedy: scrub_envelopes.py, then re-embed the affected files.")

    if args.report:
        with open(args.report, "w", encoding="ascii") as fh:
            json.dump({"kinds": dict(r["kinds"]),
                       "blocking": r["blocking"], "recorded": r["recorded"],
                       "disagreement": dict(r["stale"]),
                       "locations": [{"corpus": c, "envelope": e, "node": n,
                                      "kind": k} for c, e, n, k in r["locations"]]},
                      fh, ensure_ascii=True, sort_keys=True, indent=1)
        print("\n  report -> %s (values omitted by design)" % args.report)

    if args.gate and status_path:
        # Derived from the SAME count as the return value below, so sentinel
        # and exit code agree by construction.
        write_status(status_path, "RED" if r["blocking"] else "GREEN",
                     r["blocking"])

    if args.gate and r["blocking"]:
        print("\nEGRESS GATE FAILED: %d blocking finding(s) reachable by retrieval."
              % r["blocking"], file=sys.stderr)
        print("Recorded (non-blocking) kinds: %s"
              % ", ".join(sorted(RECORDED)), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
