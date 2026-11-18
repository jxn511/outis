#!/usr/bin/env python3
"""scrub_envelopes.py -- remove personal data from BUILT structure envelopes.

WHY THIS EXISTS SEPARATELY FROM pii_scrub.py.

`pii_scrub.py` cleans source files. It does not help here, because an envelope
is derived data: each node's `summary` was COPIED out of the markdown when the
envelope was built, and the embedding was computed from that copy. Scrubbing the
markdown afterwards leaves both untouched. The address is still in the retrieval
index, which is the only place it actually reaches a reader.

This is the stale-artifact defect class -- an artifact that is present,
plausible and stale. Nothing is missing, so no accounting check fires.

WHY SCRUB AND NOT EXCLUDE.

Dropping a whole node is right for a collaboration author block, which is 400
names and no physics. It is WRONG here: the finding
that prompted this was a thesis title page whose paragraph runs straight on into
the abstract. Excluding it would delete a genuinely useful summary to remove one
address. Scrub the text, keep the node, re-embed it.

WHY THE EMBEDDING IS CLEARED AND NOT LEFT ALONE.

A stale vector is the whole problem. The scrubbed summary and an embedding
computed from the UNSCRUBBED text disagree, and the vector -- not the text -- is
what retrieval matches on. Any node whose text changed has its `embedding` and
`sparse_embedding` set to null here, so it is unretrievable until re-embedded.
Failing closed: a node that vanishes from results is recoverable, an address
that stays in the index is not.

The envelope is quarantined before it is rewritten, so the pre-scrub text and
its vectors remain checkable. Dry run by default; `--apply` writes.

THE ENVELOPE INTERFACE (README.md, "The node schema"): a JSON object with a
`nodes` mapping of node id -> node; a node's reader-visible text is in
`summary` and `title`; it is reachable when `embedding` or `sparse_embedding`
is non-empty.

Exit status: 0 done (or dry run), 1 an envelope could not be read (it has not
been cleared), 2 nothing matched or the RULINGS file was refused.
"""

import argparse
import collections
import glob as globmod
import json
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pii_gate
import pii_scan
import pii_scrub

TOOL_VERSION = "scrub_envelopes.py 0.1.0"

# Node fields holding text a reader can see. `summary` is what gets embedded;
# `title` is displayed with the hit, so an address there is equally reachable.
TEXT_FIELDS = ("summary", "title")


def scrub_envelope(doc, keep_orcid=True):
    """(changed_node_ids, Counter of removals). Mutates `doc` in place."""
    removed = collections.Counter()
    changed = []
    for nid, node in doc.get("nodes", {}).items():
        hit = False
        for field in TEXT_FIELDS:
            val = node.get(field)
            if not isinstance(val, str) or not val:
                continue
            new, rem = pii_scrub.scrub_text(val, keep_orcid=keep_orcid)
            if not rem:
                continue
            node[field] = new
            for k, _v in rem:
                removed[k] += 1
            hit = True
        if hit:
            # Clear BOTH vectors. Clearing only the dense one leaves the sparse
            # index still matching on the removed token, which is exactly the
            # kind of half-fix that reads as done.
            node["embedding"] = None
            node["sparse_embedding"] = None
            node["pii_scrubbed"] = True
            changed.append(nid)
    return changed, removed


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--structure", required=True,
                    help="glob over built envelopes, e.g. 'structure/*.json'")
    ap.add_argument("--quarantine", required=True)
    ap.add_argument("--label", required=True, help="strand name, for the quarantine tree")
    ap.add_argument("--keep-orcid", action="store_true",
                    help="leave ORCIDs; strip contact addresses only (the "
                         "instance's privacy owner decides)")
    ap.add_argument("--rulings", default=None,
                    help="local RULINGS file (else $%s); the same exemptions "
                         "the scanner applies" % pii_scan.RULINGS_ENV)
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--version", action="version", version=TOOL_VERSION)
    args = ap.parse_args(argv)

    refused = pii_scan._rulings_cli(args.rulings)
    if refused:
        return refused

    # The ledger-file filter is pii_gate's ONE definition, which matches the
    # BASENAME. The reference copy of this tool tested the whole PATH
    # ("ledger" not in f), so a corpus parked under any directory whose name
    # contained the word was silently skipped -- the defect pii_gate's
    # is_ledger_artifact docstring records, still live in this second copy.
    files = sorted(f for f in globmod.glob(args.structure)
                   if not pii_gate.is_ledger_artifact(f))
    if not files:
        print("  no envelopes matched: %s" % args.structure, file=sys.stderr)
        return 2

    totals = collections.Counter()
    touched, changed_files = 0, []
    for path in files:
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError) as e:
            print("  UNREADABLE %s: %s" % (path, e), file=sys.stderr)
            totals["unreadable"] += 1
            continue

        before = len(doc.get("nodes", {}))
        changed, removed = scrub_envelope(doc, keep_orcid=args.keep_orcid)
        if not changed:
            continue
        after = len(doc.get("nodes", {}))
        # A scrub rewrites text. It must never add or drop a node; if it did,
        # the envelope's structure changed and the page/exclusion passes that
        # ran over it are no longer describing this document.
        assert after == before, "%s: node count moved %d -> %d" % (path, before, after)

        touched += len(changed)
        changed_files.append(path)
        totals.update(removed)

        if not args.apply:
            continue

        q = os.path.join(args.quarantine, args.label, os.path.basename(path))
        os.makedirs(os.path.dirname(q), exist_ok=True)
        shutil.copyfile(path, q + ".original")
        tmp = path + ".new"
        with open(tmp, "w", encoding="ascii") as fh:
            json.dump(doc, fh, ensure_ascii=True, sort_keys=True)
        os.replace(tmp, path)

    print("  envelopes scanned      : %d" % len(files))
    print("  envelopes changed      : %d" % len(changed_files))
    print("  nodes scrubbed         : %d" % touched)
    for k, v in sorted(totals.items()):
        print("    %-22s %5d" % (k, v))
    # An unreadable envelope has NOT been cleared. The reference copy counted
    # it and still exited 0; the exit convention reserves 1 for "ran with
    # degradation", which is exactly this.
    rc = 1 if totals["unreadable"] else 0
    if not args.apply:
        print("\n  DRY RUN. Nothing written. Re-run with --apply.")
        return rc

    print("  originals quarantined  : %s"
          % os.path.join(args.quarantine, args.label))
    # The scrubbed nodes are now unretrievable BY CONSTRUCTION. Name the exact
    # command that restores them, because a corpus left silently short of
    # vectors is the failure this tool would otherwise introduce.
    listing = os.path.join(args.quarantine, "%s_reembed.txt" % args.label)
    with open(listing, "w", encoding="ascii") as fh:
        fh.write("\n".join(changed_files) + "\n")
    print("  RE-EMBED REQUIRED for %d file(s); list -> %s"
          % (len(changed_files), listing))
    return rc


if __name__ == "__main__":
    sys.exit(main())
