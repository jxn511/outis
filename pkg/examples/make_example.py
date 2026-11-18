#!/usr/bin/env python3
"""make_example.py -- write the tiny synthetic corpus the README's commands run on.

    python3 examples/make_example.py <empty-or-new directory>

WHY A GENERATOR AND NOT A SHIPPED TREE. The example must FAIL the gate before
it is scrubbed -- that is what it demonstrates -- and the package must PASS its
own gate. A dirty tree shipped inside the package would make the second
impossible. So the dirty values are assembled at run time from fragments
(tests/_support.py records the same convention) and written OUTSIDE the
package.

Every value is synthetic. Addresses that must be scrubbed or ruled use the
top-level label `zz` (an ISO 3166-1 user-assigned code, never delegated), so
no real mailbox can be named; names are placeholders.

What it writes:

    <dir>/markdown/note-001/paper.md   the converted source (S1)
    <dir>/structure/note-001.json      its envelope (S2/S3): nodes with
                                       summary, title, embedding, sparse_embedding
    <dir>/corpora.registry             the corpus registry pii_gate.py reads
    <dir>/RULINGS                      two local rulings in the RULINGS.template form

Exit status: 0 written, 2 the directory exists and is not empty.
"""

import json
import os
import sys

AT = "@"
TLD = "z" + "z"


def site(label):
    return label + "." + TLD


def addr(local, label):
    return local + AT + site(label)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        sys.stderr.write("usage: make_example.py <directory>\n")
        return 2
    root = argv[0]
    if os.path.isdir(root) and os.listdir(root):
        sys.stderr.write("REFUSED: %s exists and is not empty\n" % root)
        return 2

    person = addr("jdoe", "lab")                       # must be scrubbed
    desk = addr("desk", "service")                     # ruled: an office address
    officer = addr("officer", "grants.agency")         # ruled: domain class
    home = "/" + "home" + "/" + "jdoe" + "/calib/v3"   # must be scrubbed
    orcid = "0000-0001-" + "2345-678X"                 # published identifier

    paper = "\n".join([
        "# Calibration of the example detector",
        "",
        "Authors: A. Author, B. Writer",
        "Referees: C. Reviewer, D. Checker",
        "Contact: " + person,
        "",
        "The calibration constants are stored under " + home + ".",
        "Questions about the service go to " + desk + ".",
        "Programme questions go to " + officer + ".",
        "",
    ])
    envelope = {"doc_id": "note-001", "nodes": {
        "n0": {"title": "Calibration of the example detector",
               "summary": "Referees: C. Reviewer, D. Checker\nContact: " + person
                          + "\nThe calibration constants are described.",
               "embedding": [0.12, 0.34, 0.56], "sparse_embedding": {"17": 0.8}},
        "n1": {"title": "Method",
               "summary": "The constants are fitted per run; questions go to "
                          + desk + ".",
               "embedding": [0.21, 0.43, 0.65], "sparse_embedding": {"5": 0.4}},
        "n2": {"title": "Authors",
               "summary": "A. Author (ORCID " + orcid + ")",
               "embedding": [0.31, 0.53, 0.75], "sparse_embedding": None},
        "n3": {"title": "Withdrawn draft text",
               "summary": "Contact: " + person,
               "embedding": None, "sparse_embedding": None},
    }}
    rulings = "\n".join([
        "# Local rulings for the example corpus (RULINGS.template form).",
        "address:" + desk + " | EXEMPT | a published service desk: an office, "
        "not a person | privacy owner | 2026-11-17",
        "domain:" + site("agency") + " | EXEMPT | illustration of a domain-class "
        "ruling; a real one cites an external oracle | privacy owner | 2026-11-17",
        "",
    ])
    registry = "\n".join([
        "# label | structure glob | markdown root (or -)",
        "example | structure/*.json | markdown",
        "",
    ])

    files = {
        os.path.join("markdown", "note-001", "paper.md"): paper,
        os.path.join("structure", "note-001.json"):
            json.dumps(envelope, sort_keys=True, indent=1) + "\n",
        "RULINGS": rulings,
        "corpora.registry": registry,
    }
    for rel, text in sorted(files.items()):
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="ascii") as fh:
            fh.write(text)
    # Reported from what was written, after it was written.
    print("  example corpus written: %d files under %s" % (len(files), root))
    return 0


if __name__ == "__main__":
    sys.exit(main())
