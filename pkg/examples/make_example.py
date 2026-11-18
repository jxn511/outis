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
    <dir>/corpus/                      a corpus of every file type `outis.py clean`
                                       takes, with planted findings, synthetic
                                       names and must-survive items
    <dir>/names.txt                    the synthetic roster for that corpus
    <dir>/planted.json                 what was planted, by kind and count

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


# --- the corpus `outis.py clean` runs on (X16) -------------------------------
# Synthetic names, one per line: the ROSTER. Each word is one listed token.
# Max and Ada (three letters or fewer) and De (a particle) are AMBIGUOUS by
# the name tool's own rule; Kestrel is also a code identifier in the corpus,
# so the tool classes it IDENTIFIER; the rest are UNAMBIGUOUS.
NAMES_FILE = "\n".join([
    "# synthetic roster for the Outis example; no real person carries these names",
    "Quentara Velsmith",
    "Orvald Pymbridge",
    "Ada De Wilde",
    "Max Holloway",
    "Mira Kestrel",
    "",
])

# Items that must come through `outis.py clean` UNCHANGED.
MUST_SURVIVE = [
    ("notes/analysis.md", "the De Morgan rule"),            # rule name, ambiguous token
    ("notes/analysis.md", "a max-likelihood fit"),          # hyphenated compound
    ("steering/run_fit.py", "kestrel = 0.5"),               # code identifier = a name
    ("notes/analysis.md", "A. Author, B. Writer"),          # published authorship
    ("notes/analysis.md", "0000-0001-" + "2345-678X"),      # ORCID, published
]


def corpus_files():
    """{relpath: text or bytes} and the planted record (counts by kind)."""
    a1 = addr("jdoe", "lab")
    a2 = addr("q.velsmith", "inst")
    a3 = addr("opymbridge", "uni")
    ent = "q.velsmith&#64;" + site("inst")            # entity-encoded address
    home = "/" + "home" + "/" + "jdoe" + "/runs/2026"
    orcid = "0000-0001-" + "2345-678X"
    pem = ("-----BEGIN OPENSSH PRIVATE" + " KEY-----\n"
           "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
           "-----END OPENSSH PRIVATE" + " KEY-----\n")
    files = {
        "notes/analysis.md": "\n".join([
            "# Branching-fraction study (synthetic)",
            "",
            "Authors: A. Author, B. Writer (ORCID " + orcid + ")",
            "Referees: Quentara Velsmith, Max Holloway",
            "",
            "We use a max-likelihood fit and the De Morgan rule to combine vetoes.",
            "Inputs were staged under " + home + " before the fit.",
            "Questions to " + a1 + " please.",
            "Written by Orvald Pymbridge.",
            ""]),
        "paper/draft.tex": "\n".join([
            "\\documentclass{article}",
            "\\begin{document}",
            "Contact: " + a3,
            "The measurement uses the full sample.",
            "\\end{document}",
            ""]),
        "logs/session.txt": "\n".join([
            "[jdoe" + AT + "node7 ~]$ ls runs",
            "then ssh jdoe" + AT + "192.0.2.10 and copy the ntuples",
            ""]),
        "decay/B0_example.dec": "\n".join([
            "# B0 decay table (synthetic)",
            "# Author: Ada De Wilde",
            "Decay B0",
            "1.0000 K+ pi- PHSP;",
            "Enddecay",
            "End",
            ""]),
        "decay/particles.table": "\n".join([
            "# particle table (synthetic), maintained by Max Holloway",
            "PARTICLE B0 5.27966 0.0 0",
            ""]),
        "steering/run_fit.py": "\n".join([
            "# Steering for the example fit.",
            "# Written by Quentara Velsmith",
            "kestrel = 0.5",
            assign_line("password", "Zq7xK2pwX9"),
            "print(kestrel)",
            ""]),
        "src/fit.cc": "\n".join([
            "// fit.cc -- Author: Orvald Pymbridge",
            "const char* kTok = \"" + "glpat" + "-" + "Zq7xK2pwX9abcdef0123" + "\";",
            "int main() { return 0; }",
            ""]),
        "data/runs.csv": "\n".join([
            "run,events,contact",
            "101,5000," + a1,
            ""]),
        "records/meta.json": json.dumps({"title": "example record", "maintainer": a2,
                                         "events": 5000}, sort_keys=True) + "\n",
        "records/log.jsonl": "".join(json.dumps(r, sort_keys=True) + "\n" for r in (
            {"msg": "run 101 done", "who": "shift crew"},
            {"msg": "mail " + a3 + " about run 102", "who": "shift crew"})),
        "threads/thread-001.html": "\n".join([
            "<html><body>",
            "<p>From: Quentara Velsmith &lt;" + ent + "&gt;</p>",
            "<p>The fit converges.</p>",
            "</body></html>",
            ""]),
        "keys/deploy_key.txt": "deploy key, do not share:\n" + pem,
        "bin/hist.bin": bytes(range(256)) * 4,
    }
    planted = {
        # pii_scrub kinds the clean must remove, by count
        "removed_by_kind": {
            "address": 5, "confidential_role_line": 1, "contact_value": 1,
            "credential": 1, "gitlab_token": 1, "home_path": 1,
            "host_account": 1, "private_key": 1, "shell_prompt": 1},
        "binary_files": ["bin/hist.bin"],
        "names_unambiguous_planted": ["Quentara", "Velsmith", "Orvald", "Pymbridge",
                                      "Wilde", "Holloway"],
        "must_survive": [list(x) for x in MUST_SURVIVE],
    }
    return files, planted


def assign_line(key, value):
    return key + " = " + '"' + value + '"'


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
    corpus, planted = corpus_files()
    files.update((os.path.join("corpus", k), v) for k, v in corpus.items())
    files["names.txt"] = NAMES_FILE
    files["planted.json"] = json.dumps(planted, sort_keys=True, indent=1) + "\n"
    for rel, text in sorted(files.items()):
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        if isinstance(text, bytes):
            with open(p, "wb") as fh:
                fh.write(text)
            continue
        with open(p, "w", encoding="ascii") as fh:
            fh.write(text)
    # Reported from what was written, after it was written.
    print("  example written: %d files under %s (the corpus for outis.py clean: %s)"
          % (len(files), root, os.path.join(root, "corpus")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
