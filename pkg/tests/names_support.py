"""Shared test support for redact_names (carried from the loop's redact_pass5): the module under test, the INVENTED
fixture tree, an independent token matcher and an independent diff checker.

The module under test is ../redact_names.py unless REDACT_NAMES_MODULE names
another copy (the mutation harness points it at a mutated one)."""

import contextlib
import hashlib
import importlib.util
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MODULE = os.environ.get("REDACT_NAMES_MODULE",
                        os.path.join(os.path.dirname(HERE), "redact_names.py"))
NAMES = os.path.join(HERE, "names_fixture_names.txt")
UNAMB = os.path.join(HERE, "names_fixture_unambiguous_names.txt")
AMBIG = os.path.join(HERE, "names_fixture_ambiguous_names.txt")
IDENT = os.path.join(HERE, "names_fixture_identifier_names.txt")
MEMBERSHIP = ["--unambiguous-names", UNAMB, "--ambiguous-names", AMBIG,
              "--identifier-names", IDENT]
AMB_TOKENS = ["De", "Re", "Max"]
AMB_RX = re.compile(r"(?<![A-Za-z0-9_-])(?:%s)(?![A-Za-z0-9_-])" % "|".join(AMB_TOKENS),
                    re.IGNORECASE)
# Outside the package tree, so a run never leaves files inside it.
TMP = os.path.join(tempfile.gettempdir(), "outis-names-tests")

# The listed tokens, written out here a second time ON PURPOSE: the tests'
# matcher must not be the tool's matcher, or a defect in it is invisible.
TOKENS = ["Alphonzo", "Bravoson", "Charlot", "Deltason", "Echoway", "Foxtrotson",
          "Golfwick", "Indiason", "Julietta", "Kiloson", "Mikel"]
TOKEN_RX = re.compile(r"(?<![A-Za-z0-9_])(?:%s)(?![A-Za-z0-9_])" % "|".join(TOKENS),
                      re.IGNORECASE)

WHITELIST = {"src/EvtGen/testEvtGen.cc": (1910, 1940),
             "src/EvtGenBase/EvtDecayTable.cc": (101, 130, 420)}
WHITELIST_LINE = "    tokenValue = parser.getToken();"


def old_form_lists(outdir):
    """Membership files that reproduce the pre-P19 form: every token
    unambiguous, the other two classes EMPTY."""
    paths = []
    for name, text in (("old_unamb.txt", open(NAMES).read()),
                       ("old_amb.txt", "# empty: the pre-P19 form\n"),
                       ("old_ident.txt", "# empty: the pre-P19 form\n")):
        p = os.path.join(outdir, name)
        with open(p, "w") as f:
            f.write(text)
        paths.append(p)
    return ["--unambiguous-names", paths[0], "--ambiguous-names", paths[1],
            "--identifier-names", paths[2]]


def load_module():
    spec = importlib.util.spec_from_file_location("redact_names_under_test", MODULE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def mkdtemp():
    os.makedirs(TMP, exist_ok=True)
    return tempfile.mkdtemp(dir=TMP)


def _numbered_cc(total, header, specials):
    lines = list(header)
    while len(lines) < total:
        n = len(lines) + 1
        if n in specials:
            lines.append(specials[n])
        else:
            lines.append("    acc += %d;" % (n % 7))
    return "\n".join(lines) + "\n"


TEST_EVTGEN_HEADER = [
    "// testEvtGen.cc (an INVENTED fixture mimicking the shape only)",
    "// Author: Alphonzo Bravoson",
    "/* Golfwick wrote the first",
    "   version; Echoway Foxtrotson 1998-03-02 */",
    "#include \"EvtGenBase/EvtPDL.hh\"",
    "int Golfwick = 0;             // Golfwick counter, by Golfwick",
    "const char* url = \"http://example.org // by Golfwick\";",
    "int Bravoson_count = 0; /* Bravoson */ int Mikelson = 1;",
    "char c = '\"'; // quote char by Indiason",
    "/* block start Charlot",
    "   Deltason continues */ int Indiason = 2; // Indiason",
    "int acc = 0;",
]

NONCANON_RECORD = ('{"source_line":"Alias Indiason K+",  "id" : "r6", '
                   '"note":"# by Golfwick", "path":"a\\/b by Golfwick", '
                   '"Golfwick":"key stays"}')
NONCANON_AFTER = ('{"source_line":"Alias Indiason K+",  "id" : "r6", '
                  '"note":"# by <name>", "path":"a\\/b by <name>", '
                  '"Golfwick":"key stays"}')

FILES = {
    "root/dec/B0_fixture.dec": (
        "# B0 fixture decay file (invented)\n"
        "# Author: Alphonzo Bravoson 2004-05-12\n"
        "# Alphonzo Bravoson 2004-05-12\n"
        "#   modified by C. Deltason\n"
        "# uses the Mikelson model; see Mikel's note\n"
        "Alias Indiason K+\n"
        "Decay B0\n"
        "1.0   Indiason pi-   PHSP; # tuned by Echoway Foxtrotson\n"
        "Enddecay\n"
        "End\n"),
    "root/dec/B0_upper.DEC": (
        "# revised by Julietta Kiloson\n"
        "Decay B+\n"
        "1.0 K+ pi0 PHSP;\n"
        "Enddecay\n"
        "End\n"),
    "root/pdl/evt.pdl": (
        "* name type (invented particle list)\n"
        "# particle list, revised by Charlot Deltason\n"
        "add  p Particle Indiason  999  1.0 0.0 0.0 0 0 0.0 1\n"
        "end\n"),
    "root/tcl/run.tcl": (
        "# set up by Golfwick\n"
        "set Golfwick 3 ;# Golfwick knob\n"
        "puts \"# Golfwick\"\n"),
    "root/txt/notes.txt": (
        "Fixture notes (invented)\n"
        "Alphonzo Bravoson 2004-05-12\n"
        "The Golfwick method is used here.  # Golfwick\n"
        "quote: \"# not a comment Golfwick\"\n"),
    "root/README_EXTRA": (
        "Contact for this tree, Charlot Deltason\n"
        "$Id: EvtFoo.cc,v 1.2 2004/05/12 deltason Exp $\n"
        "The Indiason resonance is described below.\n"),
    "root/pdt.table": (
        "# pdt table fixture, by Mikel\n"
        "  1   d   0.33\n"),
    "root/scripts/run.sh": (
        "#!/bin/sh\n"
        "# maintained by Golfwick\n"
        "label=\"Golfwick\"   # Golfwick\n"
        "echo \"$#\"\n"),
    "agents/records.jsonl": (
        '{"fixes": [{"new": "1.0   K+ pi-   PHSP;", "old": "1.0   Indiason pi-   PHSP; # tuned by Echoway Foxtrotson"}], "id": "r1"}\n'
        '{"id": "r2", "source_line": "Alias Indiason K+"}\n'
        '{"id": "r3", "line": "# Author: Alphonzo Bravoson 2004-05-12", "path": "dec/B0_fixture.dec"}\n'
        '{"Golfwick": "x", "id": "r4"}\n'
        '{"id": "r5", "note": "Golfwick ran the fit"}\n'
        # P12: NOT the canonical serialisation (key order, spacing, an escaped
        # solidus) -- edited on the raw bytes, never re-serialised
        + NONCANON_RECORD + "\n"
        # P15: a gate token in a record prose field (not attribution) is replaced
        '{"id": "r7", "note": "the fit Kiloson ran"}\n'
        # P15: a --code-keys field keeps comment-only semantics (model name kept)
        '{"id": "r8", "new": "1.0   Indiason K- PHSP; # by Golfwick"}\n'
        # P16: a prose field quoting a snapshot code line with a by-line: the
        # json-string rule (b) would replace all three, the snapshot's
        # decision leaves the identifier in code
        '{"id": "r9", "note": "int Golfwick = 0;             // Golfwick counter, by Golfwick"}\n'),
    # P13: prose types -- every occurrence replaced
    "root/logs/run.history": (
        "cd work; ran fit with Golfwick tuning\n"
        "Golfwick 2004-05-12\n"
        "plain Indiason line\n"),
    "root/NOTES": (
        "notes kept by the shift\n"
        "Indiason resonance seen, Mikel's check\n"),
    # an extensionless file with a shebang is a script (code), not prose
    "root/configure": (
        "#!/bin/sh\n"
        "# by Golfwick\n"
        "Golfwick=1\n"),
    "agents/DOC_fixture.md": (
        "# Fixture DOC (invented)\n"
        "\n"
        "Written by Julietta Kiloson.\n"
        "\n"
        "The Kiloson estimator is described below.\n"
        "\n"
        "Julietta Kiloson\n"
        "\n"
        "The snapshot line `# Alphonzo Bravoson 2004-05-12` is the header form.\n"
        "See `1.0   Indiason pi-   PHSP; # tuned by Echoway Foxtrotson` in the table.\n"),
}

TEST_EVTGEN_SPECIALS = {1909: "    // next token read here (Golfwick)",
                        1910: WHITELIST_LINE, 1940: WHITELIST_LINE}
DECAYTABLE_HEADER = ["// EvtDecayTable.cc (an INVENTED fixture mimicking the shape only)",
                     "// Modified: Julietta Kiloson 2001-07-09", "int acc = 0;"]
DECAYTABLE_SPECIALS = {100: "  // by Julietta Kiloson", 101: WHITELIST_LINE,
                       130: WHITELIST_LINE, 420: WHITELIST_LINE}


MANIFEST_HEADER = "path,sha256_pass4,sha256_pass5,change"
# class = the path's top directory; src/<pkg> under src; "root" for a file
# outside any class directory
EXPECTED_CLASSES = {"dec": 2, "pdl": 1, "src/EvtGen": 1, "src/EvtGenBase": 1, "tcl": 1,
                    "txt": 1, "scripts": 1, "logs": 1, "root": 4}


def build(base):
    """Write the INVENTED fixture tree under base; returns (root, agents)."""
    for rel, text in FILES.items():
        p = os.path.join(base, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", newline="") as f:
            f.write(text)
    p = os.path.join(base, "root/src/EvtGen/testEvtGen.cc")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", newline="") as f:
        f.write(_numbered_cc(1950, TEST_EVTGEN_HEADER, TEST_EVTGEN_SPECIALS))
    p = os.path.join(base, "root/src/EvtGenBase/EvtDecayTable.cc")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", newline="") as f:
        f.write(_numbered_cc(430, DECAYTABLE_HEADER, DECAYTABLE_SPECIALS))
    p = os.path.join(base, "root/bin/blob.bin")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(b"\x00\x01Golfwick\x00")
    return os.path.join(base, "root"), os.path.join(base, "agents")


def snapshot(top):
    """{relpath: bytes} of every file under top."""
    out = {}
    for d, _dirs, files in os.walk(top):
        for fn in files:
            p = os.path.join(d, fn)
            with open(p, "rb") as f:
                out[os.path.relpath(p, top)] = f.read()
    return out


def run_cli(*args):
    """Run the module under test as a program -> (rc, stdout, stderr)."""
    p = subprocess.run([sys.executable, MODULE] + list(args), capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def run_inproc(mod, *args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stderr(err):
        rc = mod.main(list(args), out=out)
    return rc, out.getvalue(), err.getvalue()


def only_span_diff(old, new):
    """True iff `new` is `old` with some subset of its listed-token
    occurrences replaced by <name> -- and nothing else changed."""
    parts, prev = [], 0
    for m in TOKEN_RX.finditer(old):
        parts.append(re.escape(old[prev:m.start()]))
        parts.append("(?:%s|<name>)" % re.escape(m.group(0)))
        prev = m.end()
    parts.append(re.escape(old[prev:]))
    return re.fullmatch("".join(parts), new, re.DOTALL) is not None


def sha(b):
    return hashlib.sha256(b).hexdigest()


def rmtree(p):
    shutil.rmtree(p, ignore_errors=True)
