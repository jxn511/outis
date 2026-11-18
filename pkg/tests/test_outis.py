"""outis.py clean (X14, X16): a defined corpus in, the same corpus out, stripped.

The corpus is examples/make_example.py's: every file type the command takes,
synthetic findings of every kind, a synthetic roster, and the items that must
come through unchanged. One --apply run is shared by the property tests.
"""
import hashlib
import importlib.util
import json
import os
import re
import shutil
import tempfile
import unittest

from _support import oracle, PKG, AT, addr, run_tool
import pii_gate
import pii_scan


def load_example():
    spec = importlib.util.spec_from_file_location(
        "make_example_under_test", os.path.join(PKG, "examples", "make_example.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


EX = load_example()


def tree(root):
    out = {}
    for d, ds, fs in os.walk(root):
        for n in ds:
            out[os.path.relpath(os.path.join(d, n), root)] = "dir"
        for n in fs:
            p = os.path.join(d, n)
            with open(p, "rb") as fh:
                out[os.path.relpath(p, root)] = hashlib.sha256(fh.read()).hexdigest()
    return out


def read(p):
    with open(p, "rb") as fh:
        return fh.read().decode("utf-8", "replace")


class Shared(unittest.TestCase):
    """One example, one dry run, one --apply run."""

    @classmethod
    def setUpClass(cls):
        pii_scan.set_rulings([])
        cls.w = tempfile.mkdtemp(prefix="outis-test-")
        r = run_tool(os.path.join("examples", "make_example.py"), cls.w)
        assert r.returncode == 0, r.stderr
        cls.inp = os.path.join(cls.w, "corpus")
        cls.out = os.path.join(cls.w, "clean")
        cls.meta = cls.out + ".outis"
        with open(os.path.join(cls.w, "planted.json"), encoding="ascii") as fh:
            cls.planted = json.load(fh)
        cls.before = tree(cls.inp)
        base = [cls.inp, "--out", cls.out, "--rulings", os.path.join(cls.w, "RULINGS"),
                "--names", os.path.join(cls.w, "names.txt")]
        cls.dry = run_tool("outis.py", "clean", *base)
        cls.dry_out_exists = os.path.exists(cls.out)
        cls.apply = run_tool("outis.py", "clean", *(base + ["--jobs", "2", "--apply"]))
        cls.after = tree(cls.inp)
        # Tolerant on purpose: a broken run must fail the TESTS that measure
        # it, not the class setup (which would hide which property broke).
        try:
            with open(os.path.join(cls.meta, "summary.json"), encoding="ascii") as fh:
                cls.summary = json.load(fh)
        except (OSError, ValueError):
            cls.summary = {}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.w, ignore_errors=True)


class Properties(Shared):

    @oracle("spec", "X14: dry run by default -- it exits with the verdict the "
            "apply would get, prints the counts, writes the record beside "
            "OUT_DIR, and does not create OUT_DIR.")
    def test_the_dry_run_delivers_nothing(self):
        self.assertEqual(self.dry.returncode, 0, self.dry.stdout + self.dry.stderr)
        self.assertFalse(self.dry_out_exists)
        self.assertIn("DRY RUN", self.dry.stdout)

    @oracle("spec", "X16: the apply run delivers and gates green (exit 0).")
    def test_the_apply_run_passes_its_gate(self):
        self.assertEqual(self.apply.returncode, 0, self.apply.stdout + self.apply.stderr)
        self.assertEqual(self.summary.get("gate"), "PASS")

    @oracle("metamorphic", "X16: the output tree equals the input tree in file "
            "set -- every file and directory at the same relative path.")
    def test_the_output_has_the_input_file_set(self):
        self.assertEqual(sorted(tree(self.out)), sorted(self.before))

    @oracle("metamorphic", "X16: the input is byte-identical after the run; it "
            "is the quarantine.")
    def test_the_input_is_byte_identical_after_the_run(self):
        self.assertEqual(self.after, self.before)

    @oracle("metamorphic", "X14: binaries are copied byte-for-byte and listed in "
            "the report.")
    def test_binaries_are_byte_identical_and_listed(self):
        out = tree(self.out)
        for rel in self.planted["binary_files"]:
            self.assertEqual(out[rel], self.before[rel])
            with open(os.path.join(self.meta, "REPORT.md"), encoding="ascii") as fh:
                self.assertIn(rel, fh.read())

    @oracle("spec", "X16: every planted finding is gone -- each blocking "
            "finding the scanner sees in an input file is absent from its output "
            "file, and the output scan has no blocking kind.")
    def test_every_planted_finding_is_gone(self):
        found = pii_scan.scan_path(self.inp)
        self.assertTrue(found, "fixture plants nothing")
        for rel, hits in found.items():
            body = read(os.path.join(self.out, rel))
            for kind, _l, snip, _w in hits:
                if not pii_gate.is_blocking(kind) or kind.startswith("role_field"):
                    continue
                with self.subTest(rel=rel, kind=kind):
                    self.assertNotIn(snip, body)
        left = [(r, k) for r, hs in pii_scan.scan_path(self.out).items()
                for k, *_ in hs if pii_gate.is_blocking(k)]
        self.assertEqual(left, [])

    @oracle("spec", "X16: every planted unambiguous name is gone from every "
            "output text file (whole word, case-insensitive; an independent "
            "matcher, not the tool's).")
    def test_every_planted_name_is_gone(self):
        rx = re.compile(r"(?<![A-Za-z0-9_])(?:%s)(?![A-Za-z0-9_])"
                        % "|".join(self.planted["names_unambiguous_planted"]), re.I)
        for rel, h in tree(self.out).items():
            if h == "dir" or rel.startswith("bin/"):
                continue
            with self.subTest(rel=rel):
                self.assertIsNone(rx.search(read(os.path.join(self.out, rel))))

    @oracle("spec", "X16: every must-survive item is intact -- a rule name and a "
            "hyphenated compound containing an ambiguous token, a code "
            "identifier equal to a listed name, published authorship and an "
            "ORCID.")
    def test_every_must_survive_item_is_intact(self):
        for rel, text in self.planted["must_survive"]:
            with self.subTest(rel=rel, text=text):
                self.assertIn(text, read(os.path.join(self.inp, rel)), "fixture")
                self.assertIn(text, read(os.path.join(self.out, rel)))

    @oracle("spec", "X16: the report's counts equal the planted counts.")
    def test_the_report_counts_equal_the_planted_counts(self):
        self.assertEqual(self.summary.get("removed_by_kind"), self.planted["removed_by_kind"])
        self.assertEqual(self.summary.get("names_residue"), 0)
        self.assertTrue(self.summary.get("ledger_balanced"))
        self.assertEqual(self.summary.get("ledger_rows"), self.summary.get("files_in"))

    @oracle("spec", "X14: the record (REPORT.md, ledger, summary, names "
            "files) lies BESIDE OUT_DIR, never inside it, and carries no value: "
            "no planted address, no planted name.")
    def test_the_record_is_beside_and_carries_no_value(self):
        self.assertFalse(any(n in ("REPORT.md", "ledger.jsonl", "summary.json")
                             for n in os.listdir(self.out)))
        rx = re.compile("|".join(self.planted["names_unambiguous_planted"]), re.I)
        for n in os.listdir(self.meta):
            body = read(os.path.join(self.meta, n))
            with self.subTest(file=n):
                self.assertEqual([k for k, *_ in pii_scan.scan_text(body)
                                  if pii_gate.is_blocking(k)], [])
                if n != "names_manifest.csv":
                    self.assertIsNone(rx.search(body))


class Refusals(unittest.TestCase):

    def setUp(self):
        pii_scan.set_rulings([])
        self.w = tempfile.mkdtemp(prefix="outis-ref-")
        self.inp = os.path.join(self.w, "in")
        os.makedirs(os.path.join(self.inp, "sub"))
        with open(os.path.join(self.inp, "sub", "a.txt"), "w") as fh:
            fh.write("write to %s\n" % addr())

    def tearDown(self):
        shutil.rmtree(self.w, ignore_errors=True)

    @oracle("spec", "X14: OUT_DIR inside IN_DIR refuses (2); so does an existing "
            "OUT_DIR, and IN_DIR is untouched by either.")
    def test_out_inside_in_and_existing_out_refuse(self):
        before = tree(self.inp)
        r = run_tool("outis.py", "clean", self.inp, "--out", os.path.join(self.inp, "sub", "o"),
                     "--apply")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        os.makedirs(os.path.join(self.w, "exists"))
        r = run_tool("outis.py", "clean", self.inp, "--out", os.path.join(self.w, "exists"),
                     "--apply")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertEqual(tree(self.inp), before)

    @oracle("spec", "X14: the run gates its OUTPUT. A finding the scrub cannot "
            "remove (here: a file NAMED after an address) fails the gate: exit 1, "
            "the tree is left at OUT_DIR.FAILED_GATE, OUT_DIR is not delivered, "
            "and the report names the file without the value.")
    def test_an_output_finding_fails_the_gate_and_is_named(self):
        bad = "mail-" + "jdoe" + AT + "lab." + "zz" + ".txt"
        with open(os.path.join(self.inp, bad), "w") as fh:
            fh.write("nothing personal inside\n")
        out = os.path.join(self.w, "out")
        r = run_tool("outis.py", "clean", self.inp, "--out", out, "--apply")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertFalse(os.path.exists(out))
        self.assertTrue(os.path.isdir(out + ".FAILED_GATE"))
        with open(out + ".outis/REPORT.md", encoding="ascii") as fh:
            rep = fh.read()
        self.assertIn("path:email", rep)
        self.assertNotIn("jdoe", rep + r.stdout)

    @oracle("spec", "X14/X15: with --names, what the name tool cannot clear "
            "fails the gate: a file whose PATH carries a listed name (the tool "
            "never renames) exits 1, names the file with the token masked, and "
            "the tree is not delivered. A name in running prose is replaced.")
    def test_a_name_the_tool_cannot_clear_fails_the_gate(self):
        names = os.path.join(self.w, "names.txt")
        with open(names, "w") as fh:
            fh.write("Quentara Velsmith\n")
        with open(os.path.join(self.inp, "sub", "a.txt"), "w") as fh:
            fh.write("clean\n")
        with open(os.path.join(self.inp, "p.tex"), "w") as fh:
            fh.write("\\section{Intro}\nAs shown by the Velsmith method we proceed.\n")
        with open(os.path.join(self.inp, "velsmith_notes.txt"), "w") as fh:
            fh.write("notes\n")
        out = os.path.join(self.w, "out")
        r = run_tool("outis.py", "clean", self.inp, "--out", out, "--names", names, "--apply")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertFalse(os.path.exists(out))
        self.assertIn("(file path)", r.stdout)
        self.assertNotIn("velsmith", r.stdout.lower())
        self.assertNotIn("Velsmith", read(os.path.join(out + ".FAILED_GATE", "p.tex")))

    @oracle("spec", "X15: --sample writes the reviewer's sample and the outlier "
            "table into the record on a DRY run, so it is read before --apply; "
            "OUT_DIR is not created.")
    def test_the_sample_is_written_on_a_dry_run(self):
        names = os.path.join(self.w, "names.txt")
        with open(names, "w") as fh:
            fh.write("Quentara Velsmith\n")
        with open(os.path.join(self.inp, "n.md"), "w") as fh:
            fh.write("Written by Quentara Velsmith.\n")
        out = os.path.join(self.w, "out")
        r = run_tool("outis.py", "clean", self.inp, "--out", out, "--names", names,
                     "--sample", "5")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(os.path.exists(out))
        samples = [n for n in os.listdir(out + ".outis") if "sample" in n]
        self.assertTrue(samples, os.listdir(out + ".outis"))
        body = read(os.path.join(out + ".outis", samples[0]))
        self.assertNotIn("Velsmith", body)


if __name__ == "__main__":
    unittest.main()
