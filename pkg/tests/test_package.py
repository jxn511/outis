"""The package's own invariants: provenance census, hygiene, its own gate, and
the README's commands run end to end.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from _support import oracle, CLASSES, PKG, clean_env, run_tool
import pii_scan

SKIP_DIRS = {"__pycache__", ".git"}


def package_files():
    for d, ds, fs in os.walk(PKG):
        ds[:] = sorted(x for x in ds if x not in SKIP_DIRS)
        for f in sorted(fs):
            if f.endswith(".pyc"):
                continue
            yield os.path.join(d, f)


def all_test_methods():
    here = os.path.dirname(os.path.abspath(__file__))
    suite = unittest.defaultTestLoader.discover(here, top_level_dir=here)
    out = []

    def walk(s):
        for t in s:
            if isinstance(t, unittest.TestSuite):
                walk(t)
            else:
                out.append(t)
    walk(suite)
    return out


class Census(unittest.TestCase):

    @oracle("spec", "an untagged test is an error, not a default: every test "
            "declares its oracle class and authority (the reference's "
            "collection-time refusal, carried as a census test for a "
            "standard-library runner).")
    def test_every_test_declares_its_oracle(self):
        bad, n = [], 0
        for t in all_test_methods():
            if isinstance(t, unittest.loader._FailedTest):
                bad.append((t.id(), "failed to import"))
                continue
            n += 1
            fn = getattr(t, t._testMethodName)
            tag = getattr(fn, "__oracle__", None)
            if not tag:
                bad.append((t.id(), "no oracle declared"))
            elif tag[0] not in CLASSES:
                bad.append((t.id(), "unknown class %r" % (tag[0],)))
        self.assertGreater(n, 50, "the census saw too few tests to mean anything")
        self.assertEqual(bad, [])


class Hygiene(unittest.TestCase):

    @oracle("external", "7-bit ASCII (ANSI X3.4): every byte of every shipped "
            "file is below 0x80, so no editor renders a glyph as '???', and no "
            "homoglyph or non-breaking space can hide in a pattern.")
    def test_every_file_is_seven_bit_ascii(self):
        bad = []
        for p in package_files():
            with open(p, "rb") as fh:
                data = fh.read()
            hi = [i for i, b in enumerate(data) if b > 0x7F]
            if hi:
                bad.append((os.path.relpath(p, PKG), data[:hi[0]].count(b"\n") + 1))
        self.assertEqual(bad, [])

    @oracle("external", "POSIX home directories: a path component after /home/ "
            "names an account. No shipped file may carry one (the generic form "
            "of the bare-token scan; placeholders are upper case or bracketed).")
    def test_no_home_path_of_any_account(self):
        pat = re.compile(rb"/home/[a-z]{2,}/|/Users/[a-z]{2,}/|-home-[a-z]{2,}-")
        hits = []
        for p in package_files():
            with open(p, "rb") as fh:
                for n, line in enumerate(fh, 1):
                    if pat.search(line):
                        hits.append((os.path.relpath(p, PKG), n))
        self.assertEqual(hits, [])

    @oracle("spec", "documents are written in third person: no first-person "
            "authorship voice and no second-person address (the procedure's "
            "mixed-mode person); verbatim quotations aside, which these files "
            "do not carry.")
    def test_documents_are_third_person(self):
        pat = re.compile(r"\b(we|our|ours|us|you|your|yours)\b", re.I)
        hits = []
        for name in ("README.md", "CHANGELOG.md", "PROCEDURE.md", "RULINGS.template"):
            with open(os.path.join(PKG, name), encoding="ascii") as fh:
                for n, line in enumerate(fh, 1):
                    if pat.search(line):
                        hits.append((name, n))
        self.assertEqual(hits, [])

    @oracle("structural", "the RULINGS.template examples are in the form the "
            "parser accepts: uncommented, they load as three EXEMPT rows of "
            "the three classes.")
    def test_the_template_examples_parse(self):
        with open(os.path.join(PKG, "RULINGS.template"), encoding="ascii") as fh:
            lines = [l[2:] for l in fh if re.match(r"# (address|domain|literal):", l)]
        rows = pii_scan.parse_rulings("".join(lines))
        self.assertEqual(sorted(r.cls for r in rows), ["address", "domain", "literal"])


class OwnGate(unittest.TestCase):

    @oracle("spec", "X6: the package passes its own gate -- pii_scan.py over the "
            "package tree, no RULINGS, exits 0, judged by exit status and never "
            "through a pipe.")
    def test_the_package_passes_its_own_gate(self):
        r = run_tool("pii_scan.py", PKG, "--gate")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("findings            : 0", r.stdout)


class ReadmeCommands(unittest.TestCase):

    @oracle("metamorphic", "X7: the README's command block runs end to end on "
            "the synthetic example, every line returning the exit status its "
            "comment states -- scan fails, ruling narrows, scrub clears the "
            "source, egress fails with a disagreement, the envelope scrub nulls "
            "the vectors, egress is green.")
    def test_the_readme_commands_run_end_to_end(self):
        with open(os.path.join(PKG, "README.md"), encoding="ascii") as fh:
            text = fh.read()
        block = text.split("<!-- example-commands:begin -->", 1)[1]
        block = block.split("<!-- example-commands:end -->", 1)[0]
        lines = [l for l in block.splitlines()
                 if l.strip() and not l.startswith("```")]
        cmds = []
        for l in lines:
            if l.startswith("W="):
                continue
            m = re.match(r"(.*?)\s+# exit (\d+)\s*$", l)
            self.assertTrue(m, "README command without an expected exit: %r" % l)
            cmds.append((m.group(1), int(m.group(2))))
        self.assertGreaterEqual(len(cmds), 9)
        w = tempfile.mkdtemp(prefix="pii-readme-")
        try:
            env = clean_env(W=w)
            for cmd, want in cmds:
                if "tests/run_tests.py" in cmd:
                    continue          # this suite IS that command; no recursion
                with self.subTest(cmd=cmd):
                    r = subprocess.run(["bash", "-c", cmd], cwd=PKG, env=env,
                                       capture_output=True, text=True, timeout=300)
                    self.assertEqual(r.returncode, want,
                                     "%s\n%s%s" % (cmd, r.stdout, r.stderr))
            # the end state the README promises, checked on the artifacts
            import json
            with open(os.path.join(w, "structure", "note-001.json"), encoding="ascii") as fh:
                doc = json.load(fh)
            n0 = doc["nodes"]["n0"]
            self.assertIsNone(n0["embedding"])
            self.assertIsNone(n0["sparse_embedding"])
            self.assertTrue(os.path.exists(os.path.join(w, "quarantine", "example_reembed.txt")))
        finally:
            shutil.rmtree(w, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
