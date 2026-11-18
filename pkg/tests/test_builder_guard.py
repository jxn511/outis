"""builder_guard.py (X11): the builder refuses markdown with a blocking finding."""
import json
import os
import shutil
import tempfile
import unittest

from _support import oracle, addr, home, orcid, run_tool
import builder_guard
import pii_scan

CLEAN = "# Results\n\nAuthors: A. Author, B. Writer\n\nThe CKM angle phi3 is measured.\n"


def rows(path):
    with open(path, encoding="ascii") as fh:
        return [json.loads(l) for l in fh if l.strip()]


class Base(unittest.TestCase):
    def setUp(self):
        pii_scan.set_rulings([])
        self.tmp = tempfile.mkdtemp(prefix="pii-builder-")
        self.led = os.path.join(self.tmp, "build_ledger.jsonl")

    def tearDown(self):
        pii_scan.set_rulings([])
        shutil.rmtree(self.tmp, ignore_errors=True)

    def md(self, name, text):
        p = os.path.join(self.tmp, name)
        with open(p, "w", encoding="ascii") as fh:
            fh.write(text)
        return p


class Guard(Base):

    @oracle("spec", "X11: a clean markdown passes -- not refused, and one ok "
            "row naming the file in the ledger.")
    def test_clean_markdown_passes(self):
        v = builder_guard.guard_markdown(self.md("a.md", CLEAN), self.led)
        self.assertFalse(v.refused)
        self.assertEqual(v.blocking, [])
        r = rows(self.led)
        self.assertEqual([(x["status"], x["detail"]) for x in r], [("ok", "built")])

    @oracle("human", "X11, the reference instance's builder rule (derived "
            "text is new material): markdown carrying a synthetic address is "
            "REFUSED, and the ledger row names the KIND in a pii_blocked detail "
            "and never the value.")
    def test_markdown_with_an_address_is_refused_by_kind_never_value(self):
        a = addr("jdoe", "lab")
        v = builder_guard.guard_markdown(self.md("b.md", CLEAN + "Write to %s.\n" % a), self.led)
        self.assertTrue(v.refused)
        self.assertIn("email", v.blocking)
        with open(self.led, encoding="ascii") as fh:
            body = fh.read()
        self.assertNotIn(a, body)
        self.assertNotIn("jdoe", body)
        r = rows(self.led)[0]
        self.assertEqual(r["status"], "dropped")
        self.assertTrue(r["detail"].startswith("pii_blocked: "))
        self.assertIn("email", r["detail"])

    @oracle("spec", "the guard reads TEXT as well as a path; the key of a text "
            "is a digest, so the row cannot carry the text it reports.")
    def test_text_input_is_keyed_by_digest(self):
        a = addr("jdoe", "lab")
        v = builder_guard.guard_markdown("line one\nmail " + a + "\n", self.led)
        self.assertTrue(v.refused)
        self.assertTrue(v.key.startswith("text:"))
        with open(self.led, encoding="ascii") as fh:
            self.assertNotIn("jdoe", fh.read())

    @oracle("human", "the partition is the egress gate's: a RECORDED kind (a "
            "published ORCID) never blocks a build, while every other kind does.")
    def test_a_recorded_kind_does_not_refuse(self):
        v = builder_guard.guard_markdown(self.md("c.md", CLEAN + "ORCID " + orcid() + "\n"), self.led)
        self.assertEqual(v.kinds, ["orcid"])
        self.assertFalse(v.refused)

    @oracle("spec", "rulings apply at the build exactly as at the scan: an "
            "address exempted by a RULINGS row does not refuse the build.")
    def test_rulings_apply_at_the_build(self):
        a = addr("desk", "service")
        rp = self.md("RULINGS", "address:%s | EXEMPT | an office | privacy owner | 2026-11-17\n" % a)
        p = self.md("d.md", CLEAN + "Write to %s.\n" % a)
        self.assertTrue(builder_guard.guard_markdown(p, self.led).refused)
        self.assertFalse(builder_guard.guard_markdown(p, self.led, rulings=rp).refused)


class Cli(Base):

    @oracle("metamorphic", "X11: the ledger conserves records -- files in = "
            "passed + refused, one row per file, the refused rows naming kinds; "
            "the CLI exits 1 on any refusal and 0 when all pass.")
    def test_the_ledger_conserves_records_and_the_cli_exits_1(self):
        files = [self.md("p1.md", CLEAN), self.md("p2.md", CLEAN),
                 self.md("r1.md", CLEAN + "Write to %s.\n" % addr("jdoe", "lab")),
                 self.md("r2.md", CLEAN + "Data in %s.\n" % home("jsmith", "calib"))]
        r = run_tool("builder_guard.py", *(files + ["--ledger", self.led]))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        got = rows(self.led)
        passed = [x for x in got if x["status"] == "ok"]
        refused = [x for x in got if x["status"] == "dropped"
                   and x["detail"].startswith("pii_blocked: ")]
        self.assertEqual(len(files), len(passed) + len(refused))
        self.assertEqual((len(passed), len(refused)), (2, 2))
        self.assertEqual(sorted(x["key"] for x in got), sorted(files))
        self.assertIn("4 in, 2 passed, 2 refused, 0 unaccounted", r.stdout)
        with open(self.led, encoding="ascii") as fh:
            self.assertNotIn("jdoe", r.stdout + fh.read())
        r = run_tool("builder_guard.py", files[0], files[1], "--ledger", self.led)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    @oracle("spec", "fail closed: an unreadable file is refused (it has not "
            "been cleared) and a malformed RULINGS file refuses the run (2).")
    def test_unreadable_refuses_and_bad_rulings_exit_2(self):
        missing = os.path.join(self.tmp, "gone", "x.md")
        self.assertEqual(builder_guard.assess(missing, is_path=True)[2], ["unreadable"])
        r = run_tool("builder_guard.py", missing, "--ledger", self.led)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("pii_blocked: unreadable", r.stdout)
        p = self.md("u.md", CLEAN)
        os.chmod(p, 0)
        try:
            if os.access(p, os.R_OK):
                self.skipTest("running with permission to read a mode-0 file")
            self.assertEqual(builder_guard.assess(p)[2], ["unreadable"])
        finally:
            os.chmod(p, 0o644)
        bad = self.md("RULINGS", "not a row\n")
        r = run_tool("builder_guard.py", p, "--ledger", self.led, "--rulings", bad)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
