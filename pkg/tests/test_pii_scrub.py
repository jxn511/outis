"""pii_scrub.py -- file-level scrubbing. Carried from the reference instance's
suite, re-fixtured; plus scrub_envelopes.py, which the carried suite reached
only indirectly.
"""
import json
import os
import shutil
import tempfile
import unittest

from _support import oracle, addr, site, home, assign, orcid, run_tool
import pii_scan
import pii_scrub


class Base(unittest.TestCase):
    def setUp(self):
        pii_scan.set_rulings([])
        self.tmp = tempfile.mkdtemp(prefix="pii-scrub-")

    def tearDown(self):
        pii_scan.set_rulings([])
        shutil.rmtree(self.tmp, ignore_errors=True)

    def p(self, *parts):
        return os.path.join(self.tmp, *parts)

    def write(self, rel, text):
        path = self.p(rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def read(self, path):
        with open(path, encoding="utf-8") as fh:
            return fh.read()


class FileScrub(Base):

    @oracle("human", "the two-sieve representational failure, observed on the "
            "reference instance: the scrubber must remove what the scanner finds "
            "-- an entity-encoded address in an .html working copy is decoded and "
            "scrubbed; non-HTML files are never entity-decoded.")
    def test_html_entity_encoded_address_is_scrubbed(self):
        dom = site("example-lab")
        p = self.write("page.html", "<p>write to someone&#64;%s today</p>" % dom)
        new, removed = pii_scrub.scrub_file_text(p, self.read(p))
        self.assertTrue(removed)
        self.assertNotIn(dom, new)
        self.assertNotIn("&#64;", new)
        t = "literal someone&#64;%s stays" % dom
        self.assertEqual(pii_scrub.scrub_file_text(self.p("note.txt"), t), (t, []))

    @oracle("metamorphic", "the run summary once iterated a HARDCODED class "
            "list, so a credential it had just removed was invisible in the "
            "report. Whatever kind scrub_file_text reports removing must appear "
            "in the summary.")
    def test_the_run_summary_names_every_class_it_removed(self):
        self.write("raw/creds.txt", "* root " + assign("passwd", "Ab3xK9wQz1", quote="") + "\n")
        self.write("raw/paths.txt", "look in %s for the ntuples\n" % home("someuser", "analysis"))
        self.write("raw/mail.txt", "write to %s about it\n" % addr("someone", "example-lab"))
        r = run_tool("pii_scrub.py", self.p("raw"), "--quarantine", self.p("q"))
        kinds = set()
        for name in ("creds.txt", "paths.txt", "mail.txt"):
            path = self.p("raw", name)
            kinds.update(k for k, _ in pii_scrub.scrub_file_text(path, self.read(path))[1])
        self.assertTrue(kinds, "fixture removed nothing; the test would pass vacuously")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        missing = sorted(k for k in kinds if k not in r.stdout)
        self.assertFalse(missing, "removed but absent from the summary: %s" % missing)

    @oracle("metamorphic", "scrubbing a JSON file AS TEXT corrupted 18 of 2,812 "
            "files on the reference instance: an address right after a \\n "
            "escape absorbed the 'n'. The personal data is gone AND the file "
            "still parses as the JSON it was.")
    def test_scrubbing_a_json_file_neither_corrupts_it_nor_leaves_the_address(self):
        original = {"wikitext": "known hosts.\n%s's password:\ncvs checkout"
                                % addr("someuser", "example-lab"),
                    "title": "SSH notes", "pageid": 3701, "revid": 17}
        p = self.write("3701.json", json.dumps(original, sort_keys=True))
        new, removed = pii_scrub.scrub_file_text(p, self.read(p))
        self.assertTrue(removed)
        self.assertNotIn("someuser", new)
        self.assertNotIn(site("example-lab"), new)
        rt = json.loads(new)
        self.assertEqual((rt["pageid"], rt["title"]), (3701, "SSH notes"))
        self.assertTrue(rt["wikitext"].startswith("known hosts.\n"))
        self.assertTrue(rt["wikitext"].endswith("cvs checkout"))

    @oracle("spec", "the target is sometimes ONE FILE. os.walk over a file yields "
            "nothing, so the CLI once scrubbed zero files and exited 0: a tool "
            "reporting success for work it did not do.")
    def test_a_single_file_is_a_valid_target(self):
        f = self.write("report.md", "The run lived in %s and wrote 3 files.\n"
                       % home("someuser", "project", "workspace"))
        r = run_tool("pii_scrub.py", f, "--quarantine", self.p("q"), "--apply")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("home_path", r.stdout)
        after = self.read(f)
        self.assertNotIn("someuser", after)
        self.assertIn("wrote 3 files", after)
        originals = [os.path.join(d, n) for d, _s, fs in os.walk(self.p("q"))
                     for n in fs if n.endswith(".original")]
        self.assertTrue(originals)
        self.assertIn("someuser", self.read(originals[0]))

    @oracle("metamorphic", "SCRUB-THEN-SCAN MUST CONVERGE. If scanning the "
            "scrubber's own output still reports a finding, the gate can never "
            "be cleared. Includes the real signature-block shape (value aligned "
            "with 22 spaces) that once stopped an ingest.")
    def test_scanning_the_scrubbers_own_output_finds_nothing(self):
        a, b = addr("someone", "example-lab"), addr("a.person", "example-lab")
        cases = ["Email: " + a, "Email:    " + a,
                 "Email:                      " + a,
                 "Contact:                          " + b,
                 "email:  %s  " % a, "Contact: " + a,
                 "  Email: %s (Example Group, Office 218)" % b,
                 assign("password", "Ab3xK9wQz1", quote="").replace(" = ", ": "),
                 "look in " + home("someuser", "analysis")]
        for text in cases:
            with self.subTest(text=text):
                self.assertTrue(pii_scan.scan_text(text), "fixture must be a finding")
                scrubbed, removed = pii_scrub.scrub_text(text)
                self.assertTrue(removed)
                self.assertEqual(pii_scan.scan_text(scrubbed), [])

    @oracle("spec", "the convergence fix must not blind the detector: a REAL "
            "address next to the placeholder still fires, and a role field whose "
            "value is a real address still fires.")
    def test_the_placeholder_exemption_does_not_blind_the_detector(self):
        real = addr("real", "example-lab")
        self.assertTrue(pii_scan.scan_text("Email: [address removed] and also " + real))
        self.assertTrue(pii_scan.scan_text("Email: " + real))
        self.assertTrue(pii_scan.scan_text("Referees: A. Person, B. Other"))
        self.assertEqual(pii_scan.scan_text("Email: [address removed]"), [])

    @oracle("metamorphic", "a dry run leaves the tree byte-identical; paired with "
            "a positive control (--apply changes it), because a tool that writes "
            "nothing at all would satisfy the dry-run invariant vacuously.")
    def test_a_dry_run_writes_nothing_and_apply_does(self):
        f = self.write("raw/a.txt", "write to %s\n" % addr())
        before = self.read(f)
        r = run_tool("pii_scrub.py", self.p("raw"), "--quarantine", self.p("q"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.read(f), before)
        self.assertFalse([n for _d, _s, fs in os.walk(self.p("q")) for n in fs
                          if n.endswith(".original")])
        r = run_tool("pii_scrub.py", self.p("raw"), "--quarantine", self.p("q"), "--apply")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotEqual(self.read(f), before)


    @oracle("spec", "a target that does not exist refuses (2): the reference "
            "walked nothing and exited 0, reporting success for no work.")
    def test_a_missing_target_refuses(self):
        r = run_tool("pii_scrub.py", self.p("no-such-dir"), "--quarantine", self.p("q"))
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)


class EnvelopeScrub(Base):
    """scrub_envelopes.py: a scrub at stage k must invalidate stage k+1."""

    def envelope(self, name="d1"):
        a = addr("jdoe", "lab")
        doc = {"nodes": {
            "dirty": {"title": "Notes", "summary": "Contact: %s\nThe calibration." % a,
                      "embedding": [0.1, 0.2], "sparse_embedding": {"3": 0.5}},
            "clean": {"title": "Results", "summary": "The CKM angle phi3.",
                      "embedding": [0.3], "sparse_embedding": {"4": 0.1}},
            "orcid": {"title": "Author", "summary": "ORCID " + orcid(),
                      "embedding": [0.4]},
        }}
        return self.write("structure/%s.json" % name, json.dumps(doc)), a

    @oracle("spec", "the scrub must null BOTH vectors of every node whose text "
            "changed -- clearing only the dense one leaves the sparse index "
            "matching on the removed token -- and leave other nodes untouched.")
    def test_a_scrubbed_node_loses_both_vectors_and_others_keep_theirs(self):
        import scrub_envelopes
        _p, a = self.envelope()
        with open(_p, encoding="utf-8") as fh:
            doc = json.load(fh)
        changed, removed = scrub_envelopes.scrub_envelope(doc, keep_orcid=True)
        self.assertEqual(changed, ["dirty"])
        n = doc["nodes"]["dirty"]
        self.assertIsNone(n["embedding"])
        self.assertIsNone(n["sparse_embedding"])
        self.assertTrue(n["pii_scrubbed"])
        self.assertNotIn(a, n["summary"])
        self.assertEqual(doc["nodes"]["clean"]["embedding"], [0.3])
        self.assertEqual(doc["nodes"]["orcid"]["embedding"], [0.4])

    @oracle("metamorphic", "after scrub_envelopes --apply the egress gate is "
            "GREEN over the same tree that was RED, the original is quarantined, "
            "and the re-embed list names the file; a dry run changes nothing.")
    def test_apply_turns_the_egress_gate_green_and_names_the_reembed(self):
        import pii_gate
        p, _a = self.envelope()
        glob_ = self.p("structure", "*.json")
        self.assertGreaterEqual(pii_gate.egress([("T", glob_, None)])["blocking"], 1)
        before = self.read(p)
        r = run_tool("scrub_envelopes.py", "--structure", glob_, "--quarantine",
                     self.p("q"), "--label", "t", "--keep-orcid")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.read(p), before, "a dry run must not write")
        r = run_tool("scrub_envelopes.py", "--structure", glob_, "--quarantine",
                     self.p("q"), "--label", "t", "--keep-orcid", "--apply")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(pii_gate.egress([("T", glob_, None)])["blocking"], 0)
        self.assertTrue(os.path.exists(self.p("q", "t", "d1.json.original")))
        self.assertIn(p, self.read(self.p("q", "t_reembed.txt")))

    @oracle("metamorphic", "the ledger-file filter must not depend on where the "
            "corpus is parked (the reference copy of this tool tested the whole "
            "path): an envelope under a directory named 'ledgers' is scrubbed.")
    def test_a_parked_envelope_is_not_skipped(self):
        import scrub_envelopes
        doc = {"nodes": {"n": {"summary": "Contact: " + addr(), "embedding": [0.1]}}}
        self.write("ledgers_2026/structure/d1.json", json.dumps(doc))
        r = run_tool("scrub_envelopes.py", "--structure",
                     self.p("ledgers_2026", "structure", "*.json"),
                     "--quarantine", self.p("q"), "--label", "t")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("envelopes changed      : 1", r.stdout)

    @oracle("spec", "an unreadable envelope has NOT been cleared: exit 1 (ran "
            "with degradation), never 0.")
    def test_an_unreadable_envelope_is_not_a_clean_exit(self):
        self.write("structure/bad.json", "{not json")
        r = run_tool("scrub_envelopes.py", "--structure", self.p("structure", "*.json"),
                     "--quarantine", self.p("q"), "--label", "t")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
