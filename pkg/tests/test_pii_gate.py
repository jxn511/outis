"""The egress sieve. Carried from the reference instance's suite, re-fixtured.

The reference gate had a built-in list of the instance's corpora and a default
sentinel path inside the instance's output tree. The package has neither: the
instance registers its corpora (--corpus / --registry), names its inventory
root (--inventory-root) and its sentinel (--status). The tests that pinned the
built-in behaviour are carried in that explicit form.
"""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from _support import oracle, addr, orcid, PKG
import pii_gate
import pii_scan


def env(d, name, nodes):
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, name + ".json")
    with open(p, "w", encoding="utf-8") as fh:
        json.dump({"nodes": nodes}, fh)
    return p


def run_main(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = pii_gate.main(argv)
    return rc, out.getvalue(), err.getvalue()


def read(p):
    with open(p, encoding="ascii") as fh:
        return fh.read()


class Base(unittest.TestCase):
    def setUp(self):
        pii_scan.set_rulings([])
        self.tmp = tempfile.mkdtemp(prefix="pii-gate-")

    def tearDown(self):
        pii_scan.set_rulings([])
        shutil.rmtree(self.tmp, ignore_errors=True)

    def p(self, *parts):
        return os.path.join(self.tmp, *parts)


class Egress(Base):

    @oracle("spec", "pii_gate contract: 'reachable' means carries a vector. "
            "scrub_envelopes takes a node out of circulation by nulling its "
            "embedding, so an unembedded node is not in the index and reporting "
            "it would claim an exposure that does not exist.")
    def test_only_nodes_with_a_vector_are_scanned(self):
        env(self.tmp, "d1", {
            "a": {"summary": "write to " + addr("a.person"), "embedding": [0.1]},
            "b": {"summary": "write to " + addr("b.person"), "embedding": None},
            "c": {"summary": "write to " + addr("c.person"), "sparse_embedding": {"7": 0.5}},
        })
        got = list(pii_gate.retrievable_nodes(self.p("*.json")))
        self.assertEqual({nid for _p, nid, _t in got}, {"a", "c"})

    @oracle("human", "ruled on the reference instance: gate the egress, and keep "
            "ORCIDs as RECORDED. The line is published versus confidential; if "
            "every finding blocked, the published ORCIDs would hold the gate red "
            "forever, and a gate that cannot reach green trains its own bypass.")
    def test_orcid_is_recorded_and_an_address_blocks(self):
        env(self.tmp, "d1", {"a": {"summary": "ORCID: " + orcid(), "embedding": [0.1]}})
        r = pii_gate.egress([("T", self.p("*.json"), None)])
        self.assertEqual((r["blocking"], r["recorded"]), (0, 1))
        env(self.tmp, "d2", {"a": {"summary": "contact " + addr(), "embedding": [0.1]}})
        r = pii_gate.egress([("T", self.p("*.json"), None)])
        self.assertEqual(r["blocking"], 1, "a contact address must always block")

    @oracle("spec", "pii_gate contract: RECORDED is a short explicit allowlist "
            "and everything else blocks, so a detector added later is blocking "
            "until a human rules on it.")
    def test_an_unknown_finding_kind_blocks_by_default(self):
        self.assertEqual(pii_gate.RECORDED, frozenset(["orcid"]))
        self.assertTrue(pii_gate.is_blocking("some_detector_invented_next_year"))
        self.assertTrue(pii_gate.is_blocking("email"))
        self.assertFalse(pii_gate.is_blocking("orcid"))

    @oracle("metamorphic", "the disagreement is the product. Regression on the "
            "reference instance: clean markdown and an envelope still naming "
            "three internal referees, because the envelope predated the scrub. "
            "Source clean + index dirty is a BROKEN PROPAGATION PATH.")
    def test_source_clean_but_index_dirty_is_counted_as_disagreement(self):
        import pii_scrub
        md = self.p("md", "d1")
        os.makedirs(md)
        dirty = "Referees: M. Someone, J. Other\nThe measurement follows.\n"
        scrubbed, removed = pii_scrub.scrub_text(dirty, keep_orcid=True)
        self.assertTrue(removed, "fixture must actually exercise the scrubber")
        with open(os.path.join(md, "paper.md"), "w", encoding="utf-8") as fh:
            fh.write(scrubbed)
        self.assertFalse(pii_scan.scan_text(scrubbed))
        env(self.p("st"), "d1", {"n0": {"summary": "Referees: M. Someone, J. Other",
                                        "embedding": [0.1]}})
        r = pii_gate.egress([("T", self.p("st", "*.json"), self.p("md"))])
        self.assertGreaterEqual(r["blocking"], 1)
        self.assertGreaterEqual(sum(r["stale"].values()), 1)
        with open(os.path.join(md, "paper.md"), "w", encoding="utf-8") as fh:
            fh.write("Referees: M. Someone, J. Other\n")
        r2 = pii_gate.egress([("T", self.p("st", "*.json"), self.p("md"))])
        self.assertGreaterEqual(r2["blocking"], 1)
        self.assertEqual(sum(r2["stale"].values()), 0)

    @oracle("spec", "a report of personal data must not contain the personal "
            "data, in the printed summary or the JSON report.")
    def test_the_report_never_contains_a_value(self):
        env(self.tmp, "d1", {"a": {"summary": "reach me at " + addr("secret.person"),
                                   "embedding": [0.1]}})
        rep = self.p("r.json")
        rc, out, err = run_main(["--egress", "--report", rep,
                                 "--corpus", "T:" + self.p("*.json")])
        for blob in (out, err, read(rep)):
            self.assertNotIn("secret.person", blob)

    @oracle("spec", "pii_gate contract: an unreadable envelope is a FINDING, "
            "never a pass.")
    def test_an_unreadable_envelope_is_a_finding(self):
        with open(self.p("broken.json"), "w", encoding="utf-8") as fh:
            fh.write("{not json")
        r = pii_gate.egress([("T", self.p("*.json"), None)])
        self.assertEqual(r["blocking"], 1)
        self.assertEqual(r["kinds"]["unreadable_envelope"], 1)

    @oracle("spec", "an envelope of the wrong SHAPE (nodes not a mapping of "
            "objects) cannot be read as the node schema, so it is a blocking "
            "finding like any unreadable envelope -- never a crash, never a pass.")
    def test_a_misshapen_envelope_is_a_finding(self):
        for i, body in enumerate(('{"nodes": [1, 2]}', '[1, 2]', '{"nodes": {"a": 7}}')):
            with self.subTest(body=body):
                d = self.p("shape%d" % i)
                os.makedirs(d)
                with open(os.path.join(d, "x.json"), "w", encoding="utf-8") as fh:
                    fh.write(body)
                r = pii_gate.egress([("T", os.path.join(d, "*.json"), None)])
                self.assertEqual(r["kinds"]["unreadable_envelope"], 1)
                self.assertEqual(r["blocking"], 1)

    @oracle("metamorphic", "a filter that skips ledger FILES must not depend on "
            "where the corpus is parked: same envelopes, one extra directory "
            "level whose name contains 'ledger', same findings.")
    def test_a_parked_corpus_directory_does_not_hide_a_strand(self):
        nodes = {"a": {"summary": "contact " + addr(), "embedding": [0.1]}}
        env(self.p("plain"), "d1", nodes)
        env(self.p("ledgers_2026", "structure"), "d1", nodes)
        here = pii_gate.egress([("T", self.p("plain", "*.json"), None)])
        there = pii_gate.egress([("T", self.p("ledgers_2026", "structure", "*.json"), None)])
        self.assertEqual(here["blocking"], 1)
        self.assertEqual(there["blocking"], here["blocking"])
        env(self.p("plain"), "convert_ledger", nodes)
        self.assertEqual(pii_gate.egress([("T", self.p("plain", "*.json"), None)])["blocking"], 1)


class Sentinel(Base):

    @oracle("spec", "the gate-pipe trap: `gate | tail; echo $?` prints 0 under a "
            "FAILED banner because $? binds to the last command of a pipeline. "
            "The verdict must therefore live in a FILE, written from the same "
            "count that sets the exit code.")
    def test_gate_verdict_survives_a_pipeline(self):
        env(self.tmp, "d1", {"a": {"summary": "contact " + addr(), "embedding": [0.1]}})
        status = self.p("gate_status")
        cmd = ("'%s' '%s' --egress --gate --corpus 'T:%s' --status '%s' | tail -1; echo rc=$?"
               % (sys.executable, os.path.join(PKG, "pii_gate.py"), self.p("*.json"), status))
        out = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True)
        self.assertIn("rc=0", out.stdout, "precondition: the pipeline really eats the rc")
        body = read(status)
        self.assertIn("status=RED", body)
        self.assertIn("blocking=1", body)

    @oracle("spec", "the sentinel and the exit code are derived from the same "
            "blocking count, so they cannot disagree.")
    def test_gate_status_agrees_with_the_exit_code(self):
        env(self.tmp, "d1", {"a": {"summary": "measurement of the CKM angle phi3",
                                   "embedding": [0.1]}})
        status = self.p("gate_status")
        rc, _o, _e = run_main(["--egress", "--gate", "--corpus", "T:" + self.p("*.json"),
                               "--status", status])
        body = read(status)
        self.assertEqual(rc, 0)
        self.assertIn("status=GREEN", body)
        self.assertIn("blocking=0", body)

    @oracle("spec", "fail closed: if the gate dies mid-scan, the previous run's "
            "GREEN must not remain on disk. ERROR is stamped BEFORE the scan and "
            "overwritten only by a completed one.")
    def test_a_crash_mid_scan_leaves_error_never_a_stale_green(self):
        status = self.p("gate_status")
        with open(status, "w", encoding="ascii") as fh:
            fh.write("status=GREEN\nblocking=0\n")

        def boom(_corpora):
            raise RuntimeError("simulated death mid-scan")
        with mock.patch.object(pii_gate, "egress", boom):
            with self.assertRaises(RuntimeError):
                run_main(["--egress", "--gate", "--corpus", "T:" + self.p("*.json"),
                          "--status", status])
        self.assertIn("status=ERROR", read(status))

    @oracle("spec", "carried from the reference's 'a --corpus subset does not "
            "stamp the corpus-wide verdict': the package has no default sentinel "
            "at all, so a gate run without --status writes no verdict file "
            "anywhere -- not in the working directory, not beside the corpus.")
    def test_no_sentinel_is_written_without_status(self):
        env(self.p("st"), "d1", {"a": {"summary": "the CKM angle phi3", "embedding": [0.1]}})
        before = sorted(os.listdir(self.tmp))
        cwd = os.getcwd()
        os.chdir(self.tmp)
        try:
            rc, _o, _e = run_main(["--egress", "--gate", "--corpus", "T:st/*.json"])
        finally:
            os.chdir(cwd)
        self.assertEqual(rc, 0)
        self.assertEqual(sorted(os.listdir(self.tmp)), before)

    @oracle("spec", "fail closed on configuration: with no built-in corpus list, "
            "a gate given nothing to scan would report GREEN over nothing. It "
            "refuses (2) and stamps ERROR when a sentinel was asked for.")
    def test_a_gate_with_no_corpus_refuses(self):
        status = self.p("gate_status")
        with open(status, "w", encoding="ascii") as fh:
            fh.write("status=GREEN\n")
        rc, _o, _e = run_main(["--egress", "--gate", "--status", status])
        self.assertEqual(rc, 2)
        self.assertIn("status=ERROR", read(status))


class Inventory(Base):

    def build(self):
        clean = {"n": {"summary": "the CKM angle phi3", "embedding": [0.1]}}
        env(self.p("structure", "a"), "a", clean)
        env(self.p("structure", "new"), "b", clean)
        with open(self.p("structure", "new", "x_ledger.jsonl"), "w") as fh:
            fh.write("")

    @oracle("spec", "the two-sieve invariant is only as strong as the registry's "
            "enumeration. A structure tree absent from it was INVISIBLE to the "
            "egress sieve on the reference instance (703 envelopes, 64,023 "
            "reachable nodes never gated). The omission must be detectable.")
    def test_unregistered_envelopes_are_enumerated(self):
        self.build()
        corpora = [("a", self.p("structure", "a", "*.json"), None)]
        un = pii_gate.unregistered_envelopes(corpora, self.p("structure"))
        self.assertEqual([os.path.basename(p) for p in un], ["b.json"])
        corpora.append(("new", self.p("structure", "new", "*.json"), None))
        self.assertEqual(pii_gate.unregistered_envelopes(corpora, self.p("structure")), [])

    @oracle("spec", "an unregistered tree HOLDS THE GATE RED: content nobody "
            "scanned must not ride a green verdict.")
    def test_gate_fails_red_on_an_unregistered_tree(self):
        self.build()
        status = self.p("gate_status")
        rc, _o, _e = run_main(["--egress", "--gate", "--status", status,
                               "--inventory-root", self.p("structure"),
                               "--corpus", "a:" + self.p("structure", "a", "*.json")])
        self.assertEqual(rc, 1, "zero PII findings, but an ungated tree exists")
        self.assertIn("status=RED", read(status))
        rc, _o, _e = run_main(["--egress", "--gate", "--status", status,
                               "--inventory-root", self.p("structure"),
                               "--corpus", "a:" + self.p("structure", "a", "*.json"),
                               "--corpus", "new:" + self.p("structure", "new", "*.json")])
        self.assertEqual(rc, 0)
        self.assertIn("status=GREEN", read(status))

    @oracle("spec", "carried from 'a corpus subset skips the inventory check': "
            "the inventory is judged only when an inventory root is named, so a "
            "run pointed at one tree judges only that tree.")
    def test_without_an_inventory_root_the_inventory_is_not_judged(self):
        self.build()
        rc, _o, _e = run_main(["--egress", "--gate",
                               "--corpus", "a:" + self.p("structure", "a", "*.json")])
        self.assertEqual(rc, 0)


class Registry(Base):

    @oracle("spec", "a registry file is the instance's one definition of its "
            "corpora; relative paths resolve against the file's own directory, "
            "so the verdict does not depend on the working directory.")
    def test_a_registry_resolves_relative_to_itself(self):
        env(self.p("structure"), "d1", {"a": {"summary": "contact " + addr(),
                                              "embedding": [0.1]}})
        reg = self.p("corpora.registry")
        with open(reg, "w", encoding="ascii") as fh:
            fh.write("# label | structure glob | markdown root\n"
                     "T | structure/*.json | -\n")
        rc, _o, _e = run_main(["--egress", "--gate", "--registry", reg])
        self.assertEqual(rc, 1)

    @oracle("spec", "a malformed registry row refuses (2) and is named: a "
            "registry that half-loads gates part of the corpus and reports "
            "green.")
    def test_a_malformed_registry_refuses(self):
        reg = self.p("corpora.registry")
        for body in ("T | structure/*.json\n", "T | a/*.json | -\nT | b/*.json | -\n"):
            with self.subTest(body=body):
                with open(reg, "w", encoding="ascii") as fh:
                    fh.write(body)
                rc, _o, err = run_main(["--egress", "--gate", "--registry", reg])
                self.assertEqual(rc, 2)
                self.assertIn("registry line", err)


if __name__ == "__main__":
    unittest.main()
