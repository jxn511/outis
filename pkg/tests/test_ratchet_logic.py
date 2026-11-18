"""The ratchet template (X12) exercised on synthetic egress reports.

Each case runs the template's own TestCase against files written here, so what
is tested is exactly what an adopting instance runs.
"""
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from _support import oracle, addr, run_tool
import test_ratchet_template as T


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pii-ratchet-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def report(self, blocking, disagreement=None):
        p = os.path.join(self.tmp, "egress_report.json")
        with open(p, "w", encoding="ascii") as fh:
            json.dump({"blocking": blocking, "recorded": 0, "kinds": {},
                       "disagreement": disagreement or {}, "locations": []}, fh)
        return p

    def baseline(self, n, extra=""):
        p = os.path.join(self.tmp, "ratchet_baseline.txt")
        with open(p, "w", encoding="ascii") as fh:
            fh.write("# committed ratchet\nreachable_blocking=%s\n%s" % (n, extra))
        return p

    def run_template(self, report=None, baseline=None):
        env = {}
        if report:
            env[T.REPORT_ENV] = report
        if baseline:
            env[T.BASELINE_ENV] = baseline
        with mock.patch.dict(os.environ, env, clear=False):
            for k in (T.REPORT_ENV, T.BASELINE_ENV):
                if k not in env:
                    os.environ.pop(k, None)
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(T.EgressRatchet)
            res = unittest.TestResult()
            suite.run(res)
        return res


class Ratchet(Base):

    @oracle("spec", "X12: a fall passes -- fewer reachable blocking findings "
            "than the committed baseline, disagreement zero.")
    def test_a_fall_passes(self):
        res = self.run_template(self.report(3), self.baseline(5))
        self.assertTrue(res.wasSuccessful())
        self.assertEqual((res.testsRun, len(res.skipped)), (1, 0))

    @oracle("spec", "an unchanged count passes: the ratchet forbids a rise, "
            "not a standstill.")
    def test_an_equal_count_passes(self):
        res = self.run_template(self.report(5), self.baseline(5))
        self.assertTrue(res.wasSuccessful())
        self.assertEqual(len(res.skipped), 0)

    @oracle("spec", "X12: a rise fails -- one more reachable blocking finding "
            "than the baseline is a regression in the index.")
    def test_a_rise_fails(self):
        res = self.run_template(self.report(6), self.baseline(5))
        self.assertEqual(len(res.failures), 1)
        self.assertIn("ROSE", res.failures[0][1])

    @oracle("spec", "X12: a non-zero disagreement fails whatever the count -- "
            "a broken propagation path, the only symptom it emits.")
    def test_a_disagreement_fails(self):
        res = self.run_template(self.report(0, {"email": 1}), self.baseline(5))
        self.assertEqual(len(res.failures), 1)
        self.assertIn("disagreement", res.failures[0][1])

    @oracle("spec", "X12: no report SKIPS and is never counted as a pass: "
            "'not checked' and 'checked and clean' must not look alike.")
    def test_no_report_skips(self):
        res = self.run_template(None, self.baseline(5))
        self.assertEqual(len(res.skipped), 1)
        self.assertEqual((len(res.failures), len(res.errors)), (0, 0))
        res = self.run_template(os.path.join(self.tmp, "absent.json"), self.baseline(5))
        self.assertEqual(len(res.skipped), 1)

    @oracle("spec", "fail closed on adoption: a report without a committed "
            "baseline, or a baseline that does not parse, FAILS rather than "
            "skips.")
    def test_a_missing_or_broken_baseline_fails(self):
        rep = self.report(1)
        res = self.run_template(rep, None)
        self.assertEqual(len(res.failures), 1)
        p = os.path.join(self.tmp, "bad.txt")
        for body in ("reachable_blocking=many\n", "# nothing\n", "blocking 3\n"):
            with self.subTest(body=body):
                with open(p, "w", encoding="ascii") as fh:
                    fh.write(body)
                res = self.run_template(rep, p)
                self.assertEqual(len(res.failures), 1)

    @oracle("metamorphic", "the template reads the report pii_gate.py actually "
            "writes: a real egress run over a synthetic corpus with one reachable "
            "address yields blocking 1, which a baseline of 1 accepts and a "
            "baseline of 0 rejects.")
    def test_it_reads_a_real_pii_gate_report(self):
        st = os.path.join(self.tmp, "st")
        os.makedirs(st)
        with open(os.path.join(st, "d1.json"), "w", encoding="ascii") as fh:
            json.dump({"nodes": {"a": {"summary": "contact " + addr(),
                                       "embedding": [0.1]}}}, fh)
        rep = os.path.join(self.tmp, "real_report.json")
        r = run_tool("pii_gate.py", "--egress", "--corpus", "T:" + os.path.join(st, "*.json"),
                     "--report", rep)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(T.read_report(rep), (1, 0))
        self.assertTrue(self.run_template(rep, self.baseline(1)).wasSuccessful())
        self.assertFalse(self.run_template(rep, self.baseline(0)).wasSuccessful())


if __name__ == "__main__":
    unittest.main()
