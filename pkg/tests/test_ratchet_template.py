"""THE EGRESS RATCHET -- a test template an instance adopts (X12).

THE RULE. Reachable blocking findings may only FALL between releases, and the
ingress/egress disagreement stays at ZERO. A count that rises is a regression
in the index a reader queries; a non-zero disagreement is a broken propagation
path (a source scrubbed, a derived envelope not rebuilt) -- the only symptom
such a break emits.

WHAT IT READS.

  the egress report   the JSON `pii_gate.py --egress --report FILE` writes:
                      {"blocking": <int>, "disagreement": {<kind>: <int>}, ...}
  the baseline        a small committed text file, one `key=value` per line:
                          reachable_blocking=<int>
                      `#` comments allowed. It is the instance's ratchet: it is
                      lowered (never raised) when the count falls.

WHERE IT LOOKS. The environment variables OUTIS_EGRESS_REPORT and
OUTIS_RATCHET_BASELINE, else the constants REPORT_PATH and BASELINE_PATH below,
which an adopting instance edits in its own copy.

VERDICTS.

  no report at all             SKIPPED, never passed: "not checked" and "checked
                               and clean" must not look alike.
  report, no/broken baseline   FAILS: an instance that produces a report has
                               adopted the ratchet and must commit its baseline.
  blocking > baseline          FAILS (a rise).
  blocking <= baseline         passes; when it fell, the message says to lower
                               the committed baseline to the new count.
  disagreement != 0            FAILS, whatever the count.

ADOPTION (README.md, "The egress ratchet"): copy this file into the instance's
own test tree, run `pii_gate.py --egress --report <report>` before the suite,
write `reachable_blocking=<that report's blocking>` to the baseline file and
commit it. In this package no report exists, so the test SKIPS.
"""
import json
import os
import unittest

try:                                    # inside the package
    from _support import oracle
except ImportError:                     # adopted elsewhere: tag-only shim
    def oracle(cls, authority):
        def deco(fn):
            fn.__oracle__ = (cls, authority)
            return fn
        return deco

REPORT_PATH = None          # an adopting instance sets these two
BASELINE_PATH = None
REPORT_ENV = "OUTIS_EGRESS_REPORT"
BASELINE_ENV = "OUTIS_RATCHET_BASELINE"


class RatchetError(ValueError):
    """The report or the baseline cannot be read as the ratchet's inputs."""


def read_baseline(path):
    """{key: int} from a baseline file; `reachable_blocking` is required."""
    out = {}
    with open(path, encoding="ascii") as fh:
        for n, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise RatchetError("baseline line %d: expected key=value" % n)
            k, v = (x.strip() for x in line.split("=", 1))
            if not v.isdigit():
                raise RatchetError("baseline line %d: %s is not a count" % (n, k))
            out[k] = int(v)
    if "reachable_blocking" not in out:
        raise RatchetError("baseline has no reachable_blocking=<count> line")
    return out


def read_report(path):
    """(blocking, disagreement_total) from a pii_gate --egress JSON report."""
    with open(path, encoding="ascii") as fh:
        rep = json.load(fh)
    try:
        blocking = int(rep["blocking"])
        dis = sum(int(v) for v in rep.get("disagreement", {}).values())
    except (KeyError, TypeError, ValueError, AttributeError):
        raise RatchetError("not an egress report: needs 'blocking' and 'disagreement'")
    return blocking, dis


def ratchet_violations(blocking, disagreement, baseline):
    """[messages]; empty means the ratchet holds. The ONE comparison."""
    out = []
    if blocking > baseline:
        out.append("reachable blocking findings ROSE: %d now, baseline %d"
                   % (blocking, baseline))
    if disagreement != 0:
        out.append("ingress/egress disagreement is %d, must be 0" % disagreement)
    return out


def configured_paths(environ=None):
    environ = os.environ if environ is None else environ
    return (environ.get(REPORT_ENV) or REPORT_PATH,
            environ.get(BASELINE_ENV) or BASELINE_PATH)


class EgressRatchet(unittest.TestCase):

    @oracle("human", "the reference instance's egress ratchet, ruled there: "
            "reachable blocking findings may only fall between releases and the "
            "ingress/egress disagreement must stay at zero.")
    def test_reachable_blocking_only_falls_and_disagreement_is_zero(self):
        report, baseline = configured_paths()
        if not report or not os.path.exists(report):
            self.skipTest("no egress report configured (%s): the ratchet was "
                          "NOT checked" % REPORT_ENV)
        if not baseline or not os.path.exists(baseline):
            self.fail("an egress report exists but no baseline is committed "
                      "(%s): adopt the ratchet by committing "
                      "reachable_blocking=<count>" % BASELINE_ENV)
        try:
            blocking, dis = read_report(report)
            base = read_baseline(baseline)["reachable_blocking"]
        except (RatchetError, OSError, ValueError) as e:
            self.fail("ratchet inputs unreadable: %s" % e)
        bad = ratchet_violations(blocking, dis, base)
        self.assertEqual(bad, [], "; ".join(bad))
        if blocking < base:
            print("\n  ratchet: blocking fell %d -> %d; lower the committed "
                  "baseline to reachable_blocking=%d" % (base, blocking, blocking))


if __name__ == "__main__":
    unittest.main()
